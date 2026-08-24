import { execFile } from 'node:child_process'
import { mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { promisify } from 'node:util'
import { Context } from '@deepseek-ai/cordis'
import TypertGatewayService from '@deepseek-ai/dsh-api-gateway'
import TypertRegistry, { type TypertContribution } from '@deepseek-ai/dsh-typert-registry'
import { TYPERT } from 'dsh-security-assurance/typert'
import { afterEach, describe, expect, it } from 'vitest'
import SecurityAssuranceService, {
  RISK_DECISION_WINDOW_CONTROL_ID,
  type AssessmentId,
  type AssessmentSnapshotV1,
  type FindingDetailViewV1,
  type FindingListPageV1,
  type SecurityResult,
} from '../src/index.ts'
import SecurityAssuranceWorkbenchRemote, {
  type AuthenticatedWorkbenchOperatorV1,
  type WorkbenchAuthorityContextId,
  type WorkbenchEvidenceMetadataViewV1,
} from '../src/workbench-remote.ts'
import { referenceHostInvocation } from './support/reference-host.ts'

const run = promisify(execFile)
const temporaryRoots: string[] = []
const contexts: Context[] = []

afterEach(async () => {
  await Promise.all(contexts.splice(0).map(ctx => ctx.fiber.dispose()))
  await Promise.all(temporaryRoots.splice(0).map(path => rm(path, { recursive: true, force: true })))
})

function authorityContextId(value: string): WorkbenchAuthorityContextId {
  return value as WorkbenchAuthorityContextId
}

async function repositoryFixture(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), 'dsh-security-workbench-repository-'))
  temporaryRoots.push(root)
  await run('git', ['init', '-b', 'main'], { cwd: root })
  await run('git', ['config', 'user.email', 'fixture@example.invalid'], { cwd: root })
  await run('git', ['config', 'user.name', 'Fixture'], { cwd: root })
  await writeFile(join(root, 'package.json'), `${JSON.stringify({
    name: 'workbench-risk-decision-fixture',
    version: '1.0.0',
    scripts: { postinstall: 'node setup.js' },
  }, null, 2)}\n`, 'utf8')
  await run('git', ['add', '.'], { cwd: root })
  await run('git', ['commit', '-m', 'workbench fixture'], { cwd: root })
  return root
}

async function waitUntilBlocked(ctx: Context, assessmentId: AssessmentId): Promise<void> {
  const invocation = referenceHostInvocation(ctx.securityAssurance)
  let revision = 1
  for (let attempt = 0; attempt < 5; attempt += 1) {
    const changed = await ctx.securityAssurance.waitForAssessmentRevision(invocation, {
      schemaVersion: 1,
      assessmentId,
      afterRevision: revision,
      timeoutMs: 5_000,
    })
    if (!changed.ok) throw new Error(`wait failed: ${changed.error.code}`)
    const current = await ctx.securityAssurance.getAssessment(invocation, {
      schemaVersion: 1,
      assessmentId,
    })
    if (!current.ok) throw new Error(`query failed: ${current.error.code}`)
    if (current.value.state === 'BLOCKED') return
    revision = current.value.assessmentRevision
  }
  throw new Error('Assessment did not open its Risk Decision Window')
}

async function harness(strictTypert = false): Promise<{
  readonly ctx: Context
  readonly assessmentId: AssessmentId
  readonly resolvedContextIds: WorkbenchAuthorityContextId[]
  readonly remoteFiber: { dispose(): Promise<void> }
}> {
  const repository = await repositoryFixture()
  const dshHome = await mkdtemp(join(tmpdir(), 'dsh-security-workbench-home-'))
  temporaryRoots.push(dshHome)
  const ctx = new Context()
  contexts.push(ctx)
  await ctx.plugin(TypertRegistry)
  if (strictTypert) ctx.typert.register(TYPERT as TypertContribution)
  await ctx.plugin(SecurityAssuranceService, { dshHome })
  await ctx.securityAssurance.whenReady()
  const resolvedContextIds: WorkbenchAuthorityContextId[] = []
  const operators = new Map<WorkbenchAuthorityContextId, AuthenticatedWorkbenchOperatorV1>([
    [authorityContextId('workbench-session-reviewer'), {
      principalId: 'workbench-reviewer',
      permissions: ['assessment:read', 'risk:decide'],
    }],
    [authorityContextId('workbench-session-disclosure-reviewer'), {
      principalId: 'workbench-disclosure-reviewer',
      permissions: ['assessment:read', 'evidence:disclose:validation-review'],
    }],
    [authorityContextId('workbench-session-cancellation-operator'), {
      principalId: 'workbench-cancellation-operator',
      permissions: ['assessment:read', 'assessment:cancel'],
    }],
    [authorityContextId('workbench-session-starter'), {
      principalId: 'workbench-starter',
      permissions: ['repository:read', 'assessment:start', 'assessment:read'],
    }],
  ])
  const remoteFiber = await ctx.plugin(SecurityAssuranceWorkbenchRemote, {
    async resolveAuthorityContext(contextId: WorkbenchAuthorityContextId) {
      resolvedContextIds.push(contextId)
      return operators.get(contextId)
    },
  })
  await ctx.plugin(TypertGatewayService)

  const hostInvocation = referenceHostInvocation(ctx.securityAssurance)
  const registered = await ctx.securityAssurance.registerRepository(hostInvocation, {
    schemaVersion: 1,
    idempotencyKey: 'workbench-repository-register-v1',
    root: repository,
    displayName: 'Workbench fixture',
    bindings: {
      policyId: 'security/node-package-lifecycle',
      assessmentProfileId: 'security/standard',
      evidenceProtectionId: 'evidence/local-protected',
      dataEgressPolicyId: 'egress/deny-by-default',
      platform: process.platform as 'win32' | 'linux' | 'darwin',
      deliveryDestinationIds: [],
    },
  })
  if (!registered.ok) throw new Error(`registration failed: ${registered.error.code}`)
  const started = await ctx.securityAssurance.startAssessment(hostInvocation, {
    schemaVersion: 1,
    idempotencyKey: 'workbench-assessment-start-v1',
    repositoryId: registered.value.repositoryId,
    subject: { kind: 'workspace_snapshot' },
    assessmentMode: 'REPOSITORY',
    assessmentProfileId: 'security/standard',
    target: { kind: 'repository' },
    requestedStrongerControlIds: [RISK_DECISION_WINDOW_CONTROL_ID],
  })
  if (!started.ok) throw new Error(`start failed: ${started.error.code}`)
  await waitUntilBlocked(ctx, started.value.assessmentId)
  return { ctx, assessmentId: started.value.assessmentId, resolvedContextIds, remoteFiber }
}

describe('Security Assurance Workbench Remote', () => {
  it('lists Repositories, resolves a digest-bound preflight, and confirms the exact start', async () => {
    const { ctx, resolvedContextIds } = await harness(true)
    const authorityId = authorityContextId('workbench-session-starter')
    const repositories = await ctx.typertGateway.invoke({
      namespace: 'securityAssuranceWorkbench',
      method: 'listRepositories',
      args: {
        securityAssuranceWorkbenchContextId: authorityId,
        request: { schemaVersion: 1, limit: 50, state: 'ENABLED' },
      },
    }) as SecurityResult<import('../src/index.ts').RepositoryListSnapshotV1>
    if (!repositories.ok || repositories.value.repositories[0] === undefined) {
      throw new Error('Workbench starter could not list the Repository')
    }
    const repository = repositories.value.repositories[0]
    const selection = {
      schemaVersion: 1 as const,
      repositoryId: repository.repositoryId,
      subject: { kind: 'workspace_snapshot' as const },
      assessmentMode: 'REPOSITORY' as const,
      assessmentProfileId: repository.bindings.assessmentProfileId,
      target: { kind: 'repository' as const },
      requestedStrongerControlIds: [],
    }
    const catalog = await ctx.typertGateway.invoke({
      namespace: 'securityAssuranceWorkbench',
      method: 'getCatalog',
      args: {
        securityAssuranceWorkbenchContextId: authorityId,
        request: {
          schemaVersion: 1,
          repositoryId: repository.repositoryId,
          proposedStart: selection,
        },
      },
    }) as SecurityResult<import('../src/index.ts').SecurityCatalogSnapshotV1>
    if (!catalog.ok || catalog.value.startPreflight === null) {
      throw new Error('Workbench starter could not resolve Start Preflight')
    }
    expect(catalog.value.startPreflight).toMatchObject({
      admissible: true,
      selection,
      dataEgress: { categories: ['NONE'] },
    })

    await expect(ctx.typertGateway.invoke({
      namespace: 'securityAssuranceWorkbench',
      method: 'startAssessment',
      args: {
        securityAssuranceWorkbenchContextId: authorityId,
        request: {
          ...selection,
          idempotencyKey: 'workbench-confirmed-start-v1',
          startPreflightDigest: catalog.value.startPreflight.proposalDigest,
        },
      },
    })).resolves.toMatchObject({
      ok: true,
      value: {
        operation: 'start_assessment',
        repositoryId: repository.repositoryId,
        state: 'CREATED',
      },
    })
    expect(resolvedContextIds).toEqual([authorityId, authorityId, authorityId])
  })

  it('lists only redacted Assessments through a freshly resolved Host authority', async () => {
    const { ctx, assessmentId, resolvedContextIds } = await harness()
    const authorityId = authorityContextId('workbench-session-reviewer')

    await expect(ctx.typertGateway.invoke({
      namespace: 'securityAssuranceWorkbench',
      method: 'listAssessments',
      args: {
        securityAssuranceWorkbenchContextId: authorityId,
        request: { schemaVersion: 1, limit: 50 },
      },
    })).resolves.toMatchObject({
      ok: true,
      value: {
        assessments: [{ assessmentId }],
        nextCursor: null,
      },
    })
    expect(resolvedContextIds).toEqual([authorityId])
  })

  it('lists redacted Finding summaries through freshly resolved Host authority', async () => {
    const { ctx, assessmentId, resolvedContextIds } = await harness()
    const authorityId = authorityContextId('workbench-session-reviewer')

    const listed = await ctx.typertGateway.invoke({
      namespace: 'securityAssuranceWorkbench',
      method: 'listFindings',
      args: {
        securityAssuranceWorkbenchContextId: authorityId,
        request: { schemaVersion: 1, assessmentId, limit: 50 },
      },
    }) as SecurityResult<FindingListPageV1>

    expect(listed).toMatchObject({
      ok: true,
      value: {
        assessmentId,
        findings: [{
          recordKind: 'FINDING',
          validationState: 'VALIDATED',
          technicalSeverity: 'MEDIUM',
          policySignificance: 'BLOCKING',
          hasProtectedDetail: true,
        }],
        nextCursor: null,
      },
    })
    expect(JSON.stringify(listed)).not.toContain('sourceAnchor')
    expect(JSON.stringify(listed)).not.toContain('evidenceLinks')
    expect(resolvedContextIds).toEqual([authorityId])
  })

  it('reads one exact revision-bound Finding Detail without Evidence payload', async () => {
    const { ctx, assessmentId, resolvedContextIds } = await harness()
    const authorityId = authorityContextId('workbench-session-reviewer')
    const listed = await ctx.typertGateway.invoke({
      namespace: 'securityAssuranceWorkbench',
      method: 'listFindings',
      args: {
        securityAssuranceWorkbenchContextId: authorityId,
        request: { schemaVersion: 1, assessmentId, limit: 50 },
      },
    }) as SecurityResult<FindingListPageV1>
    if (!listed.ok || listed.value.findings[0] === undefined) {
      throw new Error('Workbench fixture did not project a Finding')
    }
    const summary = listed.value.findings[0]

    const detail = await ctx.typertGateway.invoke({
      namespace: 'securityAssuranceWorkbench',
      method: 'getFinding',
      args: {
        securityAssuranceWorkbenchContextId: authorityId,
        request: {
          schemaVersion: 1,
          assessmentId,
          assessmentRevision: summary.assessmentRevision,
          recordId: summary.recordId,
          recordRevision: summary.recordRevision,
        },
      },
    }) as SecurityResult<FindingDetailViewV1>

    expect(detail).toMatchObject({
      ok: true,
      value: {
        assessmentId,
        assessmentRevision: summary.assessmentRevision,
        recordId: summary.recordId,
        recordRevision: summary.recordRevision,
        sourceAnchor: { path: 'package.json' },
        validation: { state: 'VALIDATED' },
        technicalSeverity: { value: 'MEDIUM' },
        evidenceConfidence: { value: 'HIGH' },
        policySignificance: 'BLOCKING',
      },
    })
    expect(JSON.stringify(detail)).not.toContain('contentBase64')
    expect(JSON.stringify(detail)).not.toContain('storagePath')
    expect(resolvedContextIds).toEqual([authorityId, authorityId])
  })

  it('reads metadata-only Evidence through a freshly resolved Host authority', async () => {
    const { ctx, assessmentId, resolvedContextIds } = await harness(true)
    const authorityId = authorityContextId('workbench-session-reviewer')
    const blocked = await ctx.typertGateway.invoke({
      namespace: 'securityAssuranceWorkbench',
      method: 'getAssessment',
      args: {
        securityAssuranceWorkbenchContextId: authorityId,
        request: { schemaVersion: 1, assessmentId },
      },
    }) as SecurityResult<AssessmentSnapshotV1>
    if (!blocked.ok) throw new Error(`remote query failed: ${blocked.error.code}`)
    const action = blocked.value.availableActions.find(candidate =>
      candidate.kind === 'RECORD_RISK_DECISION')
    if (action?.kind !== 'RECORD_RISK_DECISION') {
      throw new Error('Risk Decision action was not projected')
    }
    await expect(ctx.typertGateway.invoke({
      namespace: 'securityAssuranceWorkbench',
      method: 'recordRiskDecision',
      args: {
        securityAssuranceWorkbenchContextId: authorityId,
        request: {
          schemaVersion: 1,
          idempotencyKey: 'workbench-evidence-risk-denial-v1',
          assessmentId,
          expectedAssessmentRevision: action.expectedAssessmentRevision,
          finding: action.finding,
          decision: 'DENY',
          rationale: 'The blocking Finding remains denied before Evidence metadata review.',
          compensatingControls: [],
          expiresAt: null,
        },
      },
    })).resolves.toMatchObject({ ok: true, value: { operation: 'record_risk_decision' } })

    const listed = await ctx.typertGateway.invoke({
      namespace: 'securityAssuranceWorkbench',
      method: 'listFindings',
      args: {
        securityAssuranceWorkbenchContextId: authorityId,
        request: { schemaVersion: 1, assessmentId, limit: 50 },
      },
    }) as SecurityResult<FindingListPageV1>
    if (!listed.ok || listed.value.findings[0] === undefined) {
      throw new Error('Sealed Workbench fixture did not project a Finding')
    }
    const summary = listed.value.findings[0]
    const detail = await ctx.typertGateway.invoke({
      namespace: 'securityAssuranceWorkbench',
      method: 'getFinding',
      args: {
        securityAssuranceWorkbenchContextId: authorityId,
        request: {
          schemaVersion: 1,
          assessmentId,
          assessmentRevision: summary.assessmentRevision,
          recordId: summary.recordId,
          recordRevision: summary.recordRevision,
        },
      },
    }) as SecurityResult<FindingDetailViewV1>
    if (!detail.ok || detail.value.evidenceLinks[0] === undefined) {
      throw new Error('Sealed Finding Detail did not expose an Evidence Link')
    }
    const link = detail.value.evidenceLinks[0]

    const view = await ctx.typertGateway.invoke({
      namespace: 'securityAssuranceWorkbench',
      method: 'getEvidenceView',
      args: {
        securityAssuranceWorkbenchContextId: authorityId,
        request: {
          schemaVersion: 1,
          assessmentId,
          assessmentRevision: detail.value.assessmentRevision,
          context: {
            kind: 'finding',
            recordId: detail.value.recordId,
            recordRevision: detail.value.recordRevision,
          },
          evidenceArtifactId: link.artifactId,
          evidenceDigest: link.digest,
          purpose: 'FINDING_TRIAGE',
          viewProfileId: 'security/evidence-view/metadata-only-v1',
        },
      },
    }) as SecurityResult<WorkbenchEvidenceMetadataViewV1>

    expect(view).toMatchObject({
      ok: true,
      value: {
        assessmentId,
        assessmentRevision: detail.value.assessmentRevision,
        context: {
          kind: 'finding',
          recordId: detail.value.recordId,
          recordRevision: detail.value.recordRevision,
        },
        evidence: {
          artifactId: link.artifactId,
          digest: link.digest,
          classification: 'CONTROL_PLANE',
        },
        link: {
          purpose: link.purpose,
          eligibilityDecision: link.eligibilityDecision,
          eligibilityDecisionArtifactId: link.eligibilityDecisionArtifactId,
        },
        purpose: 'FINDING_TRIAGE',
        viewProfileId: 'security/evidence-view/metadata-only-v1',
        protection: { policyId: 'evidence/local-protected', status: 'AVAILABLE' },
        retention: { status: 'RETAINED' },
        egress: { policyId: 'egress/deny-by-default', status: 'LOCAL_ONLY' },
        content: { kind: 'REDACTED', reason: 'PROFILE_METADATA_ONLY' },
      },
    })
    const serialized = JSON.stringify(view)
    expect(serialized).not.toContain('storagePath')
    expect(serialized).not.toContain('encryptionKey')
    expect(serialized).not.toContain('contentBase64')
    expect(serialized).not.toContain('postinstall')
    expect(serialized).not.toContain('principalId')
    expect(serialized).not.toContain('workbench-reviewer')
    expect(resolvedContextIds).toEqual(Array.from({ length: 5 }, () => authorityId))
  })

  it('does not expose the bounded-content Evidence Profile through the metadata Remote', async () => {
    const { ctx, assessmentId, resolvedContextIds } = await harness(true)
    const authorityId = authorityContextId('workbench-session-reviewer')

    await expect(ctx.typertGateway.invoke({
      namespace: 'securityAssuranceWorkbench',
      method: 'getEvidenceView',
      args: {
        securityAssuranceWorkbenchContextId: authorityId,
        request: {
          schemaVersion: 1,
          assessmentId,
          assessmentRevision: 1,
          context: {
            kind: 'finding',
            recordId: `finding-${'a'.repeat(64)}`,
            recordRevision: 1,
          },
          evidenceArtifactId: 'evidence/reference-bounded-json',
          evidenceDigest: {
            schemaVersion: 1,
            algorithm: 'sha256',
            mediaType: 'application/vnd.dsh.canonical-json',
            byteLength: 1,
            canonicalization: 'dsh-canonical-json-v1',
            value: '0'.repeat(64),
          },
          purpose: 'VALIDATION_REVIEW',
          viewProfileId: 'security/evidence-view/bounded-json-v1',
        },
      },
    })).rejects.toMatchObject({ code: 'input-invalid' })
    expect(resolvedContextIds).toEqual([authorityId])
  })

  it('discloses one expiring bounded Evidence View only through a separate freshly authorized Remote action', async () => {
    const { ctx, assessmentId, resolvedContextIds } = await harness(true)
    const hostInvocation = referenceHostInvocation(ctx.securityAssurance)
    const blocked = await ctx.securityAssurance.getAssessment(hostInvocation, {
      schemaVersion: 1,
      assessmentId,
    })
    if (!blocked.ok) throw new Error(`query failed: ${blocked.error.code}`)
    const action = blocked.value.availableActions.find(candidate =>
      candidate.kind === 'RECORD_RISK_DECISION')
    if (action?.kind !== 'RECORD_RISK_DECISION') {
      throw new Error('Risk Decision action was not projected')
    }
    const denied = await ctx.securityAssurance.recordRiskDecision(hostInvocation, {
      schemaVersion: 1,
      idempotencyKey: 'workbench-bounded-evidence-risk-denial-v1',
      assessmentId,
      expectedAssessmentRevision: action.expectedAssessmentRevision,
      finding: action.finding,
      decision: 'DENY',
      rationale: 'The blocking Finding remains denied before bounded Evidence review.',
      compensatingControls: [],
      expiresAt: null,
    })
    if (!denied.ok) throw new Error(`risk denial failed: ${denied.error.code}`)
    const listed = await ctx.securityAssurance.listFindings(hostInvocation, {
      schemaVersion: 1,
      assessmentId,
      limit: 50,
    })
    if (!listed.ok || listed.value.findings[0] === undefined) {
      throw new Error('Sealed Workbench fixture did not project a Finding')
    }
    const summary = listed.value.findings[0]
    const detail = await ctx.securityAssurance.getFinding(hostInvocation, {
      schemaVersion: 1,
      assessmentId,
      assessmentRevision: summary.assessmentRevision,
      recordId: summary.recordId,
      recordRevision: summary.recordRevision,
    })
    if (!detail.ok || detail.value.evidenceLinks[0] === undefined) {
      throw new Error('Sealed Finding Detail did not expose an Evidence Link')
    }
    const link = detail.value.evidenceLinks[0]
    const authorityId = authorityContextId('workbench-session-disclosure-reviewer')
    const request = {
      schemaVersion: 1 as const,
      assessmentId,
      assessmentRevision: detail.value.assessmentRevision,
      context: {
        kind: 'finding' as const,
        recordId: detail.value.recordId,
        recordRevision: detail.value.recordRevision,
      },
      evidenceArtifactId: link.artifactId,
      evidenceDigest: link.digest,
      purpose: 'VALIDATION_REVIEW' as const,
      viewProfileId: 'security/evidence-view/bounded-json-v1' as const,
    }
    const startedAt = Date.now()

    const view = await ctx.typertGateway.invoke({
      namespace: 'securityAssuranceWorkbench',
      method: 'discloseEvidence',
      args: {
        securityAssuranceWorkbenchContextId: authorityId,
        request,
      },
    })
    const completedAt = Date.now()

    expect(view).toMatchObject({
      ok: true,
      value: {
        assessmentId,
        assessmentRevision: detail.value.assessmentRevision,
        context: {
          kind: 'finding',
          recordId: detail.value.recordId,
          recordRevision: detail.value.recordRevision,
        },
        evidence: {
          artifactId: link.artifactId,
          digest: link.digest,
          classification: 'CONTROL_PLANE',
        },
        purpose: 'VALIDATION_REVIEW',
        viewProfileId: 'security/evidence-view/bounded-json-v1',
        content: {
          kind: 'BOUNDED_JSON',
          byteLength: expect.any(Number),
          expiresAt: expect.any(String),
          value: {
            schemaVersion: 1,
            manifests: expect.arrayContaining([expect.objectContaining({
              path: 'package.json',
              parseStatus: 'VALID',
              installLifecycleScripts: ['postinstall'],
            })]),
          },
        },
      },
    })
    const expiresAt = Date.parse((view as {
      readonly value: { readonly content: { readonly expiresAt: string } }
    }).value.content.expiresAt)
    expect(expiresAt).toBeGreaterThanOrEqual(startedAt + 5 * 60_000)
    expect(expiresAt).toBeLessThanOrEqual(completedAt + 5 * 60_000)
    expect(JSON.stringify(view)).not.toContain('node setup.js')
    expect(JSON.stringify(view)).not.toContain('principalId')
    expect(JSON.stringify(view)).not.toContain('storagePath')
    const metadataAuthorityId = authorityContextId('workbench-session-reviewer')
    await expect(ctx.typertGateway.invoke({
      namespace: 'securityAssuranceWorkbench',
      method: 'discloseEvidence',
      args: {
        securityAssuranceWorkbenchContextId: metadataAuthorityId,
        request,
      },
    })).resolves.toMatchObject({
      ok: true,
      value: {
        purpose: 'VALIDATION_REVIEW',
        viewProfileId: 'security/evidence-view/bounded-json-v1',
        content: { kind: 'REDACTED', reason: 'DISCLOSURE_NOT_AUTHORIZED' },
      },
    })
    expect(resolvedContextIds).toEqual([authorityId, metadataAuthorityId])
  })

  it('exposes bounded revision signals through the authenticated Remote seam', async () => {
    const { ctx, assessmentId } = await harness()
    const authorityId = authorityContextId('workbench-session-reviewer')

    await expect(ctx.typertGateway.invoke({
      namespace: 'securityAssuranceWorkbench',
      method: 'waitForAssessmentRevision',
      args: {
        securityAssuranceWorkbenchContextId: authorityId,
        request: {
          schemaVersion: 1,
          assessmentId,
          afterRevision: 1,
          timeoutMs: 1_000,
        },
      },
    })).resolves.toMatchObject({
      ok: true,
      value: {
        assessmentId,
        kind: 'CHANGED',
      },
    })
  })

  it('derives Host Operator authority outside the wire request and projects available actions', async () => {
    const { ctx, assessmentId, resolvedContextIds } = await harness()

    const result = await ctx.typertGateway.invoke({
      namespace: 'securityAssuranceWorkbench',
      method: 'getAssessment',
      args: {
        securityAssuranceWorkbenchContextId: authorityContextId('workbench-session-reviewer'),
        request: { schemaVersion: 1, assessmentId },
      },
    })

    expect(result).toMatchObject({
      ok: true,
      value: {
        assessmentId,
        state: 'BLOCKED',
        blockedRecovery: {
          blocker: {
            code: 'RISK_DECISION_WINDOW',
            phase: 'RISK_DECISION',
            interruption: 'GOVERNANCE_HOLD',
          },
          evidence: { status: 'RETAINED', publishedArtifactCount: expect.any(Number) },
          recovery: {
            requiredCondition: 'RISK_DECISION_REQUIRED',
            remainingExecutionBudget: { status: 'NOT_REPORTED' },
          },
        },
        availableActions: [{
          kind: 'RECORD_RISK_DECISION',
          finding: { recordRevision: 1 },
          options: [
            { decision: 'DENY', consequence: 'KEEPS_FINDING_BLOCKING' },
            { decision: 'ACCEPT', consequence: 'MAKES_FINDING_NON_BLOCKING' },
          ],
        }],
      },
    })
    expect(resolvedContextIds).toEqual([authorityContextId('workbench-session-reviewer')])

    await expect(ctx.typertGateway.invoke({
      namespace: 'securityAssuranceWorkbench',
      method: 'getAssessment',
      args: {
        securityAssuranceWorkbenchContextId: authorityContextId('workbench-session-reviewer'),
        principalId: 'browser-forged-principal',
        permissions: ['risk:break-glass'],
        request: { schemaVersion: 1, assessmentId },
      },
    })).rejects.toMatchObject({ code: 'arguments-invalid' })
    expect(resolvedContextIds).toHaveLength(1)
  })

  it('commits a cancellation request through the authenticated Remote without claiming terminal cancellation', async () => {
    const { ctx, assessmentId } = await harness()
    const authorityId = authorityContextId('workbench-session-cancellation-operator')
    const snapshot = await ctx.typertGateway.invoke({
      namespace: 'securityAssuranceWorkbench',
      method: 'getAssessment',
      args: {
        securityAssuranceWorkbenchContextId: authorityId,
        request: { schemaVersion: 1, assessmentId },
      },
    }) as SecurityResult<AssessmentSnapshotV1>
    if (!snapshot.ok) throw new Error(`remote query failed: ${snapshot.error.code}`)
    const action = snapshot.value.availableActions.find(candidate =>
      candidate.kind === 'CANCEL_ASSESSMENT')
    if (action?.kind !== 'CANCEL_ASSESSMENT') throw new Error('Cancel action was not projected')

    const receipt = await ctx.typertGateway.invoke({
      namespace: 'securityAssuranceWorkbench',
      method: 'cancelAssessment',
      args: {
        securityAssuranceWorkbenchContextId: authorityId,
        request: {
          schemaVersion: 1,
          assessmentId,
          expectedAssessmentRevision: action.expectedAssessmentRevision,
          idempotencyKey: 'workbench-cancel-blocked-v1',
          reason: {
            code: 'OPERATOR_CANCEL',
            summary: 'Cancel the blocked assessment after retaining all published Evidence.',
          },
        },
      },
    })
    expect(receipt).toMatchObject({
      ok: true,
      value: {
        operation: 'cancel_assessment',
        assessmentId,
        assessmentRevision: action.expectedAssessmentRevision + 1,
        acceptedState: 'BLOCKED',
      },
    })
  })

  it('records one revision-bound Risk Decision and exposes the same Service truth', async () => {
    const { ctx, assessmentId } = await harness()
    const authorityId = authorityContextId('workbench-session-reviewer')
    const snapshot = await ctx.typertGateway.invoke({
      namespace: 'securityAssuranceWorkbench',
      method: 'getAssessment',
      args: {
        securityAssuranceWorkbenchContextId: authorityId,
        request: { schemaVersion: 1, assessmentId },
      },
    }) as SecurityResult<AssessmentSnapshotV1>
    if (!snapshot.ok) throw new Error(`remote query failed: ${snapshot.error.code}`)
    const action = snapshot.value.availableActions.find(candidate =>
      candidate.kind === 'RECORD_RISK_DECISION')
    if (action?.kind !== 'RECORD_RISK_DECISION') {
      throw new Error('Risk Decision action was not projected')
    }
    const request = {
      schemaVersion: 1 as const,
      idempotencyKey: 'workbench-risk-denial-v1',
      assessmentId,
      expectedAssessmentRevision: action.expectedAssessmentRevision,
      finding: action.finding,
      decision: 'DENY' as const,
      rationale: 'The blocking Finding remains denied and must be remediated before release.',
      compensatingControls: [],
      expiresAt: null,
    }

    const receipt = await ctx.typertGateway.invoke({
      namespace: 'securityAssuranceWorkbench',
      method: 'recordRiskDecision',
      args: { securityAssuranceWorkbenchContextId: authorityId, request },
    })
    expect(receipt).toMatchObject({
      ok: true,
      value: {
        operation: 'record_risk_decision',
        assessmentId,
        decision: 'DENY',
        resolution: 'DENIED',
        idempotencyKey: request.idempotencyKey,
      },
    })
    await expect(ctx.typertGateway.invoke({
      namespace: 'securityAssuranceWorkbench',
      method: 'recordRiskDecision',
      args: { securityAssuranceWorkbenchContextId: authorityId, request },
    })).resolves.toEqual(receipt)

    const hostSnapshot = await ctx.securityAssurance.getAssessment(
      referenceHostInvocation(ctx.securityAssurance),
      { schemaVersion: 1, assessmentId },
    )
    expect(hostSnapshot).toMatchObject({
      ok: true,
      value: {
        state: 'SEALED',
        verdict: 'FAILED',
        availableActions: [],
      },
    })
  })

  it('maps cancellation, fails closed on missing authority, and withdraws only its adapter state', async () => {
    const { ctx, assessmentId, resolvedContextIds, remoteFiber } = await harness()
    const abort = new AbortController()
    abort.abort()
    await expect(ctx.typertGateway.invoke({
      namespace: 'securityAssuranceWorkbench',
      method: 'getAssessment',
      args: {
        securityAssuranceWorkbenchContextId: authorityContextId('workbench-session-reviewer'),
        request: { schemaVersion: 1, assessmentId },
      },
      signal: abort.signal,
    })).resolves.toMatchObject({ ok: false, error: { code: 'CANCELED' } })

    await expect(ctx.typertGateway.invoke({
      namespace: 'securityAssuranceWorkbench',
      method: 'getAssessment',
      args: {
        securityAssuranceWorkbenchContextId: authorityContextId('workbench-session-unknown'),
        request: { schemaVersion: 1, assessmentId },
      },
    })).rejects.toMatchObject({ code: 'lookup-not-found' })
    await expect(ctx.typertGateway.invoke({
      namespace: 'securityAssuranceWorkbench',
      method: 'getAssessment',
      args: {
        securityAssuranceWorkbenchContextId: authorityContextId('short'),
        request: { schemaVersion: 1, assessmentId },
      },
    })).rejects.toMatchObject({ code: 'lookup-not-found' })
    expect(resolvedContextIds).toEqual([
      authorityContextId('workbench-session-reviewer'),
      authorityContextId('workbench-session-unknown'),
    ])

    await remoteFiber.dispose()
    expect(ctx.typert.lookups.get('securityAssuranceWorkbenchContext')).toBeUndefined()
    const rootResult = await ctx.securityAssurance.getAssessment(
      referenceHostInvocation(ctx.securityAssurance),
      { schemaVersion: 1, assessmentId },
    )
    expect(rootResult).toMatchObject({ ok: true, value: { assessmentId } })
    await expect(ctx.typertGateway.invoke({
      namespace: 'securityAssuranceWorkbench',
      method: 'getAssessment',
      args: {
        securityAssuranceWorkbenchContextId: authorityContextId('workbench-session-reviewer'),
        request: { schemaVersion: 1, assessmentId },
      },
    })).rejects.toMatchObject({ code: 'invocation-unavailable' })
  })
})
