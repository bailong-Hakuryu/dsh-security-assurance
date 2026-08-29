import { Context } from '@deepseek-ai/cordis'
import {
  apply as applyClientRemote,
  inject as clientRemoteInject,
} from '../../deepseek-harness-master/packages/api/gateway/lib/types/client/index.js'
import TypertRegistry from '@deepseek-ai/dsh-typert-registry'
import { SlotRegistry } from '../../deepseek-harness-master/packages/client/runtime/lib/types/client/slots.js'
import { afterEach, describe, expect, it, vi } from 'vitest'
import type {
  AssessmentId,
  AssessmentListItemV1,
  AssessmentSnapshotV1,
  FindingDetailViewV1,
  FindingSummaryV1,
} from '../src/contracts.ts'
import {
  apply as applyWorkbenchClient,
  inject as workbenchClientInject,
  type SecurityAssuranceWorkbenchController,
  type WorkbenchAuthorityContextId,
} from '../src/client/index.ts'
import type {
  WorkbenchEvidenceDisclosureViewV1,
  WorkbenchEvidenceMetadataViewV1,
} from '../src/workbench-remote.ts'

const contexts: Context[] = []

afterEach(async () => {
  await Promise.all(contexts.splice(0).map(ctx => ctx.fiber.dispose()))
  vi.useRealTimers()
})

function assessmentId(value: string): AssessmentId {
  return value as AssessmentId
}

function authorityContextId(value: string): WorkbenchAuthorityContextId {
  return value as WorkbenchAuthorityContextId
}

async function installClientUiFoundation(ctx: Context): Promise<void> {
  await ctx.plugin(SlotRegistry)
  ctx.provide('locale', { register: () => () => {} } as never)
}

function snapshotAt(
  id: AssessmentId,
  revision: number,
  state: AssessmentSnapshotV1['state'],
): AssessmentSnapshotV1 {
  const digest = {
    schemaVersion: 1 as const,
    algorithm: 'sha256' as const,
    mediaType: 'application/vnd.dsh.canonical-json',
    byteLength: 1,
    canonicalization: 'dsh-canonical-json-v1' as const,
    value: '0'.repeat(64),
  }
  return {
    schemaVersion: 1,
    assessmentId: id,
    assessmentRevision: revision,
    state,
    repository: {
      repositoryId: 'repo-00000000-0000-0000-0000-000000000001',
      repositoryRevision: 1,
    },
    subject: { kind: 'workspace_snapshot', digest },
    contract: {
      schemaVersion: 1,
      assessmentMode: 'REPOSITORY',
      assessmentProfileId: 'security/standard',
      target: { kind: 'repository' },
      targetDigest: digest,
      requestedStrongerControlIds: [],
    },
    policy: { policyId: 'security/standard', digest },
    coverage: {
      status: 'PENDING',
      mandatoryObligations: 1,
      satisfiedObligations: 0,
      gapObligations: 0,
      resolutions: [],
      digest,
    },
    blockedRecovery: state === 'BLOCKED'
      ? {
          schemaVersion: 1,
          blocker: {
            code: 'ASSESSMENT_EXECUTION_FAILED',
            phase: 'ASSESSMENT_EXECUTION',
            interruption: 'FAILED',
            affectedObligations: [],
          },
          evidence: { status: 'RETAINED', publishedArtifactCount: null },
          recovery: {
            requiredCondition: 'EXPLICIT_RESUME_REQUIRED',
            remainingExecutionBudget: { status: 'NOT_REPORTED' },
            coverageReconciliation: { required: false, possibleVerdict: null },
          },
        }
      : null,
    availableActions: [],
    verdict: null,
    seal: null,
    createdAt: '2026-08-24T00:00:00.000Z',
    updatedAt: '2026-08-24T00:00:00.000Z',
  }
}

function assessmentListItem(id: AssessmentId, ordinal: number): AssessmentListItemV1 {
  return {
    schemaVersion: 1,
    assessmentId: id,
    assessmentRevision: ordinal,
    state: 'SEALED',
    repository: {
      repositoryId: `repo-00000000-0000-0000-0000-${String(ordinal).padStart(12, '0')}`,
      repositoryRevision: 1,
    } as AssessmentListItemV1['repository'],
    subjectKind: 'workspace_snapshot',
    policyId: 'security/standard',
    coverageStatus: 'COMPLETE',
    verdict: 'SATISFIED',
    createdAt: `2026-08-24T00:0${ordinal}:00.000Z`,
    updatedAt: `2026-08-24T00:0${ordinal}:30.000Z`,
  }
}

function findingSummary(
  id: AssessmentId,
  assessmentRevision: number,
  hex: string,
): FindingSummaryV1 {
  return {
    schemaVersion: 1,
    assessmentId: id,
    assessmentRevision,
    recordKind: 'FINDING',
    recordId: `finding-${hex.repeat(64)}`,
    candidateId: `candidate-${hex.repeat(64)}`,
    recordRevision: 1,
    validationState: 'VALIDATED',
    validationContractId: 'security/validation/reference-v1',
    weaknessClassification: {
      primary: 'cwe/79',
      secondary: [],
    },
    technicalSeverity: 'HIGH',
    evidenceConfidence: 'HIGH',
    policySignificance: 'BLOCKING',
    component: 'src',
    sensitivity: 'PROTECTED_DETAIL',
    coverageRelations: [{ obligationId: 'security/output-encoding', state: 'SATISFIED' }],
    hasProtectedDetail: true,
  }
}

function findingDetail(summary: FindingSummaryV1): FindingDetailViewV1 {
  const digest = {
    schemaVersion: 1 as const,
    algorithm: 'sha256' as const,
    mediaType: 'application/vnd.dsh.canonical-json',
    byteLength: 42,
    canonicalization: 'dsh-canonical-json-v1' as const,
    value: 'd'.repeat(64),
  }
  return {
    schemaVersion: 1,
    assessmentId: summary.assessmentId,
    assessmentRevision: summary.assessmentRevision,
    recordKind: summary.recordKind,
    recordId: summary.recordId,
    candidateId: summary.candidateId,
    recordRevision: summary.recordRevision,
    revisionChain: [{
      recordRevision: summary.recordRevision,
      supersedesRecordRevision: null,
      isCurrent: true,
    }],
    weaknessClassification: summary.weaknessClassification,
    affectedControlId: 'security/control/output-encoding',
    sourceAnchor: {
      path: 'src/render.ts',
      fileDigest: digest,
      locator: { kind: 'JSON_POINTER', value: '/render/html' },
    },
    validation: {
      state: summary.validationState,
      contractId: summary.validationContractId,
      contractVersion: 1,
      outcomeArtifactId: 'validation/outcome/reference',
      rejectionCondition: null,
      proofGaps: [],
      negativeControls: ['security/negative-control/encoded-output'],
    },
    technicalSeverity: {
      value: 'HIGH',
      methodVersion: 'security/severity/v1',
      inputs: [{ dimension: 'impact', value: 'account-takeover' }],
    },
    evidenceConfidence: {
      value: 'HIGH',
      methodVersion: 'security/confidence/v1',
      rubric: [{ dimension: 'reproducible', value: true }],
    },
    policySignificance: 'BLOCKING',
    coverageRelations: [{
      obligationId: 'security/output-encoding',
      state: 'SATISFIED',
      reason: 'ELIGIBLE_EVIDENCE',
    }],
    riskDecision: { state: 'NOT_RECORDED' },
    evidenceLinks: [{
      artifactId: 'evidence/reference-output-encoding',
      schemaId: 'security/evidence/reference-v1',
      digest,
      purpose: 'VALIDATION_EVIDENCE',
      eligibilityDecision: 'ELIGIBLE',
      eligibilityDecisionArtifactId: 'eligibility/reference-output-encoding',
    }],
    attackPath: { state: 'NOT_AVAILABLE' },
  }
}

function evidenceMetadataView(detail: FindingDetailViewV1): WorkbenchEvidenceMetadataViewV1 {
  const link = detail.evidenceLinks[0]
  if (link === undefined) throw new Error('Finding Detail fixture has no Evidence Link')
  return {
    schemaVersion: 1,
    assessmentId: detail.assessmentId,
    assessmentRevision: detail.assessmentRevision,
    context: {
      kind: 'finding',
      recordId: detail.recordId,
      recordRevision: detail.recordRevision,
    },
    evidence: {
      artifactId: link.artifactId,
      schemaId: link.schemaId,
      digest: link.digest,
      classification: 'CONTROL_PLANE',
    },
    link: {
      purpose: link.purpose,
      eligibilityDecision: link.eligibilityDecision,
      eligibilityDecisionArtifactId: link.eligibilityDecisionArtifactId,
    },
    producerLineage: {
      status: 'VERIFIED',
      producer: {
        analyzerId: 'security/reference-analyzer',
        analyzerVersion: '1.0.0',
        buildDigest: { ...link.digest, value: 'b'.repeat(64) },
      },
      lineageArtifactId: link.eligibilityDecisionArtifactId,
    },
    redactedSummary: {
      kind: 'SCHEMA_METADATA',
      byteLength: link.digest.byteLength,
      contentStatus: 'REDACTED',
    },
    purpose: 'FINDING_TRIAGE',
    viewProfileId: 'security/evidence-view/metadata-only-v1',
    protection: { policyId: 'evidence/local-protected', status: 'AVAILABLE' },
    retention: { status: 'RETAINED' },
    egress: { policyId: 'egress/deny-by-default', status: 'LOCAL_ONLY' },
    content: { kind: 'REDACTED', reason: 'PROFILE_METADATA_ONLY' },
  }
}

function evidenceDisclosureView(
  detail: FindingDetailViewV1,
  expiresAt: string,
): WorkbenchEvidenceDisclosureViewV1 {
  const metadata = evidenceMetadataView(detail)
  return {
    ...metadata,
    purpose: 'VALIDATION_REVIEW',
    viewProfileId: 'security/evidence-view/bounded-json-v1',
    content: {
      kind: 'BOUNDED_JSON',
      byteLength: 44,
      expiresAt,
      value: { schemaVersion: 1, proof: 'bounded-secret' },
    },
  }
}

async function openMetadataReadyFixture(options: {
  readonly id: AssessmentId
  readonly revision: number
  readonly findingHex: string
  readonly disclosure: (
    detail: FindingDetailViewV1,
    payload: unknown,
    signal: AbortSignal,
  ) => Promise<unknown>
}): Promise<{
  readonly controller: SecurityAssuranceWorkbenchController
  readonly detail: FindingDetailViewV1
  readonly metadata: WorkbenchEvidenceMetadataViewV1
  readonly authorityId: WorkbenchAuthorityContextId
}> {
  const ctx = new Context()
  contexts.push(ctx)
  await ctx.plugin(TypertRegistry)
  await installClientUiFoundation(ctx)
  const snapshot = snapshotAt(options.id, options.revision, 'SEALED')
  const summary = findingSummary(options.id, options.revision, options.findingHex)
  const detail = findingDetail(summary)
  const metadata = evidenceMetadataView(detail)
  ctx.provide('connection', { rpc: { call(
    _path: string,
    endpoint: string,
    payload: unknown,
    signal: AbortSignal,
  ): Promise<unknown> {
    if (endpoint === 'securityAssuranceWorkbench/getAssessment') {
      return Promise.resolve({ ok: true, value: { ok: true, value: snapshot } })
    }
    if (endpoint === 'securityAssuranceWorkbench/listFindings') {
      return Promise.resolve({
        ok: true,
        value: {
          ok: true,
          value: {
            schemaVersion: 1,
            assessmentId: options.id,
            assessmentRevision: options.revision,
            findings: [summary],
            nextCursor: null,
          },
        },
      })
    }
    if (endpoint === 'securityAssuranceWorkbench/getFinding') {
      return Promise.resolve({ ok: true, value: { ok: true, value: detail } })
    }
    if (endpoint === 'securityAssuranceWorkbench/getEvidenceView') {
      return Promise.resolve({ ok: true, value: { ok: true, value: metadata } })
    }
    if (endpoint === 'securityAssuranceWorkbench/discloseEvidence') {
      return options.disclosure(detail, payload, signal)
    }
    throw new Error(`Unexpected endpoint: ${endpoint}`)
  } } } as never)
  await ctx.plugin({ inject: clientRemoteInject, apply: applyClientRemote })
  await ctx.plugin({ inject: workbenchClientInject, apply: applyWorkbenchClient })
  const controller = ctx.securityAssuranceWorkbench as SecurityAssuranceWorkbenchController
  const authorityId = authorityContextId(`workbench-session-bounded-${options.findingHex}`)
  await controller.openAssessment({
    securityAssuranceWorkbenchContextId: authorityId,
    assessmentId: options.id,
  })
  await controller.openFindings()
  await controller.selectFinding(summary.recordId)
  await controller.selectEvidence(metadata.evidence.artifactId)
  return { controller, detail, metadata, authorityId }
}

const disclosureBindingMismatches: readonly [
  label: string,
  mutate: (
    view: WorkbenchEvidenceDisclosureViewV1,
  ) => WorkbenchEvidenceDisclosureViewV1,
][] = [
  ['Assessment revision', view => ({ ...view, assessmentRevision: view.assessmentRevision + 1 })],
  ['artifact digest', view => ({
    ...view,
    evidence: {
      ...view.evidence,
      digest: { ...view.evidence.digest, value: 'e'.repeat(64) },
    },
  })],
  ['expired deadline', view => ({
    ...view,
    content: view.content.kind === 'BOUNDED_JSON'
      ? { ...view.content, expiresAt: '2020-01-01T00:00:00.000Z' }
      : view.content,
  })],
  ['bounded byte length', view => ({
    ...view,
    content: view.content.kind === 'BOUNDED_JSON'
      ? { ...view.content, byteLength: view.content.byteLength + 1 }
      : view.content,
  })],
]

const evidenceBindingMismatches: readonly [
  label: string,
  mutate: (view: WorkbenchEvidenceMetadataViewV1) => WorkbenchEvidenceMetadataViewV1,
  transportRejection?: boolean,
][] = [
  ['Assessment identity', view => ({
    ...view,
    assessmentId: assessmentId('asm-00000000-0000-0000-0000-000000000099'),
  })],
  ['Assessment revision', view => ({ ...view, assessmentRevision: view.assessmentRevision + 1 })],
  ['Finding identity', view => ({
    ...view,
    context: { ...view.context, recordId: `finding-${'b'.repeat(64)}` },
  })],
  ['Finding revision', view => ({
    ...view,
    context: { ...view.context, recordRevision: view.context.recordRevision + 1 },
  })],
  ['artifact identity', view => ({
    ...view,
    evidence: { ...view.evidence, artifactId: 'evidence/different-artifact' },
  })],
  ['artifact schema', view => ({
    ...view,
    evidence: { ...view.evidence, schemaId: 'security/evidence/different-v1' },
  })],
  ['artifact digest', view => ({
    ...view,
    evidence: {
      ...view.evidence,
      digest: { ...view.evidence.digest, value: 'f'.repeat(64) },
    },
  })],
  ['Link purpose', view => ({
    ...view,
    link: { ...view.link, purpose: 'COUNTER_EVIDENCE' },
  })],
  ['Eligibility decision', view => ({
    ...view,
    link: { ...view.link, eligibilityDecision: 'INELIGIBLE' },
  })],
  ['Eligibility decision artifact', view => ({
    ...view,
    link: { ...view.link, eligibilityDecisionArtifactId: 'eligibility/different-artifact' },
  })],
  ['View purpose', view => ({
    ...view,
    purpose: 'VALIDATION_REVIEW',
  }) as unknown as WorkbenchEvidenceMetadataViewV1, true],
  ['View Profile', view => ({
    ...view,
    viewProfileId: 'security/evidence-view/bounded-json-v1',
  }) as unknown as WorkbenchEvidenceMetadataViewV1, true],
  ['content disclosure', view => ({
    ...view,
    content: { kind: 'BOUNDED_JSON', byteLength: 16, value: { secret: true } },
  }) as unknown as WorkbenchEvidenceMetadataViewV1, true],
]

describe('Security Assurance Workbench Client', () => {
  it('loads a revision-bound Finding list while the terminal Assessment view remains open', async () => {
    const ctx = new Context()
    contexts.push(ctx)
    await ctx.plugin(TypertRegistry)
    await installClientUiFoundation(ctx)

    const id = assessmentId('asm-00000000-0000-0000-0000-000000000061')
    const snapshot = snapshotAt(id, 3, 'SEALED')
    const summary = findingSummary(id, 3, 'a')
    const authorityId = authorityContextId('workbench-session-finding-list')
    const payloads: unknown[] = []
    ctx.provide('connection', { rpc: { call(
      _path: string,
      endpoint: string,
      payload: unknown,
    ): Promise<unknown> {
      payloads.push(payload)
      if (endpoint === 'securityAssuranceWorkbench/getAssessment') {
        return Promise.resolve({ ok: true, value: { ok: true, value: snapshot } })
      }
      if (endpoint === 'securityAssuranceWorkbench/listFindings') {
        return Promise.resolve({
          ok: true,
          value: {
            ok: true,
            value: {
              schemaVersion: 1,
              assessmentId: id,
              assessmentRevision: 3,
              findings: [summary],
              nextCursor: null,
            },
          },
        })
      }
      throw new Error(`Unexpected endpoint: ${endpoint}`)
    } } } as never)
    await ctx.plugin({ inject: clientRemoteInject, apply: applyClientRemote })
    await ctx.plugin({ inject: workbenchClientInject, apply: applyWorkbenchClient })
    const controller = ctx.securityAssuranceWorkbench as SecurityAssuranceWorkbenchController

    await controller.openAssessment({
      securityAssuranceWorkbenchContextId: authorityId,
      assessmentId: id,
    })
    await expect(controller.openFindings()).resolves.toMatchObject({
      kind: 'READY',
      snapshot: { assessmentId: id, assessmentRevision: 3 },
      findings: {
        kind: 'LIST_READY',
        assessmentRevision: 3,
        items: [{ recordId: summary.recordId }],
        nextCursor: null,
      },
    })
    expect(payloads[1]).toMatchObject({
      args: { request: { schemaVersion: 1, assessmentId: id, limit: 50 } },
    })
    expect(JSON.stringify(controller.getState())).not.toContain(authorityId)
  })

  it('fails closed when a Finding Summary crosses the page Assessment revision', async () => {
    const ctx = new Context()
    contexts.push(ctx)
    await ctx.plugin(TypertRegistry)
    await installClientUiFoundation(ctx)

    const id = assessmentId('asm-00000000-0000-0000-0000-000000000064')
    const snapshot = snapshotAt(id, 6, 'SEALED')
    const authorityId = authorityContextId('workbench-session-finding-protocol')
    ctx.provide('connection', { rpc: { call(
      _path: string,
      endpoint: string,
    ): Promise<unknown> {
      if (endpoint === 'securityAssuranceWorkbench/getAssessment') {
        return Promise.resolve({ ok: true, value: { ok: true, value: snapshot } })
      }
      if (endpoint === 'securityAssuranceWorkbench/listFindings') {
        return Promise.resolve({
          ok: true,
          value: {
            ok: true,
            value: {
              schemaVersion: 1,
              assessmentId: id,
              assessmentRevision: 6,
              findings: [findingSummary(id, 5, '6')],
              nextCursor: null,
            },
          },
        })
      }
      throw new Error(`Unexpected endpoint: ${endpoint}`)
    } } } as never)
    await ctx.plugin({ inject: clientRemoteInject, apply: applyClientRemote })
    await ctx.plugin({ inject: workbenchClientInject, apply: applyWorkbenchClient })
    const controller = ctx.securityAssuranceWorkbench as SecurityAssuranceWorkbenchController

    await controller.openAssessment({
      securityAssuranceWorkbenchContextId: authorityId,
      assessmentId: id,
    })
    await expect(controller.openFindings()).resolves.toMatchObject({
      kind: 'FAILED',
      assessmentId: id,
      failure: { source: 'CLIENT', code: 'FINDING_PROTOCOL_VIOLATION' },
    })
    expect(controller.getState()).not.toHaveProperty('snapshot')
    expect(JSON.stringify(controller.getState())).not.toContain(authorityId)
  })

  it('appends one Finding continuation at a time inside the original Assessment revision', async () => {
    const ctx = new Context()
    contexts.push(ctx)
    await ctx.plugin(TypertRegistry)
    await installClientUiFoundation(ctx)

    const id = assessmentId('asm-00000000-0000-0000-0000-000000000062')
    const snapshot = snapshotAt(id, 4, 'SEALED')
    const first = findingSummary(id, 4, 'b')
    const second = findingSummary(id, 4, 'c')
    let findingCalls = 0
    const findingPayloads: unknown[] = []
    let resolveContinuation: ((value: unknown) => void) | undefined
    ctx.provide('connection', { rpc: { call(
      _path: string,
      endpoint: string,
      payload: unknown,
    ): Promise<unknown> {
      if (endpoint === 'securityAssuranceWorkbench/getAssessment') {
        return Promise.resolve({ ok: true, value: { ok: true, value: snapshot } })
      }
      if (endpoint === 'securityAssuranceWorkbench/listFindings') {
        findingCalls += 1
        findingPayloads.push(payload)
        if (findingCalls === 1) {
          return Promise.resolve({
            ok: true,
            value: {
              ok: true,
              value: {
                schemaVersion: 1,
                assessmentId: id,
                assessmentRevision: 4,
                findings: [first],
                nextCursor: 'finding.cursor',
              },
            },
          })
        }
        return new Promise(resolve => { resolveContinuation = resolve })
      }
      throw new Error(`Unexpected endpoint: ${endpoint}`)
    } } } as never)
    await ctx.plugin({ inject: clientRemoteInject, apply: applyClientRemote })
    await ctx.plugin({ inject: workbenchClientInject, apply: applyWorkbenchClient })
    const controller = ctx.securityAssuranceWorkbench as SecurityAssuranceWorkbenchController

    await controller.openAssessment({
      securityAssuranceWorkbenchContextId: authorityContextId('workbench-session-finding-pagination'),
      assessmentId: id,
    })
    await controller.openFindings()
    const continuation = controller.loadMoreFindings()
    expect(controller.getState()).toMatchObject({
      kind: 'READY',
      findings: {
        kind: 'LIST_LOADING_MORE',
        items: [{ recordId: first.recordId }],
      },
    })
    await controller.loadMoreFindings()
    expect(findingCalls).toBe(2)
    expect(findingPayloads[1]).toMatchObject({
      args: {
        request: {
          schemaVersion: 1,
          assessmentId: id,
          limit: 50,
          cursor: 'finding.cursor',
        },
      },
    })

    resolveContinuation?.({
      ok: true,
      value: {
        ok: true,
        value: {
          schemaVersion: 1,
          assessmentId: id,
          assessmentRevision: 4,
          findings: [second],
          nextCursor: null,
        },
      },
    })
    await expect(continuation).resolves.toMatchObject({
      kind: 'READY',
      findings: {
        kind: 'LIST_READY',
        items: [{ recordId: first.recordId }, { recordId: second.recordId }],
        nextCursor: null,
      },
    })
  })

  it('opens only an exact listed Finding revision and returns to its redacted list', async () => {
    const ctx = new Context()
    contexts.push(ctx)
    await ctx.plugin(TypertRegistry)
    await installClientUiFoundation(ctx)

    const id = assessmentId('asm-00000000-0000-0000-0000-000000000063')
    const snapshot = snapshotAt(id, 5, 'SEALED')
    const summary = findingSummary(id, 5, 'e')
    const detail = findingDetail(summary)
    const payloads: unknown[] = []
    ctx.provide('connection', { rpc: { call(
      _path: string,
      endpoint: string,
      payload: unknown,
    ): Promise<unknown> {
      payloads.push(payload)
      if (endpoint === 'securityAssuranceWorkbench/getAssessment') {
        return Promise.resolve({ ok: true, value: { ok: true, value: snapshot } })
      }
      if (endpoint === 'securityAssuranceWorkbench/listFindings') {
        return Promise.resolve({
          ok: true,
          value: {
            ok: true,
            value: {
              schemaVersion: 1,
              assessmentId: id,
              assessmentRevision: 5,
              findings: [summary],
              nextCursor: null,
            },
          },
        })
      }
      if (endpoint === 'securityAssuranceWorkbench/getFinding') {
        return Promise.resolve({ ok: true, value: { ok: true, value: detail } })
      }
      throw new Error(`Unexpected endpoint: ${endpoint}`)
    } } } as never)
    await ctx.plugin({ inject: clientRemoteInject, apply: applyClientRemote })
    await ctx.plugin({ inject: workbenchClientInject, apply: applyWorkbenchClient })
    const controller = ctx.securityAssuranceWorkbench as SecurityAssuranceWorkbenchController

    await controller.openAssessment({
      securityAssuranceWorkbenchContextId: authorityContextId('workbench-session-finding-detail'),
      assessmentId: id,
    })
    await controller.openFindings()
    await expect(controller.selectFinding(summary.recordId)).resolves.toMatchObject({
      kind: 'READY',
      findings: {
        kind: 'DETAIL_READY',
        detail: {
          recordId: summary.recordId,
          sourceAnchor: { path: 'src/render.ts' },
          evidenceLinks: [{ artifactId: 'evidence/reference-output-encoding' }],
        },
      },
    })
    expect(payloads[2]).toMatchObject({
      args: {
        request: {
          schemaVersion: 1,
          assessmentId: id,
          assessmentRevision: 5,
          recordId: summary.recordId,
          recordRevision: 1,
        },
      },
    })
    expect(controller.backToFindingList()).toMatchObject({
      kind: 'READY',
      findings: {
        kind: 'LIST_READY',
        items: [{ recordId: summary.recordId }],
      },
    })
    expect(payloads).toHaveLength(3)
  })

  it('opens metadata only from an Evidence Link in the exact Finding Detail', async () => {
    const ctx = new Context()
    contexts.push(ctx)
    await ctx.plugin(TypertRegistry)
    await installClientUiFoundation(ctx)

    const id = assessmentId('asm-00000000-0000-0000-0000-000000000065')
    const snapshot = snapshotAt(id, 8, 'SEALED')
    const summary = findingSummary(id, 8, '8')
    const detail = findingDetail(summary)
    const view = evidenceMetadataView(detail)
    const payloads: unknown[] = []
    ctx.provide('connection', { rpc: { call(
      _path: string,
      endpoint: string,
      payload: unknown,
    ): Promise<unknown> {
      payloads.push(payload)
      if (endpoint === 'securityAssuranceWorkbench/getAssessment') {
        return Promise.resolve({ ok: true, value: { ok: true, value: snapshot } })
      }
      if (endpoint === 'securityAssuranceWorkbench/listFindings') {
        return Promise.resolve({
          ok: true,
          value: {
            ok: true,
            value: {
              schemaVersion: 1,
              assessmentId: id,
              assessmentRevision: 8,
              findings: [summary],
              nextCursor: null,
            },
          },
        })
      }
      if (endpoint === 'securityAssuranceWorkbench/getFinding') {
        return Promise.resolve({ ok: true, value: { ok: true, value: detail } })
      }
      if (endpoint === 'securityAssuranceWorkbench/getEvidenceView') {
        return Promise.resolve({ ok: true, value: { ok: true, value: view } })
      }
      throw new Error(`Unexpected endpoint: ${endpoint}`)
    } } } as never)
    await ctx.plugin({ inject: clientRemoteInject, apply: applyClientRemote })
    await ctx.plugin({ inject: workbenchClientInject, apply: applyWorkbenchClient })
    const controller = ctx.securityAssuranceWorkbench as SecurityAssuranceWorkbenchController
    const authorityId = authorityContextId('workbench-session-evidence-metadata')

    await controller.openAssessment({
      securityAssuranceWorkbenchContextId: authorityId,
      assessmentId: id,
    })
    await controller.openFindings()
    await controller.selectFinding(summary.recordId)
    await expect(controller.selectEvidence(view.evidence.artifactId)).resolves.toMatchObject({
      kind: 'READY',
      findings: {
        kind: 'DETAIL_READY',
        detail: { recordId: summary.recordId },
        evidence: {
          kind: 'METADATA_READY',
          view: {
            evidence: { artifactId: view.evidence.artifactId },
            content: { kind: 'REDACTED', reason: 'PROFILE_METADATA_ONLY' },
          },
        },
      },
    })
    expect(payloads[3]).toMatchObject({
      args: {
        request: {
          schemaVersion: 1,
          assessmentId: id,
          assessmentRevision: detail.assessmentRevision,
          context: {
            kind: 'finding',
            recordId: detail.recordId,
            recordRevision: detail.recordRevision,
          },
          evidenceArtifactId: view.evidence.artifactId,
          evidenceDigest: view.evidence.digest,
          purpose: 'FINDING_TRIAGE',
          viewProfileId: 'security/evidence-view/metadata-only-v1',
        },
      },
    })
    expect(JSON.stringify(controller.getState())).not.toContain(authorityId)
    expect(controller.backToFindingDetail()).toMatchObject({
      kind: 'READY',
      findings: {
        kind: 'DETAIL_READY',
        detail: { recordId: summary.recordId },
        evidence: { kind: 'NOT_LOADED' },
      },
    })
    expect(payloads).toHaveLength(4)
  })

  it('requires a separate disclosure action and discards bounded content at Service expiry', async () => {
    const ctx = new Context()
    contexts.push(ctx)
    await ctx.plugin(TypertRegistry)
    await installClientUiFoundation(ctx)

    const id = assessmentId('asm-00000000-0000-0000-0000-000000000069')
    const snapshot = snapshotAt(id, 12, 'SEALED')
    const summary = findingSummary(id, 12, '6')
    const detail = findingDetail(summary)
    const metadata = evidenceMetadataView(detail)
    const payloads: Array<{ readonly endpoint: string; readonly payload: unknown }> = []
    ctx.provide('connection', { rpc: { call(
      _path: string,
      endpoint: string,
      payload: unknown,
    ): Promise<unknown> {
      payloads.push({ endpoint, payload })
      if (endpoint === 'securityAssuranceWorkbench/getAssessment') {
        return Promise.resolve({ ok: true, value: { ok: true, value: snapshot } })
      }
      if (endpoint === 'securityAssuranceWorkbench/listFindings') {
        return Promise.resolve({
          ok: true,
          value: {
            ok: true,
            value: {
              schemaVersion: 1,
              assessmentId: id,
              assessmentRevision: 12,
              findings: [summary],
              nextCursor: null,
            },
          },
        })
      }
      if (endpoint === 'securityAssuranceWorkbench/getFinding') {
        return Promise.resolve({ ok: true, value: { ok: true, value: detail } })
      }
      if (endpoint === 'securityAssuranceWorkbench/getEvidenceView') {
        return Promise.resolve({ ok: true, value: { ok: true, value: metadata } })
      }
      if (endpoint === 'securityAssuranceWorkbench/discloseEvidence') {
        return Promise.resolve({
          ok: true,
          value: {
            ok: true,
            value: evidenceDisclosureView(detail, new Date(Date.now() + 1_000).toISOString()),
          },
        })
      }
      throw new Error(`Unexpected endpoint: ${endpoint}`)
    } } } as never)
    await ctx.plugin({ inject: clientRemoteInject, apply: applyClientRemote })
    await ctx.plugin({ inject: workbenchClientInject, apply: applyWorkbenchClient })
    const controller = ctx.securityAssuranceWorkbench as SecurityAssuranceWorkbenchController
    const authorityId = authorityContextId('workbench-session-evidence-disclosure')

    await controller.openAssessment({
      securityAssuranceWorkbenchContextId: authorityId,
      assessmentId: id,
    })
    await controller.openFindings()
    await controller.selectFinding(summary.recordId)
    await controller.selectEvidence(metadata.evidence.artifactId)
    expect(controller.getState()).toMatchObject({
      kind: 'READY',
      findings: { detail: { recordId: detail.recordId }, evidence: { kind: 'METADATA_READY' } },
    })

    vi.useFakeTimers()
    await expect(controller.discloseEvidence()).resolves.toMatchObject({
      kind: 'READY',
      findings: {
        kind: 'DETAIL_READY',
        evidence: {
          kind: 'DISCLOSURE_READY',
          metadata: { content: { kind: 'REDACTED', reason: 'PROFILE_METADATA_ONLY' } },
          view: {
            purpose: 'VALIDATION_REVIEW',
            viewProfileId: 'security/evidence-view/bounded-json-v1',
            content: {
              kind: 'BOUNDED_JSON',
              value: { schemaVersion: 1, proof: 'bounded-secret' },
            },
          },
        },
      },
    })
    expect(payloads.at(-1)).toMatchObject({
      endpoint: 'securityAssuranceWorkbench/discloseEvidence',
      payload: {
        args: {
          securityAssuranceWorkbenchContextId: authorityId,
          request: {
            schemaVersion: 1,
            assessmentId: id,
            assessmentRevision: detail.assessmentRevision,
            context: {
              kind: 'finding',
              recordId: detail.recordId,
              recordRevision: detail.recordRevision,
            },
            evidenceArtifactId: metadata.evidence.artifactId,
            evidenceDigest: metadata.evidence.digest,
            purpose: 'VALIDATION_REVIEW',
            viewProfileId: 'security/evidence-view/bounded-json-v1',
          },
        },
      },
    })

    expect(controller.hideEvidenceDisclosure()).toMatchObject({
      kind: 'READY',
      findings: {
        kind: 'DETAIL_READY',
        evidence: { kind: 'METADATA_READY', disclosureStatus: 'NOT_REQUESTED' },
      },
    })
    expect(JSON.stringify(controller.getState())).not.toContain('bounded-secret')
    await controller.discloseEvidence()

    await vi.advanceTimersByTimeAsync(999)
    expect(JSON.stringify(controller.getState())).toContain('bounded-secret')
    await vi.advanceTimersByTimeAsync(1)
    expect(controller.getState()).toMatchObject({
      kind: 'READY',
      findings: {
        kind: 'DETAIL_READY',
        evidence: {
          kind: 'METADATA_READY',
          disclosureStatus: 'EXPIRED',
          view: { evidence: { artifactId: metadata.evidence.artifactId } },
        },
      },
    })
    expect(JSON.stringify(controller.getState())).not.toContain('bounded-secret')

    await controller.discloseEvidence()
    expect(JSON.stringify(controller.getState())).toContain('bounded-secret')
    controller.closeAssessment()
    expect(controller.getState()).toEqual({ kind: 'CLOSED' })
    expect(JSON.stringify(controller.getState())).not.toContain('bounded-secret')
  })

  it('ignores a bounded disclosure response that arrives after Evidence navigation', async () => {
    let resolveDisclosure: ((value: unknown) => void) | undefined
    let disclosureSignal: AbortSignal | undefined
    const { controller, detail } = await openMetadataReadyFixture({
      id: assessmentId('asm-00000000-0000-0000-0000-000000000070'),
      revision: 13,
      findingHex: '5',
      disclosure: (_detail, _payload, signal) => {
        disclosureSignal = signal
        return new Promise(resolve => { resolveDisclosure = resolve })
      },
    })

    const pending = controller.discloseEvidence()
    expect(controller.getState()).toMatchObject({
      kind: 'READY',
      findings: { kind: 'DETAIL_READY', evidence: { kind: 'DISCLOSURE_LOADING' } },
    })
    controller.backToFindingDetail()
    expect(disclosureSignal?.aborted).toBe(true)
    expect(controller.getState()).toMatchObject({
      kind: 'READY',
      findings: { kind: 'DETAIL_READY', evidence: { kind: 'NOT_LOADED' } },
    })

    resolveDisclosure?.({
      ok: true,
      value: {
        ok: true,
        value: evidenceDisclosureView(detail, new Date(Date.now() + 60_000).toISOString()),
      },
    })
    await pending
    expect(controller.getState()).toMatchObject({
      kind: 'READY',
      findings: { kind: 'DETAIL_READY', evidence: { kind: 'NOT_LOADED' } },
    })
    expect(JSON.stringify(controller.getState())).not.toContain('bounded-secret')
  })

  it('erases the session when fresh disclosure authority is unavailable', async () => {
    const { controller, authorityId } = await openMetadataReadyFixture({
      id: assessmentId('asm-00000000-0000-0000-0000-000000000071'),
      revision: 14,
      findingHex: '4',
      disclosure: () => Promise.resolve({
        ok: true,
        value: {
          ok: false,
          error: {
            schemaVersion: 1,
            code: 'UNAUTHORIZED',
            message: 'The current Host Operator no longer has disclosure authority.',
            retryable: false,
            correlationId: 'corr-workbench-authority-loss',
          },
        },
      }),
    })

    await expect(controller.discloseEvidence()).resolves.toMatchObject({
      kind: 'FAILED',
      failure: { source: 'SECURITY', code: 'UNAUTHORIZED' },
    })
    expect(controller.getState()).not.toHaveProperty('snapshot')
    expect(controller.getState()).not.toHaveProperty('findings')
    expect(JSON.stringify(controller.getState())).not.toContain('bounded-secret')
    expect(JSON.stringify(controller.getState())).not.toContain(authorityId)
  })

  it.each(disclosureBindingMismatches)(
    'fails closed when bounded Evidence changes its %s binding',
    async (_label, mutate) => {
      let producedView: WorkbenchEvidenceDisclosureViewV1 | undefined
      const { controller } = await openMetadataReadyFixture({
        id: assessmentId('asm-00000000-0000-0000-0000-000000000072'),
        revision: 15,
        findingHex: '3',
        disclosure: detail => {
          producedView = mutate(evidenceDisclosureView(
            detail,
            new Date(Date.now() + 60_000).toISOString(),
          ))
          return Promise.resolve({ ok: true, value: { ok: true, value: producedView } })
        },
      })

      await expect(controller.discloseEvidence()).resolves.toMatchObject({
        kind: 'FAILED',
        failure: { code: 'EVIDENCE_DISCLOSURE_PROTOCOL_VIOLATION' },
      })
      expect(controller.getState()).not.toHaveProperty('snapshot')
      expect(controller.getState()).not.toHaveProperty('findings')
      expect(JSON.stringify(controller.getState())).not.toContain('bounded-secret')
      expect(producedView).toBeDefined()
    },
  )

  it('ignores earlier failed and successful attempts after the same Evidence is reopened', async () => {
    const ctx = new Context()
    contexts.push(ctx)
    await ctx.plugin(TypertRegistry)
    await installClientUiFoundation(ctx)

    const id = assessmentId('asm-00000000-0000-0000-0000-000000000068')
    const snapshot = snapshotAt(id, 11, 'SEALED')
    const summary = findingSummary(id, 11, '8')
    const detail = findingDetail(summary)
    const view = evidenceMetadataView(detail)
    const evidenceDeferred: Array<{
      readonly resolve: (value: unknown) => void
      readonly reject: (reason: unknown) => void
    }> = []
    ctx.provide('connection', { rpc: { call(
      _path: string,
      endpoint: string,
    ): Promise<unknown> {
      if (endpoint === 'securityAssuranceWorkbench/getAssessment') {
        return Promise.resolve({ ok: true, value: { ok: true, value: snapshot } })
      }
      if (endpoint === 'securityAssuranceWorkbench/listFindings') {
        return Promise.resolve({
          ok: true,
          value: {
            ok: true,
            value: {
              schemaVersion: 1,
              assessmentId: id,
              assessmentRevision: 11,
              findings: [summary],
              nextCursor: null,
            },
          },
        })
      }
      if (endpoint === 'securityAssuranceWorkbench/getFinding') {
        return Promise.resolve({ ok: true, value: { ok: true, value: detail } })
      }
      if (endpoint === 'securityAssuranceWorkbench/getEvidenceView') {
        return new Promise((resolve, reject) => { evidenceDeferred.push({ resolve, reject }) })
      }
      throw new Error(`Unexpected endpoint: ${endpoint}`)
    } } } as never)
    await ctx.plugin({ inject: clientRemoteInject, apply: applyClientRemote })
    await ctx.plugin({ inject: workbenchClientInject, apply: applyWorkbenchClient })
    const controller = ctx.securityAssuranceWorkbench as SecurityAssuranceWorkbenchController

    await controller.openAssessment({
      securityAssuranceWorkbenchContextId: authorityContextId('workbench-session-evidence-race'),
      assessmentId: id,
    })
    await controller.openFindings()
    await controller.selectFinding(summary.recordId)

    const first = controller.selectEvidence(view.evidence.artifactId)
    expect(evidenceDeferred).toHaveLength(1)
    controller.backToFindingDetail()
    const second = controller.selectEvidence(view.evidence.artifactId)
    expect(evidenceDeferred).toHaveLength(2)

    evidenceDeferred[0]?.reject(new Error('The earlier authority context expired.'))
    await first
    expect(controller.getState()).toMatchObject({
      kind: 'READY',
      findings: {
        kind: 'DETAIL_READY',
        evidence: { kind: 'METADATA_LOADING', artifactId: view.evidence.artifactId },
      },
    })

    controller.backToFindingDetail()
    const third = controller.selectEvidence(view.evidence.artifactId)
    expect(evidenceDeferred).toHaveLength(3)
    evidenceDeferred[1]?.resolve({ ok: true, value: { ok: true, value: view } })
    await second
    expect(controller.getState()).toMatchObject({
      kind: 'READY',
      findings: {
        kind: 'DETAIL_READY',
        evidence: { kind: 'METADATA_LOADING', artifactId: view.evidence.artifactId },
      },
    })

    evidenceDeferred[2]?.resolve({ ok: true, value: { ok: true, value: view } })
    await expect(third).resolves.toMatchObject({
      kind: 'READY',
      findings: {
        kind: 'DETAIL_READY',
        evidence: {
          kind: 'METADATA_READY',
          view: { evidence: { artifactId: view.evidence.artifactId } },
        },
      },
    })
  })

  it('fails closed without a Remote call for browser-authored Evidence identity', async () => {
    const ctx = new Context()
    contexts.push(ctx)
    await ctx.plugin(TypertRegistry)
    await installClientUiFoundation(ctx)

    const id = assessmentId('asm-00000000-0000-0000-0000-000000000066')
    const snapshot = snapshotAt(id, 9, 'SEALED')
    const summary = findingSummary(id, 9, '9')
    const detail = findingDetail(summary)
    const endpoints: string[] = []
    ctx.provide('connection', { rpc: { call(
      _path: string,
      endpoint: string,
    ): Promise<unknown> {
      endpoints.push(endpoint)
      if (endpoint === 'securityAssuranceWorkbench/getAssessment') {
        return Promise.resolve({ ok: true, value: { ok: true, value: snapshot } })
      }
      if (endpoint === 'securityAssuranceWorkbench/listFindings') {
        return Promise.resolve({
          ok: true,
          value: {
            ok: true,
            value: {
              schemaVersion: 1,
              assessmentId: id,
              assessmentRevision: 9,
              findings: [summary],
              nextCursor: null,
            },
          },
        })
      }
      if (endpoint === 'securityAssuranceWorkbench/getFinding') {
        return Promise.resolve({ ok: true, value: { ok: true, value: detail } })
      }
      throw new Error(`Unexpected endpoint: ${endpoint}`)
    } } } as never)
    await ctx.plugin({ inject: clientRemoteInject, apply: applyClientRemote })
    await ctx.plugin({ inject: workbenchClientInject, apply: applyWorkbenchClient })
    const controller = ctx.securityAssuranceWorkbench as SecurityAssuranceWorkbenchController
    const authorityId = authorityContextId('workbench-session-evidence-forgery')

    await controller.openAssessment({
      securityAssuranceWorkbenchContextId: authorityId,
      assessmentId: id,
    })
    await controller.openFindings()
    await controller.selectFinding(summary.recordId)
    await expect(controller.selectEvidence('evidence/browser-authored')).resolves.toMatchObject({
      kind: 'FAILED',
      assessmentId: id,
      failure: { source: 'CLIENT', code: 'EVIDENCE_NOT_LISTED' },
    })
    expect(endpoints).toEqual([
      'securityAssuranceWorkbench/getAssessment',
      'securityAssuranceWorkbench/listFindings',
      'securityAssuranceWorkbench/getFinding',
    ])
    expect(controller.getState()).not.toHaveProperty('snapshot')
    expect(controller.getState()).not.toHaveProperty('findings')
    expect(JSON.stringify(controller.getState())).not.toContain(authorityId)
  })

  it.each(evidenceBindingMismatches)(
    'fails closed when Evidence metadata changes its %s binding',
    async (_label, mutate, transportRejection = false) => {
      const ctx = new Context()
      contexts.push(ctx)
      await ctx.plugin(TypertRegistry)
      await installClientUiFoundation(ctx)

      const id = assessmentId('asm-00000000-0000-0000-0000-000000000067')
      const snapshot = snapshotAt(id, 10, 'SEALED')
      const summary = findingSummary(id, 10, '7')
      const detail = findingDetail(summary)
      const view = mutate(evidenceMetadataView(detail))
      ctx.provide('connection', { rpc: { call(
        _path: string,
        endpoint: string,
      ): Promise<unknown> {
        if (endpoint === 'securityAssuranceWorkbench/getAssessment') {
          return Promise.resolve({ ok: true, value: { ok: true, value: snapshot } })
        }
        if (endpoint === 'securityAssuranceWorkbench/listFindings') {
          return Promise.resolve({
            ok: true,
            value: {
              ok: true,
              value: {
                schemaVersion: 1,
                assessmentId: id,
                assessmentRevision: 10,
                findings: [summary],
                nextCursor: null,
              },
            },
          })
        }
        if (endpoint === 'securityAssuranceWorkbench/getFinding') {
          return Promise.resolve({ ok: true, value: { ok: true, value: detail } })
        }
        if (endpoint === 'securityAssuranceWorkbench/getEvidenceView') {
          return Promise.resolve({ ok: true, value: { ok: true, value: view } })
        }
        throw new Error(`Unexpected endpoint: ${endpoint}`)
      } } } as never)
      await ctx.plugin({ inject: clientRemoteInject, apply: applyClientRemote })
      await ctx.plugin({ inject: workbenchClientInject, apply: applyWorkbenchClient })
      const controller = ctx.securityAssuranceWorkbench as SecurityAssuranceWorkbenchController
      const authorityId = authorityContextId('workbench-session-evidence-binding')

      await controller.openAssessment({
        securityAssuranceWorkbenchContextId: authorityId,
        assessmentId: id,
      })
      await controller.openFindings()
      await controller.selectFinding(summary.recordId)
      await expect(controller.selectEvidence(
        detail.evidenceLinks[0]?.artifactId ?? 'missing',
      )).resolves.toMatchObject({
        kind: 'FAILED',
        assessmentId: id,
        failure: transportRejection
          ? { source: 'TRANSPORT', code: 'internal' }
          : { source: 'CLIENT', code: 'EVIDENCE_PROTOCOL_VIOLATION' },
      })
      expect(controller.getState()).not.toHaveProperty('snapshot')
      expect(controller.getState()).not.toHaveProperty('findings')
      expect(JSON.stringify(controller.getState())).not.toContain(authorityId)
    },
  )

  it('appends the next authority-bound Assessment page and stops at its stable end', async () => {
    const ctx = new Context()
    contexts.push(ctx)
    await ctx.plugin(TypertRegistry)
    await installClientUiFoundation(ctx)

    const firstId = assessmentId('asm-00000000-0000-0000-0000-000000000021')
    const secondId = assessmentId('asm-00000000-0000-0000-0000-000000000022')
    const listPayloads: unknown[] = []
    ctx.provide('connection', { rpc: { call(
      _path: string,
      endpoint: string,
      payload: unknown,
    ): Promise<unknown> {
      if (endpoint !== 'securityAssuranceWorkbench/listAssessments') {
        throw new Error(`Unexpected endpoint: ${endpoint}`)
      }
      listPayloads.push(payload)
      const firstPage = listPayloads.length === 1
      return Promise.resolve({
        ok: true,
        value: {
          ok: true,
          value: {
            schemaVersion: 1,
            consistencyWatermark: 'watermark.signature',
            assessments: [assessmentListItem(firstPage ? firstId : secondId, firstPage ? 1 : 2)],
            nextCursor: firstPage ? 'cursor.signature' : null,
          },
        },
      })
    } } } as never)
    await ctx.plugin({ inject: clientRemoteInject, apply: applyClientRemote })
    await ctx.plugin({ inject: workbenchClientInject, apply: applyWorkbenchClient })
    const controller = ctx.securityAssuranceWorkbench as SecurityAssuranceWorkbenchController

    await controller.openAssessmentSelection({
      securityAssuranceWorkbenchContextId: authorityContextId('workbench-session-pagination'),
    })
    await expect(controller.loadMoreAssessments()).resolves.toMatchObject({
      kind: 'SELECTION_READY',
      consistencyWatermark: 'watermark.signature',
      assessments: [{ assessmentId: firstId }, { assessmentId: secondId }],
      nextCursor: null,
    })
    expect(listPayloads[1]).toMatchObject({
      args: {
        request: { schemaVersion: 1, limit: 50, cursor: 'cursor.signature' },
      },
    })

    await controller.loadMoreAssessments()
    expect(listPayloads).toHaveLength(2)
  })

  it('fails closed when a continuation page leaves the first-page consistency window', async () => {
    const ctx = new Context()
    contexts.push(ctx)
    await ctx.plugin(TypertRegistry)
    await installClientUiFoundation(ctx)

    const firstId = assessmentId('asm-00000000-0000-0000-0000-000000000031')
    const secondId = assessmentId('asm-00000000-0000-0000-0000-000000000032')
    let page = 0
    ctx.provide('connection', { rpc: { call(): Promise<unknown> {
      page += 1
      return Promise.resolve({
        ok: true,
        value: {
          ok: true,
          value: {
            schemaVersion: 1,
            consistencyWatermark: page === 1 ? 'first.signature' : 'different.signature',
            assessments: [assessmentListItem(page === 1 ? firstId : secondId, page)],
            nextCursor: page === 1 ? 'cursor.signature' : null,
          },
        },
      })
    } } } as never)
    await ctx.plugin({ inject: clientRemoteInject, apply: applyClientRemote })
    await ctx.plugin({ inject: workbenchClientInject, apply: applyWorkbenchClient })
    const controller = ctx.securityAssuranceWorkbench as SecurityAssuranceWorkbenchController
    const authorityId = authorityContextId('workbench-session-protocol-fence')

    await controller.openAssessmentSelection({
      securityAssuranceWorkbenchContextId: authorityId,
    })
    await expect(controller.loadMoreAssessments()).resolves.toMatchObject({
      kind: 'FAILED',
      assessmentId: null,
      failure: { source: 'CLIENT', code: 'SELECTION_PROTOCOL_VIOLATION' },
    })
    expect(controller.getState()).not.toHaveProperty('assessments')
    expect(JSON.stringify(controller.getState())).not.toContain(authorityId)
  })

  it('admits only one continuation request for the current Assessment cursor', async () => {
    const ctx = new Context()
    contexts.push(ctx)
    await ctx.plugin(TypertRegistry)
    await installClientUiFoundation(ctx)

    const firstId = assessmentId('asm-00000000-0000-0000-0000-000000000041')
    const secondId = assessmentId('asm-00000000-0000-0000-0000-000000000042')
    let calls = 0
    let resolveContinuation: ((value: unknown) => void) | undefined
    ctx.provide('connection', { rpc: { call(): Promise<unknown> {
      calls += 1
      if (calls === 1) {
        return Promise.resolve({
          ok: true,
          value: {
            ok: true,
            value: {
              schemaVersion: 1,
              consistencyWatermark: 'stable.signature',
              assessments: [assessmentListItem(firstId, 1)],
              nextCursor: 'cursor.signature',
            },
          },
        })
      }
      return new Promise(resolve => { resolveContinuation = resolve })
    } } } as never)
    await ctx.plugin({ inject: clientRemoteInject, apply: applyClientRemote })
    await ctx.plugin({ inject: workbenchClientInject, apply: applyWorkbenchClient })
    const controller = ctx.securityAssuranceWorkbench as SecurityAssuranceWorkbenchController

    await controller.openAssessmentSelection({
      securityAssuranceWorkbenchContextId: authorityContextId('workbench-session-pagination-fence'),
    })
    const continuation = controller.loadMoreAssessments()
    expect(controller.getState()).toMatchObject({
      kind: 'SELECTION_LOADING_MORE',
      assessments: [{ assessmentId: firstId }],
    })
    await expect(controller.loadMoreAssessments()).resolves.toMatchObject({
      kind: 'SELECTION_LOADING_MORE',
    })
    expect(calls).toBe(2)

    resolveContinuation?.({
      ok: true,
      value: {
        ok: true,
        value: {
          schemaVersion: 1,
          consistencyWatermark: 'stable.signature',
          assessments: [assessmentListItem(secondId, 2)],
          nextCursor: null,
        },
      },
    })
    await expect(continuation).resolves.toMatchObject({
      kind: 'SELECTION_READY',
      assessments: [{ assessmentId: firstId }, { assessmentId: secondId }],
    })
  })

  it('opens an authenticated selection session and selects only a listed Assessment', async () => {
    const ctx = new Context()
    contexts.push(ctx)
    await ctx.plugin(TypertRegistry)
    await installClientUiFoundation(ctx)

    const id = assessmentId('asm-00000000-0000-0000-0000-000000000010')
    const snapshot = snapshotAt(id, 3, 'SEALED')
    const authorityId = authorityContextId('workbench-session-selector')
    const endpoints: string[] = []
    ctx.provide('connection', { rpc: { call(
      _path: string,
      endpoint: string,
      payload: unknown,
    ): Promise<unknown> {
      endpoints.push(endpoint)
      expect(JSON.stringify(payload)).not.toContain('principalId')
      if (endpoint === 'securityAssuranceWorkbench/listAssessments') {
        return Promise.resolve({
          ok: true,
          value: {
            ok: true,
            value: {
              schemaVersion: 1,
              consistencyWatermark: 'watermark.signature',
              assessments: [{
                schemaVersion: 1,
                assessmentId: id,
                assessmentRevision: 3,
                state: 'SEALED',
                repository: {
                  repositoryId: 'repo-00000000-0000-0000-0000-000000000010',
                  repositoryRevision: 1,
                },
                subjectKind: 'workspace_snapshot',
                policyId: 'security/standard',
                coverageStatus: 'COMPLETE',
                verdict: 'SATISFIED',
                createdAt: '2026-08-24T00:00:00.000Z',
                updatedAt: '2026-08-24T00:03:00.000Z',
              }],
              nextCursor: null,
            },
          },
        })
      }
      if (endpoint === 'securityAssuranceWorkbench/getAssessment') {
        return Promise.resolve({ ok: true, value: { ok: true, value: snapshot } })
      }
      throw new Error(`Unexpected endpoint: ${endpoint}`)
    } } } as never)
    await ctx.plugin({ inject: clientRemoteInject, apply: applyClientRemote })
    await ctx.plugin({ inject: workbenchClientInject, apply: applyWorkbenchClient })
    const controller = ctx.securityAssuranceWorkbench as SecurityAssuranceWorkbenchController

    await expect(controller.openAssessmentSelection({
      securityAssuranceWorkbenchContextId: authorityId,
    })).resolves.toMatchObject({
      kind: 'SELECTION_READY',
      assessments: [{ assessmentId: id }],
    })
    expect(JSON.stringify(controller.getState())).not.toContain(authorityId)

    await expect(controller.selectAssessment(
      assessmentId('asm-00000000-0000-0000-0000-000000000099'),
    )).resolves.toMatchObject({
      kind: 'FAILED',
      assessmentId: null,
      failure: { source: 'CLIENT', code: 'ASSESSMENT_NOT_LISTED' },
    })
    await controller.openAssessmentSelection({
      securityAssuranceWorkbenchContextId: authorityId,
    })
    await expect(controller.selectAssessment(id)).resolves.toMatchObject({
      kind: 'READY',
      assessmentId: id,
      snapshot: { assessmentRevision: 3, state: 'SEALED' },
    })
    expect(endpoints).toEqual([
      'securityAssuranceWorkbench/listAssessments',
      'securityAssuranceWorkbench/listAssessments',
      'securityAssuranceWorkbench/getAssessment',
    ])
  })

  it('records only the service-projected Risk Decision and refetches the committed Snapshot', async () => {
    const ctx = new Context()
    contexts.push(ctx)
    await ctx.plugin(TypertRegistry)
    await installClientUiFoundation(ctx)

    const id = assessmentId('asm-00000000-0000-0000-0000-000000000081')
    const summary = findingSummary(id, 7, '8')
    const detail = findingDetail(summary)
    const blocked: AssessmentSnapshotV1 = {
      ...snapshotAt(id, 7, 'BLOCKED'),
      availableActions: [{
        kind: 'RECORD_RISK_DECISION',
        expectedAssessmentRevision: 7,
        finding: {
          recordId: summary.recordId,
          recordRevision: summary.recordRevision,
        },
        options: [{
          decision: 'DENY',
          consequence: 'KEEPS_FINDING_BLOCKING',
        }],
      }],
    }
    const committed: AssessmentSnapshotV1 = {
      ...snapshotAt(id, 8, 'SEALED'),
      availableActions: [],
      verdict: 'FAILED',
    }
    const endpoints: string[] = []
    const riskPayloads: unknown[] = []
    let assessmentReads = 0
    ctx.provide('connection', { rpc: { call(
      _path: string,
      endpoint: string,
      payload: unknown,
      signal: AbortSignal,
    ): Promise<unknown> {
      endpoints.push(endpoint)
      if (endpoint === 'securityAssuranceWorkbench/getAssessment') {
        assessmentReads += 1
        return Promise.resolve({
          ok: true,
          value: { ok: true, value: assessmentReads === 1 ? blocked : committed },
        })
      }
      if (endpoint === 'securityAssuranceWorkbench/waitForAssessmentRevision') {
        return new Promise(resolve => {
          signal.addEventListener('abort', () => {
            resolve({ ok: false, error: { code: 'aborted' } })
          }, { once: true })
        })
      }
      if (endpoint === 'securityAssuranceWorkbench/listFindings') {
        return Promise.resolve({
          ok: true,
          value: {
            ok: true,
            value: {
              schemaVersion: 1,
              assessmentId: id,
              assessmentRevision: 7,
              findings: [summary],
              nextCursor: null,
            },
          },
        })
      }
      if (endpoint === 'securityAssuranceWorkbench/getFinding') {
        return Promise.resolve({ ok: true, value: { ok: true, value: detail } })
      }
      if (endpoint === 'securityAssuranceWorkbench/recordRiskDecision') {
        riskPayloads.push(payload)
        const request = (payload as {
          readonly args: {
            readonly request: {
              readonly idempotencyKey: string
            }
          }
        }).args.request
        return Promise.resolve({
          ok: true,
          value: {
            ok: true,
            value: {
              schemaVersion: 1,
              operation: 'record_risk_decision',
              assessmentId: id,
              assessmentRevision: 8,
              acceptedState: 'BLOCKED',
              decisionId: 'risk-decision-00000000-0000-0000-0000-000000000081',
              finding: {
                recordId: summary.recordId,
                recordRevision: summary.recordRevision,
              },
              decision: 'DENY',
              resolution: 'DENIED',
              idempotencyKey: request.idempotencyKey,
              recordedAt: '2026-08-24T00:08:00.000Z',
              correlationId: 'sec-00000000-0000-0000-0000-000000000081',
            },
          },
        })
      }
      throw new Error(`Unexpected endpoint: ${endpoint}`)
    } } } as never)
    await ctx.plugin({ inject: clientRemoteInject, apply: applyClientRemote })
    await ctx.plugin({ inject: workbenchClientInject, apply: applyWorkbenchClient })
    const controller = ctx.securityAssuranceWorkbench as SecurityAssuranceWorkbenchController
    const authorityId = authorityContextId('workbench-session-risk-decision')

    await controller.openAssessment({
      securityAssuranceWorkbenchContextId: authorityId,
      assessmentId: id,
    })
    await controller.openFindings()
    await controller.selectFinding(summary.recordId)
    await expect(controller.recordRiskDecision({
      decision: 'DENY',
      rationale: 'The validated risk must remain blocking for this release.',
      compensatingControls: [],
      expiresAt: null,
    })).resolves.toMatchObject({
      kind: 'READY',
      snapshot: { assessmentRevision: 8, availableActions: [] },
      findings: { kind: 'NOT_LOADED' },
    })

    expect(riskPayloads).toHaveLength(1)
    expect(riskPayloads[0]).toMatchObject({
      args: {
        securityAssuranceWorkbenchContextId: authorityId,
        request: {
          schemaVersion: 1,
          contractVersion: 1,
          idempotencyKey: expect.stringMatching(/^workbench-risk-decision:[0-9a-f-]{36}$/),
          assessmentId: id,
          expectedAssessmentRevision: 7,
          finding: {
            recordId: summary.recordId,
            recordRevision: summary.recordRevision,
          },
          decision: 'DENY',
          rationale: 'The validated risk must remain blocking for this release.',
          compensatingControls: [],
          expiresAt: null,
        },
      },
    })
    expect(JSON.stringify(riskPayloads[0])).not.toContain('principalId')
    expect(endpoints).toEqual([
      'securityAssuranceWorkbench/getAssessment',
      'securityAssuranceWorkbench/waitForAssessmentRevision',
      'securityAssuranceWorkbench/listFindings',
      'securityAssuranceWorkbench/getFinding',
      'securityAssuranceWorkbench/recordRiskDecision',
      'securityAssuranceWorkbench/getAssessment',
    ])
  })

  it('requests cancellation only from the current Service action and does not treat its receipt as terminal', async () => {
    const ctx = new Context()
    contexts.push(ctx)
    await ctx.plugin(TypertRegistry)
    await installClientUiFoundation(ctx)

    const id = assessmentId('asm-00000000-0000-0000-0000-000000000084')
    const blocked: AssessmentSnapshotV1 = {
      ...snapshotAt(id, 4, 'BLOCKED'),
      availableActions: [{ kind: 'CANCEL_ASSESSMENT', expectedAssessmentRevision: 4 }],
    }
    const cancellationRequested: AssessmentSnapshotV1 = {
      ...blocked,
      assessmentRevision: 5,
      availableActions: [],
      updatedAt: '2026-08-24T00:05:00.000Z',
    }
    let assessmentReads = 0
    const cancelPayloads: unknown[] = []
    ctx.provide('connection', { rpc: { call(
      _path: string,
      endpoint: string,
      payload: unknown,
      signal: AbortSignal,
    ): Promise<unknown> {
      if (endpoint === 'securityAssuranceWorkbench/getAssessment') {
        assessmentReads += 1
        return Promise.resolve({
          ok: true,
          value: {
            ok: true,
            value: assessmentReads === 1 ? blocked : cancellationRequested,
          },
        })
      }
      if (endpoint === 'securityAssuranceWorkbench/waitForAssessmentRevision') {
        return new Promise(resolve => {
          signal.addEventListener('abort', () => {
            resolve({ ok: false, error: { code: 'aborted' } })
          }, { once: true })
        })
      }
      if (endpoint === 'securityAssuranceWorkbench/cancelAssessment') {
        cancelPayloads.push(payload)
        const idempotencyKey = (payload as {
          readonly args: { readonly request: { readonly idempotencyKey: string } }
        }).args.request.idempotencyKey
        return Promise.resolve({
          ok: true,
          value: {
            ok: true,
            value: {
              schemaVersion: 1,
              operation: 'cancel_assessment',
              assessmentId: id,
              assessmentRevision: 5,
              acceptedState: 'BLOCKED',
              idempotencyKey,
              acceptedAt: '2026-08-24T00:05:00.000Z',
              correlationId: 'sec-00000000-0000-0000-0000-000000000084',
            },
          },
        })
      }
      throw new Error(`Unexpected endpoint: ${endpoint}`)
    } } } as never)
    await ctx.plugin({ inject: clientRemoteInject, apply: applyClientRemote })
    await ctx.plugin({ inject: workbenchClientInject, apply: applyWorkbenchClient })
    const controller = ctx.securityAssuranceWorkbench as SecurityAssuranceWorkbenchController
    const authorityId = authorityContextId('workbench-session-cancel')

    await controller.openAssessment({
      securityAssuranceWorkbenchContextId: authorityId,
      assessmentId: id,
    })
    await expect(controller.cancelAssessment({
      code: 'OPERATOR_CANCEL',
      summary: 'Cancel this blocked assessment and wait for durable quiescence.',
    })).resolves.toMatchObject({
      kind: 'READY',
      snapshot: {
        assessmentRevision: 5,
        state: 'BLOCKED',
        availableActions: [],
      },
      assessmentCommand: { kind: 'IDLE' },
    })
    expect(cancelPayloads).toHaveLength(1)
    expect(cancelPayloads[0]).toMatchObject({
      args: {
        securityAssuranceWorkbenchContextId: authorityId,
        request: {
          schemaVersion: 1,
          contractVersion: 1,
          assessmentId: id,
          expectedAssessmentRevision: 4,
          idempotencyKey: expect.stringMatching(/^workbench-cancel:[0-9a-f-]{36}$/),
          reason: {
            code: 'OPERATOR_CANCEL',
            summary: 'Cancel this blocked assessment and wait for durable quiescence.',
          },
        },
      },
    })
    expect(JSON.stringify(cancelPayloads[0])).not.toContain('principalId')
  })

  it('refetches the Service Snapshot after a stale projected action conflicts', async () => {
    const ctx = new Context()
    contexts.push(ctx)
    await ctx.plugin(TypertRegistry)
    await installClientUiFoundation(ctx)

    const id = assessmentId('asm-00000000-0000-0000-0000-000000000085')
    const displayed: AssessmentSnapshotV1 = {
      ...snapshotAt(id, 4, 'BLOCKED'),
      availableActions: [{ kind: 'CANCEL_ASSESSMENT', expectedAssessmentRevision: 4 }],
    }
    const refreshed: AssessmentSnapshotV1 = {
      ...snapshotAt(id, 5, 'BLOCKED'),
      availableActions: [],
      updatedAt: '2026-08-24T00:05:00.000Z',
    }
    let assessmentReads = 0
    const cancelPayloads: unknown[] = []
    ctx.provide('connection', { rpc: { call(
      _path: string,
      endpoint: string,
      payload: unknown,
      signal: AbortSignal,
    ): Promise<unknown> {
      if (endpoint === 'securityAssuranceWorkbench/getAssessment') {
        assessmentReads += 1
        return Promise.resolve({
          ok: true,
          value: { ok: true, value: assessmentReads === 1 ? displayed : refreshed },
        })
      }
      if (endpoint === 'securityAssuranceWorkbench/waitForAssessmentRevision') {
        return new Promise(resolve => {
          signal.addEventListener('abort', () => {
            resolve({ ok: false, error: { code: 'aborted' } })
          }, { once: true })
        })
      }
      if (endpoint === 'securityAssuranceWorkbench/cancelAssessment') {
        cancelPayloads.push(payload)
        return Promise.resolve({
          ok: true,
          value: {
            ok: false,
            error: {
              schemaVersion: 1,
              code: 'CONFLICT',
              message: 'The Assessment revision changed before the command was admitted.',
              retryable: false,
              correlationId: 'sec-00000000-0000-0000-0000-000000000085',
            },
          },
        })
      }
      throw new Error(`Unexpected endpoint: ${endpoint}`)
    } } } as never)
    await ctx.plugin({ inject: clientRemoteInject, apply: applyClientRemote })
    await ctx.plugin({ inject: workbenchClientInject, apply: applyWorkbenchClient })
    const controller = ctx.securityAssuranceWorkbench as SecurityAssuranceWorkbenchController

    await controller.openAssessment({
      securityAssuranceWorkbenchContextId: authorityContextId('workbench-session-stale-action'),
      assessmentId: id,
    })
    await expect(controller.cancelAssessment({
      code: 'OPERATOR_CANCEL',
      summary: 'Cancel only if the displayed Service revision is still current.',
    })).resolves.toMatchObject({
      kind: 'READY',
      snapshot: { assessmentRevision: 5, availableActions: [] },
      assessmentCommand: { kind: 'IDLE' },
    })
    expect(assessmentReads).toBe(2)
    expect(cancelPayloads).toHaveLength(1)
    expect(cancelPayloads[0]).toMatchObject({
      args: { request: { assessmentId: id, expectedAssessmentRevision: 4 } },
    })
    expect(controller.getState()).not.toHaveProperty('failure')
  })

  it('opens and reauthorizes the exact Runtime Health projection without browser derivation', async () => {
    const ctx = new Context()
    contexts.push(ctx)
    await ctx.plugin(TypertRegistry)
    await installClientUiFoundation(ctx)
    const authorityId = authorityContextId('workbench-session-health-client')
    const payloads: Array<{ readonly endpoint: string; readonly payload: unknown }> = []
    let healthRead = 0
    const healthSnapshot = (state: 'READ_ONLY_SAFE' | 'READY') => ({
      schemaVersion: 1 as const,
      product: { name: 'dsh-security-assurance' as const, version: '0.1.0-rc.1' as const },
      compatibility: {
        targetHarnessVersion: '0.1.1-rc.2' as const,
        requiredNodeRange: '^22.19.0 || >=24.0.0' as const,
        actualNodeVersion: '24.7.0',
        harnessVerification: 'PENDING_INVARIANT' as const,
      },
      state,
      admission: {
        queries: true,
        mutations: state === 'READY',
        sealedExports: state === 'READY',
      },
      checks: [{
        id: 'persistence.sqlite',
        status: state === 'READY' ? 'PASS' as const : 'FAIL' as const,
        required: true,
        message: state === 'READY' ? 'SQLite persistence is ready.' : 'SQLite persistence is unavailable.',
      }],
    })
    ctx.provide('connection', { rpc: { call(
      _path: string,
      endpoint: string,
      payload: unknown,
    ): Promise<unknown> {
      payloads.push({ endpoint, payload })
      if (endpoint === 'securityAssuranceWorkbench/listAssessments') {
        return Promise.resolve({
          ok: true,
          value: { ok: true, value: {
            schemaVersion: 1,
            consistencyWatermark: 'health.signature',
            assessments: [],
            nextCursor: null,
          } },
        })
      }
      if (endpoint === 'securityAssuranceWorkbench/getHealth') {
        healthRead += 1
        return Promise.resolve({
          ok: true,
          value: { ok: true, value: healthSnapshot(healthRead === 1 ? 'READ_ONLY_SAFE' : 'READY') },
        })
      }
      throw new Error(`Unexpected endpoint: ${endpoint}`)
    } } } as never)
    await ctx.plugin({ inject: clientRemoteInject, apply: applyClientRemote })
    await ctx.plugin({ inject: workbenchClientInject, apply: applyWorkbenchClient })
    const controller = ctx.securityAssuranceWorkbench as SecurityAssuranceWorkbenchController

    await controller.openAssessmentSelection({ securityAssuranceWorkbenchContextId: authorityId })
    await expect(controller.openRuntimeHealth()).resolves.toMatchObject({
      kind: 'HEALTH_READY',
      health: {
        state: 'READ_ONLY_SAFE',
        admission: { queries: true, mutations: false, sealedExports: false },
        checks: [{ id: 'persistence.sqlite', status: 'FAIL' }],
      },
    })
    await expect(controller.refreshRuntimeHealth()).resolves.toMatchObject({
      kind: 'HEALTH_READY',
      health: {
        state: 'READY',
        admission: { queries: true, mutations: true, sealedExports: true },
        checks: [{ id: 'persistence.sqlite', status: 'PASS' }],
      },
    })
    expect(payloads.map(item => item.endpoint)).toEqual([
      'securityAssuranceWorkbench/listAssessments',
      'securityAssuranceWorkbench/getHealth',
      'securityAssuranceWorkbench/getHealth',
    ])
    expect(payloads[1]?.payload).toMatchObject({
      args: {
        securityAssuranceWorkbenchContextId: authorityId,
        request: { schemaVersion: 1 },
      },
    })
    expect(JSON.stringify(payloads)).not.toContain('principalId')
  })

  it('opens a matching SEALED Bundle and registered destination IDs, then refetches Assessment detail', async () => {
    const ctx = new Context()
    contexts.push(ctx)
    await ctx.plugin(TypertRegistry)
    await installClientUiFoundation(ctx)
    const id = assessmentId('asm-00000000-0000-0000-0000-0000000000b1')
    const digest = {
      schemaVersion: 1 as const,
      algorithm: 'sha256' as const,
      mediaType: 'application/vnd.dsh.canonical-json',
      byteLength: 42,
      canonicalization: 'dsh-canonical-json-v1' as const,
      value: 'b'.repeat(64),
    }
    const seal = {
      schemaVersion: 1 as const,
      sealId: 'seal-00000000-0000-0000-0000-0000000000b1',
      assessmentRevision: 7,
      verdict: 'SATISFIED' as const,
      digest,
      sealedAt: '2026-08-25T00:07:00.000Z',
    }
    const snapshot: AssessmentSnapshotV1 = {
      ...snapshotAt(id, 7, 'SEALED'),
      coverage: {
        ...snapshotAt(id, 7, 'SEALED').coverage,
        status: 'COMPLETE',
        satisfiedObligations: 1,
      },
      verdict: 'SATISFIED',
      seal,
    }
    const manifest = {
      schemaVersion: 1 as const,
      assessmentId: id,
      assessmentRevision: 7,
      verdict: 'SATISFIED' as const,
      seal,
      records: [{
        recordId: 'bundle/assessment-snapshot',
        schemaId: 'security/assessment-snapshot',
        schemaVersion: 1 as const,
        classification: 'INTERNAL' as const,
        digest,
      }],
      omissions: [{ schemaId: 'security/threat-model', reason: 'NO_ELIGIBLE_ANALYZER' as const }],
      digest,
    }
    let manifestResponse = manifest
    const payloads: Array<{ readonly endpoint: string; readonly payload: unknown }> = []
    ctx.provide('connection', { rpc: { call(
      _path: string,
      endpoint: string,
      payload: unknown,
    ): Promise<unknown> {
      payloads.push({ endpoint, payload })
      if (endpoint === 'securityAssuranceWorkbench/getAssessment') {
        return Promise.resolve({ ok: true, value: { ok: true, value: snapshot } })
      }
      if (endpoint === 'securityAssuranceWorkbench/getBundleManifest') {
        return Promise.resolve({ ok: true, value: { ok: true, value: manifestResponse } })
      }
      if (endpoint === 'securityAssuranceWorkbench/getRepository') {
        return Promise.resolve({ ok: true, value: { ok: true, value: {
          schemaVersion: 1,
          repositoryId: snapshot.repository.repositoryId,
          repositoryRevision: snapshot.repository.repositoryRevision,
          state: 'ENABLED',
          displayName: 'Bundle fixture',
          rootIdentityDigest: `sha256:${'c'.repeat(64)}`,
          bindings: {
            policyId: 'security/standard',
            assessmentProfileId: 'security/standard',
            evidenceProtectionId: 'evidence/local-protected',
            dataEgressPolicyId: 'egress/deny-by-default',
            platform: 'win32',
            deliveryDestinationIds: ['delivery/local-audit', 'delivery/team-report'],
          },
          createdAt: '2026-08-25T00:00:00.000Z',
          updatedAt: '2026-08-25T00:00:00.000Z',
        } } })
      }
      throw new Error(`Unexpected endpoint: ${endpoint}`)
    } } } as never)
    await ctx.plugin({ inject: clientRemoteInject, apply: applyClientRemote })
    await ctx.plugin({ inject: workbenchClientInject, apply: applyWorkbenchClient })
    const controller = ctx.securityAssuranceWorkbench as SecurityAssuranceWorkbenchController
    const authorityId = authorityContextId('workbench-session-bundle-client')

    await controller.openAssessment({
      securityAssuranceWorkbenchContextId: authorityId,
      assessmentId: id,
    })
    await expect(controller.openBundle()).resolves.toMatchObject({
      kind: 'BUNDLE_READY',
      assessmentId: id,
      manifest: { digest, records: [{ recordId: 'bundle/assessment-snapshot' }] },
      deliveryDestinationIds: ['delivery/local-audit', 'delivery/team-report'],
    })
    await expect(controller.backToAssessmentDetail()).resolves.toMatchObject({
      kind: 'READY',
      assessmentId: id,
      snapshot: { state: 'SEALED', seal: { sealId: seal.sealId } },
    })
    manifestResponse = { ...manifest, assessmentRevision: 8 }
    await expect(controller.openBundle()).resolves.toMatchObject({
      kind: 'FAILED',
      failure: { source: 'CLIENT', code: 'BUNDLE_PROTOCOL_VIOLATION', retryable: false },
    })
    expect(payloads.map(item => item.endpoint)).toEqual([
      'securityAssuranceWorkbench/getAssessment',
      'securityAssuranceWorkbench/getBundleManifest',
      'securityAssuranceWorkbench/getRepository',
      'securityAssuranceWorkbench/getAssessment',
      'securityAssuranceWorkbench/getBundleManifest',
    ])
    expect(payloads[1]?.payload).toMatchObject({
      args: {
        securityAssuranceWorkbenchContextId: authorityId,
        request: { schemaVersion: 1, assessmentId: id },
      },
    })
    expect(JSON.stringify(payloads)).not.toContain('principalId')
  })

  it('drives Repository selection, digest-bound preflight, and exact Assessment start', async () => {
    const ctx = new Context()
    contexts.push(ctx)
    await ctx.plugin(TypertRegistry)
    await installClientUiFoundation(ctx)
    const repository = {
      schemaVersion: 1 as const,
      repositoryId: 'repo-00000000-0000-0000-0000-000000000001' as const,
      repositoryRevision: 1,
      state: 'ENABLED' as const,
      displayName: 'Workbench starter fixture',
      rootIdentityDigest: `sha256:${'1'.repeat(64)}`,
      bindings: {
        policyId: 'security/node-package-lifecycle',
        assessmentProfileId: 'security/standard',
        evidenceProtectionId: 'evidence/local-protected',
        dataEgressPolicyId: 'egress/deny-by-default',
        platform: 'win32' as const,
        deliveryDestinationIds: [],
      },
      createdAt: '2026-08-24T00:00:00.000Z',
      updatedAt: '2026-08-24T00:00:00.000Z',
    }
    const selection = {
      schemaVersion: 1 as const,
      repositoryId: repository.repositoryId,
      subject: { kind: 'workspace_snapshot' as const },
      assessmentMode: 'REPOSITORY' as const,
      assessmentProfileId: 'security/standard',
      target: { kind: 'repository' as const },
      requestedStrongerControlIds: [] as readonly string[],
    }
    const proposalDigest = {
      schemaVersion: 1 as const,
      algorithm: 'sha256' as const,
      mediaType: 'application/vnd.dsh.security.start-preflight+json',
      byteLength: 1,
      canonicalization: 'dsh-canonical-json-v1' as const,
      value: 'f'.repeat(64),
    }
    const baseCatalog = {
      schemaVersion: 1 as const,
      repository,
      assessmentModes: [{
        assessmentMode: 'REPOSITORY' as const,
        label: { en: 'Repository', zhCN: '完整仓库' },
        targetKind: 'repository' as const,
        subjectKinds: ['git_revision', 'workspace_snapshot'] as const,
        support: 'SUPPORTED' as const,
        limitations: ['Package lifecycle only.'],
      }],
      assessmentProfiles: [{
        assessmentProfileId: 'security/standard',
        label: { en: 'Standard', zhCN: '标准' },
        maximumBudget: { status: 'NOT_REPORTED' as const },
        limitations: [],
      }],
      strongerControls: [],
      supportedEcosystemIds: ['node-package-manifest'],
      supportedPlatforms: ['win32', 'linux', 'darwin'] as const,
      supportMatrixReferences: ['dsh-security-assurance/support-matrix/v0.1-development'],
      startPreflight: null,
    }
    const preflight = {
      schemaVersion: 1 as const,
      repository: {
        repositoryId: repository.repositoryId,
        repositoryRevision: 1,
        displayName: repository.displayName,
      },
      selection,
      effectivePolicyId: repository.bindings.policyId,
      effectiveProfileId: repository.bindings.assessmentProfileId,
      providerComposition: [{
        providerId: 'dsh-security-assurance',
        analyzerId: 'dsh/builtin-node-package-lifecycle',
        analyzerVersion: '1.0.0',
        executionClass: 'PURE' as const,
        eligibility: 'ELIGIBLE' as const,
        reason: null,
        supportedEcosystemIds: ['node-package-manifest'],
        supportedPlatforms: ['win32', 'linux', 'darwin'] as const,
        coverageObligationIds: ['node-package-install-lifecycle-policy'],
      }],
      dataEgress: {
        policyId: repository.bindings.dataEgressPolicyId,
        destinationIds: [],
        categories: ['NONE'] as const,
      },
      evidenceProtection: { policyId: repository.bindings.evidenceProtectionId },
      maximumBudget: { status: 'NOT_REPORTED' as const },
      unsupportedConditions: [],
      claimLimitations: ['Package lifecycle only.'],
      coverageLimitations: ['Package lifecycle only.'],
      admissible: true,
      proposalDigest,
    }
    const id = assessmentId('asm-00000000-0000-0000-0000-000000000091')
    const payloads: Array<{ readonly endpoint: string; readonly payload: unknown }> = []
    ctx.provide('connection', { rpc: { call(
      _path: string,
      endpoint: string,
      payload: unknown,
    ): Promise<unknown> {
      payloads.push({ endpoint, payload })
      if (endpoint === 'securityAssuranceWorkbench/listAssessments') {
        return Promise.resolve({
          ok: true,
          value: { ok: true, value: {
            schemaVersion: 1,
            consistencyWatermark: 'starter.signature',
            assessments: [],
            nextCursor: null,
          } },
        })
      }
      if (endpoint === 'securityAssuranceWorkbench/listRepositories') {
        return Promise.resolve({
          ok: true,
          value: { ok: true, value: { schemaVersion: 1, repositories: [repository], truncated: false } },
        })
      }
      if (endpoint === 'securityAssuranceWorkbench/getCatalog') {
        const request = (payload as { readonly args: { readonly request: { readonly proposedStart?: unknown } } }).args.request
        return Promise.resolve({
          ok: true,
          value: { ok: true, value: request.proposedStart === undefined
            ? baseCatalog
            : { ...baseCatalog, startPreflight: preflight } },
        })
      }
      if (endpoint === 'securityAssuranceWorkbench/startAssessment') {
        const request = (payload as { readonly args: { readonly request: { readonly idempotencyKey: string } } }).args.request
        return Promise.resolve({
          ok: true,
          value: { ok: true, value: {
            schemaVersion: 1,
            operation: 'start_assessment',
            assessmentId: id,
            assessmentRevision: 1,
            state: 'CREATED',
            repositoryId: repository.repositoryId,
            repositoryRevision: 1,
            subject: { kind: 'workspace_snapshot', digest: proposalDigest },
            idempotencyKey: request.idempotencyKey,
            acceptedAt: '2026-08-24T00:01:00.000Z',
            correlationId: 'sec-00000000-0000-0000-0000-000000000091',
          } },
        })
      }
      if (endpoint === 'securityAssuranceWorkbench/getAssessment') {
        return Promise.resolve({ ok: true, value: { ok: true, value: snapshotAt(id, 2, 'SEALED') } })
      }
      throw new Error(`Unexpected endpoint: ${endpoint}`)
    } } } as never)
    await ctx.plugin({ inject: clientRemoteInject, apply: applyClientRemote })
    await ctx.plugin({ inject: workbenchClientInject, apply: applyWorkbenchClient })
    const controller = ctx.securityAssuranceWorkbench as SecurityAssuranceWorkbenchController

    await controller.openAssessmentSelection({
      securityAssuranceWorkbenchContextId: authorityContextId('workbench-session-starter-client'),
    })
    await expect(controller.openRepositories()).resolves.toMatchObject({
      kind: 'REPOSITORIES_READY',
      repositories: [{ repositoryId: repository.repositoryId }],
    })
    await expect(controller.selectRepository(repository.repositoryId)).resolves.toMatchObject({
      kind: 'WIZARD_READY',
      startPreflight: null,
    })
    await expect(controller.requestStartPreflight(selection)).resolves.toMatchObject({
      kind: 'WIZARD_READY',
      startPreflight: { proposalDigest },
    })
    await expect(controller.confirmStartAssessment()).resolves.toMatchObject({
      kind: 'READY',
      assessmentId: id,
      snapshot: { assessmentRevision: 2, state: 'SEALED' },
    })
    expect(payloads.map(item => item.endpoint)).toEqual([
      'securityAssuranceWorkbench/listAssessments',
      'securityAssuranceWorkbench/listRepositories',
      'securityAssuranceWorkbench/getCatalog',
      'securityAssuranceWorkbench/getCatalog',
      'securityAssuranceWorkbench/startAssessment',
      'securityAssuranceWorkbench/getAssessment',
    ])
    expect(payloads[4]?.payload).toMatchObject({
      args: {
        request: {
          ...selection,
          idempotencyKey: expect.stringMatching(/^workbench-start:[0-9a-f-]{36}$/u),
          startPreflightDigest: proposalDigest,
        },
      },
    })
    expect(JSON.stringify(payloads)).not.toContain('principalId')
  })

  it('keeps one in-memory Snapshot current by revision and erases it on close', async () => {
    const ctx = new Context()
    contexts.push(ctx)
    await ctx.plugin(TypertRegistry)
    await installClientUiFoundation(ctx)

    const id = assessmentId('asm-00000000-0000-0000-0000-000000000001')
    const first = snapshotAt(id, 1, 'RUNNING')
    const second = snapshotAt(id, 2, 'BLOCKED')
    let getCount = 0
    let waitSignal: AbortSignal | undefined
    const waitResolvers: Array<(value: unknown) => void> = []
    const call = (
      _path: string,
      endpoint: string,
      _payload: unknown,
      signal: AbortSignal,
    ): Promise<unknown> => {
      if (endpoint === 'securityAssuranceWorkbench/getAssessment') {
        getCount += 1
        return Promise.resolve({
          ok: true,
          value: { ok: true, value: getCount === 1 ? first : second },
        })
      }
      if (endpoint === 'securityAssuranceWorkbench/waitForAssessmentRevision') {
        waitSignal = signal
        return new Promise(resolve => { waitResolvers.push(resolve) })
      }
      throw new Error(`Unexpected endpoint: ${endpoint}`)
    }
    ctx.provide('connection', { rpc: { call } } as never)
    await ctx.plugin({ inject: clientRemoteInject, apply: applyClientRemote })
    const workbenchFiber = ctx.plugin({
      inject: workbenchClientInject,
      apply: applyWorkbenchClient,
    })
    await workbenchFiber

    const controller = ctx.securityAssuranceWorkbench as SecurityAssuranceWorkbenchController
    const revisions: number[] = []
    controller.subscribe(state => {
      if (state.kind === 'READY') revisions.push(state.snapshot.assessmentRevision)
    })
    const opened = await controller.openAssessment({
      securityAssuranceWorkbenchContextId: authorityContextId('workbench-session-reviewer'),
      assessmentId: id,
    })
    expect(opened).toMatchObject({
      kind: 'READY',
      snapshot: { assessmentId: id, assessmentRevision: 1, state: 'RUNNING' },
    })
    expect(revisions).toEqual([1])
    expect(waitSignal?.aborted).toBe(false)

    waitResolvers[0]?.({
      ok: true,
      value: {
        ok: true,
        value: {
          schemaVersion: 1,
          assessmentId: id,
          kind: 'TIMED_OUT',
          changed: false,
          assessmentRevision: 1,
          state: 'RUNNING',
          terminal: false,
          snapshotRefreshRequired: false,
        },
      },
    })
    await expect.poll(() => waitResolvers.length).toBe(2)
    waitResolvers[1]?.({
      ok: true,
      value: {
        ok: true,
        value: {
          schemaVersion: 1,
          assessmentId: id,
          kind: 'CHANGED',
          changed: true,
          assessmentRevision: 2,
          state: 'BLOCKED',
          terminal: false,
          snapshotRefreshRequired: true,
        },
      },
    })
    await expect.poll(() => controller.getState()).toMatchObject({
      kind: 'READY',
      snapshot: { assessmentId: id, assessmentRevision: 2, state: 'BLOCKED' },
    })
    expect(revisions).toEqual([1, 2])

    controller.closeAssessment()
    expect(waitSignal?.aborted).toBe(true)
    expect(controller.getState()).toEqual({ kind: 'CLOSED' })

    await workbenchFiber.dispose()
    expect(ctx.get('securityAssuranceWorkbench')).toBeUndefined()
    expect(ctx.get('remote.securityAssuranceWorkbench')).toBeUndefined()
  })

  it('fails closed and erases the authority-bound payload when Host authority disappears', async () => {
    const ctx = new Context()
    contexts.push(ctx)
    await ctx.plugin(TypertRegistry)
    await installClientUiFoundation(ctx)

    const id = assessmentId('asm-00000000-0000-0000-0000-000000000002')
    const authorityId = authorityContextId('workbench-session-expiring')
    let waitSignal: AbortSignal | undefined
    let rejectAuthority: (() => void) | undefined
    const call = (
      _path: string,
      endpoint: string,
      _payload: unknown,
      signal: AbortSignal,
    ): Promise<unknown> => {
      if (endpoint === 'securityAssuranceWorkbench/getAssessment') {
        return Promise.resolve({ ok: true, value: { ok: true, value: snapshotAt(id, 1, 'RUNNING') } })
      }
      if (endpoint === 'securityAssuranceWorkbench/waitForAssessmentRevision') {
        waitSignal = signal
        return new Promise(resolve => {
          rejectAuthority = () => resolve({
            ok: false,
            error: {
              code: 'lookup-not-found',
              message: 'The authenticated Workbench authority context is no longer available.',
              details: {},
            },
          })
        })
      }
      throw new Error(`Unexpected endpoint: ${endpoint}`)
    }
    ctx.provide('connection', { rpc: { call } } as never)
    await ctx.plugin({ inject: clientRemoteInject, apply: applyClientRemote })
    await ctx.plugin({ inject: workbenchClientInject, apply: applyWorkbenchClient })
    const controller = ctx.securityAssuranceWorkbench as SecurityAssuranceWorkbenchController

    await expect(controller.openAssessment({
      securityAssuranceWorkbenchContextId: authorityId,
      assessmentId: id,
    })).resolves.toMatchObject({ kind: 'READY', snapshot: { assessmentRevision: 1 } })

    rejectAuthority?.()
    await expect.poll(() => controller.getState()).toMatchObject({
      kind: 'FAILED',
      assessmentId: id,
      failure: { source: 'TRANSPORT', code: 'lookup-not-found' },
    })
    expect(controller.getState()).not.toHaveProperty('snapshot')
    expect(JSON.stringify(controller.getState())).not.toContain(authorityId)
    expect(waitSignal?.aborted).toBe(true)
  })
})
