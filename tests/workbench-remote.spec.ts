import { execFile } from 'node:child_process'
import { mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { promisify } from 'node:util'
import { Context } from '@deepseek-ai/cordis'
import TypertGatewayService from '@deepseek-ai/dsh-api-gateway'
import TypertRegistry from '@deepseek-ai/dsh-typert-registry'
import { afterEach, describe, expect, it } from 'vitest'
import SecurityAssuranceService, {
  RISK_DECISION_WINDOW_CONTROL_ID,
  type AssessmentId,
  type AssessmentSnapshotV1,
  type SecurityResult,
} from '../src/index.ts'
import SecurityAssuranceWorkbenchRemote, {
  type AuthenticatedWorkbenchOperatorV1,
  type WorkbenchAuthorityContextId,
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

async function harness(): Promise<{
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
  await ctx.plugin(SecurityAssuranceService, { dshHome })
  await ctx.securityAssurance.whenReady()
  const resolvedContextIds: WorkbenchAuthorityContextId[] = []
  const operators = new Map<WorkbenchAuthorityContextId, AuthenticatedWorkbenchOperatorV1>([
    [authorityContextId('workbench-session-reviewer'), {
      principalId: 'workbench-reviewer',
      permissions: ['assessment:read', 'risk:decide'],
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
