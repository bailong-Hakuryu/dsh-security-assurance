import { execFile } from 'node:child_process'
import { mkdtemp, realpath, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { promisify } from 'node:util'
import { Context } from '@deepseek-ai/cordis'
import TypertGatewayService from '@deepseek-ai/dsh-api-gateway'
import TypertRegistry from '@deepseek-ai/dsh-typert-registry'
import { afterEach, describe, expect, it } from 'vitest'
import {
  RISK_DECISION_WINDOW_CONTROL_ID,
  type AssessmentId,
  type AssessmentSnapshotV1,
  type SecurityResult,
} from '../src/index.ts'
import * as workbenchLocal from '../src/workbench-local.ts'
import {
  LOCAL_WORKBENCH_PERMISSIONS,
  LOCAL_WORKBENCH_PRINCIPAL_ID,
  LocalWorkbenchAuthority,
  type LocalWorkbenchContextV1,
} from '../src/workbench-local.ts'
import type { WorkbenchAuthorityContextId } from '../src/workbench-remote.ts'
import { SecurityAssuranceTestComposition } from './support/security-assurance-test-composition.ts'
import { referenceHostInvocation } from './support/reference-host.ts'
import { removeTemporaryRoots } from './support/remove-temporary-root.ts'

const run = promisify(execFile)
const temporaryRoots: string[] = []
const contexts: Context[] = []

afterEach(async () => {
  await Promise.all(contexts.splice(0).map(ctx => ctx.fiber.dispose()))
  await removeTemporaryRoots(temporaryRoots)
})

function gatewayErrorCode(code: string): RegExp {
  return new RegExp(`^(?:gateway/)?${code}$`)
}

describe('ADR 0321 local Workbench authority', () => {
  it('issues bounded, expiring contexts with exactly the model-tool permissions', () => {
    let now = Date.parse('2026-09-26T00:00:00.000Z')
    const authority = new LocalWorkbenchAuthority({ ttlMs: 60_000, now: () => now })
    const context = authority.issue()
    expect(context.contextId).toMatch(/^[A-Za-z0-9_-]{16,256}$/u)
    expect(context).toEqual({
      schemaVersion: 1,
      contextId: context.contextId,
      expiresAt: '2026-09-26T00:01:00.000Z',
      permissions: [...LOCAL_WORKBENCH_PERMISSIONS],
    })
    expect(authority.resolveAuthorityContext(context.contextId as WorkbenchAuthorityContextId)).toEqual({
      principalId: LOCAL_WORKBENCH_PRINCIPAL_ID,
      permissions: [...LOCAL_WORKBENCH_PERMISSIONS],
    })
    expect(authority.issue().contextId).not.toBe(context.contextId)
    now += 60_000
    expect(authority.resolveAuthorityContext(context.contextId as WorkbenchAuthorityContextId)).toBeUndefined()
  })

  it('grants the model tools\' reach and never Risk, break-glass, disclosure, download, submission, or admin', () => {
    expect([...LOCAL_WORKBENCH_PERMISSIONS].sort()).toEqual([
      'assessment:cancel',
      'assessment:read',
      'assessment:resume',
      'assessment:start',
      'export:read',
      'export:request',
      'health:read',
      'repository:read',
    ])
    for (const denied of [
      'risk:decide',
      'risk:break-glass',
      'evidence:disclose:validation-review',
      'export:download',
      'assurance-submission:read',
      'repository:admin',
    ]) {
      expect(LOCAL_WORKBENCH_PERMISSIONS).not.toContain(denied)
    }
  })

  it('forgets unknown, evicted, and revoked contexts', () => {
    const authority = new LocalWorkbenchAuthority({ capacity: 2 })
    const first = authority.issue()
    const second = authority.issue()
    const third = authority.issue()
    const resolve = (context: LocalWorkbenchContextV1) =>
      authority.resolveAuthorityContext(context.contextId as WorkbenchAuthorityContextId)
    expect(resolve(first)).toBeUndefined()
    expect(resolve(second)).toBeDefined()
    expect(resolve(third)).toBeDefined()
    expect(authority.resolveAuthorityContext('workbench-session-unknown' as WorkbenchAuthorityContextId))
      .toBeUndefined()
    authority.revokeAll()
    expect(resolve(second)).toBeUndefined()
    expect(resolve(third)).toBeUndefined()
  })

  it('lets the authenticated local browser work only within the model-tool permissions', async () => {
    const ctx = new Context()
    contexts.push(ctx)
    const dshHome = await realpath(await mkdtemp(join(tmpdir(), 'dsh-security-local-workbench-home-')))
    temporaryRoots.push(dshHome)
    const repository = await mkdtemp(join(tmpdir(), 'dsh-security-local-workbench-repository-'))
    temporaryRoots.push(repository)
    await run('git', ['init', '-b', 'main'], { cwd: repository })
    await run('git', ['config', 'user.email', 'fixture@example.invalid'], { cwd: repository })
    await run('git', ['config', 'user.name', 'Fixture'], { cwd: repository })
    await writeFile(join(repository, 'package.json'), `${JSON.stringify({
      name: 'local-workbench-fixture',
      version: '1.0.0',
      scripts: { postinstall: 'node setup.js' },
    }, null, 2)}\n`, 'utf8')
    await run('git', ['add', '.'], { cwd: repository })
    await run('git', ['commit', '-m', 'local workbench fixture'], { cwd: repository })

    await ctx.plugin(TypertRegistry)
    await ctx.plugin(SecurityAssuranceTestComposition, { dshHome })
    await ctx.securityAssurance.whenReady()
    await ctx.plugin(workbenchLocal, {})
    await ctx.plugin(TypertGatewayService)

    const host = referenceHostInvocation(ctx.securityAssurance)
    const registered = await ctx.securityAssurance.registerRepository(host, {
      schemaVersion: 1,
      contractVersion: 1,
      idempotencyKey: 'local-workbench-repository-v1',
      root: repository,
      displayName: 'Local Workbench fixture',
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
    const started = await ctx.securityAssurance.startAssessment(host, {
      schemaVersion: 1,
      contractVersion: 1,
      idempotencyKey: 'local-workbench-start-v1',
      repositoryId: registered.value.repositoryId,
      subject: { kind: 'workspace_snapshot' },
      assessmentMode: 'REPOSITORY',
      assessmentProfileId: 'security/standard',
      target: { kind: 'repository' },
      requestedStrongerControlIds: [RISK_DECISION_WINDOW_CONTROL_ID],
    })
    if (!started.ok) throw new Error(`start failed: ${started.error.code}`)
    const assessmentId: AssessmentId = started.value.assessmentId
    let revision = 1
    for (let attempt = 0; attempt < 5; attempt += 1) {
      const current = await ctx.securityAssurance.getAssessment(host, { schemaVersion: 1, assessmentId })
      if (current.ok && current.value.state === 'BLOCKED') break
      if (current.ok) revision = current.value.assessmentRevision
      await ctx.securityAssurance.waitForAssessmentRevision(host, {
        schemaVersion: 1,
        assessmentId,
        afterRevision: revision,
        timeoutMs: 5_000,
      })
    }

    const opened = await ctx.typertGateway.invoke({
      namespace: 'securityAssuranceWorkbenchSession',
      method: 'openLocalContext',
      args: { request: { schemaVersion: 1 } },
    }) as LocalWorkbenchContextV1
    expect(opened.permissions).toEqual([...LOCAL_WORKBENCH_PERMISSIONS])
    const contextId = opened.contextId

    await expect(ctx.typertGateway.invoke({
      namespace: 'securityAssuranceWorkbench',
      method: 'listRepositories',
      args: { securityAssuranceWorkbenchContextId: contextId, request: { schemaVersion: 1, limit: 10 } },
    })).resolves.toMatchObject({ ok: true })

    const local = await ctx.typertGateway.invoke({
      namespace: 'securityAssuranceWorkbench',
      method: 'getAssessment',
      args: { securityAssuranceWorkbenchContextId: contextId, request: { schemaVersion: 1, assessmentId } },
    }) as SecurityResult<AssessmentSnapshotV1>
    if (!local.ok) throw new Error(`local read failed: ${local.error.code}`)
    expect(local.value.state).toBe('BLOCKED')
    expect(local.value.availableActions.map(action => action.kind)).not.toContain('RECORD_RISK_DECISION')

    const hostView = await ctx.securityAssurance.getAssessment(host, { schemaVersion: 1, assessmentId })
    if (!hostView.ok) throw new Error('host read failed')
    const action = hostView.value.availableActions.find(candidate => candidate.kind === 'RECORD_RISK_DECISION')
    if (action?.kind !== 'RECORD_RISK_DECISION') throw new Error('Risk Decision action was not projected')
    await expect(ctx.typertGateway.invoke({
      namespace: 'securityAssuranceWorkbench',
      method: 'recordRiskDecision',
      args: {
        securityAssuranceWorkbenchContextId: contextId,
        request: {
          schemaVersion: 1,
          contractVersion: 1,
          idempotencyKey: 'local-workbench-risk-attempt-v1',
          assessmentId,
          expectedAssessmentRevision: action.expectedAssessmentRevision,
          finding: action.finding,
          decision: 'DENY',
          rationale: 'A local browser must not decide Risk without deployment authority.',
          compensatingControls: [],
          expiresAt: null,
        },
      },
    })).resolves.toMatchObject({ ok: false, error: { code: 'UNAUTHORIZED' } })

    await expect(ctx.typertGateway.invoke({
      namespace: 'securityAssuranceWorkbench',
      method: 'cancelAssessment',
      args: {
        securityAssuranceWorkbenchContextId: contextId,
        request: {
          schemaVersion: 1,
          contractVersion: 1,
          idempotencyKey: 'local-workbench-cancel-v1',
          assessmentId,
          expectedAssessmentRevision: local.value.assessmentRevision,
          reason: { code: 'OPERATOR_CANCEL', summary: 'The local operator stopped this assessment.' },
        },
      },
    })).resolves.toMatchObject({ ok: true, value: { operation: 'cancel_assessment' } })

    await expect(ctx.typertGateway.invoke({
      namespace: 'securityAssuranceWorkbench',
      method: 'getAssessment',
      args: {
        securityAssuranceWorkbenchContextId: 'workbench-session-forged',
        request: { schemaVersion: 1, assessmentId },
      },
    })).rejects.toMatchObject({ code: expect.stringMatching(gatewayErrorCode('lookup-not-found')) })
  })
})
