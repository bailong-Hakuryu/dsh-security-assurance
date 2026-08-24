import { Context } from '@deepseek-ai/cordis'
import {
  apply as applyClientRemote,
  inject as clientRemoteInject,
} from '../../deepseek-harness-master/packages/api/gateway/lib/types/client/index.js'
import TypertRegistry from '@deepseek-ai/dsh-typert-registry'
import { SlotRegistry } from '../../deepseek-harness-master/packages/client/runtime/lib/types/client/slots.js'
import { afterEach, describe, expect, it } from 'vitest'
import type { AssessmentId, AssessmentSnapshotV1 } from '../src/contracts.ts'
import {
  apply as applyWorkbenchClient,
  inject as workbenchClientInject,
  type SecurityAssuranceWorkbenchController,
  type WorkbenchAuthorityContextId,
} from '../src/client/index.ts'

const contexts: Context[] = []

afterEach(async () => {
  await Promise.all(contexts.splice(0).map(ctx => ctx.fiber.dispose()))
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
    policy: { policyId: 'security/standard', digest },
    coverage: {
      status: 'PENDING',
      mandatoryObligations: 1,
      satisfiedObligations: 0,
      gapObligations: 0,
      resolutions: [],
      digest,
    },
    availableActions: [],
    verdict: null,
    seal: null,
    createdAt: '2026-08-24T00:00:00.000Z',
    updatedAt: '2026-08-24T00:00:00.000Z',
  }
}

describe('Security Assurance Workbench Client', () => {
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
          assessmentRevision: 1,
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
          assessmentRevision: 2,
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
