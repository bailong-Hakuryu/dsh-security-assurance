import { Context } from '@deepseek-ai/cordis'
import {
  apply as applyClientRemote,
  inject as clientRemoteInject,
} from '../../deepseek-harness-master/packages/api/gateway/lib/types/client/index.js'
import TypertRegistry from '@deepseek-ai/dsh-typert-registry'
import { SlotRegistry } from '../../deepseek-harness-master/packages/client/runtime/lib/types/client/slots.js'
import { afterEach, describe, expect, it } from 'vitest'
import type {
  AssessmentId,
  AssessmentListItemV1,
  AssessmentSnapshotV1,
} from '../src/contracts.ts'
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

describe('Security Assurance Workbench Client', () => {
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
