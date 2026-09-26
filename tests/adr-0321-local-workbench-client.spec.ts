import { Context, type Plugin } from '@deepseek-ai/cordis'
import {
  apply as applyClientRemote,
  inject as clientRemoteInject,
} from '@deepseek-ai/dsh-api-gateway/src/client/index.ts'
import TypertRegistry from '@deepseek-ai/dsh-typert-registry'
import { afterEach, describe, expect, it } from 'vitest'
import type { AssessmentId, AssessmentListItemV1 } from '../src/contracts.ts'
import {
  apply as applyWorkbenchClient,
  inject as workbenchClientInject,
  type SecurityAssuranceWorkbenchController,
} from '../src/web-client/workbench/controller.ts'
import * as securityClient from '../src/web-client/index.ts'
import { LOCAL_WORKBENCH_PERMISSIONS } from '../src/workbench-local.ts'
import {
  provideConnection,
  provideSlotRecorder,
  type RecordedSlotEntry,
  type WorkbenchRemoteCall,
} from './support/workbench-client-host.ts'

const contexts: Context[] = []

afterEach(async () => {
  await Promise.all(contexts.splice(0).map(ctx => ctx.fiber.dispose()))
})

const ISSUED_CONTEXT_ID = 'local-workbench-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
const OPEN_LOCAL_CONTEXT = 'securityAssuranceWorkbenchSession/openLocalContext'
const LIST_ASSESSMENTS = 'securityAssuranceWorkbench/listAssessments'

interface RecordedCall {
  readonly endpoint: string
  readonly payload: unknown
}

function issuedContext(contextId = ISSUED_CONTEXT_ID): unknown {
  return {
    ok: true,
    value: {
      schemaVersion: 1,
      contextId,
      expiresAt: '2026-09-26T08:00:00.000Z',
      permissions: [...LOCAL_WORKBENCH_PERMISSIONS],
    },
  }
}

function listedAssessment(): AssessmentListItemV1 {
  return {
    schemaVersion: 1,
    assessmentId: 'asm-00000000-0000-0000-0000-000000000321' as AssessmentId,
    assessmentRevision: 4,
    state: 'SEALED',
    repository: {
      repositoryId: 'repo-00000000-0000-0000-0000-000000000321',
      repositoryRevision: 1,
    } as AssessmentListItemV1['repository'],
    subjectKind: 'workspace_snapshot',
    policyId: 'security/standard',
    coverageStatus: 'COMPLETE',
    verdict: 'SATISFIED',
    createdAt: '2026-09-26T00:00:00.000Z',
    updatedAt: '2026-09-26T00:01:00.000Z',
  }
}

const listedPage = {
  ok: true,
  value: {
    ok: true,
    value: {
      schemaVersion: 1,
      consistencyWatermark: 'local.signature',
      assessments: [listedAssessment()],
      nextCursor: null,
    },
  },
}

async function mountWorkbench(
  answer: (endpoint: string) => Promise<unknown>,
): Promise<{
  readonly controller: SecurityAssuranceWorkbenchController
  readonly calls: RecordedCall[]
  readonly slots: RecordedSlotEntry[]
}> {
  const ctx = new Context()
  contexts.push(ctx)
  await ctx.plugin(TypertRegistry)
  const slots = provideSlotRecorder(ctx)
  const calls: RecordedCall[] = []
  const call: WorkbenchRemoteCall = (_path, endpoint, payload) => {
    calls.push({ endpoint, payload })
    return answer(endpoint)
  }
  provideConnection(ctx, { call })
  await ctx.plugin({ inject: clientRemoteInject, apply: applyClientRemote })
  await ctx.plugin({ inject: workbenchClientInject, apply: applyWorkbenchClient })
  const controller = ctx.securityAssuranceWorkbench as SecurityAssuranceWorkbenchController
  return { controller, calls, slots }
}

function answerLocally(endpoint: string): Promise<unknown> {
  if (endpoint === OPEN_LOCAL_CONTEXT) return Promise.resolve(issuedContext())
  if (endpoint === LIST_ASSESSMENTS) return Promise.resolve(listedPage)
  throw new Error(`Unexpected endpoint: ${endpoint}`)
}

describe('ADR 0321 local Workbench Client', () => {
  it('opens the Assessment selector under a context the local authority issues', async () => {
    const { controller, calls } = await mountWorkbench(answerLocally)

    await expect(controller.openLocalAssessmentSelection()).resolves.toMatchObject({
      kind: 'SELECTION_READY',
      assessments: [{ assessmentId: listedAssessment().assessmentId }],
    })
    expect(calls.map(recorded => recorded.endpoint)).toEqual([OPEN_LOCAL_CONTEXT, LIST_ASSESSMENTS])
    expect(calls[0]?.payload).toEqual({ args: { request: { schemaVersion: 1 } } })
    expect(calls[1]?.payload).toMatchObject({
      args: { securityAssuranceWorkbenchContextId: ISSUED_CONTEXT_ID },
    })
    expect(JSON.stringify(controller.getState())).not.toContain(ISSUED_CONTEXT_ID)
  })

  it.each(['invocation-unavailable', 'gateway/invocation-unavailable'])(
    'stays closed for the Host integration when no local authority exports the session (%s)',
    async code => {
      const { controller, calls } = await mountWorkbench(endpoint => {
        if (endpoint === OPEN_LOCAL_CONTEXT) {
          return Promise.resolve({ ok: false, error: { code, message: 'no active Remote method', details: {} } })
        }
        throw new Error(`Unexpected endpoint: ${endpoint}`)
      })

      await expect(controller.openLocalAssessmentSelection()).resolves.toEqual({ kind: 'CLOSED' })
      expect(calls.map(recorded => recorded.endpoint)).toEqual([OPEN_LOCAL_CONTEXT])
    },
  )

  it('fails closed when the local authority cannot issue a context', async () => {
    const { controller, calls } = await mountWorkbench(endpoint => {
      if (endpoint === OPEN_LOCAL_CONTEXT) {
        return Promise.resolve({ ok: false, error: { code: 'service-unavailable', message: 'down', details: {} } })
      }
      throw new Error(`Unexpected endpoint: ${endpoint}`)
    })

    await expect(controller.openLocalAssessmentSelection()).resolves.toMatchObject({
      kind: 'FAILED',
      assessmentId: null,
      failure: { source: 'TRANSPORT', code: 'service-unavailable' },
    })
    expect(calls).toHaveLength(1)
  })

  it.each([
    ['an unversioned context', { ok: true, value: { contextId: ISSUED_CONTEXT_ID } }],
    ['a malformed context identity', issuedContext('short')],
  ])('fails closed on %s without using it', async (_label, answer) => {
    const { controller, calls } = await mountWorkbench(endpoint => {
      if (endpoint === OPEN_LOCAL_CONTEXT) return Promise.resolve(answer)
      throw new Error(`Unexpected endpoint: ${endpoint}`)
    })

    await expect(controller.openLocalAssessmentSelection()).resolves.toMatchObject({
      kind: 'FAILED',
      failure: { source: 'CLIENT', code: 'LOCAL_CONTEXT_PROTOCOL_VIOLATION' },
    })
    expect(calls).toHaveLength(1)
  })

  it('discards a context that arrives after the Workbench closed', async () => {
    let release: ((value: unknown) => void) | undefined
    const { controller, calls } = await mountWorkbench(endpoint => {
      if (endpoint === OPEN_LOCAL_CONTEXT) return new Promise(resolve => { release = resolve })
      throw new Error(`Unexpected endpoint: ${endpoint}`)
    })

    const opening = controller.openLocalAssessmentSelection()
    expect(controller.getState()).toEqual({ kind: 'SELECTION_LOADING' })
    controller.closeAssessment()
    release?.(issuedContext())
    await expect(opening).resolves.toEqual({ kind: 'CLOSED' })
    expect(calls.map(recorded => recorded.endpoint)).toEqual([OPEN_LOCAL_CONTEXT])
  })

  it('lets the sidebar launcher open the selector only from a closed Workbench', async () => {
    const { controller, calls, slots } = await mountWorkbench(answerLocally)
    const launcher = slots.find(entry => entry.id === 'security-assurance-workbench-launcher')
    const showWorkbench = launcher?.inject()['showWorkbench'] as (returnFocus: unknown) => Promise<unknown>
    const returnFocus = { focus() {} }

    await showWorkbench(returnFocus)
    expect(controller.getState()).toMatchObject({ kind: 'SELECTION_READY' })
    await showWorkbench(returnFocus)
    expect(calls.map(recorded => recorded.endpoint)).toEqual([OPEN_LOCAL_CONTEXT, LIST_ASSESSMENTS])
  })

  it('adds the Workbench beside the tool cards once the Remote transport exists', async () => {
    const ctx = new Context()
    contexts.push(ctx)
    await ctx.plugin(TypertRegistry)
    const slots = provideSlotRecorder(ctx)
    await ctx.plugin(securityClient as unknown as Plugin)
    expect(slots.map(entry => entry.name)).toEqual(Array(8).fill('tool.call.toolview'))

    provideConnection(ctx, { call: (_path, endpoint) => answerLocally(endpoint) })
    await ctx.plugin({ inject: clientRemoteInject, apply: applyClientRemote })
    await expect.poll(() => slots.map(entry => entry.id).filter(Boolean)).toEqual([
      'security-assurance-workbench-launcher',
      'security-assurance-workbench-overlay',
    ])
  })
})
