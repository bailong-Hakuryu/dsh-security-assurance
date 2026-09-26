import { Context, type Plugin } from '@deepseek-ai/cordis'
import {
  apply as applyClientRemote,
  inject as clientRemoteInject,
} from '@deepseek-ai/dsh-api-gateway/src/client/index.ts'
import TypertRegistry from '@deepseek-ai/dsh-typert-registry'
import { createElement } from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import { afterEach, describe, expect, it, vi } from 'vitest'
import type { AssessmentId } from '../src/contracts.ts'
import { SecurityToolCard, type SecurityToolCardProps } from '../src/web-client/card.ts'
import * as securityClient from '../src/web-client/index.ts'
import { zh } from '../src/web-client/locales.ts'
import { zh as workbenchZh, type WorkbenchKey } from '../src/web-client/workbench/locales.ts'
import {
  WorkbenchOverlay,
  type WorkbenchOverlayProps,
} from '../src/web-client/workbench/WorkbenchOverlay.tsx'
import { securityToolCard } from '../src/web-client/model.ts'
import { WorkbenchBridge } from '../src/web-client/workbench-bridge.ts'
import { LOCAL_WORKBENCH_PERMISSIONS } from '../src/workbench-local.ts'
import { assessmentSnapshot } from './support/workbench-fixtures.ts'
import { provideConnection, provideSlotRecorder } from './support/workbench-client-host.ts'

const ASSESSMENT_ID = 'asm-2b81034d-a81b-4705-9f91-ea5044e98ea4'
const contexts: Context[] = []

afterEach(async () => {
  await Promise.all(contexts.splice(0).map(ctx => ctx.fiber.dispose()))
})

function running(name: string, args: unknown) {
  return { callId: `call-${name}`, name, argsRaw: JSON.stringify(args), turn: 1, step: 1, time: 0, subCalls: [] }
}

function settled(name: string, args: unknown, output: unknown, isError = false) {
  return {
    kind: 'tool-result' as const,
    seq: 1,
    time: 0,
    callId: `call-${name}`,
    call: { name, argsRaw: JSON.stringify(args) },
    callTime: 0,
    content: [{ type: 'text', text: typeof output === 'string' ? output : JSON.stringify(output) }],
    isError,
    subCalls: [],
  }
}

const focusTarget = { focus() {} } as unknown as HTMLElement

describe('ADR 0323 tool cards name the Assessment they concern', () => {
  it('takes the Assessment from the settled result or the call arguments', () => {
    expect(securityToolCard('security_assessment_start', settled(
      'security_assessment_start',
      { repository_id: 'repo-1' },
      { assessmentId: ASSESSMENT_ID, state: 'CREATED' },
    )).assessmentId).toBe(ASSESSMENT_ID)
    expect(securityToolCard('security_assessment_status', settled(
      'security_assessment_status',
      { assessment_id: ASSESSMENT_ID },
      { assessmentId: ASSESSMENT_ID, state: 'SEALED' },
    )).assessmentId).toBe(ASSESSMENT_ID)
    expect(securityToolCard('security_assessment_findings', running(
      'security_assessment_findings',
      { assessment_id: ASSESSMENT_ID },
    )).assessmentId).toBe(ASSESSMENT_ID)
  })

  it('names no Assessment for failed calls, discovery tools, or malformed identities', () => {
    expect(securityToolCard('security_assessment_status', settled(
      'security_assessment_status',
      { assessment_id: ASSESSMENT_ID },
      'SECURITY_NOT_FOUND: no such Assessment',
      true,
    )).assessmentId).toBeNull()
    expect(securityToolCard('security_repositories', settled(
      'security_repositories',
      {},
      { assessmentId: ASSESSMENT_ID, repositories: [] },
    )).assessmentId).toBeNull()
    for (const forged of ['asm-../../settings', `${ASSESSMENT_ID} `, 'repo-2b81034d-a81b-4705-9f91-ea5044e98ea4']) {
      expect(securityToolCard('security_assessment_findings', running(
        'security_assessment_findings',
        { assessment_id: forged },
      )).assessmentId).toBeNull()
    }
  })
})

describe('ADR 0323 Workbench bridge', () => {
  it('is unavailable until the Workbench attaches and after it detaches', () => {
    const bridge = new WorkbenchBridge()
    const listener = vi.fn()
    bridge.subscribe(listener)
    expect(bridge.getSnapshot()).toEqual({ available: false })

    const detach = bridge.attach(() => Promise.resolve())
    expect(bridge.getSnapshot()).toEqual({ available: true })
    detach()
    expect(bridge.getSnapshot()).toEqual({ available: false })
    expect(listener).toHaveBeenCalledTimes(2)
  })

  it('forwards only well-formed Assessment identities to the attached Workbench', () => {
    const bridge = new WorkbenchBridge()
    const opener = vi.fn(() => Promise.resolve())
    bridge.open(ASSESSMENT_ID, focusTarget)
    expect(opener).not.toHaveBeenCalled()

    bridge.attach(opener)
    bridge.open('asm-../../settings', focusTarget)
    bridge.open(ASSESSMENT_ID, focusTarget)
    expect(opener).toHaveBeenCalledExactlyOnceWith(ASSESSMENT_ID, focusTarget)
  })

  it('keeps a newer Workbench attached when a stale one detaches', () => {
    const bridge = new WorkbenchBridge()
    const staleDetach = bridge.attach(() => Promise.resolve())
    const current = vi.fn(() => Promise.resolve())
    bridge.attach(current)
    staleDetach()
    expect(bridge.getSnapshot()).toEqual({ available: true })
    bridge.open(ASSESSMENT_ID, focusTarget)
    expect(current).toHaveBeenCalledOnce()
  })
})

describe('ADR 0323 card action', () => {
  function render(block: unknown, available: boolean): string {
    const props: SecurityToolCardProps = {
      toolName: 'security_assessment_status',
      block,
      t: key => zh[key as keyof typeof zh],
      useWorkbench: select => select({ available }),
      openInWorkbench: () => {},
    }
    return renderToStaticMarkup(createElement(SecurityToolCard, props))
  }

  const sealed = settled(
    'security_assessment_status',
    { assessment_id: ASSESSMENT_ID },
    { assessmentId: ASSESSMENT_ID, state: 'SEALED' },
  )

  it('offers to open the Assessment when the Workbench is available', () => {
    expect(render(sealed, true)).toContain(`aria-label="${zh['action.openInWorkbench']}"`)
  })

  it('offers nothing while the Workbench is unavailable or the call names no Assessment', () => {
    expect(render(sealed, false)).not.toContain(zh['action.openInWorkbench'])
    expect(render(settled(
      'security_assessment_status',
      { assessment_id: ASSESSMENT_ID },
      'SECURITY_NOT_FOUND',
      true,
    ), true)).not.toContain(zh['action.openInWorkbench'])
  })
})

describe('ADR 0323 card-to-Workbench flow', () => {
  async function mountClient(withRemote: boolean) {
    const ctx = new Context()
    contexts.push(ctx)
    await ctx.plugin(TypertRegistry)
    const slots = provideSlotRecorder(ctx)
    const endpoints: string[] = []
    const snapshot = assessmentSnapshot(ASSESSMENT_ID as AssessmentId, 3, 'SEALED')
    if (withRemote) {
      provideConnection(ctx, {
        call: (_path, endpoint) => {
          endpoints.push(endpoint)
          if (endpoint === 'securityAssuranceWorkbenchSession/openLocalContext') {
            return Promise.resolve({
              ok: true,
              value: {
                schemaVersion: 1,
                contextId: 'local-workbench-CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC',
                expiresAt: '2026-09-26T08:00:00.000Z',
                permissions: [...LOCAL_WORKBENCH_PERMISSIONS],
              },
            })
          }
          if (endpoint === 'securityAssuranceWorkbench/getAssessment') {
            return Promise.resolve({ ok: true, value: { ok: true, value: snapshot } })
          }
          if (endpoint === 'securityAssuranceWorkbench/listAssessments') {
            return Promise.resolve({
              ok: true,
              value: {
                ok: true,
                value: { schemaVersion: 1, consistencyWatermark: 'card.signature', assessments: [], nextCursor: null },
              },
            })
          }
          throw new Error(`Unexpected endpoint: ${endpoint}`)
        },
      })
      await ctx.plugin({ inject: clientRemoteInject, apply: applyClientRemote })
    }
    await ctx.plugin(securityClient as unknown as Plugin)
    const card = slots.find(entry => entry.name === 'tool.call.toolview')
    const face = card?.inject() as {
      readonly hooks: { readonly workbench: WorkbenchBridge }
      readonly openInWorkbench: (assessmentId: string, returnFocus: HTMLElement) => void
    }
    return { slots, endpoints, face }
  }

  it('opens the named Assessment in the Workbench under the local authority', async () => {
    const { slots, endpoints, face } = await mountClient(true)
    await expect.poll(() => face.hooks.workbench.getSnapshot()).toEqual({ available: true })

    face.openInWorkbench(ASSESSMENT_ID, focusTarget)
    const overlay = slots.find(entry => entry.id === 'security-assurance-workbench-overlay')
    const hooks = overlay?.inject()['hooks'] as {
      readonly presentation: { getSnapshot(): unknown }
      readonly assessment: { getSnapshot(): unknown }
    }
    expect(hooks.presentation.getSnapshot()).toEqual({ open: true })
    await expect.poll(() => hooks.assessment.getSnapshot()).toMatchObject({
      kind: 'READY',
      assessmentId: ASSESSMENT_ID,
    })
    expect(endpoints).toEqual([
      'securityAssuranceWorkbenchSession/openLocalContext',
      'securityAssuranceWorkbench/getAssessment',
    ])

    // A card-opened Assessment is not a dead end: the same context lists the rest.
    const back = overlay?.inject()['backToAssessmentSelection'] as () => void
    back()
    await expect.poll(() => hooks.assessment.getSnapshot()).toMatchObject({ kind: 'SELECTION_READY' })
    expect(endpoints.slice(2)).toEqual(['securityAssuranceWorkbench/listAssessments'])
  })

  it('shows the named Assessment loading, then fails closed on it when no context is issued', async () => {
    const ctx = new Context()
    contexts.push(ctx)
    await ctx.plugin(TypertRegistry)
    const slots = provideSlotRecorder(ctx)
    let answer: ((value: unknown) => void) | undefined
    provideConnection(ctx, {
      call: (_path, endpoint) => {
        if (endpoint !== 'securityAssuranceWorkbenchSession/openLocalContext') {
          throw new Error(`Unexpected endpoint: ${endpoint}`)
        }
        return new Promise(resolve => { answer = resolve })
      },
    })
    await ctx.plugin({ inject: clientRemoteInject, apply: applyClientRemote })
    await ctx.plugin(securityClient as unknown as Plugin)
    const face = slots.find(entry => entry.name === 'tool.call.toolview')?.inject() as {
      readonly hooks: { readonly workbench: WorkbenchBridge }
      readonly openInWorkbench: (assessmentId: string, returnFocus: HTMLElement) => void
    }
    await expect.poll(() => face.hooks.workbench.getSnapshot()).toEqual({ available: true })
    const overlay = slots.find(entry => entry.id === 'security-assurance-workbench-overlay')
    if (overlay === undefined) throw new Error('The Workbench overlay was not registered')
    const assessment = (overlay.inject()['hooks'] as { readonly assessment: { getSnapshot(): unknown } }).assessment

    face.openInWorkbench(ASSESSMENT_ID, focusTarget)
    expect(assessment.getSnapshot()).toEqual({ kind: 'LOADING', assessmentId: ASSESSMENT_ID })
    await expect.poll(() => answer).toBeDefined()
    answer?.({ ok: false, error: { code: 'gateway/service-unavailable', message: 'down', details: {} } })
    await expect.poll(() => assessment.getSnapshot()).toMatchObject({
      kind: 'FAILED',
      assessmentId: ASSESSMENT_ID,
      failure: { source: 'TRANSPORT', code: 'gateway/service-unavailable' },
    })
  })

  it('leaves the cards inert while no Remote transport exists', async () => {
    const { slots, face } = await mountClient(false)
    expect(face.hooks.workbench.getSnapshot()).toEqual({ available: false })
    face.openInWorkbench(ASSESSMENT_ID, focusTarget)
    expect(slots.some(entry => entry.id === 'security-assurance-workbench-overlay')).toBe(false)
  })
})

describe('ADR 0323 Assessment detail navigation', () => {
  it('leads from an opened Assessment back to the Assessment list', () => {
    const state = {
      kind: 'READY' as const,
      assessmentId: ASSESSMENT_ID as AssessmentId,
      snapshot: assessmentSnapshot(ASSESSMENT_ID as AssessmentId, 3, 'SEALED'),
      findings: { kind: 'NOT_LOADED' as const },
      assessmentCommand: { kind: 'IDLE' as const },
    }
    const props = {
      t: (key: WorkbenchKey) => workbenchZh[key],
      usePresentation: <S>(select: (snapshot: { readonly open: boolean }) => S) => select({ open: true }),
      useAssessment: <S>(select: (snapshot: typeof state) => S) => select(state),
    } as unknown as WorkbenchOverlayProps
    const markup = renderToStaticMarkup(createElement(WorkbenchOverlay, props))
    expect(markup).toContain(workbenchZh['detail.backToSelection'])
  })
})
