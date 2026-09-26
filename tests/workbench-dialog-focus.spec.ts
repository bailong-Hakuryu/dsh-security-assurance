// @vitest-environment jsdom
import { act, createElement, useSyncExternalStore } from 'react'
import { createRoot, type Root } from 'react-dom/client'
import { afterEach, describe, expect, it, vi } from 'vitest'
import type { AssessmentId, AssessmentListItemV1 } from '../src/contracts.ts'
import type { SecurityAssuranceWorkbenchStateV1 } from '../src/web-client/workbench/controller.ts'
import { en, type WorkbenchKey } from '../src/web-client/workbench/locales.ts'
import {
  WorkbenchOverlay,
  type WorkbenchOverlayProps,
} from '../src/web-client/workbench/WorkbenchOverlay.tsx'

;(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true

const ASSESSMENT_ID = 'asm-00000000-0000-0000-0000-000000000294' as AssessmentId
let root: Root | undefined

afterEach(() => {
  act(() => { root?.unmount() })
  root = undefined
  document.body.innerHTML = ''
})

function listed(): AssessmentListItemV1 {
  return {
    schemaVersion: 1,
    assessmentId: ASSESSMENT_ID,
    assessmentRevision: 3,
    state: 'SEALED',
    repository: {
      repositoryId: 'repo-00000000-0000-0000-0000-000000000294',
      repositoryRevision: 1,
    } as AssessmentListItemV1['repository'],
    subjectKind: 'workspace_snapshot',
    policyId: 'security/standard',
    coverageStatus: 'COMPLETE',
    verdict: 'SATISFIED',
    createdAt: '2026-09-27T00:00:00.000Z',
    updatedAt: '2026-09-27T00:01:00.000Z',
  }
}

/** Mount the overlay over a mutable Workbench state, as the slot framework would. */
function mountOverlay(initial: SecurityAssuranceWorkbenchStateV1) {
  let state = initial
  const listeners = new Set<() => void>()
  const setState = (next: SecurityAssuranceWorkbenchStateV1) => {
    state = next
    for (const listener of listeners) listener()
  }
  const subscribe = (listener: () => void) => {
    listeners.add(listener)
    return () => { listeners.delete(listener) }
  }
  const closeWorkbench = vi.fn()
  function Host() {
    const props = {
      t: (key: WorkbenchKey) => en[key],
      usePresentation: <S>(select: (snapshot: { readonly open: boolean }) => S) => select({ open: true }),
      useAssessment: <S>(select: (snapshot: SecurityAssuranceWorkbenchStateV1) => S) =>
        select(useSyncExternalStore(subscribe, () => state)),
      closeWorkbench,
      selectAssessment: () => {},
    } as unknown as WorkbenchOverlayProps
    return createElement(WorkbenchOverlay, props)
  }
  const container = document.createElement('div')
  document.body.append(container)
  act(() => {
    root = createRoot(container)
    root.render(createElement(Host))
  })
  return { setState, closeWorkbench }
}

describe('Workbench dialog keeps keyboard focus across view changes', () => {
  it('keeps focus inside the dialog when the focused control leaves with its view', () => {
    const { setState, closeWorkbench } = mountOverlay({
      kind: 'SELECTION_READY',
      consistencyWatermark: 'focus.signature',
      assessments: [listed()],
      nextCursor: null,
    })
    const open = document.querySelector<HTMLButtonElement>(`button[aria-label="${en['selection.open']} ${ASSESSMENT_ID}"]`)
    expect(open).not.toBeNull()
    act(() => { open!.focus() })

    act(() => { setState({ kind: 'LOADING', assessmentId: ASSESSMENT_ID }) })

    const dialog = document.querySelector('[role="dialog"]')
    expect(dialog?.contains(document.activeElement)).toBe(true)
    act(() => {
      document.activeElement!.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true }))
    })
    expect(closeWorkbench).toHaveBeenCalledOnce()
  })
})
