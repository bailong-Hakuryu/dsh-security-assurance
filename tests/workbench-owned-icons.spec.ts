// @vitest-environment jsdom
import { act, createElement } from 'react'
import { createRoot, type Root } from 'react-dom/client'
import { afterEach, describe, expect, it, vi } from 'vitest'
import type { SecurityAssuranceWorkbenchStateV1 } from '../src/web-client/workbench/controller.ts'
import { en, type WorkbenchKey } from '../src/web-client/workbench/locales.ts'
import { WorkbenchLauncher } from '../src/web-client/workbench/WorkbenchLauncher.tsx'
import { WorkbenchOverlay, type WorkbenchOverlayProps } from '../src/web-client/workbench/WorkbenchOverlay.tsx'

// Harness 0.1.7 renamed every primitives icon (IconDataOutline16 became
// IconDataOutlineRegular), so the names earlier Harness pages supply are gone.
vi.mock('@deepseek-ai/dsh-client-ui-primitives', () => ({
  IconDataOutlineRegular: () => null,
  IconCloseOutlineRegular: () => null,
}))

;(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true

let root: Root | undefined

afterEach(() => {
  act(() => { root?.unmount() })
  root = undefined
  document.body.innerHTML = ''
})

function render(element: ReturnType<typeof createElement>): HTMLElement {
  const container = document.createElement('div')
  document.body.append(container)
  act(() => {
    root = createRoot(container)
    root.render(element)
  })
  return container
}

describe('Workbench renders its own icons on every supported Harness', () => {
  it('renders the sidebar launcher without the Harness icon set', () => {
    const container = render(createElement(WorkbenchLauncher, {
      wide: true,
      t: (key: WorkbenchKey) => en[key],
      showWorkbench: vi.fn(async () => {}),
    } as Parameters<typeof WorkbenchLauncher>[0]))

    const launcher = container.querySelector<HTMLButtonElement>('button.dsh-security-launcher')
    expect(launcher?.getAttribute('aria-label')).toBe(en['launcher.open'])
    expect(launcher?.querySelector('svg')).not.toBeNull()
  })

  it('renders the dialog close control and empty-state icon without the Harness icon set', () => {
    // A closed Workbench shows the empty-state message with its icon.
    const state = { kind: 'CLOSED' } as SecurityAssuranceWorkbenchStateV1
    const container = render(createElement(WorkbenchOverlay, {
      t: (key: WorkbenchKey) => en[key],
      usePresentation: <S>(select: (snapshot: { readonly open: boolean }) => S) => select({ open: true }),
      useAssessment: <S>(select: (snapshot: SecurityAssuranceWorkbenchStateV1) => S) => select(state),
      closeWorkbench: () => {},
      selectAssessment: () => {},
    } as unknown as WorkbenchOverlayProps))

    const close = container.querySelector<HTMLButtonElement>(`button[aria-label="${en['dialog.close']}"]`)
    expect(close?.querySelector('svg')).not.toBeNull()
    expect(container.querySelector('.dsh-security-empty__icon svg')).not.toBeNull()
  })
})
