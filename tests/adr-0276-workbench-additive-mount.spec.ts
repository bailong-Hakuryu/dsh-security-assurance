import { readFile } from 'node:fs/promises'
import { join } from 'node:path'
import { describe, expect, it, vi } from 'vitest'
import { inject as workbenchClientInject } from '../src/client/index.ts'
import { WorkbenchPresentation } from '../src/client/workbench/presentation.ts'

describe('ADR 0276 additive Workbench mount', () => {
  it('contributes only the additive launcher and overlay Host slots', async () => {
    const source = await readFile(join(import.meta.dirname, '..', 'src', 'client', 'index.ts'), 'utf8')
    expect(workbenchClientInject).toEqual(['remote', 'slots', 'locale'])
    expect(source).toContain("ctx.slots.inject('sidebar.footer.action'")
    expect(source).toContain("ctx.slots.inject('shell.overlay'")
    expect(source).not.toMatch(/ctx\.slots\.inject\(['"](?:shell|sidebar|conversation|details|router)(?:\.root)?['"]/u)
  })

  it('closes transient state, restores focus, and disposes without retained presentation state', async () => {
    const closeAssessment = vi.fn()
    const focus = vi.fn()
    const presentation = new WorkbenchPresentation({ closeAssessment } as never)
    const listener = vi.fn()
    presentation.subscribe(listener)

    presentation.show({ focus } as unknown as HTMLElement)
    expect(presentation.getSnapshot()).toEqual({ open: true })
    presentation.hide()
    await Promise.resolve()

    expect(closeAssessment).toHaveBeenCalledOnce()
    expect(focus).toHaveBeenCalledOnce()
    expect(presentation.getSnapshot()).toEqual({ open: false })

    presentation.show({ focus } as unknown as HTMLElement)
    presentation.dispose()
    expect(closeAssessment).toHaveBeenCalledTimes(2)
    expect(presentation.getSnapshot()).toEqual({ open: false })
  })
})
