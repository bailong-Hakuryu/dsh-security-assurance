import { readFile } from 'node:fs/promises'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { en, zh } from '../src/web-client/workbench/locales.ts'

const clientFiles = [
  'controller.ts',
  'actions.ts',
  'finding-triage.ts',
  'locales.ts',
  'navigation.ts',
  'presentation.ts',
  'progress.ts',
  'styles.ts',
  'WorkbenchLauncher.tsx',
  'WorkbenchOverlay.tsx',
  'slot-types.ts',
] as const

describe('ADR 0294 Host web security, accessibility, and bilingual UI', () => {
  it('ships complete English and Simplified Chinese dictionaries for one canonical key set', () => {
    expect(Object.keys(en).sort()).toEqual(Object.keys(zh).sort())
    expect(zh['dialog.title']).toBe('安全保障工作台')
    expect(en['dialog.title']).toBe('Security Assurance Workbench')
    expect(zh['exports.destinationSummary']).not.toBe(en['exports.destinationSummary'])
  })

  it('adds no independent remote channel or asset origin and preserves semantic focus controls', async () => {
    const sources = await Promise.all(clientFiles.map(file => (
      readFile(join(import.meta.dirname, '..', 'src', 'web-client', 'workbench', file), 'utf8')
    )))
    const source = sources.join('\n')
    const styles = sources[7]
    const overlay = sources[9]

    expect(source).not.toMatch(/https?:\/\/|@import|\b(?:fetch|WebSocket|EventSource|sendBeacon|Worker)\s*\(/u)
    expect(styles).not.toMatch(/url\s*\(/u)
    expect(overlay).toContain('role="dialog"')
    expect(overlay).toContain('aria-modal="true"')
    expect(overlay).toContain("event.key === 'Escape'")
    expect(overlay).toContain("event.key === 'Tab'")
    expect(overlay).toContain('closeRef.current?.focus()')
    expect(overlay).toContain('<MachineBadge value=')
    expect(overlay).toContain('{value}')
  })
})
