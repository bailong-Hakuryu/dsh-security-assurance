import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'

import { SECURITY_ASSURANCE_PRODUCT_VERSION } from '../src/contracts.js'

const packageJson = JSON.parse(
  readFileSync(new URL('../package.json', import.meta.url), 'utf8'),
) as {
  version: string
  private: boolean
  license: string
  publishConfig?: { access?: string }
  files?: string[]
  scripts?: Record<string, string>
}

describe('v0.1 release candidate package', () => {
  it('binds runtime and package identity to the candidate version', () => {
    expect(packageJson.version).toBe('0.1.0-rc.2')
    expect(SECURITY_ASSURANCE_PRODUCT_VERSION).toBe(packageJson.version)
  })

  it('is explicitly publishable under the reviewed license', () => {
    expect(packageJson.private).toBe(false)
    expect(packageJson.license).toBe('MIT')
    expect(packageJson.publishConfig?.access).toBe('public')
    expect(packageJson.files).toEqual(expect.arrayContaining([
      'README.md',
      'CHANGELOG.md',
      'LICENSE',
      'SECURITY.md',
    ]))
  })

  it('rebuilds before packing and exposes one complete release gate', () => {
    expect(packageJson.scripts?.prepack).toBe('pnpm build')
    expect(packageJson.scripts?.['release:check']).toMatch(
      /pnpm typecheck && pnpm build && pnpm test/,
    )
    expect(packageJson.scripts?.['release:check']).toContain('pnpm pack:profile-smoke')
    expect(packageJson.scripts?.['release:check']).not.toContain('pnpm pack:browser-e2e')
  })
})
