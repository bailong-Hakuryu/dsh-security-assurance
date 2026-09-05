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
  bin?: Record<string, string>
  exports?: Record<string, unknown>
}
const ciWorkflow = readFileSync(
  new URL('../.github/workflows/ci.yml', import.meta.url),
  'utf8',
)
const readme = readFileSync(new URL('../README.md', import.meta.url), 'utf8')
const changelog = readFileSync(new URL('../CHANGELOG.md', import.meta.url), 'utf8')
const releaseChecklist = readFileSync(
  new URL('../docs/release-v0.1.md', import.meta.url),
  'utf8',
)
const implementationSpecification = readFileSync(
  new URL('../docs/implementation-specification.md', import.meta.url),
  'utf8',
)

describe('v0.1 release candidate package', () => {
  it('binds runtime and package identity to the candidate version', () => {
    expect(packageJson.version).toBe('0.1.0-rc.11')
    expect(SECURITY_ASSURANCE_PRODUCT_VERSION).toBe(packageJson.version)
  })

  it('keeps every current-candidate identity carrier aligned', () => {
    const version = packageJson.version

    expect(readme).toContain(`- Version: <code>${version}</code>`)
    expect(changelog).toContain(`## [${version}] -`)
    expect(releaseChecklist).toContain(`- Candidate version: \`${version}\``)
    expect(implementationSpecification).toContain(
      `| current candidate package version | \`${version}\` |`,
    )
    expect(implementationSpecification).toContain(
      `The qualified candidate uses \`${version}\``,
    )
  })

  it('is explicitly publishable under the reviewed license', () => {
    expect(packageJson.private).toBe(false)
    expect(packageJson.license).toBe('MIT')
    expect(packageJson.publishConfig?.access).toBe('public')
    expect(packageJson.files).toEqual(expect.arrayContaining([
      'assets/*.svg',
      'README.md',
      'CHANGELOG.md',
      'LICENSE',
      'SECURITY.md',
    ]))
  })

  it('rebuilds before packing and exposes one complete release gate', () => {
    expect(packageJson.scripts?.prepack).toBe('pnpm build')
    expect(packageJson.scripts?.['release:check']).toMatch(
      /pnpm build && pnpm typecheck && pnpm test/,
    )
    expect(packageJson.scripts?.['release:check']).toContain('pnpm pack:profile-smoke')
    expect(packageJson.scripts?.['release:check']).not.toContain('pnpm pack:browser-e2e')
    expect(packageJson.scripts?.['release:qualify']).toBe(
      'pnpm build && node lib/release-qualify.js',
    )
    expect(packageJson.scripts?.['release:bind']).toBe(
      'pnpm build && node lib/release-bind.js',
    )
    expect(packageJson.scripts?.['release:collect']).toBe(
      'pnpm build && node lib/release-collect.js',
    )
    expect(packageJson.bin?.['dsh-security-assurance-release-qualify']).toBe(
      './lib/release-qualify.js',
    )
    expect(packageJson.bin?.['dsh-security-assurance-release-bind']).toBe(
      './lib/release-bind.js',
    )
    expect(packageJson.bin?.['dsh-security-assurance-release-collect']).toBe(
      './lib/release-collect.js',
    )
    expect(packageJson.exports?.['./release-file-bindings']).toEqual({
      types: './lib/types/release-file-bindings.d.ts',
      default: './lib/release-file-bindings.js',
    })
    expect(packageJson.exports?.['./release-proof']).toEqual({
      types: './lib/types/release-proof.d.ts',
      default: './lib/release-proof.js',
    })
    expect(packageJson.files).toEqual(expect.arrayContaining([
      'lib/release-bind.js',
      'lib/release-collect.js',
      'lib/release-qualify.js',
      'lib/release-file-bindings.js',
      'lib/release-proof.js',
      'lib/types/release-file-bindings.d.ts',
      'lib/types/release-file-bindings.d.ts.map',
      'lib/types/release-proof.d.ts',
      'lib/types/release-proof.d.ts.map',
    ]))
  })

  it('builds linked packages before source and public-entry typechecking', () => {
    const controlPlaneInstall = ciWorkflow.indexOf('name: Install Control Plane dependencies')
    const controlPlaneBuild = ciWorkflow.indexOf('name: Build Control Plane')
    const securityInstall = ciWorkflow.indexOf('name: Install Security Assurance dependencies')
    const securityBuild = ciWorkflow.indexOf('name: Build Security Assurance')
    const securityTypecheck = ciWorkflow.indexOf('name: Typecheck')

    expect(controlPlaneInstall).toBeGreaterThan(-1)
    expect(controlPlaneBuild).toBeGreaterThan(controlPlaneInstall)
    expect(securityInstall).toBeGreaterThan(controlPlaneBuild)
    expect(securityBuild).toBeGreaterThan(securityInstall)
    expect(securityTypecheck).toBeGreaterThan(securityBuild)
  })
})
