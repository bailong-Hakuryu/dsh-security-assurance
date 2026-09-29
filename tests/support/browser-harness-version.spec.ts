import { describe, expect, it, vi } from 'vitest'
import {
  parseNpmLatest,
  resolveBrowserHarnessVersion,
} from '../../scripts/support/browser-harness-version.mjs'

const supported = ['0.1.5-rc.3', '0.1.7-rc.2', '0.2.0-rc.1'] as const

describe('release browser proof Harness version', () => {
  it('follows the npm latest Harness when no version is requested', async () => {
    const readLatest = vi.fn(async () => '0.1.7-rc.2\n')

    await expect(resolveBrowserHarnessVersion({ requested: undefined, supported, readLatest }))
      .resolves.toBe('0.1.7-rc.2')
    expect(readLatest).toHaveBeenCalledOnce()
  })

  it('uses a requested verified version without asking npm', async () => {
    const readLatest = vi.fn(async () => '0.1.7-rc.2')

    await expect(resolveBrowserHarnessVersion({ requested: '0.2.0-rc.1', supported, readLatest }))
      .resolves.toBe('0.2.0-rc.1')
    expect(readLatest).not.toHaveBeenCalled()
  })

  it('treats an empty request as no request', async () => {
    await expect(resolveBrowserHarnessVersion({ requested: '', supported, readLatest: async () => '0.1.5-rc.3' }))
      .resolves.toBe('0.1.5-rc.3')
  })

  it('fails closed when npm latest moves to a Harness that is not yet admitted', async () => {
    await expect(resolveBrowserHarnessVersion({ requested: undefined, supported, readLatest: async () => '0.2.0' }))
      .rejects.toThrow(/npm latest Harness 0\.2\.0 is outside the verified Harness set.*DSH_BROWSER_HARNESS_VERSION/u)
  })

  it('rejects a requested version outside the verified set', async () => {
    await expect(resolveBrowserHarnessVersion({ requested: '0.1.6-alpha.1', supported, readLatest: async () => '0.1.7-rc.2' }))
      .rejects.toThrow('DSH_BROWSER_HARNESS_VERSION 0.1.6-alpha.1 is outside the verified Harness set')
  })

  it('accepts only one semver version from npm view', () => {
    expect(parseNpmLatest(' 0.1.7-rc.2\r\n')).toBe('0.1.7-rc.2')
    for (const output of ['', 'undefined', '0.1.7-rc.2\n0.2.0-rc.1', '{"latest":"0.1.7-rc.2"}', 'latest']) {
      expect(() => parseNpmLatest(output)).toThrow('npm reported no usable latest Harness version')
    }
  })
})
