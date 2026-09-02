import { readFile } from 'node:fs/promises'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'

describe('ADR 0252: Transport Adapters contain no domain Policy', () => {
  it('keeps the Control Plane Provider as a one-call Security Service translation adapter', async () => {
    const source = await readFile(join(import.meta.dirname, '..', 'src', 'control-plane-provider.ts'), 'utf8')
    const internalImports = [...source.matchAll(/from '\.\/internal\/([^']+)'/gu)]
      .map(match => match[1])
      .sort()

    expect(internalImports).toEqual([
      'authority.ts',
      'canonical.ts',
      'control-plane-provider-operation.ts',
    ])
    expect(source).not.toMatch(/\b(?:while|for)\s*\(/u)
    expect(source).not.toContain('createHash')
    expect(source).not.toContain('.verdict')
    expect(source).not.toContain('.coverage.resolutions')
    for (const forbiddenServiceCall of [
      'getRepository',
      'startAssessment',
      'getAssessment',
      'waitForAssessmentRevision',
      'resumeAssessment',
      'cancelAssessment',
      'getAssuranceSubmission',
    ]) {
      expect(source).not.toContain(`this.service.${forbiddenServiceCall}(`)
    }
    expect(source.match(/await executeControlPlaneProviderOperation\(/gu)).toHaveLength(3)
  })

  it('restricts every shipped adapter to framing, authority, and DTO translation internals', async () => {
    const adapters = {
      'tools.ts': ['authority.ts', 'session-events.ts'],
      'workbench-remote.ts': ['authority.ts'],
      'host-repository-provider.ts': ['authority.ts', 'freeze.ts'],
      'control-plane-provider.ts': [
        'authority.ts',
        'canonical.ts',
        'control-plane-provider-operation.ts',
      ],
    } as const

    for (const [file, expectedInternalImports] of Object.entries(adapters)) {
      const source = await readFile(join(import.meta.dirname, '..', 'src', file), 'utf8')
      const internalImports = [...source.matchAll(/from '\.\/internal\/([^']+)'/gu)]
        .map(match => match[1])
        .sort()

      expect(internalImports, file).toEqual([...expectedInternalImports].sort())
      expect(source, file).not.toMatch(/from '\.\/(?:analyzer|evaluation)\.ts'/u)
    }
  })
})
