import { readFile } from 'node:fs/promises'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { parseExternalAssessmentFailureV1 } from 'dsh-engineering-control-plane/assurance-provider'

describe('ADR 0298 provider-neutral External Assessment Failure', () => {
  it('constructs one frozen bounded reason/code value and rejects Security-private payloads', () => {
    const failure = parseExternalAssessmentFailureV1({
      schemaVersion: 1,
      reason: 'blocked',
      code: 'assessment_blocked',
    })
    expect(failure).toEqual({
      schemaVersion: 1,
      reason: 'blocked',
      code: 'assessment_blocked',
    })
    expect(Object.isFrozen(failure)).toBe(true)

    for (const forbidden of [
      { message: 'C:/private/security-assurance.sqlite' },
      { stack: 'SecurityAssuranceService.run' },
      { credential: 'secret' },
      { finding: { recordId: 'finding-private' } },
      { assessment: { source: 'private payload' } },
    ]) {
      expect(() => parseExternalAssessmentFailureV1({
        schemaVersion: 1,
        reason: 'failed',
        code: 'security_internal',
        ...forbidden,
      })).toThrow('unknown or missing fields')
    }
  })

  it('routes every Adapter failure through the public Control Plane constructor without assertions', async () => {
    const source = await readFile(
      join(import.meta.dirname, '..', 'src', 'control-plane-provider.ts'),
      'utf8',
    )
    const start = source.indexOf('function externalFailure(')
    const end = source.indexOf('\n}\n\nfunction invocationOptions', start) + 2
    expect(start).toBeGreaterThan(-1)
    expect(end).toBeGreaterThan(start)
    const constructor = source.slice(start, end)

    expect(constructor).toContain('parseExternalAssessmentFailureV1({ schemaVersion: 1, reason, code })')
    expect(constructor).not.toMatch(/\bas\s+ExternalAssessmentFailureV1\b/u)
    expect(constructor).not.toMatch(/message|stack|path|credential|finding|assessmentId/u)
    expect(source).toContain('return externalFailure(outcome.reason, outcome.code)')
    expect(source).not.toMatch(/failure:\s*\{\s*schemaVersion:\s*1/u)
  })
})
