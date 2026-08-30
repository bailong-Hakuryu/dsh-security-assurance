import { readFile } from 'node:fs/promises'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'

describe('ADR 0296 Control Plane cancellation resolves only an existing Assessment', () => {
  it('uses the stable start identity lookup and never calls startAssessment while canceling', async () => {
    const source = await readFile(join(import.meta.dirname, '..', 'src', 'index.ts'), 'utf8')
    const start = source.indexOf('  private async cancelControlPlaneAssessment(')
    const end = source.indexOf('  private admitsMutations(', start)
    expect(start).toBeGreaterThan(-1)
    expect(end).toBeGreaterThan(start)
    const cancellation = source.slice(start, end)

    expect(cancellation).toContain('lookupControlPlaneAssessment(this, invocation, {')
    expect(cancellation).toContain("controlPlaneOperationIdempotencyKey(\n        'start',")
    expect(cancellation).toContain('operation.repositoryId')
    expect(cancellation).toContain("kind: 'EXTERNAL_ASSESSMENT_NOT_STARTED'")
    expect(cancellation).toContain('this.cancelAssessment(invocation, {')
    expect(cancellation).toContain('this.getAssessment(invocation, {')
    expect(cancellation).not.toContain('this.startAssessment(')
    expect(cancellation).not.toContain('verifyControlPlaneRepositoryBinding(')
    expect(cancellation).not.toContain('this.getRepository(')
  })

  it('keeps cancellation lookup authority-checked and independent of mutable bindings', async () => {
    const source = await readFile(
      join(import.meta.dirname, '..', 'src', 'internal', 'control-plane-assessment.ts'),
      'utf8',
    )
    const service = await readFile(join(import.meta.dirname, '..', 'src', 'index.ts'), 'utf8')

    expect(source).toContain('lookup-control-plane-assessment/v1')
    expect(source).toContain('idempotencyKey')
    expect(source).toContain('repositoryId')
    expect(source).not.toMatch(/canonicalRoot|bindings|startAssessment/u)
    expect(service).toContain("authority?.kind !== 'control-plane'")
    expect(service).toContain("!authority.permissions.has('assessment:read')")
    expect(service).toContain('persistence.findAssessmentStartIdentity({')
  })
})
