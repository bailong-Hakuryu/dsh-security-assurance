import { readFile } from 'node:fs/promises'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { verifyControlPlaneRepositoryBinding } from '../src/internal/control-plane-repository-binding.ts'

describe('ADR 0300 Control Plane Repository binding precedes Assessment start', () => {
  it('resolves and verifies the private canonical root before any Assessment is admitted', async () => {
    const source = await readFile(join(import.meta.dirname, '..', 'src', 'index.ts'), 'utf8')
    const start = source.indexOf('  private async runControlPlaneAssessment(')
    const end = source.indexOf('  private async cancelControlPlaneAssessment(', start)
    const operation = source.slice(start, end)
    const repository = operation.indexOf('await this.getRepository(')
    const binding = operation.indexOf('await verifyControlPlaneRepositoryBinding(')
    const assessment = operation.indexOf('await this.startAssessment(')

    expect(repository).toBeGreaterThan(-1)
    expect(binding).toBeGreaterThan(repository)
    expect(assessment).toBeGreaterThan(binding)
    expect(operation).toContain("reason: 'blocked', code: 'repository_binding_unavailable'")
    expect(operation).toContain("reason: 'failed', code: 'repository_binding_mismatch'")
    expect(operation.slice(0, assessment)).not.toContain('await this.startAssessment(')
  })

  it('keeps the canonical root inside the Service and fails closed without the private protocol', async () => {
    const source = await readFile(
      join(import.meta.dirname, '..', 'src', 'internal', 'control-plane-repository-binding.ts'),
      'utf8',
    )
    const service = await readFile(join(import.meta.dirname, '..', 'src', 'index.ts'), 'utf8')
    const matcher = { matchesCanonicalRepository: (_candidate: string) => true }

    expect(() => verifyControlPlaneRepositoryBinding(
      {},
      {} as never,
      'repo-00000000-0000-0000-0000-000000000300',
      matcher,
    )).toThrow('verifier is not installed')
    expect(service).toContain('matcher.matchesCanonicalRepository(repository.canonicalRoot)')
    expect(source).not.toMatch(/return\s+.*canonicalRoot/u)
    expect(source).not.toMatch(/from ['"]node:(?:fs|path)/u)
  })
})
