import { readFile } from 'node:fs/promises'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import SecurityAssuranceHostRepositoryProvider from '../src/host-repository-provider.ts'

describe('ADR 0301 Host Repository Provider is a trusted composition Adapter', () => {
  it('ships as an optional composition entry that invokes only the root Repository command', async () => {
    const packageJson = JSON.parse(await readFile(
      join(import.meta.dirname, '..', 'package.json'),
      'utf8',
    )) as { readonly exports?: Record<string, unknown> }
    const source = await readFile(
      join(import.meta.dirname, '..', 'src', 'host-repository-provider.ts'),
      'utf8',
    )

    expect(packageJson.exports).toHaveProperty('./host-repository-provider')
    expect(SecurityAssuranceHostRepositoryProvider.inject).toEqual(['securityAssurance'])
    expect(source).toContain('resolveTrustedInvocation(service, {')
    expect(source).toContain("permissions: ['repository:admin']")
    expect(source).toContain('await service.registerRepository(invocation, {')
    expect(source).not.toMatch(/openSecurityPersistence|SecurityPersistence|security-assurance\.sqlite/u)
  })

  it('publishes only immutable path-free bindings and preserves Registry history on disposal', async () => {
    const source = await readFile(
      join(import.meta.dirname, '..', 'src', 'host-repository-provider.ts'),
      'utf8',
    )
    const projectionStart = source.indexOf('this.resolved.set(registration.bindingId, deepFreeze({')
    const projectionEnd = source.indexOf('      }))', projectionStart) + 9
    const projection = source.slice(projectionStart, projectionEnd)
    const teardownStart = source.indexOf("ctx.effect(async () => {")
    const teardownEnd = source.indexOf("    }, 'Security Assurance Host Repository Provider teardown')", teardownStart)
    const teardown = source.slice(teardownStart, teardownEnd)

    expect(projection).toContain('bindingId: registration.bindingId')
    expect(projection).toContain('repositoryId: result.value.repositoryId')
    expect(projection).toContain('repositoryRevision: result.value.repositoryRevision')
    expect(projection).toContain('state: result.value.acceptedState')
    expect(projection).not.toMatch(/root|displayName|invocation|credential/u)
    expect(teardown).toContain('this.resolved.clear()')
    expect(teardown).not.toMatch(/disableRepository|updateRepository|delete|remove/u)
  })
})
