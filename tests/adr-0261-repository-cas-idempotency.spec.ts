import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { Context } from '@deepseek-ai/cordis'
import { afterEach, describe, expect, it } from 'vitest'
import SecurityAssuranceService from '../src/index.ts'
import { referenceHostInvocation } from './support/reference-host.ts'

const temporaryRoots: string[] = []

afterEach(async () => {
  await Promise.all(temporaryRoots.splice(0).map(path => rm(path, { recursive: true, force: true })))
})

describe('ADR 0261 Repository mutation CAS and idempotency', () => {
  it('replays exact commands and leaves no revision behind after conflicts', async () => {
    const repositoryRoot = await mkdtemp(join(tmpdir(), 'dsh-adr-0261-repository-'))
    const dshHome = await mkdtemp(join(tmpdir(), 'dsh-adr-0261-home-'))
    temporaryRoots.push(repositoryRoot, dshHome)
    const platform = process.platform
    if (platform !== 'win32' && platform !== 'linux' && platform !== 'darwin') {
      throw new Error(`unsupported test platform: ${platform}`)
    }
    const ctx = new Context()
    const fiber = await ctx.plugin(SecurityAssuranceService, { dshHome })

    try {
      const invocation = referenceHostInvocation(ctx.securityAssurance)
      const registration = {
        schemaVersion: 1 as const,
        idempotencyKey: 'adr-0261-register-v1',
        root: repositoryRoot,
        displayName: 'ADR 0261 fixture',
        bindings: {
          policyId: 'security/default',
          assessmentProfileId: 'security/standard',
          evidenceProtectionId: 'evidence/local-protected',
          dataEgressPolicyId: 'egress/deny-by-default',
          platform,
          deliveryDestinationIds: [],
        },
      }
      const registered = await ctx.securityAssurance.registerRepository(invocation, registration)
      expect(registered.ok).toBe(true)
      await expect(ctx.securityAssurance.registerRepository(invocation, registration))
        .resolves.toEqual(registered)
      await expect(ctx.securityAssurance.registerRepository(invocation, {
        ...registration,
        displayName: 'Conflicting registration replay',
      })).resolves.toMatchObject({ ok: false, error: { code: 'IDEMPOTENCY_CONFLICT' } })
      if (!registered.ok) throw new Error(`registration failed: ${registered.error.code}`)

      const update = {
        schemaVersion: 1 as const,
        idempotencyKey: 'adr-0261-update-v1',
        repositoryId: registered.value.repositoryId,
        expectedRepositoryRevision: 1,
        displayName: 'ADR 0261 updated fixture',
      }
      const updated = await ctx.securityAssurance.updateRepository(invocation, update)
      expect(updated).toMatchObject({ ok: true, value: { repositoryRevision: 2 } })
      await expect(ctx.securityAssurance.updateRepository(invocation, update)).resolves.toEqual(updated)
      await expect(ctx.securityAssurance.updateRepository(invocation, {
        ...update,
        displayName: 'Conflicting update replay',
      })).resolves.toMatchObject({ ok: false, error: { code: 'IDEMPOTENCY_CONFLICT' } })

      await expect(ctx.securityAssurance.updateRepository(invocation, {
        ...update,
        idempotencyKey: 'adr-0261-stale-update-v1',
        displayName: 'Must not be committed',
      })).resolves.toMatchObject({ ok: false, error: { code: 'CONFLICT' } })
      await expect(ctx.securityAssurance.disableRepository(invocation, {
        schemaVersion: 1,
        idempotencyKey: 'adr-0261-stale-disable-v1',
        repositoryId: registered.value.repositoryId,
        expectedRepositoryRevision: 1,
      })).resolves.toMatchObject({ ok: false, error: { code: 'CONFLICT' } })

      await expect(ctx.securityAssurance.getRepository(invocation, {
        schemaVersion: 1,
        repositoryId: registered.value.repositoryId,
      })).resolves.toMatchObject({
        ok: true,
        value: {
          repositoryRevision: 2,
          state: 'ENABLED',
          displayName: 'ADR 0261 updated fixture',
        },
      })
    } finally {
      await fiber.dispose()
    }
  })
})
