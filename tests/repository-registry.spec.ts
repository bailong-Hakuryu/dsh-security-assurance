import { execFile } from 'node:child_process'
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { DatabaseSync } from 'node:sqlite'
import { promisify } from 'node:util'
import { Context } from '@deepseek-ai/cordis'
import { afterEach, describe, expect, it } from 'vitest'
import SecurityAssuranceService from '../src/index.ts'
import type {
  GetRepositoryRequest,
  RegisterRepositoryRequest,
} from '../src/index.ts'
import { referenceHostInvocation } from './support/reference-host.ts'

const run = promisify(execFile)
const temporaryRoots: string[] = []

afterEach(async () => {
  await Promise.all(temporaryRoots.splice(0).map(path => rm(path, { recursive: true, force: true })))
})

async function cleanRepository(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), 'dsh-security-registry-repository-'))
  temporaryRoots.push(root)
  await run('git', ['init', '-b', 'main'], { cwd: root })
  await run('git', ['config', 'user.email', 'fixture@example.invalid'], { cwd: root })
  await run('git', ['config', 'user.name', 'Fixture'], { cwd: root })
  await writeFile(join(root, 'README.md'), '# registry fixture\n', 'utf8')
  await run('git', ['add', 'README.md'], { cwd: root })
  await run('git', ['commit', '-m', 'fixture baseline'], { cwd: root })
  return root
}

describe('SecurityAssuranceService Repository Administration', () => {
  it('registers one canonical Repository and returns a path-free immutable Snapshot', async () => {
    const repository = await cleanRepository()
    const dshHome = await mkdtemp(join(tmpdir(), 'dsh-security-registry-home-'))
    temporaryRoots.push(dshHome)
    const ctx = new Context()
    const fiber = await ctx.plugin(SecurityAssuranceService, { dshHome })
    const platform = process.platform
    if (platform !== 'win32' && platform !== 'linux' && platform !== 'darwin') {
      throw new Error(`unsupported test platform: ${platform}`)
    }

    try {
      const invocation = referenceHostInvocation(ctx.securityAssurance)
      const request: RegisterRepositoryRequest = {
        schemaVersion: 1,
        idempotencyKey: 'repository-register-fixture-1',
        root: repository,
        displayName: 'Registry fixture',
        bindings: {
          policyId: 'security/default',
          assessmentProfileId: 'security/standard',
          evidenceProtectionId: 'evidence/local-protected',
          dataEgressPolicyId: 'egress/deny-by-default',
          platform,
          deliveryDestinationIds: [],
        },
      }
      const registered = await ctx.securityAssurance.registerRepository(invocation, request)
      expect(registered).toMatchObject({
        ok: true,
        value: {
          schemaVersion: 1,
          operation: 'register_repository',
          repositoryId: expect.stringMatching(/^repo-[0-9a-f-]{36}$/u),
          repositoryRevision: 1,
          idempotencyKey: request.idempotencyKey,
          acceptedState: 'ENABLED',
        },
      })
      if (!registered.ok) throw new Error(`registration failed: ${registered.error.code}`)

      const query: GetRepositoryRequest = {
        schemaVersion: 1,
        repositoryId: registered.value.repositoryId,
      }
      const fetched = await ctx.securityAssurance.getRepository(invocation, query)
      expect(fetched).toMatchObject({
        ok: true,
        value: {
          schemaVersion: 1,
          repositoryId: registered.value.repositoryId,
          repositoryRevision: 1,
          state: 'ENABLED',
          displayName: 'Registry fixture',
          rootIdentityDigest: expect.stringMatching(/^sha256:[0-9a-f]{64}$/u),
          bindings: request.bindings,
        },
      })
      if (!fetched.ok) throw new Error(`repository query failed: ${fetched.error.code}`)
      expect(JSON.stringify(fetched.value)).not.toContain(repository)
      expect(Object.isFrozen(fetched)).toBe(true)
      expect(Object.isFrozen(fetched.value)).toBe(true)
      expect(Object.isFrozen(fetched.value.bindings)).toBe(true)
    } finally {
      await fiber.dispose()
    }
  })

  it('replays equal commands and applies update and disable through exact Revision CAS', async () => {
    const repository = await cleanRepository()
    const dshHome = await mkdtemp(join(tmpdir(), 'dsh-security-registry-home-'))
    temporaryRoots.push(dshHome)
    const ctx = new Context()
    const fiber = await ctx.plugin(SecurityAssuranceService, { dshHome })
    const platform = process.platform
    if (platform !== 'win32' && platform !== 'linux' && platform !== 'darwin') {
      throw new Error(`unsupported test platform: ${platform}`)
    }

    try {
      const invocation = referenceHostInvocation(ctx.securityAssurance)
      const registration = {
        schemaVersion: 1 as const,
        idempotencyKey: 'repository-register-cas-1',
        root: repository,
        displayName: 'CAS fixture',
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
      const replayed = await ctx.securityAssurance.registerRepository(invocation, registration)
      expect(replayed).toEqual(registered)
      if (!registered.ok) throw new Error(`registration failed: ${registered.error.code}`)

      await expect(ctx.securityAssurance.registerRepository(invocation, {
        ...registration,
        displayName: 'Conflicting replay',
      })).resolves.toMatchObject({ ok: false, error: { code: 'IDEMPOTENCY_CONFLICT' } })

      const updated = await ctx.securityAssurance.updateRepository(invocation, {
        schemaVersion: 1,
        idempotencyKey: 'repository-update-cas-1',
        repositoryId: registered.value.repositoryId,
        expectedRepositoryRevision: 1,
        displayName: 'Updated CAS fixture',
      })
      expect(updated).toMatchObject({
        ok: true,
        value: { operation: 'update_repository', repositoryRevision: 2, acceptedState: 'ENABLED' },
      })
      await expect(ctx.securityAssurance.updateRepository(invocation, {
        schemaVersion: 1,
        idempotencyKey: 'repository-update-cas-1',
        repositoryId: registered.value.repositoryId,
        expectedRepositoryRevision: 1,
        displayName: 'Updated CAS fixture',
      })).resolves.toEqual(updated)

      await expect(ctx.securityAssurance.updateRepository(invocation, {
        schemaVersion: 1,
        idempotencyKey: 'repository-update-stale-1',
        repositoryId: registered.value.repositoryId,
        expectedRepositoryRevision: 1,
        displayName: 'Stale update',
      })).resolves.toMatchObject({ ok: false, error: { code: 'CONFLICT' } })

      const disabled = await ctx.securityAssurance.disableRepository(invocation, {
        schemaVersion: 1,
        idempotencyKey: 'repository-disable-cas-1',
        repositoryId: registered.value.repositoryId,
        expectedRepositoryRevision: 2,
      })
      expect(disabled).toMatchObject({
        ok: true,
        value: { operation: 'disable_repository', repositoryRevision: 3, acceptedState: 'DISABLED' },
      })
      await expect(ctx.securityAssurance.disableRepository(invocation, {
        schemaVersion: 1,
        idempotencyKey: 'repository-disable-cas-1',
        repositoryId: registered.value.repositoryId,
        expectedRepositoryRevision: 2,
      })).resolves.toEqual(disabled)

      const listed = await ctx.securityAssurance.listRepositories(invocation, {
        schemaVersion: 1,
        limit: 10,
      })
      expect(listed).toMatchObject({
        ok: true,
        value: {
          schemaVersion: 1,
          truncated: false,
          repositories: [{
            repositoryId: registered.value.repositoryId,
            repositoryRevision: 3,
            state: 'DISABLED',
            displayName: 'Updated CAS fixture',
          }],
        },
      })
    } finally {
      await fiber.dispose()
    }
  })

  it('restores current Repository projections after Service restart', async () => {
    const repository = await cleanRepository()
    const dshHome = await mkdtemp(join(tmpdir(), 'dsh-security-registry-home-'))
    temporaryRoots.push(dshHome)
    const platform = process.platform
    if (platform !== 'win32' && platform !== 'linux' && platform !== 'darwin') {
      throw new Error(`unsupported test platform: ${platform}`)
    }

    const firstContext = new Context()
    const firstFiber = await firstContext.plugin(SecurityAssuranceService, { dshHome })
    const firstInvocation = referenceHostInvocation(firstContext.securityAssurance)
    const registered = await firstContext.securityAssurance.registerRepository(firstInvocation, {
      schemaVersion: 1,
      idempotencyKey: 'repository-restart-1',
      root: repository,
      displayName: 'Restart fixture',
      bindings: {
        policyId: 'security/default',
        assessmentProfileId: 'security/standard',
        evidenceProtectionId: 'evidence/local-protected',
        dataEgressPolicyId: 'egress/deny-by-default',
        platform,
        deliveryDestinationIds: [],
      },
    })
    if (!registered.ok) throw new Error(`registration failed: ${registered.error.code}`)
    await firstFiber.dispose()

    const secondContext = new Context()
    const secondFiber = await secondContext.plugin(SecurityAssuranceService, { dshHome })
    try {
      const secondInvocation = referenceHostInvocation(secondContext.securityAssurance)
      await expect(secondContext.securityAssurance.getRepository(secondInvocation, {
        schemaVersion: 1,
        repositoryId: registered.value.repositoryId,
      })).resolves.toMatchObject({
        ok: true,
        value: { repositoryId: registered.value.repositoryId, displayName: 'Restart fixture' },
      })
    } finally {
      await secondFiber.dispose()
    }
  })

  it('fails closed in READ_ONLY_SAFE mode when the private database is foreign', async () => {
    const dshHome = await mkdtemp(join(tmpdir(), 'dsh-security-registry-home-'))
    temporaryRoots.push(dshHome)
    const stateRoot = join(dshHome, 'security-assurance')
    await mkdir(stateRoot, { recursive: true })
    const foreign = new DatabaseSync(join(stateRoot, 'security-assurance.sqlite'))
    foreign.exec('CREATE TABLE foreign_owner (id INTEGER PRIMARY KEY)')
    foreign.close()
    const ctx = new Context()
    const fiber = await ctx.plugin(SecurityAssuranceService, { dshHome })

    try {
      const invocation = referenceHostInvocation(ctx.securityAssurance)
      await expect(ctx.securityAssurance.getHealth(invocation, { schemaVersion: 1 })).resolves.toMatchObject({
        ok: true,
        value: { state: 'READ_ONLY_SAFE', admission: { mutations: false, sealedExports: false } },
      })
      await expect(ctx.securityAssurance.getRepository(invocation, {
        schemaVersion: 1,
        repositoryId: 'repo-00000000-0000-0000-0000-000000000000',
      })).resolves.toMatchObject({ ok: false, error: { code: 'UNAVAILABLE', retryable: true } })
    } finally {
      await fiber.dispose()
    }
  })
})
