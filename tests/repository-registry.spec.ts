import { SecurityAssuranceTestComposition } from './support/security-assurance-test-composition.ts'
import { execFile } from 'node:child_process'
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { DatabaseSync } from 'node:sqlite'
import { promisify } from 'node:util'
import { Context } from '@deepseek-ai/cordis'
import { afterEach, describe, expect, it } from 'vitest'
import type {
  GetRepositoryRequest,
  RegisterRepositoryRequest,
  StartAssessmentRequest,
} from '../src/index.ts'
import {
  referenceHostInvocation,
  referenceHostInvocationWithPermissions,
} from './support/reference-host.ts'

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
  it('replays an accepted Assessment start after disabling its Repository while rejecting new starts', async () => {
    const repository = await cleanRepository()
    const dshHome = await mkdtemp(join(tmpdir(), 'dsh-security-registry-home-'))
    temporaryRoots.push(dshHome)
    const ctx = new Context()
    const fiber = await ctx.plugin(SecurityAssuranceTestComposition, { dshHome })
    const platform = process.platform
    if (platform !== 'win32' && platform !== 'linux' && platform !== 'darwin') {
      throw new Error(`unsupported test platform: ${platform}`)
    }

    try {
      const invocation = referenceHostInvocation(ctx.securityAssurance)
      const registered = await ctx.securityAssurance.registerRepository(invocation, {
        schemaVersion: 1,
        contractVersion: 1 as const,
        idempotencyKey: 'repository-disable-replay-register-1',
        root: repository,
        displayName: 'Disable replay fixture',
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

      const startRequest = {
        schemaVersion: 1 as const,
        contractVersion: 1 as const,
        idempotencyKey: 'repository-disable-replay-start-1',
        repositoryId: registered.value.repositoryId,
        subject: { kind: 'workspace_snapshot' as const },
        assessmentMode: 'REPOSITORY' as const,
        assessmentProfileId: 'security/standard',
        target: { kind: 'repository' as const },
        requestedStrongerControlIds: [],
      }
      const started = await ctx.securityAssurance.startAssessment(invocation, startRequest)
      if (!started.ok) throw new Error(`start failed: ${started.error.code}`)

      const disabled = await ctx.securityAssurance.disableRepository(invocation, {
        schemaVersion: 1,
        contractVersion: 1 as const,
        idempotencyKey: 'repository-disable-replay-disable-1',
        repositoryId: registered.value.repositoryId,
        expectedRepositoryRevision: 1,
      })
      expect(disabled).toMatchObject({
        ok: true,
        value: { repositoryRevision: 2, acceptedState: 'DISABLED' },
      })

      await expect(ctx.securityAssurance.startAssessment(invocation, startRequest)).resolves.toEqual(started)
      await expect(ctx.securityAssurance.startAssessment(invocation, {
        ...startRequest,
        idempotencyKey: 'repository-disable-new-start-1',
      })).resolves.toMatchObject({ ok: false, error: { code: 'CONFLICT' } })
      await expect(ctx.securityAssurance.getAssessment(invocation, {
        schemaVersion: 1,
        assessmentId: started.value.assessmentId,
      })).resolves.toMatchObject({
        ok: true,
        value: {
          repository: {
            repositoryId: registered.value.repositoryId,
            repositoryRevision: 1,
          },
          policy: { policyId: 'security/default' },
        },
      })
    } finally {
      await fiber.dispose()
    }
  })

  it('applies Repository updates only to future Assessments and preserves prior start replay', async () => {
    const repository = await cleanRepository()
    const dshHome = await mkdtemp(join(tmpdir(), 'dsh-security-registry-home-'))
    temporaryRoots.push(dshHome)
    const ctx = new Context()
    const fiber = await ctx.plugin(SecurityAssuranceTestComposition, { dshHome })
    const platform = process.platform
    if (platform !== 'win32' && platform !== 'linux' && platform !== 'darwin') {
      throw new Error(`unsupported test platform: ${platform}`)
    }

    try {
      const invocation = referenceHostInvocation(ctx.securityAssurance)
      const originalBindings = {
        policyId: 'security/default',
        assessmentProfileId: 'security/standard',
        evidenceProtectionId: 'evidence/local-protected',
        dataEgressPolicyId: 'egress/deny-by-default',
        platform,
        deliveryDestinationIds: [],
      }
      const registered = await ctx.securityAssurance.registerRepository(invocation, {
        schemaVersion: 1,
        contractVersion: 1 as const,
        idempotencyKey: 'repository-future-update-register-1',
        root: repository,
        displayName: 'Future update fixture',
        bindings: originalBindings,
      })
      if (!registered.ok) throw new Error(`registration failed: ${registered.error.code}`)

      const originalStart = {
        schemaVersion: 1 as const,
        contractVersion: 1 as const,
        idempotencyKey: 'repository-future-update-start-1',
        repositoryId: registered.value.repositoryId,
        subject: { kind: 'workspace_snapshot' as const },
        assessmentMode: 'REPOSITORY' as const,
        assessmentProfileId: originalBindings.assessmentProfileId,
        target: { kind: 'repository' as const },
        requestedStrongerControlIds: [],
      }
      const originalAssessment = await ctx.securityAssurance.startAssessment(invocation, originalStart)
      expect(originalAssessment).toMatchObject({
        ok: true,
        value: { repositoryRevision: 1 },
      })
      if (!originalAssessment.ok) throw new Error(`start failed: ${originalAssessment.error.code}`)

      const futureBindings = {
        ...originalBindings,
        assessmentProfileId: 'security/deep',
      }
      const updated = await ctx.securityAssurance.updateRepository(invocation, {
        schemaVersion: 1,
        contractVersion: 1 as const,
        idempotencyKey: 'repository-future-update-command-1',
        repositoryId: registered.value.repositoryId,
        expectedRepositoryRevision: 1,
        bindings: futureBindings,
      })
      expect(updated).toMatchObject({
        ok: true,
        value: { repositoryRevision: 2, acceptedState: 'ENABLED' },
      })

      await expect(ctx.securityAssurance.startAssessment(invocation, originalStart))
        .resolves.toEqual(originalAssessment)

      const futureAssessment = await ctx.securityAssurance.startAssessment(invocation, {
        ...originalStart,
        idempotencyKey: 'repository-future-update-start-2',
        assessmentProfileId: futureBindings.assessmentProfileId,
      })
      expect(futureAssessment).toMatchObject({
        ok: true,
        value: {
          repositoryId: registered.value.repositoryId,
          repositoryRevision: 2,
        },
      })
      if (!futureAssessment.ok) throw new Error(`future start failed: ${futureAssessment.error.code}`)

      await expect(ctx.securityAssurance.getAssessment(invocation, {
        schemaVersion: 1,
        assessmentId: originalAssessment.value.assessmentId,
      })).resolves.toMatchObject({
        ok: true,
        value: { repository: { repositoryRevision: 1 } },
      })
      await expect(ctx.securityAssurance.getAssessment(invocation, {
        schemaVersion: 1,
        assessmentId: futureAssessment.value.assessmentId,
      })).resolves.toMatchObject({
        ok: true,
        value: { repository: { repositoryRevision: 2 } },
      })
      await expect(ctx.securityAssurance.getRepository(invocation, {
        schemaVersion: 1,
        repositoryId: registered.value.repositoryId,
      })).resolves.toMatchObject({
        ok: true,
        value: { repositoryRevision: 2, bindings: futureBindings },
      })
    } finally {
      await fiber.dispose()
    }
  })

  it('authorizes Repository commands separately from Repository queries', async () => {
    const repository = await cleanRepository()
    const dshHome = await mkdtemp(join(tmpdir(), 'dsh-security-registry-home-'))
    temporaryRoots.push(dshHome)
    const ctx = new Context()
    const fiber = await ctx.plugin(SecurityAssuranceTestComposition, { dshHome })
    const platform = process.platform
    if (platform !== 'win32' && platform !== 'linux' && platform !== 'darwin') {
      throw new Error(`unsupported test platform: ${platform}`)
    }

    try {
      const registration = {
        schemaVersion: 1 as const,
        contractVersion: 1 as const,
        idempotencyKey: 'repository-separate-auth-register-1',
        root: repository,
        displayName: 'Separate authorization fixture',
        bindings: {
          policyId: 'security/default',
          assessmentProfileId: 'security/standard',
          evidenceProtectionId: 'evidence/local-protected',
          dataEgressPolicyId: 'egress/deny-by-default',
          platform,
          deliveryDestinationIds: [],
        },
      }
      const administrator = referenceHostInvocationWithPermissions(
        ctx.securityAssurance,
        ['repository:admin'],
        'repository-administrator',
      )
      const reader = referenceHostInvocationWithPermissions(
        ctx.securityAssurance,
        ['repository:read'],
        'repository-reader',
      )
      const registered = await ctx.securityAssurance.registerRepository(administrator, registration)
      if (!registered.ok) throw new Error(`registration failed: ${registered.error.code}`)

      await expect(ctx.securityAssurance.getRepository(administrator, {
        schemaVersion: 1,
        repositoryId: registered.value.repositoryId,
      })).resolves.toMatchObject({ ok: false, error: { code: 'UNAUTHORIZED' } })
      await expect(ctx.securityAssurance.listRepositories(administrator, {
        schemaVersion: 1,
        limit: 10,
      })).resolves.toMatchObject({ ok: false, error: { code: 'UNAUTHORIZED' } })

      await expect(ctx.securityAssurance.getRepository(reader, {
        schemaVersion: 1,
        repositoryId: registered.value.repositoryId,
      })).resolves.toMatchObject({ ok: true })
      await expect(ctx.securityAssurance.registerRepository(reader, {
        ...registration,
        idempotencyKey: 'repository-separate-auth-register-2',
      })).resolves.toMatchObject({ ok: false, error: { code: 'UNAUTHORIZED' } })
      await expect(ctx.securityAssurance.updateRepository(reader, {
        schemaVersion: 1,
        contractVersion: 1 as const,
        idempotencyKey: 'repository-separate-auth-update-1',
        repositoryId: registered.value.repositoryId,
        expectedRepositoryRevision: 1,
        displayName: 'Unauthorized update',
      })).resolves.toMatchObject({ ok: false, error: { code: 'UNAUTHORIZED' } })
      await expect(ctx.securityAssurance.disableRepository(reader, {
        schemaVersion: 1,
        contractVersion: 1 as const,
        idempotencyKey: 'repository-separate-auth-disable-1',
        repositoryId: registered.value.repositoryId,
        expectedRepositoryRevision: 1,
      })).resolves.toMatchObject({ ok: false, error: { code: 'UNAUTHORIZED' } })
    } finally {
      await fiber.dispose()
    }
  })

  it('bounds Repository lists and reports truncation without exposing an unbounded query', async () => {
    const repositories = await Promise.all([cleanRepository(), cleanRepository()])
    const dshHome = await mkdtemp(join(tmpdir(), 'dsh-security-registry-home-'))
    temporaryRoots.push(dshHome)
    const ctx = new Context()
    const fiber = await ctx.plugin(SecurityAssuranceTestComposition, { dshHome })
    const platform = process.platform
    if (platform !== 'win32' && platform !== 'linux' && platform !== 'darwin') {
      throw new Error(`unsupported test platform: ${platform}`)
    }

    try {
      const invocation = referenceHostInvocation(ctx.securityAssurance)
      for (const [index, repository] of repositories.entries()) {
        const registered = await ctx.securityAssurance.registerRepository(invocation, {
          schemaVersion: 1,
          contractVersion: 1 as const,
          idempotencyKey: `repository-bounded-list-register-${index + 1}`,
          root: repository,
          displayName: `Bounded list fixture ${index + 1}`,
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
      }

      await expect(ctx.securityAssurance.listRepositories(invocation, {
        schemaVersion: 1,
        limit: 1,
      })).resolves.toMatchObject({
        ok: true,
        value: { repositories: [expect.any(Object)], truncated: true },
      })
      await expect(ctx.securityAssurance.listRepositories(invocation, {
        schemaVersion: 1,
        limit: 101,
      })).resolves.toMatchObject({ ok: false, error: { code: 'INVALID_REQUEST' } })
    } finally {
      await fiber.dispose()
    }
  })

  it('rejects implicit path registration and exposes no destructive Registry operation', async () => {
    const repository = await cleanRepository()
    const dshHome = await mkdtemp(join(tmpdir(), 'dsh-security-registry-home-'))
    temporaryRoots.push(dshHome)
    const ctx = new Context()
    const fiber = await ctx.plugin(SecurityAssuranceTestComposition, { dshHome })

    try {
      const invocation = referenceHostInvocation(ctx.securityAssurance)
      const unregisteredStart = {
        schemaVersion: 1 as const,
        contractVersion: 1 as const,
        idempotencyKey: 'repository-implicit-start-1',
        repositoryId: 'repo-00000000-0000-0000-0000-000000000000',
        subject: { kind: 'workspace_snapshot' as const },
        assessmentMode: 'REPOSITORY' as const,
        assessmentProfileId: 'security/standard',
        target: { kind: 'repository' as const },
        requestedStrongerControlIds: [],
      }
      await expect(ctx.securityAssurance.startAssessment(invocation, unregisteredStart))
        .resolves.toMatchObject({ ok: false, error: { code: 'NOT_FOUND' } })
      await expect(ctx.securityAssurance.startAssessment(invocation, {
        ...unregisteredStart,
        idempotencyKey: 'repository-implicit-start-2',
        root: repository,
      } as unknown as StartAssessmentRequest)).resolves.toMatchObject({
        ok: false,
        error: { code: 'INVALID_REQUEST' },
      })
      await expect(ctx.securityAssurance.listRepositories(invocation, {
        schemaVersion: 1,
        limit: 10,
      })).resolves.toMatchObject({ ok: true, value: { repositories: [], truncated: false } })
      expect('deleteRepository' in ctx.securityAssurance).toBe(false)
      expect('mutateRepository' in ctx.securityAssurance).toBe(false)
    } finally {
      await fiber.dispose()
    }
  })

  it('registers one canonical Repository and returns a path-free immutable Snapshot', async () => {
    const repository = await cleanRepository()
    const dshHome = await mkdtemp(join(tmpdir(), 'dsh-security-registry-home-'))
    temporaryRoots.push(dshHome)
    const ctx = new Context()
    const fiber = await ctx.plugin(SecurityAssuranceTestComposition, { dshHome })
    const platform = process.platform
    if (platform !== 'win32' && platform !== 'linux' && platform !== 'darwin') {
      throw new Error(`unsupported test platform: ${platform}`)
    }

    try {
      const invocation = referenceHostInvocation(ctx.securityAssurance)
      const request: RegisterRepositoryRequest = {
        schemaVersion: 1,
        contractVersion: 1 as const,
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
    const fiber = await ctx.plugin(SecurityAssuranceTestComposition, { dshHome })
    const platform = process.platform
    if (platform !== 'win32' && platform !== 'linux' && platform !== 'darwin') {
      throw new Error(`unsupported test platform: ${platform}`)
    }

    try {
      const invocation = referenceHostInvocation(ctx.securityAssurance)
      const registration = {
        schemaVersion: 1 as const,
        contractVersion: 1 as const,
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
        contractVersion: 1 as const,
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
        contractVersion: 1 as const,
        idempotencyKey: 'repository-update-cas-1',
        repositoryId: registered.value.repositoryId,
        expectedRepositoryRevision: 1,
        displayName: 'Updated CAS fixture',
      })).resolves.toEqual(updated)

      await expect(ctx.securityAssurance.updateRepository(invocation, {
        schemaVersion: 1,
        contractVersion: 1 as const,
        idempotencyKey: 'repository-update-stale-1',
        repositoryId: registered.value.repositoryId,
        expectedRepositoryRevision: 1,
        displayName: 'Stale update',
      })).resolves.toMatchObject({ ok: false, error: { code: 'CONFLICT' } })

      const disabled = await ctx.securityAssurance.disableRepository(invocation, {
        schemaVersion: 1,
        contractVersion: 1 as const,
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
        contractVersion: 1 as const,
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
    const firstFiber = await firstContext.plugin(SecurityAssuranceTestComposition, { dshHome })
    const firstInvocation = referenceHostInvocation(firstContext.securityAssurance)
    const registered = await firstContext.securityAssurance.registerRepository(firstInvocation, {
      schemaVersion: 1,
      contractVersion: 1 as const,
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
    const secondFiber = await secondContext.plugin(SecurityAssuranceTestComposition, { dshHome })
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
    const fiber = await ctx.plugin(SecurityAssuranceTestComposition, { dshHome })

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
