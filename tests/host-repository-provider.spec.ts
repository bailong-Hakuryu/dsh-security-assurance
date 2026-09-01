import { SecurityAssuranceTestComposition } from './support/security-assurance-test-composition.ts'
import { removeTemporaryRoots } from './support/remove-temporary-root.ts'
import { execFile } from 'node:child_process'
import { createHash } from 'node:crypto'
import { mkdtemp, realpath, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { promisify } from 'node:util'
import { Context } from '@deepseek-ai/cordis'
import { afterEach, describe, expect, it, vi } from 'vitest'
import SecurityAssuranceHostRepositoryProvider from '../src/host-repository-provider.ts'

const run = promisify(execFile)
const temporaryRoots: string[] = []

afterEach(async () => {
  await removeTemporaryRoots(temporaryRoots)
})

async function cleanRepository(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), 'dsh-security-host-repository-'))
  temporaryRoots.push(root)
  await run('git', ['init', '-b', 'main'], { cwd: root })
  await run('git', ['config', 'user.email', 'fixture@example.invalid'], { cwd: root })
  await run('git', ['config', 'user.name', 'Fixture'], { cwd: root })
  await writeFile(join(root, 'README.md'), '# Host Repository Provider fixture\n', 'utf8')
  await run('git', ['add', 'README.md'], { cwd: root })
  await run('git', ['commit', '-m', 'fixture baseline'], { cwd: root })
  return root
}

describe('Security Assurance Host Repository Provider', () => {
  it('does not report plugin activation before Host registration settles', async () => {
    const repository = await cleanRepository()
    const dshHome = await mkdtemp(join(tmpdir(), 'dsh-security-host-repository-home-'))
    temporaryRoots.push(dshHome)
    const platform = process.platform
    if (platform !== 'win32' && platform !== 'linux' && platform !== 'darwin') {
      throw new Error(`unsupported test platform: ${platform}`)
    }
    const ctx = new Context()
    const securityFiber = await ctx.plugin(SecurityAssuranceTestComposition, { dshHome })
    const originalRegister = ctx.securityAssurance.registerRepository.bind(ctx.securityAssurance)
    let releaseRegistration!: () => void
    const registrationGate = new Promise<void>(resolve => {
      releaseRegistration = resolve
    })
    vi.spyOn(ctx.securityAssurance, 'registerRepository').mockImplementation(async (...args) => {
      await registrationGate
      return originalRegister(...args)
    })

    let providerFiber: Awaited<ReturnType<Context['plugin']>> | undefined
    try {
      let activated = false
      const activation = ctx.plugin(SecurityAssuranceHostRepositoryProvider, {
        repositories: [{
          schemaVersion: 1,
          bindingId: 'activation-fence',
          idempotencyKey: 'host-repository-provider:activation-fence:v1',
          root: repository,
          displayName: 'Activation Fence Repository',
          bindings: {
            policyId: 'security/node-package-lifecycle',
            assessmentProfileId: 'security/standard',
            evidenceProtectionId: 'evidence/local-protected',
            dataEgressPolicyId: 'egress/deny-by-default',
            platform,
            deliveryDestinationIds: [],
          },
        }],
      })
      void activation.then(() => {
        activated = true
      })
      await new Promise<void>(resolve => setImmediate(resolve))
      expect(activated).toBe(false)

      releaseRegistration()
      providerFiber = await activation
      await expect(ctx.securityAssuranceHostRepositories.resolve('activation-fence')).resolves.toMatchObject({
        bindingId: 'activation-fence',
        state: 'ENABLED',
      })
    } finally {
      releaseRegistration()
      await providerFiber?.dispose()
      await securityFiber.dispose()
    }
  })

  it('registers Host configuration and resolves one immutable path-free binding', async () => {
    const repository = await cleanRepository()
    const dshHome = await mkdtemp(join(tmpdir(), 'dsh-security-host-repository-home-'))
    temporaryRoots.push(dshHome)
    const platform = process.platform
    if (platform !== 'win32' && platform !== 'linux' && platform !== 'darwin') {
      throw new Error(`unsupported test platform: ${platform}`)
    }
    const ctx = new Context()
    const securityFiber = await ctx.plugin(SecurityAssuranceTestComposition, { dshHome })
    const providerFiber = await ctx.plugin(SecurityAssuranceHostRepositoryProvider, {
      repositories: [{
        schemaVersion: 1,
        bindingId: 'mission-repository',
        idempotencyKey: 'host-repository-provider:mission-repository:v1',
        root: repository,
        displayName: 'Mission Repository',
        bindings: {
          policyId: 'security/node-package-lifecycle',
          assessmentProfileId: 'security/standard',
          evidenceProtectionId: 'evidence/local-protected',
          dataEgressPolicyId: 'egress/deny-by-default',
          platform,
          deliveryDestinationIds: [],
        },
      }],
    })

    try {
      const binding = await ctx.securityAssuranceHostRepositories.resolve('mission-repository')
      expect(binding).toMatchObject({
        schemaVersion: 1,
        bindingId: 'mission-repository',
        repositoryId: expect.stringMatching(/^repo-[0-9a-f-]{36}$/u),
        repositoryRevision: 1,
        state: 'ENABLED',
      })
      expect(JSON.stringify(binding)).not.toContain(repository)
      expect(Object.isFrozen(binding)).toBe(true)
    } finally {
      await providerFiber.dispose()
      await securityFiber.dispose()
    }
  })

  it('derives a non-reversible idempotency key from the canonical Repository root', async () => {
    const repository = await cleanRepository()
    const configuredRoot = `${repository}/.`
    const canonicalRoot = await realpath(repository)
    const dshHome = await mkdtemp(join(tmpdir(), 'dsh-security-host-repository-home-'))
    temporaryRoots.push(dshHome)
    const platform = process.platform
    if (platform !== 'win32' && platform !== 'linux' && platform !== 'darwin') {
      throw new Error(`unsupported test platform: ${platform}`)
    }
    const ctx = new Context()
    const securityFiber = await ctx.plugin(SecurityAssuranceTestComposition, { dshHome })
    const originalRegister = ctx.securityAssurance.registerRepository.bind(ctx.securityAssurance)
    const requests: unknown[] = []
    vi.spyOn(ctx.securityAssurance, 'registerRepository').mockImplementation(async (invocation, request, options) => {
      requests.push(request)
      return originalRegister(invocation, request, options)
    })
    let providerFiber: Awaited<ReturnType<Context['plugin']>> | undefined
    try {
      providerFiber = await ctx.plugin(SecurityAssuranceHostRepositoryProvider, {
        repositories: [{
          schemaVersion: 1,
          bindingId: 'derived-identity',
          root: configuredRoot,
          displayName: 'Derived Identity Repository',
          bindings: {
            policyId: 'security/node-package-lifecycle',
            assessmentProfileId: 'security/standard',
            evidenceProtectionId: 'evidence/local-protected',
            dataEgressPolicyId: 'egress/deny-by-default',
            platform,
            deliveryDestinationIds: [],
          },
        }],
      })
      const expectedKey = 'host-repository-provider:root:'
        + createHash('sha256').update(canonicalRoot).digest('hex')
      expect(requests).toEqual([expect.objectContaining({
        root: canonicalRoot,
        idempotencyKey: expectedKey,
      })])
      expect(expectedKey).not.toContain(Buffer.from(canonicalRoot).toString('base64url'))
    } finally {
      await providerFiber?.dispose()
      await securityFiber.dispose()
    }
  })

  it('rejects duplicate Host binding identities', async () => {
    const repository = await cleanRepository()
    const dshHome = await mkdtemp(join(tmpdir(), 'dsh-security-host-repository-home-'))
    temporaryRoots.push(dshHome)
    const platform = process.platform
    if (platform !== 'win32' && platform !== 'linux' && platform !== 'darwin') {
      throw new Error(`unsupported test platform: ${platform}`)
    }
    const ctx = new Context()
    const securityFiber = await ctx.plugin(SecurityAssuranceTestComposition, { dshHome })
    const registration = {
      schemaVersion: 1 as const,
      bindingId: 'duplicated-repository',
      idempotencyKey: 'host-repository-provider:duplicated:v1',
      root: repository,
      displayName: 'Duplicated Repository',
      bindings: {
        policyId: 'security/node-package-lifecycle',
        assessmentProfileId: 'security/standard',
        evidenceProtectionId: 'evidence/local-protected',
        dataEgressPolicyId: 'egress/deny-by-default',
        platform,
        deliveryDestinationIds: [],
      },
    }

    let providerFiber: Awaited<ReturnType<Context['plugin']>> | undefined
    let activationFailure = ''
    try {
      try {
        providerFiber = await ctx.plugin(SecurityAssuranceHostRepositoryProvider, {
          repositories: [registration, {
            ...registration,
            idempotencyKey: 'host-repository-provider:duplicated:v2',
          }],
        })
      } catch (error) {
        activationFailure = String(error)
      }
      expect(activationFailure).toContain("Host Repository binding 'duplicated-repository' is duplicated")
    } finally {
      await providerFiber?.dispose()
      await securityFiber.dispose()
    }
  })
})
