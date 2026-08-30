import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { Context } from '@deepseek-ai/cordis'
import { afterEach, describe, expect, it } from 'vitest'
import SecurityAssuranceHostRepositoryProvider from '../src/host-repository-provider.ts'
import type { Config as HostRepositoryProviderConfig } from '../src/host-repository-provider.ts'
import SecurityAssuranceService from '../src/index.ts'
import type { Config } from '../src/index.ts'
import { referenceHostInvocation } from './support/reference-host.ts'

const temporaryRoots: string[] = []

afterEach(async () => {
  await Promise.all(temporaryRoots.splice(0).map(path => rm(path, { recursive: true, force: true })))
})

describe('ADR 0250: Plugin config contains no secrets', () => {
  it('rejects an embedded secret field without disclosing its value', async () => {
    const dshHome = await mkdtemp(join(tmpdir(), 'dsh-security-adr-0250-home-'))
    temporaryRoots.push(dshHome)
    const secret = 'sk-production-value-must-not-escape'
    const ctx = new Context()
    let fiber: Awaited<ReturnType<Context['plugin']>> | undefined
    let activationFailure: unknown

    try {
      fiber = await ctx.plugin(SecurityAssuranceService, {
        dshHome,
        apiToken: secret,
      } as unknown as Config)
    } catch (error) {
      activationFailure = error
    } finally {
      await fiber?.dispose()
    }

    expect(activationFailure).toBeInstanceOf(TypeError)
    expect(String(activationFailure)).toBe('TypeError: Security Assurance configuration is invalid')
    expect(String(activationFailure)).not.toContain(secret)
  })

  it('rejects secret-bearing Repository bootstrap config before Registry mutation', async () => {
    const dshHome = await mkdtemp(join(tmpdir(), 'dsh-security-adr-0250-home-'))
    temporaryRoots.push(dshHome)
    const secret = 'github_pat_production_value_must_not_escape'
    const platform = process.platform
    if (platform !== 'win32' && platform !== 'linux' && platform !== 'darwin') {
      throw new Error(`unsupported test platform: ${platform}`)
    }
    const ctx = new Context()
    const securityFiber = await ctx.plugin(SecurityAssuranceService, { dshHome })
    let providerFiber: Awaited<ReturnType<Context['plugin']>> | undefined
    let activationFailure: unknown

    try {
      providerFiber = await ctx.plugin(SecurityAssuranceHostRepositoryProvider, {
        repositories: [{
          schemaVersion: 1,
          bindingId: 'secret-bearing-repository',
          idempotencyKey: 'host-repository-provider:secret-bearing:v1',
          root: 'D:/configuration-must-fail-before-root-resolution',
          displayName: 'Secret-bearing Repository',
          bindings: {
            policyId: 'security/default',
            assessmentProfileId: 'security/standard',
            evidenceProtectionId: 'evidence/local-protected',
            dataEgressPolicyId: 'egress/deny-by-default',
            platform,
            deliveryDestinationIds: [],
          },
          apiToken: secret,
        }],
      } as unknown as HostRepositoryProviderConfig)
      await ctx.securityAssuranceHostRepositories.resolve('secret-bearing-repository')
    } catch (error) {
      activationFailure = error
    }

    try {
      expect(activationFailure).toBeInstanceOf(TypeError)
      expect(String(activationFailure)).toBe(
        'TypeError: Host Repository Provider configuration is invalid',
      )
      expect(String(activationFailure)).not.toContain(secret)
      const invocation = referenceHostInvocation(ctx.securityAssurance)
      await expect(ctx.securityAssurance.listRepositories(invocation, {
        schemaVersion: 1,
        limit: 10,
      })).resolves.toMatchObject({ ok: true, value: { repositories: [], truncated: false } })
    } finally {
      await providerFiber?.dispose().catch(() => {})
      await securityFiber.dispose()
    }
  })
})
