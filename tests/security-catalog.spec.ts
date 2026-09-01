import { SecurityAssuranceTestComposition } from './support/security-assurance-test-composition.ts'
import { removeTemporaryRoots } from './support/remove-temporary-root.ts'
import { execFile } from 'node:child_process'
import { mkdtemp, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { promisify } from 'node:util'
import { Context } from '@deepseek-ai/cordis'
import { afterEach, describe, expect, it } from 'vitest'
import type { StartAssessmentSelectionV1 } from '../src/index.ts'
import {
  referenceHostInvocation,
  referenceHostInvocationWithPermissions,
} from './support/reference-host.ts'

const run = promisify(execFile)
const temporaryRoots: string[] = []

afterEach(async () => {
  await removeTemporaryRoots(temporaryRoots)
})
async function repositoryFixture(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), 'dsh-security-catalog-repository-'))
  temporaryRoots.push(root)
  await run('git', ['init', '-b', 'main'], { cwd: root })
  await run('git', ['config', 'user.email', 'fixture@example.invalid'], { cwd: root })
  await run('git', ['config', 'user.name', 'Fixture'], { cwd: root })
  await writeFile(join(root, 'package.json'), '{"name":"catalog-fixture","version":"1.0.0"}\n', 'utf8')
  await run('git', ['add', '.'], { cwd: root })
  await run('git', ['commit', '-m', 'catalog fixture'], { cwd: root })
  return root
}

describe('Security Catalog and Start Preflight', () => {
  it('binds effective Service composition to the confirmed Assessment start', async () => {
    const repositoryRoot = await repositoryFixture()
    const dshHome = await mkdtemp(join(tmpdir(), 'dsh-security-catalog-home-'))
    temporaryRoots.push(dshHome)
    const ctx = new Context()
    const fiber = await ctx.plugin(SecurityAssuranceTestComposition, { dshHome })
    try {
      const invocation = referenceHostInvocation(ctx.securityAssurance)
      const registered = await ctx.securityAssurance.registerRepository(invocation, {
        schemaVersion: 1,
        contractVersion: 1 as const,
        idempotencyKey: 'catalog-repository-v1',
        root: repositoryRoot,
        displayName: 'Catalog fixture',
        bindings: {
          policyId: 'security/node-package-lifecycle',
          assessmentProfileId: 'security/standard',
          evidenceProtectionId: 'evidence/local-protected',
          dataEgressPolicyId: 'egress/deny-by-default',
          platform: process.platform as 'win32' | 'linux' | 'darwin',
          deliveryDestinationIds: ['delivery/local-audit'],
        },
      })
      if (!registered.ok) throw new Error(`registration failed: ${registered.error.code}`)

      const catalog = await ctx.securityAssurance.getCatalog(invocation, {
        schemaVersion: 1,
        repositoryId: registered.value.repositoryId,
      })
      expect(catalog).toMatchObject({
        ok: true,
        value: {
          repository: {
            repositoryId: registered.value.repositoryId,
            displayName: 'Catalog fixture',
          },
          assessmentModes: [
            { assessmentMode: 'REPOSITORY', support: 'SUPPORTED' },
            { assessmentMode: 'CHANGE', support: 'UNSUPPORTED' },
            { assessmentMode: 'TARGETED', support: 'UNSUPPORTED' },
          ],
          assessmentProfiles: [{
            assessmentProfileId: 'security/standard',
            maximumBudget: { status: 'NOT_REPORTED' },
          }],
          startPreflight: null,
        },
      })
      expect(JSON.stringify(catalog)).not.toContain(repositoryRoot)

      const selection: StartAssessmentSelectionV1 = {
        schemaVersion: 1,
        repositoryId: registered.value.repositoryId,
        subject: { kind: 'workspace_snapshot' },
        assessmentMode: 'REPOSITORY',
        assessmentProfileId: 'security/standard',
        target: { kind: 'repository' },
        requestedStrongerControlIds: [],
      }
      const proposed = await ctx.securityAssurance.getCatalog(invocation, {
        schemaVersion: 1,
        repositoryId: registered.value.repositoryId,
        proposedStart: selection,
      })
      expect(proposed).toMatchObject({
        ok: true,
        value: {
          startPreflight: {
            repository: { repositoryId: registered.value.repositoryId, repositoryRevision: 1 },
            selection,
            effectivePolicyId: 'security/node-package-lifecycle',
            effectiveProfileId: 'security/standard',
            providerComposition: [{
              providerId: 'dsh-security-assurance',
              analyzerId: 'dsh/builtin-node-package-lifecycle',
              eligibility: 'ELIGIBLE',
            }],
            dataEgress: {
              policyId: 'egress/deny-by-default',
              destinationIds: [],
              categories: ['NONE'],
            },
            evidenceProtection: { policyId: 'evidence/local-protected' },
            maximumBudget: { status: 'NOT_REPORTED' },
            unsupportedConditions: [],
            admissible: true,
            proposalDigest: {
              mediaType: 'application/vnd.dsh.security.start-preflight+json',
              value: expect.stringMatching(/^[0-9a-f]{64}$/u),
            },
          },
        },
      })
      if (!proposed.ok || proposed.value.startPreflight === null) {
        throw new Error('Start Preflight was not resolved')
      }

      await expect(ctx.securityAssurance.startAssessment(invocation, {
        ...selection,
        contractVersion: 1,
        idempotencyKey: 'catalog-stale-preflight-v1',
        requestedStrongerControlIds: ['security/risk-decision-window-v1'],
        startPreflightDigest: proposed.value.startPreflight.proposalDigest,
      })).resolves.toMatchObject({ ok: false, error: { code: 'CONFLICT', retryable: true } })

      await expect(ctx.securityAssurance.startAssessment(invocation, {
        ...selection,
        contractVersion: 1,
        idempotencyKey: 'catalog-confirmed-preflight-v1',
        startPreflightDigest: proposed.value.startPreflight.proposalDigest,
      })).resolves.toMatchObject({
        ok: true,
        value: {
          operation: 'start_assessment',
          repositoryId: registered.value.repositoryId,
          repositoryRevision: 1,
          state: 'CREATED',
        },
      })
    } finally {
      await fiber.dispose()
    }
  })

  it('requires start authority before resolving a proposal', async () => {
    const dshHome = await mkdtemp(join(tmpdir(), 'dsh-security-catalog-authority-home-'))
    temporaryRoots.push(dshHome)
    const ctx = new Context()
    const fiber = await ctx.plugin(SecurityAssuranceTestComposition, { dshHome })
    try {
      const readOnly = referenceHostInvocationWithPermissions(
        ctx.securityAssurance,
        ['repository:read'],
        'catalog-reader',
      )
      await expect(ctx.securityAssurance.getCatalog(readOnly, {
        schemaVersion: 1,
        proposedStart: {
          schemaVersion: 1,
          repositoryId: 'repo-00000000-0000-0000-0000-000000000000',
          subject: { kind: 'workspace_snapshot' },
          assessmentMode: 'REPOSITORY',
          assessmentProfileId: 'security/standard',
          target: { kind: 'repository' },
          requestedStrongerControlIds: [],
        },
      })).resolves.toMatchObject({ ok: false, error: { code: 'UNAUTHORIZED' } })
    } finally {
      await fiber.dispose()
    }
  })
})
