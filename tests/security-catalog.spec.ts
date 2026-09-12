import { SecurityAssuranceTestComposition } from './support/security-assurance-test-composition.ts'
import { removeTemporaryRoots } from './support/remove-temporary-root.ts'
import { execFile } from 'node:child_process'
import { createHash } from 'node:crypto'
import { mkdtemp, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { promisify } from 'node:util'
import { Context } from '@deepseek-ai/cordis'
import { afterEach, describe, expect, it } from 'vitest'
import SecurityAssuranceService from '../src/index.ts'
import type {
  AssessmentId,
  SecurityInvocation,
  StartAssessmentSelectionV1,
} from '../src/index.ts'
import {
  securityCatalogSnapshotV1Schema,
  startPreflightV1Schema,
} from '../src/index.ts'
import {
  referenceHostInvocation,
  referenceHostInvocationWithPermissions,
} from './support/reference-host.ts'

const run = promisify(execFile)
const temporaryRoots: string[] = []

const expectedRoleCatalog = ([
  ['threat-modeler', 103, '2f591983ccd1ffe3743dc282eaab45a8b10516e42e039e44c1bc10bca4a67c34'],
  ['discovery-analyst', 106, '1dedd74c4cd7f2f09cad1a9a4fe3283dfdcbd5a1d2f37563c921b4483b4b86cd'],
  ['validation-analyst', 107, '2effc9610eb40e9d85947164e6e0f4f0276f01427e3ac61cd13721f953a033c1'],
  ['attack-path-analyst', 108, 'f734134dcdd305aab4ea0001ea11a442f1d4de7c2f0d1f05dda76e24d109eae6'],
  ['challenge-analyst', 106, '78d10c092aab1210c0af88a538d255ddde1e3c36d40cbd4ac1301a4baccf9aef'],
] as const).map(([roleId, byteLength, value]) => ({
  roleId,
  catalogEntryVersion: '1.0.0',
  catalogEntryDigest: {
    schemaVersion: 1,
    algorithm: 'sha256',
    mediaType: 'application/vnd.dsh.security.role-catalog-entry+json',
    byteLength,
    canonicalization: 'dsh-canonical-json-v1',
    value,
  },
  executionSupport: 'UNSUPPORTED',
  authority: 'PROPOSAL_ONLY',
}))

function canonicalJsonForTest(value: unknown): string {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') {
    return JSON.stringify(value)
  }
  if (typeof value === 'number') return JSON.stringify(value)
  if (Array.isArray(value)) return `[${value.map(canonicalJsonForTest).join(',')}]`
  if (typeof value !== 'object') throw new TypeError('expected a JSON-safe value')
  const record = value as Record<string, unknown>
  return `{${Object.keys(record).sort().map(key => (
    `${JSON.stringify(key)}:${canonicalJsonForTest(record[key])}`
  )).join(',')}}`
}

function expectedStartPreflightDigest(value: unknown) {
  const encoded = canonicalJsonForTest(value)
  return {
    schemaVersion: 1,
    algorithm: 'sha256',
    mediaType: 'application/vnd.dsh.security.start-preflight+json',
    byteLength: Buffer.byteLength(encoded, 'utf8'),
    canonicalization: 'dsh-canonical-json-v1',
    value: createHash('sha256').update(encoded).digest('hex'),
  } as const
}

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

async function waitUntilSealed(
  service: SecurityAssuranceService,
  invocation: SecurityInvocation,
  assessmentId: AssessmentId,
): Promise<void> {
  let revision = 1
  for (let attempt = 0; attempt < 5; attempt += 1) {
    const changed = await service.waitForAssessmentRevision(invocation, {
      schemaVersion: 1,
      assessmentId,
      afterRevision: revision,
      timeoutMs: 5_000,
    })
    if (!changed.ok) throw new Error(`wait failed: ${changed.error.code}`)
    const assessment = await service.getAssessment(invocation, { schemaVersion: 1, assessmentId })
    if (!assessment.ok) throw new Error(`query failed: ${assessment.error.code}`)
    if (assessment.value.state === 'SEALED') return
    revision = assessment.value.assessmentRevision
  }
  throw new Error('Assessment did not seal')
}

describe('Security Catalog and Start Preflight', () => {
  it('exposes only the fixed governed Role Catalog without executable or decision authority', async () => {
    const dshHome = await mkdtemp(join(tmpdir(), 'dsh-security-role-catalog-home-'))
    temporaryRoots.push(dshHome)
    const ctx = new Context()
    const fiber = await ctx.plugin(SecurityAssuranceTestComposition, { dshHome })
    try {
      const invocation = referenceHostInvocation(ctx.securityAssurance)
      const catalog = await ctx.securityAssurance.getCatalog(invocation, { schemaVersion: 1 })
      if (!catalog.ok) throw new Error(`catalog failed: ${catalog.error.code}`)

      expect(catalog.value.securityRoles).toEqual(expectedRoleCatalog)
      expect(Object.isFrozen(catalog.value.securityRoles)).toBe(true)
      expect(catalog.value.securityRoles.every(role => (
        Object.isFrozen(role) && Object.isFrozen(role.catalogEntryDigest)
      ))).toBe(true)
      expect(JSON.stringify(catalog.value.securityRoles)).not.toMatch(
        /prompt|factory|credential|approver|risk acceptor|verdict owner/iu,
      )
    } finally {
      await fiber.dispose()
    }
  })

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
            { assessmentMode: 'CHANGE', support: 'SUPPORTED' },
            { assessmentMode: 'TARGETED', support: 'SUPPORTED' },
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
      expect(proposed.value.startPreflight.roleCatalog).toEqual(expectedRoleCatalog)
      expect(Object.isFrozen(proposed.value.startPreflight.roleCatalog)).toBe(true)
      const { proposalDigest, ...proposalCore } = proposed.value.startPreflight
      expect(proposalDigest).toEqual(expectedStartPreflightDigest(proposalCore))

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

  it('defaults the additive preflight Role Catalog for older v1 payloads', () => {
    const parsed = startPreflightV1Schema.parse({
      schemaVersion: 1,
      repository: {
        repositoryId: 'repo-00000000-0000-0000-0000-000000000000',
        repositoryRevision: 1,
        displayName: 'Older v1 payload',
      },
      selection: {
        schemaVersion: 1,
        repositoryId: 'repo-00000000-0000-0000-0000-000000000000',
        subject: { kind: 'workspace_snapshot' },
        assessmentMode: 'REPOSITORY',
        assessmentProfileId: 'security/standard',
        target: { kind: 'repository' },
        requestedStrongerControlIds: [],
      },
      effectivePolicyId: 'security/node-package-lifecycle',
      effectiveProfileId: 'security/standard',
      providerComposition: [],
      dataEgress: {
        policyId: 'egress/deny-by-default',
        destinationIds: [],
        categories: ['NONE'],
      },
      evidenceProtection: { policyId: 'evidence/local-protected' },
      maximumBudget: { status: 'NOT_REPORTED' },
      unsupportedConditions: [],
      claimLimitations: [],
      coverageLimitations: [],
      admissible: true,
      proposalDigest: {
        schemaVersion: 1,
        algorithm: 'sha256',
        mediaType: 'application/vnd.dsh.security.start-preflight+json',
        byteLength: 2,
        canonicalization: 'dsh-canonical-json-v1',
        value: '0'.repeat(64),
      },
    })

    expect(parsed.roleCatalog).toEqual([])
  })

  it('accepts an older Role summary but rejects partial Catalog lineage', () => {
    const catalog = {
      schemaVersion: 1,
      repository: null,
      assessmentModes: [],
      assessmentProfiles: [],
      strongerControls: [],
      supportedEcosystemIds: [],
      supportedPlatforms: [],
      supportMatrixReferences: [],
      startPreflight: null,
    }
    const legacyRole = {
      roleId: 'threat-modeler',
      executionSupport: 'UNSUPPORTED',
      authority: 'PROPOSAL_ONLY',
    }

    expect(securityCatalogSnapshotV1Schema.safeParse({
      ...catalog,
      securityRoles: [legacyRole],
    }).success).toBe(true)
    expect(securityCatalogSnapshotV1Schema.safeParse({
      ...catalog,
      securityRoles: [{ ...legacyRole, catalogEntryVersion: '1.0.0' }],
    }).success).toBe(false)
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

  it('does not advertise a PURE Analyzer as qualified for an unimplemented Deep Profile', async () => {
    const repositoryRoot = await repositoryFixture()
    const dshHome = await mkdtemp(join(tmpdir(), 'dsh-security-catalog-deep-home-'))
    temporaryRoots.push(dshHome)
    const ctx = new Context()
    const fiber = await ctx.plugin(SecurityAssuranceTestComposition, { dshHome })
    try {
      const invocation = referenceHostInvocation(ctx.securityAssurance)
      const registered = await ctx.securityAssurance.registerRepository(invocation, {
        schemaVersion: 1,
        contractVersion: 1,
        idempotencyKey: 'catalog-deep-repository-v1',
        root: repositoryRoot,
        displayName: 'Deep Catalog fixture',
        bindings: {
          policyId: 'security/node-package-lifecycle',
          assessmentProfileId: 'security/deep',
          evidenceProtectionId: 'evidence/local-protected',
          dataEgressPolicyId: 'egress/deny-by-default',
          platform: process.platform as 'win32' | 'linux' | 'darwin',
          deliveryDestinationIds: [],
        },
      })
      if (!registered.ok) throw new Error(`registration failed: ${registered.error.code}`)

      const selection: StartAssessmentSelectionV1 = {
        schemaVersion: 1,
        repositoryId: registered.value.repositoryId,
        subject: { kind: 'workspace_snapshot' },
        assessmentMode: 'REPOSITORY',
        assessmentProfileId: 'security/deep',
        target: { kind: 'repository' },
        requestedStrongerControlIds: [],
      }
      const catalog = await ctx.securityAssurance.getCatalog(invocation, {
        schemaVersion: 1,
        repositoryId: registered.value.repositoryId,
        proposedStart: selection,
      })

      expect(catalog).toMatchObject({
        ok: true,
        value: {
          assessmentModes: [
            { assessmentMode: 'REPOSITORY', support: 'UNSUPPORTED' },
            { assessmentMode: 'CHANGE', support: 'UNSUPPORTED' },
            { assessmentMode: 'TARGETED', support: 'UNSUPPORTED' },
          ],
          assessmentProfiles: [{
            assessmentProfileId: 'security/deep',
            limitations: [
              'Deep requires governed Role execution, but no qualified Role Provider composition is available in v0.1.',
            ],
          }],
          supportedEcosystemIds: [],
          supportedPlatforms: [],
          startPreflight: {
            selection,
            providerComposition: [],
            unsupportedConditions: [
              'NO_ELIGIBLE_ANALYZER_COMPOSITION',
              'NO_ELIGIBLE_ROLE_COMPOSITION',
            ],
            claimLimitations: [],
            coverageLimitations: [
              'Mandatory Coverage cannot be satisfied by the currently qualified composition.',
            ],
            admissible: false,
          },
        },
      })

      const started = await ctx.securityAssurance.startAssessment(invocation, {
        ...selection,
        contractVersion: 1,
        idempotencyKey: 'catalog-deep-direct-start-v1',
      })
      if (!started.ok) throw new Error(`start failed: ${started.error.code}`)
      await waitUntilSealed(
        ctx.securityAssurance,
        invocation,
        started.value.assessmentId,
      )
      await expect(ctx.securityAssurance.getAssessment(invocation, {
        schemaVersion: 1,
        assessmentId: started.value.assessmentId,
      })).resolves.toMatchObject({
        ok: true,
        value: {
          state: 'SEALED',
          verdict: 'INDETERMINATE',
          coverage: {
            status: 'GAP',
            resolutions: [{
              obligationId: 'node-package-install-lifecycle-policy',
              reason: 'NO_ELIGIBLE_ANALYZER',
            }],
          },
        },
      })
    } finally {
      await fiber.dispose()
    }
  })
})
