import { execFile } from 'node:child_process'
import { mkdtemp, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { promisify } from 'node:util'

import { Context } from '@deepseek-ai/cordis'
import { afterEach, describe, expect, it } from 'vitest'

import SecurityAssuranceService, {
  analyzePnpmLockfileIntegrity,
  analyzerContributionV1Schema,
  PNPM_LOCKFILE_ANALYZER_ID,
  PNPM_LOCKFILE_DESCRIPTOR,
  PNPM_LOCKFILE_EVIDENCE_SCHEMA_ID,
  PNPM_LOCKFILE_POLICY_ID,
  PNPM_LOCKFILE_QUALIFICATION,
  PNPM_LOCKFILE_WEAKNESS_ID,
} from '../src/index.ts'
import type {
  AnalyzerPortfolioEntryV1,
  AssessmentId,
  FindingSummaryV1,
  SecurityInvocation,
} from '../src/index.ts'
import { binaryDigest, structuredDigest } from '../src/internal/canonical.ts'
import { pnpmLockfileCoverageIsIndependentlyVerified } from '../src/internal/candidate-validation.ts'
import {
  evaluateDeterministicAssessment,
  prepareAssessmentContract,
} from '../src/internal/deterministic-kernel.ts'
import { SecurityAssuranceTestComposition } from './support/security-assurance-test-composition.ts'
import { referenceHostInvocation } from './support/reference-host.ts'
import { removeTemporaryRoots } from './support/remove-temporary-root.ts'

const run = promisify(execFile)
const temporaryRoots: string[] = []
const DEEPLY_NESTED_YAML = `${'['.repeat(5_000)}1${']'.repeat(5_000)}`
const MANIFEST = `{
  "name": "lockfile-fixture",
  "version": "1.0.0",
  "packageManager": "pnpm@11.7.0",
  "dependencies": { "alpha": "^1.0.0" }
}
`
const CLEAN_LOCKFILE = `lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      alpha:
        specifier: ^1.0.0
        version: 1.0.0
packages:
  alpha@1.0.0:
    resolution: {integrity: sha512-q6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urqw==}
snapshots:
  alpha@1.0.0: {}
`

const INVALID_LENGTH_SRI_LOCKFILE = CLEAN_LOCKFILE.replace('sha512-q6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urqw==', 'sha512-a')
const DRIFTED_LOCKFILE = `lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      alpha:
        specifier: ^2.0.0
        version: 2.0.0
packages:
  alpha@2.0.0:
    resolution: {}
snapshots:
  alpha@2.0.0: {}
`

afterEach(async () => {
  await removeTemporaryRoots(temporaryRoots)
})

function subjectDigestFixture() {
  return structuredDigest('application/vnd.dsh.security.subject-manifest+json', {
    fixture: 'pnpm-lockfile-integrity-unit',
  })
}

function textSlice(path: 'package.json' | 'pnpm-lock.yaml', text: string) {
  return {
    path,
    digest: binaryDigest('application/octet-stream', Buffer.from(text, 'utf8')),
    text,
  }
}

function eligiblePortfolioEntry(): AnalyzerPortfolioEntryV1 {
  const analyzerIdentity = {
    analyzerId: PNPM_LOCKFILE_DESCRIPTOR.analyzerId,
    analyzerVersion: PNPM_LOCKFILE_DESCRIPTOR.analyzerVersion,
    descriptorSchemaVersion: PNPM_LOCKFILE_DESCRIPTOR.descriptorSchemaVersion,
    buildDigest: PNPM_LOCKFILE_DESCRIPTOR.buildDigest,
  }
  const platform = process.platform
  if (platform !== 'win32' && platform !== 'linux' && platform !== 'darwin') {
    throw new Error(`unsupported test platform: ${platform}`)
  }
  return {
    descriptor: PNPM_LOCKFILE_DESCRIPTOR,
    qualification: PNPM_LOCKFILE_QUALIFICATION,
    eligibility: {
      schemaVersion: 1,
      decision: 'ELIGIBLE',
      reason: null,
      evaluatedAt: '2026-01-01T00:00:00.000Z',
      analyzerIdentity,
      qualificationId: PNPM_LOCKFILE_QUALIFICATION.qualificationId,
      qualificationDigest: PNPM_LOCKFILE_QUALIFICATION.qualificationDigest,
      policyId: PNPM_LOCKFILE_POLICY_ID,
      assessmentMode: 'REPOSITORY',
      platform,
    },
  }
}

describe('pnpm lockfile integrity Analyzer (unit)', () => {
  it('accepts one exact pnpm importer whose package resolutions carry SRI', () => {
    const contribution = analyzePnpmLockfileIntegrity({
      subjectDigest: subjectDigestFixture(),
      slices: [textSlice('package.json', MANIFEST), textSlice('pnpm-lock.yaml', CLEAN_LOCKFILE)],
    })
    expect(contribution).toMatchObject({
      completionDisposition: 'COMPLETE',
      coverageClaims: [{
        obligationId: 'application-security-analysis',
        completion: 'COMPLETE',
        evidenceArtifactId: 'pnpm-lockfile-integrity-analysis',
      }],
      candidateFindings: [],
      diagnostics: [],
      evidence: [{
        schemaId: PNPM_LOCKFILE_EVIDENCE_SCHEMA_ID,
        value: {
          rootManifest: { packageManagerState: 'EXACT_PNPM', dependencyCount: 1 },
          lockfile: {
            parseStatus: 'VALID',
            importerMatchesManifest: true,
            packageResolutionCount: 1,
            missingIntegrityCount: 0,
          },
          entries: [],
        },
      }],
    })
  })

  it('treats a Subject without root Node metadata as completely not applicable', () => {
    const contribution = analyzePnpmLockfileIntegrity({
      subjectDigest: subjectDigestFixture(),
      slices: [],
    })
    expect(contribution).toMatchObject({
      completionDisposition: 'COMPLETE',
      candidateFindings: [],
      diagnostics: [],
      evidence: [{ value: { rootManifest: null, lockfile: null, entries: [] } }],
    })
  })

  it('detects an unpinned package manager, importer drift and missing package SRI', () => {
    const manifest = MANIFEST.replace('pnpm@11.7.0', 'pnpm@latest')
    const contribution = analyzePnpmLockfileIntegrity({
      subjectDigest: subjectDigestFixture(),
      slices: [textSlice('package.json', manifest), textSlice('pnpm-lock.yaml', DRIFTED_LOCKFILE)],
    })
    expect(contribution.completionDisposition).toBe('COMPLETE')
    expect(contribution.candidateFindings).toHaveLength(3)
    expect(contribution.candidateFindings.map(candidate => candidate.weaknessClassification.primary))
      .toEqual(Array.from({ length: 3 }, () => PNPM_LOCKFILE_WEAKNESS_ID))
    expect(contribution.evidence[0]?.value).toMatchObject({
      rootManifest: { packageManagerState: 'UNPINNED' },
      lockfile: { importerMatchesManifest: false, missingIntegrityCount: 1 },
      entries: [
        { ruleId: 'PACKAGE_MANAGER_NOT_EXACTLY_PINNED', severity: 'MEDIUM' },
        { ruleId: 'PNPM_LOCKFILE_IMPORTER_DRIFT', severity: 'HIGH' },
        { ruleId: 'PNPM_PACKAGE_INTEGRITY_MISSING', severity: 'HIGH' },
      ],
    })
  })

  it('reports a missing pnpm lockfile as a verified violation', () => {
    const contribution = analyzePnpmLockfileIntegrity({
      subjectDigest: subjectDigestFixture(),
      slices: [textSlice('package.json', MANIFEST)],
    })
    expect(contribution).toMatchObject({
      completionDisposition: 'COMPLETE',
      candidateFindings: [{ securityClaim: expect.stringContaining('pnpm-lock.yaml') }],
      evidence: [{ value: { lockfile: null, entries: [{ ruleId: 'PNPM_LOCKFILE_MISSING' }] } }],
    })
  })

  it('fails closed on duplicate JSON, YAML aliases and unsupported lockfile versions', () => {
    const duplicateManifest = analyzePnpmLockfileIntegrity({
      subjectDigest: subjectDigestFixture(),
      slices: [textSlice('package.json', '{"name":"a","name":"b"}\n')],
    })
    expect(duplicateManifest.completionDisposition).toBe('INCOMPLETE')
    expect(duplicateManifest.diagnostics).toContain('ROOT_PACKAGE_MANIFEST_INVALID')

    const aliasLockfile = analyzePnpmLockfileIntegrity({
      subjectDigest: subjectDigestFixture(),
      slices: [
        textSlice('package.json', MANIFEST),
        textSlice('pnpm-lock.yaml', "lockfileVersion: '9.0'\nimporters:\n  .: &root {}\npackages: *root\n"),
      ],
    })
    expect(aliasLockfile.completionDisposition).toBe('INCOMPLETE')
    expect(aliasLockfile.diagnostics).toContain('PNPM_LOCKFILE_INVALID')

    const unsupported = analyzePnpmLockfileIntegrity({
      subjectDigest: subjectDigestFixture(),
      slices: [
        textSlice('package.json', MANIFEST),
        textSlice('pnpm-lock.yaml', CLEAN_LOCKFILE.replace("'9.0'", "'8.0'")),
      ],
    })
    expect(unsupported.completionDisposition).toBe('INCOMPLETE')
    expect(unsupported.coverageClaims).toEqual([])
    expect(unsupported.diagnostics).toContain('PNPM_LOCKFILE_VERSION_UNSUPPORTED')

    const otherManager = analyzePnpmLockfileIntegrity({
      subjectDigest: subjectDigestFixture(),
      slices: [textSlice('package.json', MANIFEST.replace('pnpm@11.7.0', 'npm@11.0.0'))],
    })
    expect(otherManager.completionDisposition).toBe('INCOMPLETE')
    expect(otherManager.candidateFindings).toEqual([])
    expect(otherManager.diagnostics).toContain('PNPM_PACKAGE_MANAGER_UNSUPPORTED')

    const invalidSri = analyzePnpmLockfileIntegrity({
      subjectDigest: subjectDigestFixture(),
      slices: [
        textSlice('package.json', MANIFEST),
        textSlice('pnpm-lock.yaml', INVALID_LENGTH_SRI_LOCKFILE),
      ],
    })
    expect(invalidSri.candidateFindings).toHaveLength(1)
    expect(invalidSri.evidence[0]?.value).toMatchObject({
      lockfile: { missingIntegrityCount: 1 },
      entries: [{ ruleId: 'PNPM_PACKAGE_INTEGRITY_MISSING' }],
    })
  })

  it('fails closed without leaking a stack overflow from a deeply nested lockfile', () => {
    const contribution = analyzePnpmLockfileIntegrity({
      subjectDigest: subjectDigestFixture(),
      slices: [
        textSlice('package.json', MANIFEST),
        textSlice('pnpm-lock.yaml', DEEPLY_NESTED_YAML),
      ],
    })
    expect(contribution.completionDisposition).toBe('INCOMPLETE')
    expect(contribution.coverageClaims).toEqual([])
    expect(contribution.diagnostics).toContain('PNPM_LOCKFILE_INVALID')
  })

  it('independently re-derives Coverage and never publishes a tampered claim', () => {
    const subjectDigest = subjectDigestFixture()
    const driftOnlyLockfile = DRIFTED_LOCKFILE.replace('resolution: {}', 'resolution: {integrity: sha512-q6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urqw==}')
    const slices = [
      textSlice('package.json', MANIFEST),
      textSlice('pnpm-lock.yaml', driftOnlyLockfile),
    ]
    const contribution = analyzePnpmLockfileIntegrity({ subjectDigest, slices })
    expect(contribution.candidateFindings).toHaveLength(1)
    const portfolioEntry = eligiblePortfolioEntry()
    const policyDigest = structuredDigest('application/vnd.dsh.security.policy+json', {
      policyId: PNPM_LOCKFILE_POLICY_ID,
    })
    const input = {
      portfolioEntry,
      contribution,
      subjectSlices: slices,
      policyId: PNPM_LOCKFILE_POLICY_ID,
      policyDigest,
    }
    expect(pnpmLockfileCoverageIsIndependentlyVerified(input)).toBe(true)
    const maliciousClaim = 'ATTACKER_CONTROLLED_LOCKFILE_TEXT_MUST_NOT_BE_PUBLISHED'
    const tampered = analyzerContributionV1Schema.parse({
      ...contribution,
      candidateFindings: contribution.candidateFindings.map(candidate => ({
        ...candidate,
        securityClaim: maliciousClaim,
      })),
    })
    expect(pnpmLockfileCoverageIsIndependentlyVerified({ ...input, contribution: tampered })).toBe(false)
    const contract = prepareAssessmentContract({
      policyId: PNPM_LOCKFILE_POLICY_ID,
      assessmentMode: 'REPOSITORY',
      assessmentProfileId: 'security/standard',
      target: { kind: 'repository' },
      targetDigest: subjectDigest,
      requestedStrongerControlIds: [],
      analyzerPortfolio: [portfolioEntry],
    })
    const outcome = evaluateDeterministicAssessment(
      contract,
      '2026-01-01T00:00:00.000Z',
      undefined,
      [{ portfolioEntry, contribution: tampered, subjectSlices: slices }],
    )
    expect(outcome.verdict).toBe('INDETERMINATE')
    expect(JSON.stringify(outcome)).not.toContain(maliciousClaim)
  })
})

async function repositoryFixture(lockfile: string | null, manifest = MANIFEST): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), 'dsh-security-pnpm-lockfile-'))
  temporaryRoots.push(root)
  await run('git', ['init', '-b', 'main'], { cwd: root })
  await run('git', ['config', 'user.email', 'fixture@example.invalid'], { cwd: root })
  await run('git', ['config', 'user.name', 'Fixture'], { cwd: root })
  await writeFile(join(root, 'package.json'), manifest)
  if (lockfile !== null) await writeFile(join(root, 'pnpm-lock.yaml'), lockfile)
  await run('git', ['add', '.'], { cwd: root })
  await run('git', ['commit', '-m', 'lockfile fixture'], { cwd: root })
  return root
}

async function waitUntilSealed(
  service: SecurityAssuranceService,
  invocation: SecurityInvocation,
  assessmentId: AssessmentId,
): Promise<void> {
  let revision = 1
  for (let attempt = 0; attempt < 6; attempt += 1) {
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
  throw new Error('Assessment did not reach SEALED')
}

async function runScenario(id: string, lockfile: string, manifest = MANIFEST): Promise<{
  readonly verdict: string | null
  readonly coverageStatus: string
  readonly findings: readonly FindingSummaryV1[]
}> {
  const repository = await repositoryFixture(lockfile, manifest)
  const dshHome = await mkdtemp(join(tmpdir(), 'dsh-security-pnpm-lockfile-home-'))
  temporaryRoots.push(dshHome)
  const ctx = new Context()
  const fiber = await ctx.plugin(SecurityAssuranceTestComposition, { dshHome })
  try {
    const invocation = referenceHostInvocation(ctx.securityAssurance)
    const platform = process.platform
    if (platform !== 'win32' && platform !== 'linux' && platform !== 'darwin') {
      throw new Error(`unsupported test platform: ${platform}`)
    }
    const registered = await ctx.securityAssurance.registerRepository(invocation, {
      schemaVersion: 1,
      contractVersion: 1,
      idempotencyKey: `pnpm-lockfile-register-${id}`,
      root: repository,
      displayName: 'pnpm lockfile fixture',
      bindings: {
        policyId: PNPM_LOCKFILE_POLICY_ID,
        assessmentProfileId: 'security/standard',
        evidenceProtectionId: 'evidence/local-protected',
        dataEgressPolicyId: 'egress/deny-by-default',
        platform,
        deliveryDestinationIds: [],
      },
    })
    if (!registered.ok) throw new Error(`registration failed: ${registered.error.code}`)
    const selection = {
      schemaVersion: 1 as const,
      repositoryId: registered.value.repositoryId,
      subject: { kind: 'workspace_snapshot' as const },
      assessmentMode: 'REPOSITORY' as const,
      assessmentProfileId: 'security/standard' as const,
      target: { kind: 'repository' as const },
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
        startPreflight: {
          effectivePolicyId: PNPM_LOCKFILE_POLICY_ID,
          providerComposition: [{
            providerId: 'dsh-security-assurance',
            analyzerId: PNPM_LOCKFILE_ANALYZER_ID,
            eligibility: 'ELIGIBLE',
          }],
          admissible: true,
        },
      },
    })
    const started = await ctx.securityAssurance.startAssessment(invocation, {
      ...selection,
      contractVersion: 1,
      idempotencyKey: `pnpm-lockfile-assessment-${id}`,
    })
    if (!started.ok) throw new Error(`start failed: ${started.error.code}`)
    await waitUntilSealed(ctx.securityAssurance, invocation, started.value.assessmentId)
    const assessment = await ctx.securityAssurance.getAssessment(invocation, {
      schemaVersion: 1,
      assessmentId: started.value.assessmentId,
    })
    if (!assessment.ok) throw new Error(`query failed: ${assessment.error.code}`)
    const listed = await ctx.securityAssurance.listFindings(invocation, {
      schemaVersion: 1,
      assessmentId: started.value.assessmentId,
      limit: 64,
    })
    if (!listed.ok) throw new Error(`findings failed: ${listed.error.code}`)
    return {
      verdict: assessment.value.verdict,
      coverageStatus: assessment.value.coverage.status,
      findings: listed.value.findings,
    }
  } finally {
    await fiber.dispose()
  }
}

describe('pnpm lockfile integrity Analyzer (sealed chain)', () => {
  it('seals a consistent lockfile as SATISFIED with complete Coverage', async () => {
    const result = await runScenario('safe', CLEAN_LOCKFILE)
    expect(result).toEqual({ verdict: 'SATISFIED', coverageStatus: 'COMPLETE', findings: [] })
  }, 30_000)

  it('seals reproducibility violations as validated blocking Findings', async () => {
    const manifest = MANIFEST.replace('pnpm@11.7.0', 'pnpm@latest')
    const result = await runScenario('unsafe', DRIFTED_LOCKFILE, manifest)
    expect(result.verdict).toBe('FAILED')
    expect(result.coverageStatus).toBe('COMPLETE')
    expect(result.findings).toHaveLength(3)
    expect(result.findings.every(finding => (
      finding.validationState === 'VALIDATED'
      && finding.validationContractId === 'dsh/security/pnpm-lockfile-integrity-validation/v1'
      && finding.policySignificance === 'BLOCKING'
    ))).toBe(true)
  }, 30_000)

  it('seals malformed lockfile YAML as INDETERMINATE without a fabricated Finding', async () => {
    const result = await runScenario('invalid', 'lockfileVersion: [')
    expect(result).toEqual({ verdict: 'INDETERMINATE', coverageStatus: 'GAP', findings: [] })
  }, 30_000)
})
