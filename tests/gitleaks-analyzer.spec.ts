import { execFile } from 'node:child_process'
import { mkdtemp, readFile, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { promisify } from 'node:util'
import { Context } from '@deepseek-ai/cordis'
import { afterEach, describe, expect, it } from 'vitest'
import SecurityAssuranceService, {
  analyzeGitleaksReport,
  analyzerContributionV1Schema,
  GITLEAKS_DESCRIPTOR,
  GITLEAKS_EVIDENCE_SCHEMA_ID,
  GITLEAKS_NORMALIZATION_CONTRACT_ID,
  GITLEAKS_POLICY_ID,
  GITLEAKS_QUALIFICATION,
  GITLEAKS_WEAKNESS_ID,
} from '../src/index.ts'
import type {
  AnalyzerPortfolioEntryV1,
  AssessmentId,
  FindingSummaryV1,
  SecurityInvocation,
} from '../src/index.ts'
import { binaryDigest, structuredDigest } from '../src/internal/canonical.ts'
import { gitleaksCoverageIsIndependentlyVerified } from '../src/internal/candidate-validation.ts'
import {
  evaluateDeterministicAssessment,
  prepareAssessmentContract,
} from '../src/internal/deterministic-kernel.ts'
import { SecurityAssuranceTestComposition } from './support/security-assurance-test-composition.ts'
import { referenceHostInvocation } from './support/reference-host.ts'
import { removeTemporaryRoots } from './support/remove-temporary-root.ts'

const run = promisify(execFile)
const temporaryRoots: string[] = []
const CLEAN_REPORT = '[]\n'
const FIXTURE_SECRET = 'FIXTURE_SECRET_VALUE_NOT_A_REAL_CREDENTIAL'

afterEach(async () => {
  await removeTemporaryRoots(temporaryRoots)
})

async function vulnerableReport(): Promise<string> {
  return readFile(new URL('./fixtures/gitleaks/v8-secret-report.json', import.meta.url), 'utf8')
}

async function redactedEntryFixture(): Promise<unknown> {
  return JSON.parse(await readFile(
    new URL('./fixtures/gitleaks/v8-redacted-entry.json', import.meta.url),
    'utf8',
  ))
}

function subjectDigestFixture() {
  return structuredDigest('application/vnd.dsh.security.subject-manifest+json', {
    fixture: 'gitleaks-unit',
  })
}

function reportSlice(text: string, path = 'gitleaks-report.json') {
  return {
    path,
    digest: binaryDigest('application/octet-stream', Buffer.from(text, 'utf8')),
    text,
  }
}

function eligibleGitleaksPortfolioEntry(): AnalyzerPortfolioEntryV1 {
  const analyzerIdentity = {
    analyzerId: GITLEAKS_DESCRIPTOR.analyzerId,
    analyzerVersion: GITLEAKS_DESCRIPTOR.analyzerVersion,
    descriptorSchemaVersion: GITLEAKS_DESCRIPTOR.descriptorSchemaVersion,
    buildDigest: GITLEAKS_DESCRIPTOR.buildDigest,
  }
  return {
    descriptor: GITLEAKS_DESCRIPTOR,
    qualification: GITLEAKS_QUALIFICATION,
    eligibility: {
      schemaVersion: 1,
      decision: 'ELIGIBLE',
      reason: null,
      evaluatedAt: '2026-01-01T00:00:00.000Z',
      analyzerIdentity,
      qualificationId: GITLEAKS_QUALIFICATION.qualificationId,
      qualificationDigest: GITLEAKS_QUALIFICATION.qualificationDigest,
      policyId: GITLEAKS_POLICY_ID,
      assessmentMode: 'REPOSITORY',
      platform: process.platform === 'win32' ? 'win32' : process.platform === 'darwin' ? 'darwin' : 'linux',
    },
  }
}

describe('Gitleaks Normalization Contract (unit)', () => {
  it('normalizes a v8 report while discarding every sensitive scanner field', async () => {
    const source = await vulnerableReport()
    const contribution = analyzeGitleaksReport({
      subjectDigest: subjectDigestFixture(),
      slices: [reportSlice(source)],
    })
    expect(contribution.completionDisposition).toBe('COMPLETE')
    expect(contribution.coverageClaims).toEqual([{
      obligationId: 'application-security-analysis',
      completion: 'COMPLETE',
      evidenceArtifactId: 'gitleaks-report',
    }])
    expect(contribution.candidateFindings).toHaveLength(1)
    expect(contribution.candidateFindings[0]).toMatchObject({
      weaknessClassification: {
        primary: GITLEAKS_WEAKNESS_ID,
        secondary: ['cwe/798'],
      },
      affectedControlId: 'dsh/gitleaks/no-committed-secrets',
      sourceAnchor: {
        path: 'gitleaks-report.json',
        locator: { kind: 'JSON_POINTER', value: '/0' },
      },
      evidenceArtifactIds: ['gitleaks-report'],
    })
    const evidence = contribution.evidence[0]!
    expect(evidence.schemaId).toBe(GITLEAKS_EVIDENCE_SCHEMA_ID)
    expect(evidence.value).toMatchObject({
      contractId: GITLEAKS_NORMALIZATION_CONTRACT_ID,
      reportPath: 'gitleaks-report.json',
      reportFormat: 'gitleaks-v8-json',
      findingsCount: 1,
      entries: [{
        ...(await redactedEntryFixture() as object),
        sourceAnchor: {
          path: 'gitleaks-report.json',
          locator: { kind: 'JSON_POINTER', value: '/0' },
        },
      }],
    })
    const projected = JSON.stringify(contribution)
    expect(projected).not.toContain(FIXTURE_SECRET)
    expect(projected).not.toContain('fixture_token =')
    expect(projected).not.toContain('fixture-author@example.invalid')
    expect(projected).not.toContain('fixture commit message')
    expect(projected).not.toContain('Fixture Author')
  })

  it('claims complete Coverage with zero Candidates for a clean report', () => {
    const contribution = analyzeGitleaksReport({
      subjectDigest: subjectDigestFixture(),
      slices: [reportSlice(CLEAN_REPORT)],
    })
    expect(contribution.completionDisposition).toBe('COMPLETE')
    expect(contribution.candidateFindings).toEqual([])
    expect(contribution.coverageClaims).toHaveLength(1)
    expect(contribution.evidence[0]?.value).toMatchObject({ findingsCount: 0, entries: [] })
  })

  it('fails closed for malformed, unsupported and missing reports', () => {
    const malformed = analyzeGitleaksReport({
      subjectDigest: subjectDigestFixture(),
      slices: [reportSlice('{not-json')],
    })
    expect(malformed.completionDisposition).toBe('INCOMPLETE')
    expect(malformed.coverageClaims).toEqual([])
    expect(malformed.diagnostics).toContain('GITLEAKS_REPORT_INVALID_JSON')

    const unsupported = analyzeGitleaksReport({
      subjectDigest: subjectDigestFixture(),
      slices: [reportSlice(JSON.stringify({ findings: [] }))],
    })
    expect(unsupported.completionDisposition).toBe('INCOMPLETE')
    expect(unsupported.diagnostics).toContain('GITLEAKS_REPORT_INVALID_SHAPE')

    const missing = analyzeGitleaksReport({
      subjectDigest: subjectDigestFixture(),
      slices: [],
    })
    expect(missing.completionDisposition).toBe('UNSUPPORTED')
    expect(missing.diagnostics).toContain('GITLEAKS_REPORT_MISSING')
  })

  it('independently rejects a report slice that contradicts normalized Evidence', async () => {
    const source = await vulnerableReport()
    const slice = reportSlice(source)
    const contribution = analyzeGitleaksReport({
      subjectDigest: subjectDigestFixture(),
      slices: [slice],
    })
    const portfolioEntry = eligibleGitleaksPortfolioEntry()
    const input = {
      portfolioEntry,
      contribution,
      subjectSlices: [slice],
      policyId: GITLEAKS_POLICY_ID,
      policyDigest: structuredDigest('application/vnd.dsh.security.policy+json', {
        policyId: GITLEAKS_POLICY_ID,
      }),
    }
    expect(gitleaksCoverageIsIndependentlyVerified(input)).toBe(true)
    const contradictorySlice = {
      ...slice,
      text: source.replace('generic-api-key', 'different-rule'),
    }
    expect(gitleaksCoverageIsIndependentlyVerified({
      ...input,
      subjectSlices: [contradictorySlice],
    })).toBe(false)
  })

  it('does not publish attacker-controlled secret material from a rejected Contribution', async () => {
    const source = await vulnerableReport()
    const slice = reportSlice(source)
    const subjectDigest = subjectDigestFixture()
    const contribution = analyzeGitleaksReport({ subjectDigest, slices: [slice] })
    const maliciousSecret = 'ATTACKER_CONTROLLED_SECRET_MUST_NOT_BE_PUBLISHED'
    const tampered = analyzerContributionV1Schema.parse({
      ...contribution,
      candidateFindings: contribution.candidateFindings.map(candidate => ({
        ...candidate,
        securityClaim: maliciousSecret,
      })),
    })
    const portfolioEntry = eligibleGitleaksPortfolioEntry()
    const contract = prepareAssessmentContract({
      policyId: GITLEAKS_POLICY_ID,
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
      [{ portfolioEntry, contribution: tampered, subjectSlices: [slice] }],
    )
    expect(outcome.verdict).toBe('INDETERMINATE')
    expect(JSON.stringify(outcome)).not.toContain(maliciousSecret)
    expect(JSON.stringify(outcome)).not.toContain(FIXTURE_SECRET)
  })
})

async function gitleaksRepositoryFixture(report: string | null): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), 'dsh-security-gitleaks-'))
  temporaryRoots.push(root)
  await run('git', ['init', '-b', 'main'], { cwd: root })
  await run('git', ['config', 'user.email', 'fixture@example.invalid'], { cwd: root })
  await run('git', ['config', 'user.name', 'Fixture'], { cwd: root })
  await writeFile(join(root, 'package.json'), `${JSON.stringify({
    name: 'gitleaks-fixture',
    version: '1.0.0',
  }, null, 2)}\n`, 'utf8')
  if (report !== null) await writeFile(join(root, 'gitleaks-report.json'), report, 'utf8')
  await run('git', ['add', '.'], { cwd: root })
  await run('git', ['commit', '-m', 'gitleaks fixture'], { cwd: root })
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
  throw new Error('Assessment did not reach SEALED')
}

async function runGitleaksScenario(
  id: string,
  report: string | null,
): Promise<{
  readonly verdict: string | null
  readonly coverageStatus: string
  readonly findings: readonly FindingSummaryV1[]
}> {
  const repository = await gitleaksRepositoryFixture(report)
  const dshHome = await mkdtemp(join(tmpdir(), 'dsh-security-gitleaks-home-'))
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
      idempotencyKey: `gitleaks-register-${id}`,
      root: repository,
      displayName: 'Gitleaks fixture',
      bindings: {
        policyId: GITLEAKS_POLICY_ID,
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
          effectivePolicyId: GITLEAKS_POLICY_ID,
          providerComposition: [{
            providerId: 'dsh-security-assurance',
            analyzerId: 'dsh/external-gitleaks',
            eligibility: 'ELIGIBLE',
          }],
          admissible: true,
        },
      },
    })
    const started = await ctx.securityAssurance.startAssessment(invocation, {
      ...selection,
      contractVersion: 1,
      idempotencyKey: `gitleaks-assessment-${id}`,
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

describe('Gitleaks Analyzer (sealed chain)', () => {
  it('seals a report with one secret as FAILED and a validated HIGH blocking Finding', async () => {
    const result = await runGitleaksScenario('secret', await vulnerableReport())
    expect(result.verdict).toBe('FAILED')
    expect(result.coverageStatus).toBe('COMPLETE')
    expect(result.findings).toHaveLength(1)
    expect(result.findings[0]).toMatchObject({
      weaknessClassification: { primary: GITLEAKS_WEAKNESS_ID },
      validationState: 'VALIDATED',
      validationContractId: 'dsh/security/gitleaks-validation/v1',
      technicalSeverity: 'HIGH',
      policySignificance: 'BLOCKING',
    })
    expect(JSON.stringify(result)).not.toContain(FIXTURE_SECRET)
  }, 30_000)

  it('seals a clean report as SATISFIED with complete Coverage', async () => {
    const result = await runGitleaksScenario('clean', CLEAN_REPORT)
    expect(result.verdict).toBe('SATISFIED')
    expect(result.coverageStatus).toBe('COMPLETE')
    expect(result.findings).toEqual([])
  }, 30_000)

  it('seals a missing report as INDETERMINATE', async () => {
    const result = await runGitleaksScenario('missing', null)
    expect(result.verdict).toBe('INDETERMINATE')
    expect(result.coverageStatus).toBe('GAP')
    expect(result.findings).toEqual([])
  }, 30_000)

  it('seals a malformed report as INDETERMINATE', async () => {
    const result = await runGitleaksScenario('malformed', '{not-json')
    expect(result.verdict).toBe('INDETERMINATE')
    expect(result.coverageStatus).toBe('GAP')
    expect(result.findings).toEqual([])
  }, 30_000)
})
