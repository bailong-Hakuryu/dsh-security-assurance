import { SecurityAssuranceTestComposition } from './support/security-assurance-test-composition.ts'
import { removeTemporaryRoots } from './support/remove-temporary-root.ts'
import { execFile } from 'node:child_process'
import { mkdtemp, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { promisify } from 'node:util'
import { Context } from '@deepseek-ai/cordis'
import { afterEach, describe, expect, it } from 'vitest'
import SecurityAssuranceService, {
  analyzeNpmAuditReport,
  analyzerContributionV1Schema,
  NPM_AUDIT_ANALYZER_ID,
  NPM_AUDIT_EVIDENCE_SCHEMA_ID,
  NPM_AUDIT_NORMALIZATION_CONTRACT_ID,
  NPM_AUDIT_POLICY_ID,
  NPM_AUDIT_WEAKNESS_ID,
} from '../src/index.ts'
import type {
  AnalyzerDescriptorV1,
  AnalyzerQualificationRecordV1,
  AssessmentId,
  FindingSummaryV1,
  SecurityInvocation,
} from '../src/index.ts'
import { binaryDigest, structuredDigest } from '../src/internal/canonical.ts'
import { registerAnalyzerQualification } from '../src/internal/analyzer-qualification-registration.ts'
import { referenceHostInvocation } from './support/reference-host.ts'

const run = promisify(execFile)
const temporaryRoots: string[] = []

afterEach(async () => {
  await removeTemporaryRoots(temporaryRoots)
})

const VULNERABLE_REPORT = `${JSON.stringify({
  auditReportVersion: 2,
  vulnerabilities: {
    lodash: {
      name: 'lodash',
      severity: 'high',
      isDirect: true,
      via: [{
        source: 1096809,
        name: 'lodash',
        dependency: 'lodash',
        title: 'Prototype Pollution in lodash',
        url: 'https://github.com/advisories/GHSA-35jh-r3h4-6jhm',
        severity: 'high',
        range: '<4.17.21',
      }],
      effects: [],
      range: '<4.17.21',
      nodes: ['node_modules/lodash'],
      fixAvailable: true,
    },
  },
  metadata: {
    vulnerabilities: { info: 0, low: 0, moderate: 0, high: 1, critical: 0, total: 1 },
    dependencies: { prod: 1, dev: 0, optional: 0, peer: 0, peerOptional: 0, total: 1 },
  },
}, null, 2)}\n`

const CLEAN_REPORT = `${JSON.stringify({
  auditReportVersion: 2,
  vulnerabilities: {},
  metadata: {
    vulnerabilities: { info: 0, low: 0, moderate: 0, high: 0, critical: 0, total: 0 },
    dependencies: { prod: 1, dev: 0, optional: 0, peer: 0, peerOptional: 0, total: 1 },
  },
}, null, 2)}\n`

const MODERATE_REPORT = `${JSON.stringify({
  auditReportVersion: 2,
  vulnerabilities: {
    minimist: {
      name: 'minimist',
      severity: 'moderate',
      isDirect: false,
      via: [{
        source: 1096466,
        name: 'minimist',
        dependency: 'minimist',
        title: 'Prototype Pollution in minimist',
        url: 'https://github.com/advisories/GHSA-vh95-rmgr-6w4m',
        severity: 'moderate',
        range: '<1.2.6',
      }],
      effects: [],
      range: '<1.2.6',
      nodes: ['node_modules/minimist'],
      fixAvailable: true,
    },
  },
}, null, 2)}\n`

function subjectDigestFixture() {
  return structuredDigest('application/vnd.dsh.security.subject-manifest+json', {
    fixture: 'npm-audit-unit',
  })
}

function reportSlice(text: string, path = 'npm-audit.json') {
  return {
    path,
    digest: binaryDigest('application/octet-stream', Buffer.from(text, 'utf8')),
    text,
  }
}

describe('npm audit Normalization Contract (unit)', () => {
  it('normalizes one report vulnerability into one anchored Candidate with Coverage and Evidence', () => {
    const contribution = analyzeNpmAuditReport({
      subjectDigest: subjectDigestFixture(),
      slices: [reportSlice(VULNERABLE_REPORT)],
    })
    expect(contribution.completionDisposition).toBe('COMPLETE')
    expect(contribution.coverageClaims).toHaveLength(1)
    expect(contribution.coverageClaims[0]).toMatchObject({
      obligationId: 'application-security-analysis',
      evidenceArtifactId: 'npm-audit-report',
    })
    expect(contribution.candidateFindings).toHaveLength(1)
    const candidate = contribution.candidateFindings[0]!
    expect(candidate.candidateId).toMatch(/^candidate-[0-9a-f]{64}$/)
    expect(candidate.weaknessClassification).toEqual({
      schemaVersion: 1,
      primary: NPM_AUDIT_WEAKNESS_ID,
      secondary: ['cwe/1395'],
    })
    expect(candidate.affectedControlId).toBe('dsh/npm-audit/dependency-integrity')
    expect(candidate.sourceAnchor.path).toBe('npm-audit.json')
    expect(candidate.sourceAnchor.locator).toEqual({
      kind: 'JSON_POINTER',
      value: '/vulnerabilities/lodash',
    })
    expect(candidate.securityClaim).toContain('lodash')
    expect(candidate.securityClaim).toContain('Prototype Pollution')
    expect(candidate.evidenceArtifactIds).toEqual(['npm-audit-report'])
    const report = contribution.evidence[0]!
    expect(report.schemaId).toBe(NPM_AUDIT_EVIDENCE_SCHEMA_ID)
    expect(report.value).toMatchObject({
      contractId: NPM_AUDIT_NORMALIZATION_CONTRACT_ID,
      reportPath: 'npm-audit.json',
      auditReportVersion: 2,
      totals: { CRITICAL: 0, HIGH: 1, MEDIUM: 0, LOW: 0, INFORMATIONAL: 0 },
    })
    expect(contribution.diagnostics).toEqual([])
  })

  it('escapes scoped package names in JSON Pointer anchors', () => {
    const scopedReport = JSON.stringify({
      auditReportVersion: 2,
      vulnerabilities: {
        '@scope/pkg': {
          name: '@scope/pkg',
          severity: 'critical',
          via: [{ title: 'Sandbox escape', url: 'https://example.invalid/advisory' }],
          range: '<1.0.0',
        },
      },
    })
    const contribution = analyzeNpmAuditReport({
      subjectDigest: subjectDigestFixture(),
      slices: [reportSlice(scopedReport)],
    })
    expect(contribution.candidateFindings).toHaveLength(1)
    expect(contribution.candidateFindings[0]!.sourceAnchor.locator.value).toBe(
      '/vulnerabilities/@scope~1pkg',
    )
  })

  it('claims Coverage with zero Candidates for a clean report', () => {
    const contribution = analyzeNpmAuditReport({
      subjectDigest: subjectDigestFixture(),
      slices: [reportSlice(CLEAN_REPORT)],
    })
    expect(contribution.completionDisposition).toBe('COMPLETE')
    expect(contribution.candidateFindings).toEqual([])
    expect(contribution.coverageClaims).toHaveLength(1)
    expect(contribution.evidence[0]!.value).toMatchObject({
      totals: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFORMATIONAL: 0 },
    })
  })

  it('fails closed with INCOMPLETE on malformed report JSON', () => {
    const contribution = analyzeNpmAuditReport({
      subjectDigest: subjectDigestFixture(),
      slices: [reportSlice('{not json')],
    })
    expect(contribution.completionDisposition).toBe('INCOMPLETE')
    expect(contribution.coverageClaims).toEqual([])
    expect(contribution.diagnostics).toContain('NPM_AUDIT_REPORT_INVALID_JSON')
  })

  it('fails closed with INCOMPLETE on an unsupported report shape', () => {
    const contribution = analyzeNpmAuditReport({
      subjectDigest: subjectDigestFixture(),
      slices: [reportSlice(JSON.stringify({ vulnerabilities: ['not-a-record'] }))],
    })
    expect(contribution.completionDisposition).toBe('INCOMPLETE')
    expect(contribution.coverageClaims).toEqual([])
    expect(contribution.diagnostics).toContain('NPM_AUDIT_REPORT_INVALID_SHAPE')
  })

  it('returns UNSUPPORTED when no report slice is frozen into the Subject', () => {
    const contribution = analyzeNpmAuditReport({
      subjectDigest: subjectDigestFixture(),
      slices: [],
    })
    expect(contribution.completionDisposition).toBe('UNSUPPORTED')
    expect(contribution.coverageClaims).toEqual([])
    expect(contribution.diagnostics).toContain('NPM_AUDIT_REPORT_MISSING')
  })
})

async function npmAuditRepositoryFixture(report: string | null): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), 'dsh-security-npm-audit-'))
  temporaryRoots.push(root)
  await run('git', ['init', '-b', 'main'], { cwd: root })
  await run('git', ['config', 'user.email', 'fixture@example.invalid'], { cwd: root })
  await run('git', ['config', 'user.name', 'Fixture'], { cwd: root })
  await writeFile(join(root, 'package.json'), `${JSON.stringify({
    name: 'npm-audit-fixture',
    version: '1.0.0',
  }, null, 2)}\n`, 'utf8')
  if (report !== null) await writeFile(join(root, 'npm-audit.json'), report, 'utf8')
  await run('git', ['add', '.'], { cwd: root })
  await run('git', ['commit', '-m', 'npm audit fixture'], { cwd: root })
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

async function runNpmAuditScenario(
  id: string,
  report: string | null,
  tamper?: 'severity' | 'report-digest' | 'claim' | 'directness' | 'evidence-identity' | 'clean-coverage',
): Promise<{
  readonly verdict: string | null
  readonly coverageStatus: string
  readonly findings: readonly FindingSummaryV1[]
}> {
  const repository = await npmAuditRepositoryFixture(report)
  const dshHome = await mkdtemp(join(tmpdir(), 'dsh-security-npm-audit-home-'))
  temporaryRoots.push(dshHome)
  const ctx = new Context()
  const fiber = await ctx.plugin(SecurityAssuranceTestComposition, { dshHome })
  let disposeTampered = () => {}
  try {
    if (tamper !== undefined) {
      // A lying Analyzer: it anchors at the real report entry but claims a
      // different severity in its Evidence. Independent re-verification
      // against the frozen Subject must refuse to validate it.
      const buildDigest = structuredDigest('application/vnd.fixture.tampered-analyzer+json', {
        id: 'tampered-npm-audit',
      })
      const descriptor: AnalyzerDescriptorV1 = {
        schemaVersion: 1,
        analyzerId: 'fixture/tampered-npm-audit',
        analyzerVersion: '1.0.0',
        descriptorSchemaVersion: 1,
        buildDigest,
        executionClass: 'PURE',
        supportedAssessmentModes: ['REPOSITORY'],
        supportedPolicyIds: [NPM_AUDIT_POLICY_ID],
        coverageObligationIds: ['application-security-analysis'],
        evidenceSchemaIds: [NPM_AUDIT_EVIDENCE_SCHEMA_ID],
        egress: 'NONE',
      }
      const qualificationCore = {
        schemaVersion: 1 as const,
        qualificationId: 'fixture/qualification/tampered-npm-audit/v1',
        analyzerIdentity: {
          analyzerId: descriptor.analyzerId,
          analyzerVersion: descriptor.analyzerVersion,
          descriptorSchemaVersion: descriptor.descriptorSchemaVersion,
          buildDigest: descriptor.buildDigest,
        },
        issuerId: 'fixture/qualification-authority',
        level: 'HOST_ATTESTED' as const,
        supportedEcosystemIds: ['node-npm-audit-report'],
        supportedAssessmentModes: ['REPOSITORY'] as const,
        supportedPolicyIds: [NPM_AUDIT_POLICY_ID],
        coverageObligationIds: ['application-security-analysis'],
        evidenceSchemaIds: [NPM_AUDIT_EVIDENCE_SCHEMA_ID],
        executionClass: 'PURE' as const,
        executionBackendId: 'dsh/security-assurance/in-process-pure-v1',
        providerIds: ['dsh-security-assurance'],
        egress: 'NONE' as const,
        platforms: ['win32', 'linux', 'darwin'] as const,
        issuedAt: '2026-01-01T00:00:00.000Z',
        expiresAt: '2099-01-01T00:00:00.000Z',
        evidenceDigests: [buildDigest],
        limitations: ['Tampered fixture.'],
      }
      const qualification: AnalyzerQualificationRecordV1 = {
        ...qualificationCore,
        qualificationDigest: structuredDigest(
          'application/vnd.dsh.security.analyzer-qualification+json',
          qualificationCore,
        ),
      }
      disposeTampered = ctx.securityAssurance.registerAnalyzer(descriptor, normalized => ({
        descriptor: normalized,
        async analyze(input) {
          const slice = input.subject.textSlices.find(item => (
            item.path.split('/').at(-1) === 'npm-audit.json'
          ))
          if (tamper === 'clean-coverage') {
            const tamperedArtifactId = 'tampered-npm-audit-report'
            const fabricatedReportDigest = structuredDigest(
              'application/vnd.fixture.fabricated-npm-audit-report+json',
              { vulnerabilities: {} },
            )
            return analyzerContributionV1Schema.parse({
              schemaVersion: 1,
              analyzerIdentity: {
                analyzerId: normalized.analyzerId,
                analyzerVersion: normalized.analyzerVersion,
                descriptorSchemaVersion: normalized.descriptorSchemaVersion,
                buildDigest: normalized.buildDigest,
              },
              subjectDigest: input.subject.digest,
              completionDisposition: 'COMPLETE',
              coverageClaims: [{
                obligationId: 'application-security-analysis',
                completion: 'COMPLETE',
                evidenceArtifactId: tamperedArtifactId,
              }],
              candidateFindings: [],
              evidence: [{
                artifactId: tamperedArtifactId,
                schemaId: NPM_AUDIT_EVIDENCE_SCHEMA_ID,
                mediaType: 'application/vnd.dsh.security.npm-audit-report-evidence+json',
                value: {
                  schemaVersion: 1,
                  contractId: NPM_AUDIT_NORMALIZATION_CONTRACT_ID,
                  analyzerIdentity: {
                    analyzerId: NPM_AUDIT_ANALYZER_ID,
                    analyzerVersion: '1.0.0',
                    descriptorSchemaVersion: 1,
                    buildDigest,
                  },
                  subjectDigest: input.subject.digest,
                  reportPath: 'npm-audit.json',
                  reportDigest: fabricatedReportDigest,
                  auditReportVersion: 2,
                  totals: {
                    CRITICAL: 0,
                    HIGH: 0,
                    MEDIUM: 0,
                    LOW: 0,
                    INFORMATIONAL: 0,
                  },
                  entries: [],
                },
              }],
              diagnostics: [],
              resourceUse: { filesRead: 0, bytesRead: 0 },
            })
          }
          if (slice === undefined) throw new Error('fixture report slice missing')
          const sourceAnchor = {
            path: slice.path,
            fileDigest: slice.digest,
            locator: { kind: 'JSON_POINTER' as const, value: '/vulnerabilities/lodash' },
          }
          const candidateId = `candidate-${'f'.repeat(64)}`
          const tamperedArtifactId = 'tampered-npm-audit-report'
          const claimedSeverity = tamper === 'severity' ? 'CRITICAL' : 'HIGH'
          const securityClaim = tamper === 'claim'
            ? "Dependency 'lodash' is remotely exploitable without authentication."
            : `Dependency 'lodash' has a known ${claimedSeverity.toLowerCase()}-severity vulnerability reported by npm audit: Prototype Pollution in lodash (https://github.com/advisories/GHSA-35jh-r3h4-6jhm).`
          const reportDigest = tamper === 'report-digest'
            ? structuredDigest('application/vnd.fixture.wrong-report+json', { wrong: true })
            : slice.digest
          return analyzerContributionV1Schema.parse({
            schemaVersion: 1,
            analyzerIdentity: {
              analyzerId: normalized.analyzerId,
              analyzerVersion: normalized.analyzerVersion,
              descriptorSchemaVersion: normalized.descriptorSchemaVersion,
              buildDigest: normalized.buildDigest,
            },
            subjectDigest: input.subject.digest,
            completionDisposition: 'COMPLETE' as const,
            coverageClaims: [],
            candidateFindings: [{
              schemaVersion: 1 as const,
              candidateId,
              weaknessClassification: {
                schemaVersion: 1 as const,
                primary: NPM_AUDIT_WEAKNESS_ID,
                secondary: ['cwe/1395'],
              },
              affectedControlId: 'dsh/npm-audit/dependency-integrity',
              securityClaim,
              sourceAnchor,
              evidenceArtifactIds: [tamperedArtifactId],
            }],
            evidence: [{
              artifactId: tamperedArtifactId,
              schemaId: NPM_AUDIT_EVIDENCE_SCHEMA_ID,
              mediaType: 'application/vnd.dsh.security.npm-audit-report-evidence+json',
              value: {
                schemaVersion: 1,
                contractId: NPM_AUDIT_NORMALIZATION_CONTRACT_ID,
                analyzerIdentity: {
                  analyzerId: NPM_AUDIT_ANALYZER_ID,
                  analyzerVersion: '1.0.0',
                  descriptorSchemaVersion: 1,
                  buildDigest,
                },
                subjectDigest: input.subject.digest,
                reportPath: slice.path,
                reportDigest,
                auditReportVersion: 2,
                totals: {
                  CRITICAL: claimedSeverity === 'CRITICAL' ? 1 : 0,
                  HIGH: claimedSeverity === 'HIGH' ? 1 : 0,
                  MEDIUM: 0,
                  LOW: 0,
                  INFORMATIONAL: 0,
                },
                entries: [{
                  candidateId,
                  name: 'lodash',
                  severity: claimedSeverity,
                  title: 'Prototype Pollution in lodash',
                  url: 'https://github.com/advisories/GHSA-35jh-r3h4-6jhm',
                  range: '<4.17.21',
                  fixAvailable: true,
                  isDirect: tamper === 'directness' ? false : true,
                  sourceAnchor,
                }],
              },
            }],
            diagnostics: [],
            resourceUse: { filesRead: 1, bytesRead: 1 },
          })
        },
        async dispose() {},
      }))
      registerAnalyzerQualification(ctx.securityAssurance, qualification)
    }
    const invocation = referenceHostInvocation(ctx.securityAssurance)
    const platform = process.platform
    if (platform !== 'win32' && platform !== 'linux' && platform !== 'darwin') {
      throw new Error(`unsupported test platform: ${platform}`)
    }
    const registered = await ctx.securityAssurance.registerRepository(invocation, {
      schemaVersion: 1,
      contractVersion: 1,
      idempotencyKey: `npm-audit-register-${id}`,
      root: repository,
      displayName: 'npm audit fixture',
      bindings: {
        policyId: NPM_AUDIT_POLICY_ID,
        assessmentProfileId: 'security/standard',
        evidenceProtectionId: 'evidence/local-protected',
        dataEgressPolicyId: 'egress/deny-by-default',
        platform,
        deliveryDestinationIds: [],
      },
    })
    if (!registered.ok) throw new Error(`registration failed: ${registered.error.code}`)
    const started = await ctx.securityAssurance.startAssessment(invocation, {
      schemaVersion: 1,
      contractVersion: 1,
      idempotencyKey: `npm-audit-assessment-${id}`,
      repositoryId: registered.value.repositoryId,
      subject: { kind: 'workspace_snapshot' },
      assessmentMode: 'REPOSITORY',
      assessmentProfileId: 'security/standard',
      target: { kind: 'repository' },
      requestedStrongerControlIds: [],
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
    disposeTampered()
    await fiber.dispose()
  }
}

describe('npm audit Analyzer (sealed chain)', () => {
  it('seals a vulnerable report as FAILED with a validated blocking Finding', async () => {
    const { verdict, coverageStatus, findings } = await runNpmAuditScenario(
      'vulnerable',
      VULNERABLE_REPORT,
    )
    expect(verdict).toBe('FAILED')
    expect(coverageStatus).toBe('COMPLETE')
    expect(findings).toHaveLength(1)
    expect(findings[0]).toMatchObject({
      weaknessClassification: { primary: NPM_AUDIT_WEAKNESS_ID },
      validationState: 'VALIDATED',
      validationContractId: 'dsh/security/npm-audit-validation/v1',
      technicalSeverity: 'HIGH',
      policySignificance: 'BLOCKING',
    })
  }, 30_000)

  it('normalizes npm moderate severity before independent validation', async () => {
    const { verdict, findings } = await runNpmAuditScenario('moderate', MODERATE_REPORT)
    expect(verdict).toBe('FAILED')
    expect(findings).toHaveLength(1)
    expect(findings[0]).toMatchObject({
      validationState: 'VALIDATED',
      validationContractId: 'dsh/security/npm-audit-validation/v1',
      technicalSeverity: 'MEDIUM',
      policySignificance: 'BLOCKING',
    })
  }, 30_000)

  it('seals a clean report as SATISFIED with complete Coverage', async () => {
    const { verdict, coverageStatus, findings } = await runNpmAuditScenario('clean', CLEAN_REPORT)
    expect(verdict).toBe('SATISFIED')
    expect(coverageStatus).toBe('COMPLETE')
    expect(findings).toEqual([])
  }, 30_000)

  it('seals a missing report as INDETERMINATE instead of fabricating satisfaction', async () => {
    const { verdict, findings } = await runNpmAuditScenario('missing', null)
    expect(verdict).toBe('INDETERMINATE')
    expect(findings).toEqual([])
  }, 30_000)

  it('rejects fabricated clean Coverage when no npm audit report was frozen', async () => {
    const { verdict, findings } = await runNpmAuditScenario(
      'fabricated-clean-coverage',
      null,
      'clean-coverage',
    )
    expect(verdict).toBe('INDETERMINATE')
    expect(findings).toEqual([])
  }, 30_000)

  it('refuses to validate a fabricated claim against a clean report and seals INDETERMINATE', async () => {
    // The bundled Analyzer sees a clean report (zero Candidates). Only the
    // tampered fixture claims a vulnerability that does not exist in the
    // frozen report — independent re-verification must leave it UNRESOLVED,
    // which blocks complete Coverage and fails closed to INDETERMINATE.
    const { verdict, findings } = await runNpmAuditScenario('tampered', CLEAN_REPORT, 'severity')
    expect(verdict).toBe('INDETERMINATE')
    const tampered = findings.filter(finding => finding.validationContractId !== null
      || finding.validationState !== 'VALIDATED')
    for (const finding of tampered) {
      expect(finding.validationState).not.toBe('VALIDATED')
    }
  }, 30_000)

  it('rejects Evidence whose report digest does not match the frozen slice', async () => {
    const { verdict, findings } = await runNpmAuditScenario(
      'tampered-report-digest',
      VULNERABLE_REPORT,
      'report-digest',
    )
    expect(verdict).toBe('FAILED')
    expect(findings.filter(finding => finding.validationState === 'VALIDATED')).toHaveLength(1)
    expect(findings.find(finding => finding.candidateId === `candidate-${'f'.repeat(64)}`)).toMatchObject({
      validationState: 'UNRESOLVED',
      technicalSeverity: null,
      policySignificance: null,
    })
  }, 30_000)

  it('rejects a Candidate security claim that is not derived from the frozen report', async () => {
    const { findings } = await runNpmAuditScenario('tampered-claim', VULNERABLE_REPORT, 'claim')
    expect(findings.filter(finding => finding.validationState === 'VALIDATED')).toHaveLength(1)
    expect(findings.find(finding => finding.candidateId === `candidate-${'f'.repeat(64)}`)).toMatchObject({
      validationState: 'UNRESOLVED',
      technicalSeverity: null,
      policySignificance: null,
    })
  }, 30_000)

  it('rejects a directness projection that contradicts the frozen report', async () => {
    const { findings } = await runNpmAuditScenario(
      'tampered-directness',
      VULNERABLE_REPORT,
      'directness',
    )
    expect(findings.filter(finding => finding.validationState === 'VALIDATED')).toHaveLength(1)
    expect(findings.find(finding => finding.candidateId === `candidate-${'f'.repeat(64)}`)).toMatchObject({
      validationState: 'UNRESOLVED',
      technicalSeverity: null,
      policySignificance: null,
    })
  }, 30_000)

  it('rejects Evidence whose producer identity does not match its Contribution', async () => {
    const { findings } = await runNpmAuditScenario(
      'tampered-evidence-identity',
      VULNERABLE_REPORT,
      'evidence-identity',
    )
    expect(findings.filter(finding => finding.validationState === 'VALIDATED')).toHaveLength(1)
    expect(findings.find(finding => finding.candidateId === `candidate-${'f'.repeat(64)}`)).toMatchObject({
      validationState: 'UNRESOLVED',
      technicalSeverity: null,
      policySignificance: null,
    })
  }, 30_000)
})
