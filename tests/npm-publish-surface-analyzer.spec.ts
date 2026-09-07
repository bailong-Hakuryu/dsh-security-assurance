import { execFile } from 'node:child_process'
import { mkdir, mkdtemp, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { promisify } from 'node:util'

import { Context } from '@deepseek-ai/cordis'
import { afterEach, describe, expect, it } from 'vitest'

import SecurityAssuranceService, {
  analyzeNpmPublishSurface,
  analyzerContributionV1Schema,
  NPM_PUBLISH_SURFACE_DESCRIPTOR,
  NPM_PUBLISH_SURFACE_EVIDENCE_SCHEMA_ID,
  NPM_PUBLISH_SURFACE_POLICY_ID,
  NPM_PUBLISH_SURFACE_QUALIFICATION,
  NPM_PUBLISH_SURFACE_WEAKNESS_ID,
} from '../src/index.ts'
import type {
  AnalyzerPortfolioEntryV1,
  AssessmentId,
  FindingSummaryV1,
  SecurityInvocation,
} from '../src/index.ts'
import { binaryDigest, structuredDigest } from '../src/internal/canonical.ts'
import { npmPublishSurfaceCoverageIsIndependentlyVerified } from '../src/internal/candidate-validation.ts'
import {
  evaluateDeterministicAssessment,
  prepareAssessmentContract,
} from '../src/internal/deterministic-kernel.ts'
import { SecurityAssuranceTestComposition } from './support/security-assurance-test-composition.ts'
import { referenceHostInvocation } from './support/reference-host.ts'
import { removeTemporaryRoots } from './support/remove-temporary-root.ts'

const run = promisify(execFile)
const temporaryRoots: string[] = []

const CLEAN_MANIFEST = `{
  "name": "publish-surface-fixture",
  "version": "1.0.0",
  "private": false,
  "main": "lib/index.js",
  "types": "lib/index.d.ts",
  "exports": {
    ".": {
      "types": "./lib/index.d.ts",
      "default": "./lib/index.js"
    }
  },
  "bin": { "publish-surface": "./bin/cli.js" },
  "files": ["lib/**/*.js", "lib/**/*.d.ts", "bin/*.js", "README.md"],
  "publishConfig": { "access": "public" }
}
`

afterEach(async () => {
  await removeTemporaryRoots(temporaryRoots)
})

function subjectDigestFixture() {
  return structuredDigest('application/vnd.dsh.security.subject-manifest+json', {
    fixture: 'npm-publish-surface-unit',
  })
}

function textSlice(text: string) {
  return {
    path: 'package.json',
    digest: binaryDigest('application/octet-stream', Buffer.from(text, 'utf8')),
    text,
  }
}

function eligiblePortfolioEntry(): AnalyzerPortfolioEntryV1 {
  const analyzerIdentity = {
    analyzerId: NPM_PUBLISH_SURFACE_DESCRIPTOR.analyzerId,
    analyzerVersion: NPM_PUBLISH_SURFACE_DESCRIPTOR.analyzerVersion,
    descriptorSchemaVersion: NPM_PUBLISH_SURFACE_DESCRIPTOR.descriptorSchemaVersion,
    buildDigest: NPM_PUBLISH_SURFACE_DESCRIPTOR.buildDigest,
  }
  const platform = process.platform
  if (platform !== 'win32' && platform !== 'linux' && platform !== 'darwin') {
    throw new Error(`unsupported test platform: ${platform}`)
  }
  return {
    descriptor: NPM_PUBLISH_SURFACE_DESCRIPTOR,
    qualification: NPM_PUBLISH_SURFACE_QUALIFICATION,
    eligibility: {
      schemaVersion: 1,
      decision: 'ELIGIBLE',
      reason: null,
      evaluatedAt: '2026-01-01T00:00:00.000Z',
      analyzerIdentity,
      qualificationId: NPM_PUBLISH_SURFACE_QUALIFICATION.qualificationId,
      qualificationDigest: NPM_PUBLISH_SURFACE_QUALIFICATION.qualificationDigest,
      policyId: NPM_PUBLISH_SURFACE_POLICY_ID,
      assessmentMode: 'REPOSITORY',
      platform,
    },
  }
}

describe('npm publish surface Analyzer (unit)', () => {
  it('accepts a public manifest whose declared entry points fit its files surface', () => {
    const contribution = analyzeNpmPublishSurface({
      subjectDigest: subjectDigestFixture(),
      slices: [textSlice(CLEAN_MANIFEST)],
    })
    expect(contribution).toMatchObject({
      completionDisposition: 'COMPLETE',
      coverageClaims: [{
        obligationId: 'application-security-analysis',
        completion: 'COMPLETE',
        evidenceArtifactId: 'npm-publish-surface-analysis',
      }],
      candidateFindings: [],
      diagnostics: [],
      evidence: [{
        schemaId: NPM_PUBLISH_SURFACE_EVIDENCE_SCHEMA_ID,
        value: {
          manifest: {
            parseStatus: 'VALID',
            privateState: 'PUBLIC',
            publishAccess: 'PUBLIC',
            filesPatternCount: 4,
            referencedTargetCount: 5,
          },
          entries: [],
        },
      }],
    })
  })

  it('treats a Subject without package metadata as not applicable', () => {
    const contribution = analyzeNpmPublishSurface({
      subjectDigest: subjectDigestFixture(),
      slices: [],
    })
    expect(contribution).toMatchObject({
      completionDisposition: 'COMPLETE',
      coverageClaims: [{ obligationId: 'application-security-analysis' }],
      candidateFindings: [],
      diagnostics: [],
      evidence: [{ value: { manifest: null, entries: [] } }],
    })
  })

  it('finds private, non-public, missing-file, and unbound-entry declarations', () => {
    const manifest = CLEAN_MANIFEST
      .replace('"private": false', '"private": true')
      .replace('"access": "public"', '"access": "restricted"')
      .replace('"lib/**/*.d.ts", ', '')
      .replace('"./lib/index.js"', '"./dist/index.js"')
      .replace('"./lib/index.d.ts"', '"./dist/index.d.ts"')
      .replace('"./bin/cli.js"', '"./dist/cli.js"')
    const contribution = analyzeNpmPublishSurface({
      subjectDigest: subjectDigestFixture(),
      slices: [textSlice(manifest)],
    })
    expect(contribution.completionDisposition).toBe('COMPLETE')
    expect(contribution.candidateFindings).toHaveLength(6)
    expect(contribution.candidateFindings.map(candidate => candidate.weaknessClassification.primary))
      .toEqual(Array.from({ length: 6 }, () => NPM_PUBLISH_SURFACE_WEAKNESS_ID))
    expect(contribution.evidence[0]?.value).toMatchObject({
      manifest: {
        privateState: 'PRIVATE',
        publishAccess: 'RESTRICTED',
        filesPatternCount: 3,
        referencedTargetCount: 5,
      },
      entries: [
        { ruleId: 'NPM_PACKAGE_PRIVATE' },
        { ruleId: 'NPM_PUBLISH_ACCESS_NOT_PUBLIC' },
        { ruleId: 'NPM_TYPES_NOT_INCLUDED' },
        { ruleId: 'NPM_EXPORT_TARGET_NOT_INCLUDED' },
        { ruleId: 'NPM_EXPORT_TARGET_NOT_INCLUDED' },
        { ruleId: 'NPM_BIN_TARGET_NOT_INCLUDED' },
      ],
    })
  })

  it('requires explicit public access and strict SemVer syntax', () => {
    const missingAccess = analyzeNpmPublishSurface({
      subjectDigest: subjectDigestFixture(),
      slices: [textSlice(CLEAN_MANIFEST.replace('{ "access": "public" }', '{}'))],
    })
    expect(missingAccess.candidateFindings).toHaveLength(1)
    expect(missingAccess.evidence[0]?.value).toMatchObject({
      manifest: { publishAccess: 'DEFAULT' },
      entries: [{ ruleId: 'NPM_PUBLISH_ACCESS_NOT_PUBLIC' }],
    })

    for (const version of ['01.2.3', '1.2.3-..']) {
      const invalidVersion = analyzeNpmPublishSurface({
        subjectDigest: subjectDigestFixture(),
        slices: [textSlice(CLEAN_MANIFEST.replace('1.0.0', version))],
      })
      expect(invalidVersion.candidateFindings).toHaveLength(1)
      expect(invalidVersion.evidence[0]?.value).toMatchObject({
        entries: [{ ruleId: 'NPM_PACKAGE_VERSION_MISSING' }],
      })
    }
  })

  it('fails closed on malformed JSON, duplicate keys, invalid targets, and broad files patterns', () => {
    const duplicate = analyzeNpmPublishSurface({
      subjectDigest: subjectDigestFixture(),
      slices: [textSlice('{"name":"one","name":"two"}')],
    })
    expect(duplicate.completionDisposition).toBe('INCOMPLETE')
    expect(duplicate.coverageClaims).toEqual([])
    expect(duplicate.diagnostics).toContain('NPM_PACKAGE_MANIFEST_INVALID_JSON')

    const invalidTarget = analyzeNpmPublishSurface({
      subjectDigest: subjectDigestFixture(),
      slices: [textSlice(CLEAN_MANIFEST.replace('./lib/index.js', '../secret.js'))],
    })
    expect(invalidTarget.completionDisposition).toBe('INCOMPLETE')
    expect(invalidTarget.diagnostics).toContain('NPM_PUBLISH_SURFACE_INVALID_SHAPE')

    const broadFiles = analyzeNpmPublishSurface({
      subjectDigest: subjectDigestFixture(),
      slices: [textSlice(CLEAN_MANIFEST.replace('"files": ["lib/**/*.js", "lib/**/*.d.ts", "bin/*.js", "README.md"]', '"files": ["*"]'))],
    })
    expect(broadFiles.candidateFindings).toHaveLength(1)
    expect(broadFiles.evidence[0]?.value).toMatchObject({
      entries: [{ ruleId: 'NPM_PUBLISH_FILES_BROAD' }],
    })
  })

  it('independently re-derives Coverage and rejects a tampered Contribution', () => {
    const subjectDigest = subjectDigestFixture()
    const slice = textSlice(CLEAN_MANIFEST)
    const contribution = analyzeNpmPublishSurface({ subjectDigest, slices: [slice] })
    const portfolioEntry = eligiblePortfolioEntry()
    const input = {
      portfolioEntry,
      contribution,
      subjectSlices: [slice],
      policyId: NPM_PUBLISH_SURFACE_POLICY_ID,
      policyDigest: structuredDigest('application/vnd.dsh.security.policy+json', {
        policyId: NPM_PUBLISH_SURFACE_POLICY_ID,
      }),
    }
    expect(npmPublishSurfaceCoverageIsIndependentlyVerified(input)).toBe(true)
    const maliciousClaim = 'ATTACKER_CONTROLLED_PUBLISH_SURFACE_TEXT'
    const tampered = analyzerContributionV1Schema.parse({
      ...contribution,
      diagnostics: ['ATTACKER_DIAGNOSTIC'],
    })
    expect(npmPublishSurfaceCoverageIsIndependentlyVerified({ ...input, contribution: tampered })).toBe(false)

    const contract = prepareAssessmentContract({
      policyId: NPM_PUBLISH_SURFACE_POLICY_ID,
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
    expect(JSON.stringify(outcome)).not.toContain(maliciousClaim)
  })
})

async function repositoryFixture(manifest: string): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), 'dsh-security-publish-surface-'))
  temporaryRoots.push(root)
  await run('git', ['init', '-b', 'main'], { cwd: root })
  await run('git', ['config', 'user.email', 'fixture@example.invalid'], { cwd: root })
  await run('git', ['config', 'user.name', 'Fixture'], { cwd: root })
  await mkdir(join(root, 'lib'), { recursive: true })
  await mkdir(join(root, 'bin'), { recursive: true })
  await writeFile(join(root, 'package.json'), manifest)
  await writeFile(join(root, 'lib', 'index.js'), 'export const safe = true\n')
  await writeFile(join(root, 'lib', 'index.d.ts'), 'export declare const safe: boolean\n')
  await writeFile(join(root, 'bin', 'cli.js'), '#!/usr/bin/env node\n')
  await writeFile(join(root, 'README.md'), '# fixture\n')
  await run('git', ['add', '.'], { cwd: root })
  await run('git', ['commit', '-m', 'publish surface fixture'], { cwd: root })
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

async function runScenario(id: string, manifest: string): Promise<{
  readonly verdict: string | null
  readonly coverageStatus: string
  readonly findings: readonly FindingSummaryV1[]
}> {
  const repository = await repositoryFixture(manifest)
  const dshHome = await mkdtemp(join(tmpdir(), 'dsh-security-publish-surface-home-'))
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
      idempotencyKey: `publish-surface-register-${id}`,
      root: repository,
      displayName: 'Publish surface fixture',
      bindings: {
        policyId: NPM_PUBLISH_SURFACE_POLICY_ID,
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
    const started = await ctx.securityAssurance.startAssessment(invocation, {
      ...selection,
      contractVersion: 1,
      idempotencyKey: `publish-surface-assessment-${id}`,
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

describe('npm publish surface Analyzer (sealed chain)', () => {
  it('seals a safe manifest as SATISFIED with complete Coverage', async () => {
    const result = await runScenario('safe', CLEAN_MANIFEST)
    expect(result).toEqual({ verdict: 'SATISFIED', coverageStatus: 'COMPLETE', findings: [] })
  }, 30_000)

  it('seals an unsafe manifest as FAILED with validated blocking Findings', async () => {
    const unsafe = CLEAN_MANIFEST
      .replace('"private": false', '"private": true')
      .replace('"access": "public"', '"access": "restricted"')
    const result = await runScenario('unsafe', unsafe)
    expect(result.verdict).toBe('FAILED')
    expect(result.coverageStatus).toBe('COMPLETE')
    expect(result.findings.length).toBeGreaterThanOrEqual(2)
    expect(result.findings.every(finding => (
      finding.validationState === 'VALIDATED'
      && finding.validationContractId === 'dsh/security/npm-publish-surface-validation/v1'
      && finding.policySignificance === 'BLOCKING'
    ))).toBe(true)
  }, 30_000)

  it('seals malformed package metadata as INDETERMINATE without a fabricated Finding', async () => {
    const result = await runScenario('invalid', '{"name":"broken",')
    expect(result).toEqual({ verdict: 'INDETERMINATE', coverageStatus: 'GAP', findings: [] })
  }, 30_000)
})
