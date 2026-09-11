import { execFile } from 'node:child_process'
import { mkdir, mkdtemp, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { promisify } from 'node:util'

import { Context } from '@deepseek-ai/cordis'
import { afterEach, describe, expect, it } from 'vitest'

import SecurityAssuranceService, {
  analyzeGitHubActionsWorkflows,
  analyzerContributionV1Schema,
  GITHUB_ACTIONS_ANALYZER_ID,
  GITHUB_ACTIONS_DESCRIPTOR,
  GITHUB_ACTIONS_EVIDENCE_SCHEMA_ID,
  GITHUB_ACTIONS_PERMISSION_WEAKNESS_ID,
  GITHUB_ACTIONS_POLICY_ID,
  GITHUB_ACTIONS_QUALIFICATION,
  GITHUB_ACTIONS_REFERENCE_WEAKNESS_ID,
} from '../src/index.ts'
import type {
  AnalyzerPortfolioEntryV1,
  AssessmentId,
  FindingSummaryV1,
  SecurityInvocation,
} from '../src/index.ts'
import { binaryDigest, structuredDigest } from '../src/internal/canonical.ts'
import { githubActionsCoverageIsIndependentlyVerified } from '../src/internal/candidate-validation.ts'
import {
  evaluateDeterministicAssessment,
  prepareAssessmentContract,
} from '../src/internal/deterministic-kernel.ts'
import { SecurityAssuranceTestComposition } from './support/security-assurance-test-composition.ts'
import { referenceHostInvocation } from './support/reference-host.ts'
import { removeTemporaryRoots } from './support/remove-temporary-root.ts'

const run = promisify(execFile)
const temporaryRoots: string[] = []
const PINNED_SHA = 'a'.repeat(40)
const DEEPLY_NESTED_YAML = `${'['.repeat(5_000)}1${']'.repeat(5_000)}`
const CLEAN_WORKFLOW = `name: CI
on: [push]
permissions: read-all
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@${PINNED_SHA}
      - uses: ./.github/actions/setup
      - run: pnpm test
`
const UNSAFE_WORKFLOW = `name: Unsafe CI
on: [push]
permissions: read-all
jobs:
  build:
    permissions:
      contents: write
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: docker://alpine:latest
`

function highCardinalityWorkflow(candidateCount = 32): string {
  const steps = Array.from(
    { length: candidateCount },
    (_, index) => `      - name: Unpinned action ${index + 1}\n        uses: actions/checkout@v4`,
  ).join('\n')
  return `name: High-cardinality CI
on: [push]
permissions: read-all
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
${steps}
`
}

afterEach(async () => {
  await removeTemporaryRoots(temporaryRoots)
})

function subjectDigestFixture() {
  return structuredDigest('application/vnd.dsh.security.subject-manifest+json', {
    fixture: 'github-actions-supply-chain-unit',
  })
}

function workflowSlice(text: string, path = '.github/workflows/ci.yml') {
  return {
    path,
    digest: binaryDigest('application/octet-stream', Buffer.from(text, 'utf8')),
    text,
  }
}

function eligiblePortfolioEntry(): AnalyzerPortfolioEntryV1 {
  const analyzerIdentity = {
    analyzerId: GITHUB_ACTIONS_DESCRIPTOR.analyzerId,
    analyzerVersion: GITHUB_ACTIONS_DESCRIPTOR.analyzerVersion,
    descriptorSchemaVersion: GITHUB_ACTIONS_DESCRIPTOR.descriptorSchemaVersion,
    buildDigest: GITHUB_ACTIONS_DESCRIPTOR.buildDigest,
  }
  const platform = process.platform
  if (platform !== 'win32' && platform !== 'linux' && platform !== 'darwin') {
    throw new Error(`unsupported test platform: ${platform}`)
  }
  return {
    descriptor: GITHUB_ACTIONS_DESCRIPTOR,
    qualification: GITHUB_ACTIONS_QUALIFICATION,
    eligibility: {
      schemaVersion: 1,
      decision: 'ELIGIBLE',
      reason: null,
      evaluatedAt: '2026-01-01T00:00:00.000Z',
      analyzerIdentity,
      qualificationId: GITHUB_ACTIONS_QUALIFICATION.qualificationId,
      qualificationDigest: GITHUB_ACTIONS_QUALIFICATION.qualificationDigest,
      policyId: GITHUB_ACTIONS_POLICY_ID,
      assessmentMode: 'REPOSITORY',
      platform,
    },
  }
}

describe('GitHub Actions supply-chain Analyzer (unit)', () => {
  it('keeps the largest seal-safe Candidate set complete and fails closed above it', () => {
    expect(GITHUB_ACTIONS_DESCRIPTOR.analyzerVersion).toBe('1.0.1')
    expect(GITHUB_ACTIONS_QUALIFICATION.qualificationId).toBe(
      'dsh/qualification/builtin-github-actions-supply-chain/v2',
    )

    const atLimit = analyzeGitHubActionsWorkflows({
      subjectDigest: subjectDigestFixture(),
      slices: [workflowSlice(highCardinalityWorkflow(29))],
    })
    expect(atLimit.completionDisposition).toBe('COMPLETE')
    expect(atLimit.coverageClaims).toHaveLength(1)
    expect(atLimit.candidateFindings).toHaveLength(29)
    expect(atLimit.diagnostics).not.toContain('GITHUB_ACTIONS_CANDIDATE_LIMIT')

    const aboveLimit = analyzeGitHubActionsWorkflows({
      subjectDigest: subjectDigestFixture(),
      slices: [workflowSlice(highCardinalityWorkflow(30))],
    })
    expect(aboveLimit.completionDisposition).toBe('INCOMPLETE')
    expect(aboveLimit.coverageClaims).toEqual([])
    expect(aboveLimit.candidateFindings).toHaveLength(29)
    expect(aboveLimit.diagnostics).toContain('GITHUB_ACTIONS_CANDIDATE_LIMIT')
  })

  it('accepts explicit read-only permissions, full commit pins and local actions', () => {
    const contribution = analyzeGitHubActionsWorkflows({
      subjectDigest: subjectDigestFixture(),
      slices: [workflowSlice(CLEAN_WORKFLOW)],
    })
    expect(contribution).toMatchObject({
      completionDisposition: 'COMPLETE',
      coverageClaims: [{
        obligationId: 'application-security-analysis',
        completion: 'COMPLETE',
        evidenceArtifactId: 'github-actions-supply-chain-analysis',
      }],
      candidateFindings: [],
      diagnostics: [],
    })
    expect(contribution.evidence[0]).toMatchObject({
      schemaId: GITHUB_ACTIONS_EVIDENCE_SCHEMA_ID,
      value: {
        workflowFiles: [{
          path: '.github/workflows/ci.yml',
          parseStatus: 'PARSED',
          candidateIds: [],
        }],
        entries: [],
      },
    })
  })

  it('accepts digest-pinned container actions and SHA-pinned reusable workflows', () => {
    const contribution = analyzeGitHubActionsWorkflows({
      subjectDigest: subjectDigestFixture(),
      slices: [workflowSlice(`name: Immutable dependencies
on: workflow_dispatch
permissions: {}
jobs:
  reusable:
    uses: example/automation/.github/workflows/reuse.yml@${PINNED_SHA}
  container:
    runs-on: ubuntu-latest
    steps:
      - uses: docker://ghcr.io/example/tool@sha256:${'b'.repeat(64)}
`)],
    })
    expect(contribution).toMatchObject({
      completionDisposition: 'COMPLETE',
      candidateFindings: [],
      diagnostics: [],
    })
  })

  it('proves complete coverage when the selected Subject contains no workflow files', () => {
    const contribution = analyzeGitHubActionsWorkflows({
      subjectDigest: subjectDigestFixture(),
      slices: [],
    })
    expect(contribution).toMatchObject({
      completionDisposition: 'COMPLETE',
      coverageClaims: [{
        obligationId: 'application-security-analysis',
        completion: 'COMPLETE',
        evidenceArtifactId: 'github-actions-supply-chain-analysis',
      }],
      candidateFindings: [],
      diagnostics: [],
      evidence: [{ value: { workflowFiles: [], entries: [] } }],
    })
  })

  it('finds write authority, mutable action tags and unpinned container images', () => {
    const contribution = analyzeGitHubActionsWorkflows({
      subjectDigest: subjectDigestFixture(),
      slices: [workflowSlice(UNSAFE_WORKFLOW)],
    })
    expect(contribution.completionDisposition).toBe('COMPLETE')
    expect(contribution.candidateFindings).toHaveLength(3)
    expect(contribution.candidateFindings.map(candidate => ({
      weakness: candidate.weaknessClassification.primary,
      locator: candidate.sourceAnchor.locator.value,
    }))).toEqual([
      {
        weakness: GITHUB_ACTIONS_PERMISSION_WEAKNESS_ID,
        locator: '/jobs/build/permissions',
      },
      {
        weakness: GITHUB_ACTIONS_REFERENCE_WEAKNESS_ID,
        locator: '/jobs/build/steps/0/uses',
      },
      {
        weakness: GITHUB_ACTIONS_REFERENCE_WEAKNESS_ID,
        locator: '/jobs/build/steps/1/uses',
      },
    ])
  })

  it('requires an explicit workflow permission boundary', () => {
    const contribution = analyzeGitHubActionsWorkflows({
      subjectDigest: subjectDigestFixture(),
      slices: [workflowSlice(`name: CI
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: echo safe
`)],
    })
    expect(contribution.candidateFindings).toHaveLength(1)
    expect(contribution.evidence[0]?.value).toMatchObject({
      entries: [{ ruleId: 'WORKFLOW_PERMISSIONS_MISSING', severity: 'MEDIUM' }],
    })
  })

  it('fails closed on duplicate keys, aliases and malformed workflow structure', () => {
    const duplicate = analyzeGitHubActionsWorkflows({
      subjectDigest: subjectDigestFixture(),
      slices: [workflowSlice('permissions: read-all\npermissions: {}\njobs: {}\n')],
    })
    expect(duplicate.completionDisposition).toBe('INCOMPLETE')
    expect(duplicate.coverageClaims).toEqual([])
    expect(duplicate.diagnostics).toContain('GITHUB_ACTIONS_WORKFLOW_INVALID_YAML')

    const alias = analyzeGitHubActionsWorkflows({
      subjectDigest: subjectDigestFixture(),
      slices: [workflowSlice('permissions: &p read-all\njobs:\n  test:\n    permissions: *p\n')],
    })
    expect(alias.completionDisposition).toBe('INCOMPLETE')
    expect(alias.diagnostics).toContain('GITHUB_ACTIONS_WORKFLOW_INVALID_YAML')

    const invalidJobs = analyzeGitHubActionsWorkflows({
      subjectDigest: subjectDigestFixture(),
      slices: [workflowSlice('permissions: read-all\njobs: []\n')],
    })
    expect(invalidJobs.completionDisposition).toBe('INCOMPLETE')
    expect(invalidJobs.diagnostics).toContain('GITHUB_ACTIONS_WORKFLOW_INVALID_SHAPE')

    const emptyJobs = analyzeGitHubActionsWorkflows({
      subjectDigest: subjectDigestFixture(),
      slices: [workflowSlice('permissions: read-all\njobs: {}\n')],
    })
    expect(emptyJobs.completionDisposition).toBe('INCOMPLETE')
    expect(emptyJobs.diagnostics).toContain('GITHUB_ACTIONS_WORKFLOW_INVALID_SHAPE')

    const mergeKey = analyzeGitHubActionsWorkflows({
      subjectDigest: subjectDigestFixture(),
      slices: [workflowSlice('permissions: read-all\njobs:\n  test:\n    permissions:\n      <<: {contents: none}\n')],
    })
    expect(mergeKey.completionDisposition).toBe('INCOMPLETE')
    expect(mergeKey.coverageClaims).toEqual([])
    expect(mergeKey.diagnostics).toContain('GITHUB_ACTIONS_WORKFLOW_INVALID_YAML')
  })

  it('fails closed without leaking a stack overflow from deeply nested YAML collections', () => {
    const contribution = analyzeGitHubActionsWorkflows({
      subjectDigest: subjectDigestFixture(),
      slices: [workflowSlice(DEEPLY_NESTED_YAML)],
    })
    expect(contribution.completionDisposition).toBe('INCOMPLETE')
    expect(contribution.coverageClaims).toEqual([])
    expect(contribution.diagnostics).toContain('GITHUB_ACTIONS_WORKFLOW_INVALID_YAML')
  })

  it('rejects a job permission map that widens an explicit top-level boundary', () => {
    const contribution = analyzeGitHubActionsWorkflows({
      subjectDigest: subjectDigestFixture(),
      slices: [workflowSlice(`name: Narrow boundary
on: push
permissions: {}
jobs:
  test:
    permissions: read-all
    runs-on: ubuntu-latest
    steps:
      - run: echo unsafe
`)],
    })
    expect(contribution.completionDisposition).toBe('COMPLETE')
    expect(contribution.candidateFindings).toHaveLength(1)
    expect(contribution.evidence[0]?.value).toMatchObject({
      entries: [{ ruleId: 'JOB_PERMISSIONS_NOT_READ_ONLY' }],
    })
    expect(contribution.candidateFindings[0]?.sourceAnchor.locator.value).toBe('/jobs/test/permissions')
  })

  it('independently re-derives Coverage and rejects a tampered Contribution', () => {
    const subjectDigest = subjectDigestFixture()
    const slice = workflowSlice(UNSAFE_WORKFLOW)
    const contribution = analyzeGitHubActionsWorkflows({ subjectDigest, slices: [slice] })
    const portfolioEntry = eligiblePortfolioEntry()
    const input = {
      portfolioEntry,
      contribution,
      subjectSlices: [slice],
      policyId: GITHUB_ACTIONS_POLICY_ID,
      policyDigest: structuredDigest('application/vnd.dsh.security.policy+json', {
        policyId: GITHUB_ACTIONS_POLICY_ID,
      }),
    }
    expect(githubActionsCoverageIsIndependentlyVerified(input)).toBe(true)
    const maliciousClaim = 'ATTACKER_CONTROLLED_WORKFLOW_TEXT_MUST_NOT_BE_PUBLISHED'
    const tampered = analyzerContributionV1Schema.parse({
      ...contribution,
      candidateFindings: contribution.candidateFindings.map((candidate, index) => (
        index === 0 ? { ...candidate, securityClaim: maliciousClaim } : candidate
      )),
    })
    expect(githubActionsCoverageIsIndependentlyVerified({
      ...input,
      contribution: tampered,
    })).toBe(false)

    const contract = prepareAssessmentContract({
      policyId: GITHUB_ACTIONS_POLICY_ID,
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

async function repositoryFixture(workflow: string): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), 'dsh-security-github-actions-'))
  temporaryRoots.push(root)
  await run('git', ['init', '-b', 'main'], { cwd: root })
  await run('git', ['config', 'user.email', 'fixture@example.invalid'], { cwd: root })
  await run('git', ['config', 'user.name', 'Fixture'], { cwd: root })
  await mkdir(join(root, '.github', 'workflows'), { recursive: true })
  await writeFile(join(root, 'package.json'), '{"name":"workflow-fixture","version":"1.0.0"}\n')
  await writeFile(join(root, '.github', 'workflows', 'ci.yml'), workflow)
  await run('git', ['add', '.'], { cwd: root })
  await run('git', ['commit', '-m', 'workflow fixture'], { cwd: root })
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

async function runScenario(id: string, workflow: string): Promise<{
  readonly verdict: string | null
  readonly coverageStatus: string
  readonly findings: readonly FindingSummaryV1[]
}> {
  const repository = await repositoryFixture(workflow)
  const dshHome = await mkdtemp(join(tmpdir(), 'dsh-security-github-actions-home-'))
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
      idempotencyKey: `workflow-register-${id}`,
      root: repository,
      displayName: 'Workflow fixture',
      bindings: {
        policyId: GITHUB_ACTIONS_POLICY_ID,
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
          effectivePolicyId: GITHUB_ACTIONS_POLICY_ID,
          providerComposition: [{
            providerId: 'dsh-security-assurance',
            analyzerId: GITHUB_ACTIONS_ANALYZER_ID,
            eligibility: 'ELIGIBLE',
          }],
          admissible: true,
        },
      },
    })
    const started = await ctx.securityAssurance.startAssessment(invocation, {
      ...selection,
      contractVersion: 1,
      idempotencyKey: `workflow-assessment-${id}`,
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

describe('GitHub Actions supply-chain Analyzer (sealed chain)', () => {
  it('seals a safe workflow as SATISFIED with complete Coverage', async () => {
    const result = await runScenario('safe', CLEAN_WORKFLOW)
    expect(result).toEqual({ verdict: 'SATISFIED', coverageStatus: 'COMPLETE', findings: [] })
  }, 30_000)

  it('seals unsafe workflow authority and refs as validated blocking Findings', async () => {
    const result = await runScenario('unsafe', UNSAFE_WORKFLOW)
    expect(result.verdict).toBe('FAILED')
    expect(result.coverageStatus).toBe('COMPLETE')
    expect(result.findings).toHaveLength(3)
    expect(result.findings.every(finding => (
      finding.validationState === 'VALIDATED'
      && finding.validationContractId
        === 'dsh/security/github-actions-supply-chain-validation/v1'
      && finding.policySignificance === 'BLOCKING'
    ))).toBe(true)
  }, 30_000)

  it('seals a high-cardinality workflow fail-closed without overflowing v1 Evidence', async () => {
    const result = await runScenario('high-cardinality', highCardinalityWorkflow())
    expect(result.verdict).toBe('FAILED')
    expect(result.coverageStatus).toBe('GAP')
    expect(result.findings).toHaveLength(29)
  }, 30_000)

  it('seals invalid YAML as INDETERMINATE without a fabricated Finding', async () => {
    const result = await runScenario('invalid', 'permissions: read-all\njobs: [')
    expect(result).toEqual({ verdict: 'INDETERMINATE', coverageStatus: 'GAP', findings: [] })
  }, 30_000)
})
