import { parseDocument, visit } from 'yaml'
import { z } from 'zod'

import type {
  AnalyzerCandidateFindingV1,
  AnalyzerContributionV1,
  AnalyzerDescriptorV1,
  AnalyzerFactoryV1,
  AnalyzerQualificationRecordV1,
} from '../analyzer.ts'
import { analyzerContributionV1Schema } from '../analyzer.ts'
import {
  digestEnvelopeV1Schema,
  SECURITY_ASSURANCE_PRODUCT_NAME,
} from '../contracts.ts'
import type { DigestEnvelopeV1 } from '../contracts.ts'
import { canonicalJson, sha256Hex, structuredDigest } from './canonical.ts'
import { deepFreeze } from './freeze.ts'
import type { VerifiedSubjectTextSliceV1 } from './subject-freeze.ts'

export const GITHUB_ACTIONS_ANALYSIS_CONTRACT_ID
  = 'dsh/security/github-actions-supply-chain-analysis/v1' as const
export const GITHUB_ACTIONS_ANALYZER_ID = 'dsh/builtin-github-actions-supply-chain' as const
export const GITHUB_ACTIONS_ANALYZER_VERSION = '1.0.1' as const
export const GITHUB_ACTIONS_POLICY_ID = 'security/github-actions-supply-chain' as const
export const GITHUB_ACTIONS_PERMISSION_WEAKNESS_ID
  = 'dsh/github-actions/excessive-token-permission' as const
export const GITHUB_ACTIONS_REFERENCE_WEAKNESS_ID
  = 'dsh/github-actions/mutable-dependency-reference' as const
export const GITHUB_ACTIONS_PERMISSION_CONTROL_ID
  = 'dsh/github-actions/least-privilege-token' as const
export const GITHUB_ACTIONS_REFERENCE_CONTROL_ID
  = 'dsh/github-actions/immutable-dependency-reference' as const
export const GITHUB_ACTIONS_EVIDENCE_SCHEMA_ID
  = 'dsh/security-github-actions-supply-chain-evidence' as const
export const GITHUB_ACTIONS_COVERAGE_OBLIGATION_ID = 'application-security-analysis' as const
export const GITHUB_ACTIONS_EVIDENCE_MEDIA_TYPE
  = 'application/vnd.dsh.security.github-actions-supply-chain-evidence+json' as const

export const GITHUB_ACTIONS_RULE_IDS = [
  'WORKFLOW_PERMISSIONS_MISSING',
  'WORKFLOW_PERMISSIONS_NOT_READ_ONLY',
  'JOB_PERMISSIONS_NOT_READ_ONLY',
  'ACTION_REFERENCE_NOT_COMMIT_PINNED',
  'CONTAINER_REFERENCE_NOT_DIGEST_PINNED',
] as const

export type GitHubActionsRuleId = typeof GITHUB_ACTIONS_RULE_IDS[number]

const GITHUB_ACTIONS_METHOD = {
  schemaVersion: 1,
  contractId: GITHUB_ACTIONS_ANALYSIS_CONTRACT_ID,
  analyzerId: GITHUB_ACTIONS_ANALYZER_ID,
  analyzerVersion: GITHUB_ACTIONS_ANALYZER_VERSION,
  methodVersion: 'dsh-github-actions-supply-chain-analysis-v2',
  input: 'verified .github/workflows YAML slices frozen with the Subject',
  rules: [
    'top-level permissions are explicitly read-only or empty',
    'job permissions cannot widen the token beyond read-only',
    'external actions and reusable workflows use a full 40-hex commit SHA',
    'container actions use a sha256 image digest',
  ],
  candidateLimit: 29,
  candidateLimitDisposition: 'INCOMPLETE',
  exclusions: 'workflow execution, network lookup, ref resolution and permission necessity analysis',
} as const

export const GITHUB_ACTIONS_DESCRIPTOR: AnalyzerDescriptorV1 = deepFreeze({
  schemaVersion: 1,
  analyzerId: GITHUB_ACTIONS_ANALYZER_ID,
  analyzerVersion: GITHUB_ACTIONS_ANALYZER_VERSION,
  descriptorSchemaVersion: 1,
  buildDigest: structuredDigest(
    'application/vnd.dsh.security.analyzer-method+json',
    GITHUB_ACTIONS_METHOD,
  ),
  executionClass: 'PURE',
  supportedAssessmentModes: ['REPOSITORY', 'CHANGE', 'TARGETED'],
  supportedPolicyIds: [GITHUB_ACTIONS_POLICY_ID],
  coverageObligationIds: [GITHUB_ACTIONS_COVERAGE_OBLIGATION_ID],
  evidenceSchemaIds: [GITHUB_ACTIONS_EVIDENCE_SCHEMA_ID],
  egress: 'NONE',
})

const GITHUB_ACTIONS_QUALIFICATION_CORE = {
  schemaVersion: 1 as const,
  qualificationId: 'dsh/qualification/builtin-github-actions-supply-chain/v2' as const,
  analyzerIdentity: {
    analyzerId: GITHUB_ACTIONS_DESCRIPTOR.analyzerId,
    analyzerVersion: GITHUB_ACTIONS_DESCRIPTOR.analyzerVersion,
    descriptorSchemaVersion: GITHUB_ACTIONS_DESCRIPTOR.descriptorSchemaVersion,
    buildDigest: GITHUB_ACTIONS_DESCRIPTOR.buildDigest,
  },
  issuerId: 'dsh/security-assurance-development' as const,
  level: 'HOST_ATTESTED' as const,
  supportedEcosystemIds: ['github-actions-workflow'] as const,
  supportedAssessmentModes: ['REPOSITORY', 'CHANGE', 'TARGETED'] as const,
  supportedPolicyIds: [GITHUB_ACTIONS_POLICY_ID] as const,
  coverageObligationIds: [GITHUB_ACTIONS_COVERAGE_OBLIGATION_ID] as const,
  evidenceSchemaIds: [GITHUB_ACTIONS_EVIDENCE_SCHEMA_ID] as const,
  executionClass: 'PURE' as const,
  executionBackendId: 'dsh/security-assurance/in-process-pure-v1' as const,
  providerIds: [SECURITY_ASSURANCE_PRODUCT_NAME] as const,
  egress: 'NONE' as const,
  platforms: ['win32', 'linux', 'darwin'] as const,
  issuedAt: '2026-01-01T00:00:00.000Z' as const,
  expiresAt: '2099-01-01T00:00:00.000Z' as const,
  evidenceDigests: [GITHUB_ACTIONS_DESCRIPTOR.buildDigest] as const,
  limitations: [
    'Only frozen .github/workflows YAML files selected by the Assessment Target are evaluated.',
    'This strict policy accepts only read-only or empty GitHub token permissions; workflows that need write authority require another reviewed policy.',
    'At most 29 Candidates are emitted; higher-cardinality results are truncated and reported with incomplete Coverage.',
    'The analyzer proves immutable syntax but does not resolve refs, execute workflows, inspect referenced code, or access the network.',
  ] as const,
}

export const GITHUB_ACTIONS_QUALIFICATION: AnalyzerQualificationRecordV1 = deepFreeze({
  ...GITHUB_ACTIONS_QUALIFICATION_CORE,
  qualificationDigest: structuredDigest(
    'application/vnd.dsh.security.analyzer-qualification+json',
    GITHUB_ACTIONS_QUALIFICATION_CORE,
  ),
})

const githubActionsEvidenceEntryV1Schema = z.strictObject({
  candidateId: z.string().regex(/^candidate-[0-9a-f]{64}$/),
  ruleId: z.enum(GITHUB_ACTIONS_RULE_IDS),
  severity: z.enum(['HIGH', 'MEDIUM']),
  sourceAnchor: z.strictObject({
    path: z.string().min(1).max(1024),
    fileDigest: digestEnvelopeV1Schema,
    locator: z.strictObject({
      kind: z.literal('JSON_POINTER'),
      value: z.string().min(1).max(1024),
    }),
  }),
})

export const githubActionsSupplyChainEvidenceV1Schema = z.strictObject({
  schemaVersion: z.literal(1),
  contractId: z.literal(GITHUB_ACTIONS_ANALYSIS_CONTRACT_ID),
  analyzerIdentity: z.strictObject({
    analyzerId: z.literal(GITHUB_ACTIONS_ANALYZER_ID),
    analyzerVersion: z.literal(GITHUB_ACTIONS_ANALYZER_VERSION),
    descriptorSchemaVersion: z.literal(1),
    buildDigest: digestEnvelopeV1Schema,
  }),
  subjectDigest: digestEnvelopeV1Schema,
  workflowFiles: z.array(z.strictObject({
    path: z.string().min(1).max(1024),
    fileDigest: digestEnvelopeV1Schema,
    parseStatus: z.enum(['PARSED', 'INVALID']),
    candidateIds: z.array(z.string().regex(/^candidate-[0-9a-f]{64}$/)).max(768),
  })).max(256),
  entries: z.array(githubActionsEvidenceEntryV1Schema).max(768),
})

export type GitHubActionsSupplyChainEvidenceV1 = z.infer<
  typeof githubActionsSupplyChainEvidenceV1Schema
>

type JsonRecord = Readonly<Record<string, unknown>>

interface DetectedViolation {
  readonly ruleId: GitHubActionsRuleId
  readonly severity: 'HIGH' | 'MEDIUM'
  readonly locator: string
  readonly weaknessId: string
  readonly secondaryWeaknessId: string
  readonly controlId: string
  readonly securityClaim: string
}

type GitHubActionsDiagnostic =
  | 'GITHUB_ACTIONS_WORKFLOW_INVALID_YAML'
  | 'GITHUB_ACTIONS_WORKFLOW_INVALID_SHAPE'
  | 'GITHUB_ACTIONS_WORKFLOW_LIMIT'
  | 'GITHUB_ACTIONS_CANDIDATE_LIMIT'

const MAX_WORKFLOW_SLICES = 256
// A sealed v1 bundle admits at most 128 records. Seven core records, three
// Analyzer-level records, and four independent Validation records per
// Candidate leave room for at most 29 Candidates: 7 + 3 + (4 * 29) = 126.
// Truncation is explicit and removes the complete-Coverage claim, so the
// resulting Assessment still seals fail-closed instead of becoming BLOCKED.
const MAX_CANDIDATES = 29
const FULL_COMMIT_SHA = /^[0-9a-f]{40}$/iu
const CONTAINER_DIGEST = /^docker:\/\/[^\s@]+@sha256:[0-9a-f]{64}$/iu

function analyzerIdentity(): {
  readonly analyzerId: typeof GITHUB_ACTIONS_ANALYZER_ID
  readonly analyzerVersion: typeof GITHUB_ACTIONS_ANALYZER_VERSION
  readonly descriptorSchemaVersion: 1
  readonly buildDigest: DigestEnvelopeV1
} {
  return {
    analyzerId: GITHUB_ACTIONS_ANALYZER_ID,
    analyzerVersion: GITHUB_ACTIONS_ANALYZER_VERSION,
    descriptorSchemaVersion: 1,
    buildDigest: GITHUB_ACTIONS_DESCRIPTOR.buildDigest,
  }
}

function record(value: unknown): JsonRecord | undefined {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
    ? value as JsonRecord
    : undefined
}

function pointerSegment(value: string): string {
  return value.replaceAll('~', '~0').replaceAll('/', '~1')
}

interface ReadOnlyPermissionBoundary {
  readonly all: boolean
  readonly values: ReadonlyMap<string, 'read' | 'none'>
}

function readOnlyPermissionBoundary(value: unknown): ReadOnlyPermissionBoundary | undefined {
  if (value === 'read-all') return { all: true, values: new Map() }
  const permissionMap = record(value)
  if (permissionMap === undefined) return undefined
  const values = new Map<string, 'read' | 'none'>()
  for (const [name, permission] of Object.entries(permissionMap)) {
    if (permission !== 'read' && permission !== 'none') return undefined
    values.set(name, permission)
  }
  return { all: false, values }
}

function permissionsAreReadOnly(value: unknown): boolean {
  return readOnlyPermissionBoundary(value) !== undefined
}

function permissionBoundaryIsWithin(
  parent: ReadOnlyPermissionBoundary,
  child: ReadOnlyPermissionBoundary,
): boolean {
  if (child.all) return parent.all
  if (parent.all) return true
  for (const [name, permission] of child.values) {
    if (permission === 'read' && parent.values.get(name) !== 'read') return false
  }
  return true
}

function permissionViolations(workflow: JsonRecord): readonly DetectedViolation[] {
  const violations: DetectedViolation[] = []
  if (!Object.hasOwn(workflow, 'permissions')) {
    violations.push({
      ruleId: 'WORKFLOW_PERMISSIONS_MISSING',
      severity: 'MEDIUM',
      locator: '/permissions',
      weaknessId: GITHUB_ACTIONS_PERMISSION_WEAKNESS_ID,
      secondaryWeaknessId: 'cwe/250',
      controlId: GITHUB_ACTIONS_PERMISSION_CONTROL_ID,
      securityClaim: 'The workflow does not declare an explicit read-only GitHub token permission boundary.',
    })
  } else if (!permissionsAreReadOnly(workflow.permissions)) {
    violations.push({
      ruleId: 'WORKFLOW_PERMISSIONS_NOT_READ_ONLY',
      severity: 'HIGH',
      locator: '/permissions',
      weaknessId: GITHUB_ACTIONS_PERMISSION_WEAKNESS_ID,
      secondaryWeaknessId: 'cwe/250',
      controlId: GITHUB_ACTIONS_PERMISSION_CONTROL_ID,
      securityClaim: 'The workflow grants GitHub token permissions that are not statically read-only.',
    })
  }
  const topLevelBoundary = Object.hasOwn(workflow, 'permissions')
    ? readOnlyPermissionBoundary(workflow.permissions)
    : undefined
  const jobs = record(workflow.jobs)
  if (jobs === undefined) return violations
  for (const jobId of Object.keys(jobs).sort()) {
    const job = record(jobs[jobId])
    if (job === undefined || !Object.hasOwn(job, 'permissions')) continue
    const jobBoundary = readOnlyPermissionBoundary(job.permissions)
    if (
      jobBoundary === undefined
      || (topLevelBoundary !== undefined && !permissionBoundaryIsWithin(topLevelBoundary, jobBoundary))
    ) {
      violations.push({
        ruleId: 'JOB_PERMISSIONS_NOT_READ_ONLY',
        severity: 'HIGH',
        locator: `/jobs/${pointerSegment(jobId)}/permissions`,
        weaknessId: GITHUB_ACTIONS_PERMISSION_WEAKNESS_ID,
        secondaryWeaknessId: 'cwe/250',
        controlId: GITHUB_ACTIONS_PERMISSION_CONTROL_ID,
        securityClaim: 'A workflow job grants GitHub token permissions that are not statically read-only.',
      })
    }
  }
  return violations
}

function referenceViolation(locator: string, uses: string): DetectedViolation | undefined {
  if (uses.startsWith('./')) return undefined
  if (uses.startsWith('docker://')) {
    return CONTAINER_DIGEST.test(uses)
      ? undefined
      : {
          ruleId: 'CONTAINER_REFERENCE_NOT_DIGEST_PINNED',
          severity: 'HIGH',
          locator,
          weaknessId: GITHUB_ACTIONS_REFERENCE_WEAKNESS_ID,
          secondaryWeaknessId: 'cwe/829',
          controlId: GITHUB_ACTIONS_REFERENCE_CONTROL_ID,
          securityClaim: 'A container action is not pinned to an immutable SHA-256 image digest.',
        }
  }
  const at = uses.lastIndexOf('@')
  const repositoryPath = at > 0 ? uses.slice(0, at) : ''
  const revision = at > 0 ? uses.slice(at + 1) : ''
  const validRepositoryPath = /^[^\s@/]+\/[^\s@/]+(?:\/[^\s@]+)*$/u.test(repositoryPath)
  return validRepositoryPath && FULL_COMMIT_SHA.test(revision)
    ? undefined
    : {
        ruleId: 'ACTION_REFERENCE_NOT_COMMIT_PINNED',
        severity: 'HIGH',
        locator,
        weaknessId: GITHUB_ACTIONS_REFERENCE_WEAKNESS_ID,
        secondaryWeaknessId: 'cwe/829',
        controlId: GITHUB_ACTIONS_REFERENCE_CONTROL_ID,
        securityClaim: 'An external GitHub Action or reusable workflow is not pinned to a full commit SHA.',
      }
}

function referenceViolations(workflow: JsonRecord): {
  readonly violations: readonly DetectedViolation[]
  readonly invalidShape: boolean
} {
  const jobs = record(workflow.jobs)
  if (jobs === undefined || Object.keys(jobs).length === 0) {
    return { violations: [], invalidShape: true }
  }
  const violations: DetectedViolation[] = []
  let invalidShape = false
  for (const jobId of Object.keys(jobs).sort()) {
    const job = record(jobs[jobId])
    if (job === undefined) {
      invalidShape = true
      continue
    }
    if (Object.hasOwn(job, 'uses')) {
      if (typeof job.uses !== 'string') invalidShape = true
      else {
        const locator = `/jobs/${pointerSegment(jobId)}/uses`
        const violation = referenceViolation(locator, job.uses)
        if (violation !== undefined) violations.push(violation)
      }
    }
    if (job.steps === undefined) continue
    if (!Array.isArray(job.steps)) {
      invalidShape = true
      continue
    }
    for (const [index, stepValue] of job.steps.entries()) {
      const step = record(stepValue)
      if (step === undefined) {
        invalidShape = true
        continue
      }
      if (!Object.hasOwn(step, 'uses')) continue
      if (typeof step.uses !== 'string') {
        invalidShape = true
        continue
      }
      const locator = `/jobs/${pointerSegment(jobId)}/steps/${index}/uses`
      const violation = referenceViolation(locator, step.uses)
      if (violation !== undefined) violations.push(violation)
    }
  }
  return { violations, invalidShape }
}

function parseWorkflow(text: string): JsonRecord | undefined {
  const document = parseDocument(text, {
    customTags: [],
    merge: false,
    prettyErrors: false,
    schema: 'core',
    strict: true,
    stringKeys: true,
    uniqueKeys: true,
    version: '1.2',
  })
  if (document.errors.length > 0 || document.warnings.length > 0 || document.contents === null) {
    return undefined
  }
  let hasAlias = false
  visit(document, {
    Alias() {
      hasAlias = true
      return visit.BREAK
    },
  })
  if (hasAlias) return undefined
  let hasMergeKey = false
  visit(document, (key, node) => {
    if (key !== 'key' || typeof node !== 'object' || node === null || !('value' in node)) return
    if ((node as { readonly value?: unknown }).value === '<<') {
      hasMergeKey = true
      return visit.BREAK
    }
  })
  if (hasMergeKey) return undefined
  return record(document.toJS({ maxAliasCount: 0 }))
}

function buildCandidate(
  subjectDigest: DigestEnvelopeV1,
  slice: VerifiedSubjectTextSliceV1,
  violation: DetectedViolation,
  evidenceArtifactId: string,
): AnalyzerCandidateFindingV1 {
  const sourceAnchor = {
    path: slice.path,
    fileDigest: slice.digest,
    locator: { kind: 'JSON_POINTER' as const, value: violation.locator },
  }
  const candidateId = `candidate-${sha256Hex(canonicalJson({
    analyzerIdentity: analyzerIdentity(),
    subjectDigest,
    ruleId: violation.ruleId,
    sourceAnchor,
  }))}`
  return {
    schemaVersion: 1,
    candidateId,
    weaknessClassification: {
      schemaVersion: 1,
      primary: violation.weaknessId,
      secondary: [violation.secondaryWeaknessId],
    },
    affectedControlId: violation.controlId,
    securityClaim: violation.securityClaim,
    sourceAnchor,
    evidenceArtifactIds: [evidenceArtifactId],
  }
}

/**
 * Analyze frozen workflow text without filesystem, network, process, clock,
 * model, Store or YAML execution authority.
 */
export function analyzeGitHubActionsWorkflows(input: {
  readonly subjectDigest: DigestEnvelopeV1
  readonly slices: readonly VerifiedSubjectTextSliceV1[]
}): AnalyzerContributionV1 {
  const diagnostics = new Set<GitHubActionsDiagnostic>()
  const orderedSlices = [...input.slices].sort((left, right) => left.path.localeCompare(right.path))
  const slices = orderedSlices.slice(0, MAX_WORKFLOW_SLICES)
  if (orderedSlices.length > slices.length) diagnostics.add('GITHUB_ACTIONS_WORKFLOW_LIMIT')
  const evidenceArtifactId = 'github-actions-supply-chain-analysis'
  const candidateFindings: AnalyzerCandidateFindingV1[] = []
  const workflowFiles: GitHubActionsSupplyChainEvidenceV1['workflowFiles'][number][] = []
  const entries: GitHubActionsSupplyChainEvidenceV1['entries'][number][] = []
  let incomplete = orderedSlices.length > slices.length
  let bytesRead = 0

  for (const slice of slices) {
    bytesRead += Buffer.byteLength(slice.text, 'utf8')
    let workflow: JsonRecord | undefined
    try {
      workflow = parseWorkflow(slice.text)
    } catch {
      workflow = undefined
    }
    if (workflow === undefined) {
      diagnostics.add('GITHUB_ACTIONS_WORKFLOW_INVALID_YAML')
      incomplete = true
      workflowFiles.push({
        path: slice.path,
        fileDigest: slice.digest,
        parseStatus: 'INVALID',
        candidateIds: [],
      })
      continue
    }
    const references = referenceViolations(workflow)
    if (references.invalidShape) {
      diagnostics.add('GITHUB_ACTIONS_WORKFLOW_INVALID_SHAPE')
      incomplete = true
    }
    const violations = [...permissionViolations(workflow), ...references.violations]
      .sort((left, right) => left.locator.localeCompare(right.locator)
        || left.ruleId.localeCompare(right.ruleId))
    const sliceCandidateIds: string[] = []
    for (const violation of violations) {
      if (candidateFindings.length >= MAX_CANDIDATES) {
        diagnostics.add('GITHUB_ACTIONS_CANDIDATE_LIMIT')
        incomplete = true
        break
      }
      const candidate = buildCandidate(input.subjectDigest, slice, violation, evidenceArtifactId)
      candidateFindings.push(candidate)
      sliceCandidateIds.push(candidate.candidateId)
      entries.push({
        candidateId: candidate.candidateId,
        ruleId: violation.ruleId,
        severity: violation.severity,
        sourceAnchor: candidate.sourceAnchor,
      })
    }
    workflowFiles.push({
      path: slice.path,
      fileDigest: slice.digest,
      parseStatus: references.invalidShape ? 'INVALID' : 'PARSED',
      candidateIds: sliceCandidateIds,
    })
  }

  const evidenceValue = githubActionsSupplyChainEvidenceV1Schema.parse({
    schemaVersion: 1,
    contractId: GITHUB_ACTIONS_ANALYSIS_CONTRACT_ID,
    analyzerIdentity: analyzerIdentity(),
    subjectDigest: input.subjectDigest,
    workflowFiles,
    entries,
  })
  return deepFreeze(analyzerContributionV1Schema.parse({
    schemaVersion: 1,
    analyzerIdentity: analyzerIdentity(),
    subjectDigest: input.subjectDigest,
    completionDisposition: incomplete ? 'INCOMPLETE' : 'COMPLETE',
    coverageClaims: incomplete ? [] : [{
      obligationId: GITHUB_ACTIONS_COVERAGE_OBLIGATION_ID,
      completion: 'COMPLETE',
      evidenceArtifactId,
    }],
    candidateFindings,
    evidence: [{
      artifactId: evidenceArtifactId,
      schemaId: GITHUB_ACTIONS_EVIDENCE_SCHEMA_ID,
      mediaType: GITHUB_ACTIONS_EVIDENCE_MEDIA_TYPE,
      value: evidenceValue,
    }],
    diagnostics: [...diagnostics].sort(),
    resourceUse: { filesRead: slices.length, bytesRead },
  }))
}

export const createGitHubActionsSupplyChainAnalyzer: AnalyzerFactoryV1 = descriptor => ({
  descriptor,
  async analyze(input) {
    return analyzeGitHubActionsWorkflows({
      subjectDigest: input.subject.digest,
      slices: input.subject.textSlices.filter(slice => (
        /^\.github\/workflows\/[^/]+\.ya?ml$/iu.test(slice.path)
      )),
    })
  },
  async dispose() {},
})
