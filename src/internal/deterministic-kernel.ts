import type {
  AssessmentCoverageSnapshotV1,
  AssessmentMode,
  AssessmentProfileId,
  AssessmentTargetSelectorV1,
  DigestEnvelopeV1,
  SecuritySubmissionJsonV1,
  SecurityVerdict,
} from '../contracts.ts'
import { securitySubmissionJsonV1Schema } from '../contracts.ts'
import { structuredDigest } from './canonical.ts'

const POLICY_MEDIA_TYPE = 'application/vnd.dsh.security.policy+json'
const COVERAGE_MEDIA_TYPE = 'application/vnd.dsh.security.coverage+json'

export interface PreparedAssessmentContractV1 {
  readonly schemaVersion: 1
  readonly assessmentMode: AssessmentMode
  readonly assessmentProfileId: AssessmentProfileId
  readonly target: AssessmentTargetSelectorV1
  readonly requestedStrongerControlIds: readonly string[]
  readonly policy: {
    readonly policyId: string
    readonly digest: DigestEnvelopeV1
    readonly value: SecuritySubmissionJsonV1
  }
  readonly coverage: AssessmentCoverageSnapshotV1
}

export interface DeterministicAssessmentOutcomeV1 {
  readonly coverage: AssessmentCoverageSnapshotV1
  readonly findings: SecuritySubmissionJsonV1[]
  readonly verdict: SecurityVerdict
  readonly evaluationTrace: NonNullable<SecuritySubmissionJsonV1>
}

function coverageSnapshot(
  value: Omit<AssessmentCoverageSnapshotV1, 'digest'>,
): AssessmentCoverageSnapshotV1 {
  return {
    ...value,
    digest: structuredDigest(COVERAGE_MEDIA_TYPE, value),
  }
}

/** Purely freeze the minimum v1 Policy and Coverage Plan admitted by this development slice. */
export function prepareAssessmentContract(input: {
  readonly policyId: string
  readonly assessmentMode: AssessmentMode
  readonly assessmentProfileId: AssessmentProfileId
  readonly target: AssessmentTargetSelectorV1
  readonly requestedStrongerControlIds: readonly string[]
}): PreparedAssessmentContractV1 {
  const policyValue = securitySubmissionJsonV1Schema.parse({
    schemaVersion: 1,
    policyId: input.policyId,
    methodVersion: 'dsh-security-default-policy-v1',
    obligations: [{
      obligationId: 'application-security-analysis',
      mandatory: true,
      eligibleExecutionClass: 'qualified-analyzer',
    }],
    verdictRule: 'blocking-finding-then-mandatory-coverage-v1',
  })
  return {
    schemaVersion: 1,
    assessmentMode: input.assessmentMode,
    assessmentProfileId: input.assessmentProfileId,
    target: input.target,
    requestedStrongerControlIds: input.requestedStrongerControlIds,
    policy: {
      policyId: input.policyId,
      digest: structuredDigest(POLICY_MEDIA_TYPE, policyValue),
      value: policyValue,
    },
    coverage: coverageSnapshot({
      status: 'PENDING',
      mandatoryObligations: 1,
      satisfiedObligations: 0,
      gapObligations: 0,
      resolutions: [],
    }),
  }
}

/** Pure deterministic evaluator for the currently frozen empty Analyzer composition. */
export function evaluateDeterministicAssessment(
  contract: PreparedAssessmentContractV1,
  evaluationInstant: string,
): DeterministicAssessmentOutcomeV1 {
  const coverage = coverageSnapshot({
    status: 'GAP',
    mandatoryObligations: 1,
    satisfiedObligations: 0,
    gapObligations: 1,
    resolutions: [{
      obligationId: 'application-security-analysis',
      state: 'GAP',
      reason: 'NO_ELIGIBLE_ANALYZER',
    }],
  })
  const evaluationTrace = securitySubmissionJsonV1Schema.parse({
    schemaVersion: 1,
    evaluatorVersion: 'dsh-security-policy-evaluator-v1',
    evaluationInstant,
    policyDigest: contract.policy.digest,
    rules: [
      { ruleId: 'blocking-policy-violation', matched: false },
      { ruleId: 'mandatory-coverage-gap', matched: true, outcome: 'INDETERMINATE' },
      { ruleId: 'complete-mandatory-coverage', matched: false },
    ],
    diagnostics: [{ code: 'NO_ELIGIBLE_ANALYZER', obligationId: 'application-security-analysis' }],
  })
  if (evaluationTrace === null) throw new TypeError('evaluation trace must be a JSON value')
  return {
    coverage,
    findings: [],
    verdict: 'INDETERMINATE',
    evaluationTrace,
  }
}

/** Independent pure readiness decision; evaluator output alone cannot authorize sealing. */
export function checkSealReadiness(
  contract: PreparedAssessmentContractV1,
  outcome: DeterministicAssessmentOutcomeV1,
): { readonly ready: true } | { readonly ready: false; readonly violations: readonly string[] } {
  const violations: string[] = []
  if (contract.coverage.status !== 'PENDING') violations.push('frozen_plan_not_pending_at_start')
  if (outcome.coverage.status !== 'GAP') violations.push('coverage_not_terminal_gap')
  if (outcome.coverage.mandatoryObligations !== 1) violations.push('mandatory_obligation_count_mismatch')
  if (outcome.coverage.gapObligations !== 1) violations.push('mandatory_gap_not_recorded')
  if (outcome.coverage.resolutions.length !== 1) violations.push('coverage_resolution_count_mismatch')
  if (outcome.findings.length !== 0) violations.push('unexpected_unvalidated_findings')
  if (outcome.verdict !== 'INDETERMINATE') violations.push('verdict_trace_mismatch')
  return violations.length === 0 ? { ready: true } : { ready: false, violations }
}
