import { z } from 'zod'
import type {
  AnalyzerCandidateFindingV1,
  AnalyzerContributionV1,
  AnalyzerPortfolioEntryV1,
} from '../analyzer.ts'
import type {
  DigestEnvelopeV1,
  SecuritySubmissionJsonV1,
} from '../contracts.ts'
import {
  digestEnvelopeV1Schema,
  securitySubmissionJsonV1Schema,
} from '../contracts.ts'
import { canonicalJson, sha256Hex } from './canonical.ts'
import type { EvidencePublicationInputV1 } from './evidence-persistence.ts'
import type { VerifiedSubjectTextSliceV1 } from './subject-freeze.ts'

const VALIDATION_CONTRACT_ID = 'dsh/conformance/reference-control-validation-v1'
const WEAKNESS_ID = 'dsh/conformance/reference-control-violation'
const CONTROL_ID = 'dsh/conformance/reference-control'
const SECURITY_CLAIM = 'The conformance reference security control is explicitly violated.'
const EVIDENCE_SCHEMA_ID = 'fixture/reference-validation-evidence'
const JSON_POINTER = '/dshSecurity/referenceControl'

const sourceAnchorSchema = z.strictObject({
  path: z.literal('package.json'),
  fileDigest: digestEnvelopeV1Schema,
  locator: z.strictObject({
    kind: z.literal('JSON_POINTER'),
    value: z.literal(JSON_POINTER),
  }),
})

const referenceValidationEvidenceV1Schema = z.strictObject({
  schemaVersion: z.literal(1),
  candidateId: z.string().regex(/^candidate-[0-9a-f]{64}$/),
  subjectDigest: digestEnvelopeV1Schema,
  sourceAnchor: sourceAnchorSchema,
  observedValue: z.enum(['VIOLATED', 'SATISFIED']),
  observedImpact: z.enum(['HIGH', 'CRITICAL']).default('HIGH'),
})

export interface CandidateValidationInputV1 {
  readonly portfolioEntry: AnalyzerPortfolioEntryV1
  readonly contribution: AnalyzerContributionV1
  readonly subjectSlices: readonly VerifiedSubjectTextSliceV1[]
  readonly policyId: string
  readonly policyDigest: DigestEnvelopeV1
}

export interface CandidateValidationResultV1 {
  readonly findings: readonly NonNullable<SecuritySubmissionJsonV1>[]
  readonly evidence: readonly EvidencePublicationInputV1[]
  readonly unresolvedCandidateIds: readonly string[]
}

function json(value: unknown): NonNullable<SecuritySubmissionJsonV1> {
  const normalized = securitySubmissionJsonV1Schema.parse(value)
  if (normalized === null) throw new TypeError('Candidate validation artifact must be an object')
  return normalized
}

function referenceControlState(
  slice: VerifiedSubjectTextSliceV1,
): {
  readonly value: 'VIOLATED' | 'SATISFIED'
  readonly impact: 'HIGH' | 'CRITICAL'
} | undefined {
  if ((slice.text.match(/"dshSecurity"\s*:/gu) ?? []).length !== 1) return undefined
  if ((slice.text.match(/"referenceControl"\s*:/gu) ?? []).length !== 1) return undefined
  try {
    const parsed: unknown = JSON.parse(slice.text)
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) return undefined
    const dshSecurity = (parsed as Record<string, unknown>).dshSecurity
    if (typeof dshSecurity !== 'object' || dshSecurity === null || Array.isArray(dshSecurity)) {
      return undefined
    }
    const value = (dshSecurity as Record<string, unknown>).referenceControl
    const impact = (dshSecurity as Record<string, unknown>).referenceImpact ?? 'HIGH'
    return (value === 'VIOLATED' || value === 'SATISFIED')
      && (impact === 'HIGH' || impact === 'CRITICAL')
      ? { value, impact }
      : undefined
  } catch {
    return undefined
  }
}

function candidatePrefix(candidateId: string): string {
  return candidateId.slice('candidate-'.length, 'candidate-'.length + 16)
}

function validateCandidate(
  input: CandidateValidationInputV1,
  candidate: AnalyzerCandidateFindingV1,
): {
  readonly finding?: NonNullable<SecuritySubmissionJsonV1>
  readonly evidence: readonly EvidencePublicationInputV1[]
  readonly unresolved: boolean
} {
  const prefix = candidatePrefix(candidate.candidateId)
  const admissionArtifactId = `candidate-admission-${prefix}`
  const resolutionArtifactId = `validation-contract-${prefix}`
  const eligibilityArtifactId = `validation-eligibility-${prefix}`
  const outcomeArtifactId = `validation-outcome-${prefix}`
  const contractResolved = input.policyId === 'security/reference-validation'
    && candidate.weaknessClassification.primary === WEAKNESS_ID
    && candidate.weaknessClassification.secondary.length === 0
    && candidate.affectedControlId === CONTROL_ID
    && candidate.securityClaim === SECURITY_CLAIM
    && candidate.sourceAnchor.path === 'package.json'
    && candidate.sourceAnchor.locator.kind === 'JSON_POINTER'
    && candidate.sourceAnchor.locator.value === JSON_POINTER
  const sourceSlice = input.subjectSlices.find(slice => (
    slice.path === candidate.sourceAnchor.path
    && canonicalJson(slice.digest) === canonicalJson(candidate.sourceAnchor.fileDigest)
  ))
  const referencedEvidence = candidate.evidenceArtifactIds.length === 1
    ? input.contribution.evidence.find(evidence => (
        evidence.artifactId === candidate.evidenceArtifactIds[0]
        && evidence.schemaId === EVIDENCE_SCHEMA_ID
      ))
    : undefined
  const parsedEvidence = referenceValidationEvidenceV1Schema.safeParse(referencedEvidence?.value)
  const observedReferenceControl = sourceSlice === undefined
    ? undefined
    : referenceControlState(sourceSlice)
  const evidenceBound = parsedEvidence.success
    && parsedEvidence.data.candidateId === candidate.candidateId
    && canonicalJson(parsedEvidence.data.subjectDigest) === canonicalJson(input.contribution.subjectDigest)
    && canonicalJson(parsedEvidence.data.sourceAnchor) === canonicalJson(candidate.sourceAnchor)
  const observedEvidenceValue = parsedEvidence.success ? parsedEvidence.data.observedValue : undefined
  const observedEvidenceImpact = parsedEvidence.success ? parsedEvidence.data.observedImpact : undefined
  const evidencePurpose = observedEvidenceValue === 'SATISFIED'
    ? 'COUNTER_EVIDENCE'
    : 'VALIDATION_EVIDENCE'
  const evidenceContradictsSubject = evidenceBound
    && observedEvidenceValue !== undefined
    && observedReferenceControl !== undefined
    && (
      observedEvidenceValue !== observedReferenceControl.value
      || observedEvidenceImpact !== observedReferenceControl.impact
    )
  const evidenceEligible = input.portfolioEntry.eligibility.decision === 'ELIGIBLE'
    && contractResolved
    && sourceSlice !== undefined
    && observedReferenceControl !== undefined
    && evidenceBound
    && observedEvidenceValue === observedReferenceControl.value
    && observedEvidenceImpact === observedReferenceControl.impact
  const unresolvedReason = input.portfolioEntry.eligibility.reason
    ?? (!contractResolved
      ? 'VALIDATION_CONTRACT_UNAVAILABLE'
      : sourceSlice === undefined
        ? 'SOURCE_ANCHOR_UNBOUND'
        : observedReferenceControl === undefined
          ? 'NEGATIVE_CONTROL_FAILED'
          : evidenceContradictsSubject
            ? 'VALIDATION_EVIDENCE_CONTRADICTS_SUBJECT'
            : !evidenceBound
              ? 'VALIDATION_EVIDENCE_INELIGIBLE'
              : null)
  const commonEvidence: EvidencePublicationInputV1[] = [{
    artifactId: admissionArtifactId,
    schemaId: 'dsh/security-candidate-admission',
    mediaType: 'application/vnd.dsh.security.candidate-admission+json',
    value: json({
      schemaVersion: 1,
      state: 'ADMITTED',
      candidateId: candidate.candidateId,
      producer: input.contribution.analyzerIdentity,
      subjectDigest: input.contribution.subjectDigest,
      weaknessClassification: candidate.weaknessClassification,
      affectedControlId: candidate.affectedControlId,
      securityClaim: candidate.securityClaim,
      sourceAnchor: candidate.sourceAnchor,
      evidenceArtifactIds: candidate.evidenceArtifactIds,
    }),
  }, {
    artifactId: resolutionArtifactId,
    schemaId: 'dsh/security-validation-contract-resolution',
    mediaType: 'application/vnd.dsh.security.validation-contract-resolution+json',
    value: json({
      schemaVersion: 1,
      candidateId: candidate.candidateId,
      state: contractResolved ? 'RESOLVED' : 'UNRESOLVED',
      contractId: contractResolved ? VALIDATION_CONTRACT_ID : null,
      contractVersion: contractResolved ? 1 : null,
      policyDigest: input.policyDigest,
      alternativesConsidered: [VALIDATION_CONTRACT_ID],
    }),
  }, {
    artifactId: eligibilityArtifactId,
    schemaId: 'dsh/security-validation-evidence-eligibility-decision',
    mediaType: 'application/vnd.dsh.security.validation-evidence-eligibility-decision+json',
    value: json({
      schemaVersion: 1,
      decision: evidenceEligible ? 'ELIGIBLE' : 'INELIGIBLE',
      reason: evidenceEligible ? null : unresolvedReason,
      purpose: evidencePurpose,
      candidateId: candidate.candidateId,
      securityClaim: candidate.securityClaim,
      contractId: contractResolved ? VALIDATION_CONTRACT_ID : null,
      subjectDigest: input.contribution.subjectDigest,
      evidenceArtifactIds: candidate.evidenceArtifactIds,
      producerEligibility: input.portfolioEntry.eligibility,
      negativeControls: [
        'verified-subject-digest',
        'exact-source-file-digest',
        'unique-json-security-keys',
        'exact-json-pointer',
        'exact-reference-control-marker',
        'observed-value-matches-subject',
      ],
    }),
  }]
  if (!evidenceEligible) {
    return {
      unresolved: true,
      evidence: [...commonEvidence, {
        artifactId: outcomeArtifactId,
        schemaId: 'dsh/security-validation-outcome',
        mediaType: 'application/vnd.dsh.security.validation-outcome+json',
        value: json({
          schemaVersion: 1,
          candidateId: candidate.candidateId,
          state: 'UNRESOLVED',
          contractId: contractResolved ? VALIDATION_CONTRACT_ID : null,
          evidenceEligibilityArtifactId: eligibilityArtifactId,
          proofGaps: [unresolvedReason ?? 'VALIDATION_EVIDENCE_INELIGIBLE'],
        }),
      }],
    }
  }

  if (observedEvidenceValue === 'SATISFIED') {
    return {
      unresolved: false,
      evidence: [...commonEvidence, {
        artifactId: outcomeArtifactId,
        schemaId: 'dsh/security-validation-outcome',
        mediaType: 'application/vnd.dsh.security.validation-outcome+json',
        value: json({
          schemaVersion: 1,
          candidateId: candidate.candidateId,
          state: 'REJECTED',
          contractId: VALIDATION_CONTRACT_ID,
          contractVersion: 1,
          evidenceEligibilityArtifactId: eligibilityArtifactId,
          rejectionCondition: 'EXACT_REFERENCE_CONTROL_SATISFIED',
          counterEvidenceArtifactIds: candidate.evidenceArtifactIds,
          proofGaps: [],
          negativeControls: [
            'verified-subject-digest',
            'exact-source-file-digest',
            'unique-json-security-keys',
            'exact-json-pointer',
            'exact-reference-control-marker',
            'observed-value-matches-subject',
          ],
        }),
      }],
    }
  }

  const validationOutcome = {
    schemaVersion: 1,
    candidateId: candidate.candidateId,
    state: 'VALIDATED',
    contractId: VALIDATION_CONTRACT_ID,
    contractVersion: 1,
    evidenceEligibilityArtifactId: eligibilityArtifactId,
    evidenceArtifactIds: candidate.evidenceArtifactIds,
    proofGaps: [],
    negativeControls: [
      'verified-subject-digest',
      'exact-source-file-digest',
      'unique-json-security-keys',
      'exact-json-pointer',
      'exact-reference-control-marker',
      'observed-value-matches-subject',
    ],
  }
  const finding = json({
    schemaVersion: 1,
    findingId: `finding-${sha256Hex(canonicalJson({
      candidateId: candidate.candidateId,
      contractId: VALIDATION_CONTRACT_ID,
      subjectDigest: input.contribution.subjectDigest,
    }))}`,
    candidateId: candidate.candidateId,
    weaknessClassification: candidate.weaknessClassification,
    affectedControlId: candidate.affectedControlId,
    sourceAnchor: candidate.sourceAnchor,
    securityClaim: candidate.securityClaim,
    validation: validationOutcome,
    technicalSeverity: {
      value: observedReferenceControl.impact,
      methodVersion: observedReferenceControl.impact === 'CRITICAL'
        ? 'dsh/conformance/reference-critical-severity-v1'
        : 'dsh/conformance/reference-control-severity-v1',
      vector: {
        impact: 'SECURITY_CONTROL_BYPASS',
        reachability: 'DIRECT',
        affectedScope: 'APPLICATION',
      },
    },
    evidenceConfidence: {
      value: 'HIGH',
      methodVersion: 'dsh/conformance/deterministic-evidence-confidence-v1',
      rubric: {
        producerQualification: 'PASS',
        subjectBinding: 'PASS',
        reproducibility: 'PASS',
        negativeControls: 'PASS',
        proofGaps: 0,
      },
    },
    policySignificance: 'BLOCKING',
    policySignificanceTrace: {
      ruleId: observedReferenceControl.impact === 'CRITICAL'
        ? 'baseline-critical-severity-blocks-v1'
        : 'baseline-high-severity-blocks-v1',
      policyDigest: input.policyDigest,
      matched: true,
    },
  })
  return {
    finding,
    unresolved: false,
    evidence: [...commonEvidence, {
      artifactId: outcomeArtifactId,
      schemaId: 'dsh/security-validation-outcome',
      mediaType: 'application/vnd.dsh.security.validation-outcome+json',
      value: json(validationOutcome),
    }],
  }
}

/** Pure deterministic Candidate Admission and weakness-specific Validation Module. */
export function validateExternalAnalyzerCandidates(
  inputs: readonly CandidateValidationInputV1[],
): CandidateValidationResultV1 {
  const findings: NonNullable<SecuritySubmissionJsonV1>[] = []
  const evidence: EvidencePublicationInputV1[] = []
  const unresolvedCandidateIds: string[] = []
  for (const input of inputs) {
    for (const candidate of input.contribution.candidateFindings) {
      const result = validateCandidate(input, candidate)
      evidence.push(...result.evidence)
      if (result.finding !== undefined) findings.push(result.finding)
      if (result.unresolved) unresolvedCandidateIds.push(candidate.candidateId)
    }
  }
  return { findings, evidence, unresolvedCandidateIds }
}
