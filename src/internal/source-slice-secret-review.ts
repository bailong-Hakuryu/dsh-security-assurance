import { z } from 'zod'
import type {
  AnalyzerContributionV1,
  AnalyzerIdentityV1,
  AnalyzerPortfolioEntryV1,
} from '../analyzer.ts'
import {
  analyzerContributionV1Schema,
  analyzerIdentityV1Schema,
  analyzerPortfolioEntryV1Schema,
} from '../analyzer.ts'
import type {
  AssessmentMode,
  DigestEnvelopeV1,
  RepositoryPlatform,
} from '../contracts.ts'
import {
  assessmentModeSchema,
  digestEnvelopeV1Schema,
  repositoryPlatformSchema,
  SECURITY_ASSURANCE_PRODUCT_NAME,
} from '../contracts.ts'
import { canonicalJson, structuredDigest } from './canonical.ts'
import { deepFreeze } from './freeze.ts'
import type {
  ProtectedSourceSliceRedactionV1,
} from './source-slice-protection.ts'
import {
  parseProtectedSourceSliceRedaction,
  SOURCE_SLICE_REDACTION_MEDIA_TYPE,
} from './source-slice-protection.ts'
import type { ProtectedSourceSliceMaterialV1 } from './subject-freeze.ts'

export const SOURCE_SLICE_SECRET_REVIEW_CONTRACT_ID =
  'dsh/security/source-slice-secret-review/v1' as const
export const SOURCE_SLICE_SECRET_REVIEW_POLICY_ID =
  'security/source-slice-secret-review' as const
export const SOURCE_SLICE_SECRET_REVIEW_OBLIGATION_ID =
  'source-slice-secret-redaction' as const
export const SOURCE_SLICE_SECRET_REVIEW_EVIDENCE_SCHEMA_ID =
  'dsh/security-source-slice-secret-review' as const
export const SOURCE_SLICE_SECRET_REVIEW_EVIDENCE_MEDIA_TYPE =
  'application/vnd.dsh.security.source-slice-secret-review-evidence+json' as const
export const SOURCE_SLICE_SECRET_REVIEW_INDEPENDENCE_MEDIA_TYPE =
  'application/vnd.dsh.security.source-slice-secret-review-independence+json' as const
export const SOURCE_SLICE_SECRET_REVIEW_MEDIA_TYPE =
  'application/vnd.dsh.security.qualified-source-slice-secret-review+json' as const

export type ProtectedSourceSliceSecretReviewDecisionV1 =
  | 'CLEAR'
  | 'SECRET_FOUND'
  | 'INDETERMINATE'

interface SourceSliceSecretReviewEvidenceV1 {
  readonly schemaVersion: 1
  readonly contractId: typeof SOURCE_SLICE_SECRET_REVIEW_CONTRACT_ID
  readonly reviewedAt: string
  readonly scope: 'EXACT_REDACTED_SOURCE_SLICE'
  readonly requestDigest: DigestEnvelopeV1
  readonly subjectDigest: DigestEnvelopeV1
  readonly sourceDigest: DigestEnvelopeV1
  readonly path: string
  readonly redactionDigest: DigestEnvelopeV1
  readonly redactedDigest: DigestEnvelopeV1
  readonly independenceEvidenceDigest: DigestEnvelopeV1
  readonly completion: 'COMPLETE' | 'INCOMPLETE'
  readonly decision: ProtectedSourceSliceSecretReviewDecisionV1
  readonly findingCount: number
}

export interface ProtectedSourceSliceSecretReviewCoreV1 {
  readonly schemaVersion: 1
  readonly contractId: typeof SOURCE_SLICE_SECRET_REVIEW_CONTRACT_ID
  readonly requestDigest: DigestEnvelopeV1
  readonly subjectDigest: DigestEnvelopeV1
  readonly sourceDigest: DigestEnvelopeV1
  readonly path: string
  readonly redactionDigest: DigestEnvelopeV1
  readonly redactedDigest: DigestEnvelopeV1
  readonly analyzerIdentity: AnalyzerIdentityV1
  readonly qualificationId: string
  readonly qualificationDigest: DigestEnvelopeV1
  readonly assessmentMode: AssessmentMode
  readonly platform: RepositoryPlatform
  readonly reviewedAt: string
  readonly evidenceArtifactId: string
  readonly reviewEvidenceDigest: DigestEnvelopeV1
  readonly independenceEvidenceDigest: DigestEnvelopeV1
  readonly completion: 'COMPLETE' | 'INCOMPLETE'
  readonly decision: ProtectedSourceSliceSecretReviewDecisionV1
  readonly findingCount: number
}

export interface ProtectedSourceSliceSecretReviewV1
  extends ProtectedSourceSliceSecretReviewCoreV1 {
  readonly secretReviewDigest: DigestEnvelopeV1
}

export interface AdmitQualifiedSourceSliceSecretReviewOptionsV1 {
  readonly material: ProtectedSourceSliceMaterialV1
  readonly redaction: ProtectedSourceSliceRedactionV1
  readonly assessmentMode: AssessmentMode
  readonly portfolioEntry: AnalyzerPortfolioEntryV1
  readonly contribution: AnalyzerContributionV1
}

export interface ProtectedSourceSliceSecretReviewBindingsV1 {
  readonly requestDigest: DigestEnvelopeV1
  readonly subjectDigest: DigestEnvelopeV1
  readonly sourceDigest: DigestEnvelopeV1
  readonly path: string
  readonly redactionDigest: DigestEnvelopeV1
  readonly redactedDigest: DigestEnvelopeV1
  readonly assessmentMode: AssessmentMode
}

const subjectRelativePathSchema = z.string().min(1).max(1024).refine(path => (
  !path.startsWith('/')
  && !path.startsWith('\\')
  && !/^[a-z]:/iu.test(path)
  && !path.includes('\\')
  && path.split('/').every(segment => segment.length > 0 && segment !== '.' && segment !== '..')
), 'Source Slice secret reviews require a canonical Subject-relative path')

const secretReviewEvidenceV1Schema: z.ZodType<SourceSliceSecretReviewEvidenceV1> = z.strictObject({
  schemaVersion: z.literal(1),
  contractId: z.literal(SOURCE_SLICE_SECRET_REVIEW_CONTRACT_ID),
  reviewedAt: z.iso.datetime({ offset: true }),
  scope: z.literal('EXACT_REDACTED_SOURCE_SLICE'),
  requestDigest: digestEnvelopeV1Schema,
  subjectDigest: digestEnvelopeV1Schema,
  sourceDigest: digestEnvelopeV1Schema,
  path: subjectRelativePathSchema,
  redactionDigest: digestEnvelopeV1Schema,
  redactedDigest: digestEnvelopeV1Schema,
  independenceEvidenceDigest: digestEnvelopeV1Schema,
  completion: z.enum(['COMPLETE', 'INCOMPLETE']),
  decision: z.enum(['CLEAR', 'SECRET_FOUND', 'INDETERMINATE']),
  findingCount: z.number().int().nonnegative().max(4096),
}).superRefine((evidence, context) => {
  if (
    evidence.decision === 'CLEAR'
      ? evidence.completion !== 'COMPLETE' || evidence.findingCount !== 0
      : evidence.decision === 'SECRET_FOUND'
        ? evidence.completion !== 'COMPLETE' || evidence.findingCount === 0
        : evidence.completion !== 'INCOMPLETE'
  ) {
    context.addIssue({ code: 'custom', message: 'Secret review decision contradicts completion or findings' })
  }
})

export const protectedSourceSliceSecretReviewV1Schema: z.ZodType<ProtectedSourceSliceSecretReviewV1> = z.strictObject({
  schemaVersion: z.literal(1),
  contractId: z.literal(SOURCE_SLICE_SECRET_REVIEW_CONTRACT_ID),
  requestDigest: digestEnvelopeV1Schema,
  subjectDigest: digestEnvelopeV1Schema,
  sourceDigest: digestEnvelopeV1Schema,
  path: subjectRelativePathSchema,
  redactionDigest: digestEnvelopeV1Schema,
  redactedDigest: digestEnvelopeV1Schema,
  analyzerIdentity: analyzerIdentityV1Schema,
  qualificationId: z.string().min(3).max(128),
  qualificationDigest: digestEnvelopeV1Schema,
  assessmentMode: assessmentModeSchema,
  platform: repositoryPlatformSchema,
  reviewedAt: z.iso.datetime({ offset: true }),
  evidenceArtifactId: z.string().regex(/^[a-z0-9][a-z0-9-]{0,127}$/),
  reviewEvidenceDigest: digestEnvelopeV1Schema,
  independenceEvidenceDigest: digestEnvelopeV1Schema,
  completion: z.enum(['COMPLETE', 'INCOMPLETE']),
  decision: z.enum(['CLEAR', 'SECRET_FOUND', 'INDETERMINATE']),
  findingCount: z.number().int().nonnegative().max(4096),
  secretReviewDigest: digestEnvelopeV1Schema,
})

function sameDigest(left: DigestEnvelopeV1, right: DigestEnvelopeV1): boolean {
  return canonicalJson(left) === canonicalJson(right)
}

function qualificationDigestIsValid(portfolioEntry: AnalyzerPortfolioEntryV1): boolean {
  const qualification = portfolioEntry.qualification
  if (qualification === null) return false
  const { qualificationDigest, ...core } = qualification
  return qualificationDigest.mediaType === 'application/vnd.dsh.security.analyzer-qualification+json'
    && sameDigest(qualificationDigest, structuredDigest(qualificationDigest.mediaType, core))
}

function exactBindings(
  evidence: SourceSliceSecretReviewEvidenceV1,
  material: ProtectedSourceSliceMaterialV1,
  redaction: ProtectedSourceSliceRedactionV1,
): boolean {
  return evidence.path === material.path
    && sameDigest(evidence.requestDigest, material.requestDigest)
    && sameDigest(evidence.subjectDigest, material.subjectDigest)
    && sameDigest(evidence.sourceDigest, material.digest)
    && sameDigest(evidence.redactionDigest, redaction.redactionDigest)
    && sameDigest(evidence.redactedDigest, redaction.redactedDigest)
}

/**
 * Admit one Analyzer result only after rechecking the exact redacted artifact,
 * frozen Kernel eligibility and Host-attested independence Evidence.
 */
export function admitQualifiedSourceSliceSecretReview(
  options: AdmitQualifiedSourceSliceSecretReviewOptionsV1,
): ProtectedSourceSliceSecretReviewV1 {
  const redaction = parseProtectedSourceSliceRedaction(options.redaction, options.material)
  const portfolioEntry = analyzerPortfolioEntryV1Schema.parse(options.portfolioEntry)
  const contribution = analyzerContributionV1Schema.parse(options.contribution)
  const qualification = portfolioEntry.qualification
  const eligibility = portfolioEntry.eligibility
  if (
    qualification === null
    || eligibility.decision !== 'ELIGIBLE'
    || eligibility.reason !== null
    || !qualificationDigestIsValid(portfolioEntry)
    || eligibility.policyId !== SOURCE_SLICE_SECRET_REVIEW_POLICY_ID
    || eligibility.assessmentMode !== options.assessmentMode
    || eligibility.qualificationId !== qualification.qualificationId
    || !sameDigest(eligibility.qualificationDigest!, qualification.qualificationDigest)
    || Date.parse(eligibility.evaluatedAt) < Date.parse(qualification.issuedAt)
    || Date.parse(eligibility.evaluatedAt) >= Date.parse(qualification.expiresAt)
    || !portfolioEntry.descriptor.supportedPolicyIds.includes(SOURCE_SLICE_SECRET_REVIEW_POLICY_ID)
    || !portfolioEntry.descriptor.supportedAssessmentModes.includes(options.assessmentMode)
    || !portfolioEntry.descriptor.coverageObligationIds.includes(SOURCE_SLICE_SECRET_REVIEW_OBLIGATION_ID)
    || !portfolioEntry.descriptor.evidenceSchemaIds.includes(SOURCE_SLICE_SECRET_REVIEW_EVIDENCE_SCHEMA_ID)
    || !qualification.supportedPolicyIds.includes(SOURCE_SLICE_SECRET_REVIEW_POLICY_ID)
    || !qualification.supportedAssessmentModes.includes(options.assessmentMode)
    || !qualification.coverageObligationIds.includes(SOURCE_SLICE_SECRET_REVIEW_OBLIGATION_ID)
    || !qualification.evidenceSchemaIds.includes(SOURCE_SLICE_SECRET_REVIEW_EVIDENCE_SCHEMA_ID)
    || !qualification.platforms.includes(eligibility.platform)
    || !qualification.supportedEcosystemIds.includes('source-slice-redacted-text')
    || qualification.executionBackendId !== 'dsh/security-assurance/in-process-pure-v1'
    || !qualification.providerIds.includes(SECURITY_ASSURANCE_PRODUCT_NAME)
  ) {
    throw new TypeError('Source Slice secret review Analyzer qualification is not eligible for this exact scope')
  }
  const descriptorIdentity = {
    analyzerId: portfolioEntry.descriptor.analyzerId,
    analyzerVersion: portfolioEntry.descriptor.analyzerVersion,
    descriptorSchemaVersion: portfolioEntry.descriptor.descriptorSchemaVersion,
    buildDigest: portfolioEntry.descriptor.buildDigest,
  }
  if (canonicalJson(contribution.analyzerIdentity) !== canonicalJson(descriptorIdentity)) {
    throw new TypeError('Source Slice secret review Contribution has the wrong Analyzer identity')
  }
  if (
    !sameDigest(contribution.subjectDigest, redaction.redactedDigest)
    || contribution.evidence.length !== 1
    || contribution.candidateFindings.length !== 0
    || contribution.resourceUse.filesRead !== 1
    || contribution.resourceUse.bytesRead !== redaction.redactedDigest.byteLength
  ) {
    throw new TypeError('Source Slice secret review Contribution does not cover one exact redacted artifact')
  }
  const evidenceDraft = contribution.evidence[0]!
  if (
    evidenceDraft.schemaId !== SOURCE_SLICE_SECRET_REVIEW_EVIDENCE_SCHEMA_ID
    || evidenceDraft.mediaType !== SOURCE_SLICE_SECRET_REVIEW_EVIDENCE_MEDIA_TYPE
  ) {
    throw new TypeError('Source Slice secret review Evidence uses an unsupported contract')
  }
  const evidence = secretReviewEvidenceV1Schema.parse(evidenceDraft.value)
  const completeClaim = contribution.coverageClaims.filter(claim => (
    claim.obligationId === SOURCE_SLICE_SECRET_REVIEW_OBLIGATION_ID
    && claim.evidenceArtifactId === evidenceDraft.artifactId
  ))
  if (
    !exactBindings(evidence, options.material, redaction)
    || evidence.reviewedAt !== eligibility.evaluatedAt
    || evidence.independenceEvidenceDigest.mediaType
      !== SOURCE_SLICE_SECRET_REVIEW_INDEPENDENCE_MEDIA_TYPE
    || !qualification.evidenceDigests.some(digest => sameDigest(
      digest,
      evidence.independenceEvidenceDigest,
    ))
    || sameDigest(evidence.independenceEvidenceDigest, portfolioEntry.descriptor.buildDigest)
    || (evidence.completion === 'COMPLETE'
      ? contribution.completionDisposition !== 'COMPLETE'
        || completeClaim.length !== 1
        || contribution.coverageClaims.length !== 1
      : contribution.completionDisposition !== 'INCOMPLETE'
        || completeClaim.length !== 0
        || contribution.coverageClaims.length !== 0
        || contribution.diagnostics.length === 0)
  ) {
    throw new TypeError('Source Slice secret review Evidence is incomplete, stale or not independently qualified')
  }
  const core: ProtectedSourceSliceSecretReviewCoreV1 = {
    schemaVersion: 1,
    contractId: SOURCE_SLICE_SECRET_REVIEW_CONTRACT_ID,
    requestDigest: evidence.requestDigest,
    subjectDigest: evidence.subjectDigest,
    sourceDigest: evidence.sourceDigest,
    path: evidence.path,
    redactionDigest: evidence.redactionDigest,
    redactedDigest: evidence.redactedDigest,
    analyzerIdentity: contribution.analyzerIdentity,
    qualificationId: qualification.qualificationId,
    qualificationDigest: qualification.qualificationDigest,
    assessmentMode: options.assessmentMode,
    platform: eligibility.platform,
    reviewedAt: evidence.reviewedAt,
    evidenceArtifactId: evidenceDraft.artifactId,
    reviewEvidenceDigest: structuredDigest(evidenceDraft.mediaType, evidence),
    independenceEvidenceDigest: evidence.independenceEvidenceDigest,
    completion: evidence.completion,
    decision: evidence.decision,
    findingCount: evidence.findingCount,
  }
  return deepFreeze({
    ...core,
    secretReviewDigest: structuredDigest(SOURCE_SLICE_SECRET_REVIEW_MEDIA_TYPE, core),
  })
}

/** Recompute the immutable record and bind it to one exact redaction lineage. */
export function parseProtectedSourceSliceSecretReview(
  candidate: unknown,
  expected: ProtectedSourceSliceSecretReviewBindingsV1,
): ProtectedSourceSliceSecretReviewV1 {
  const review = protectedSourceSliceSecretReviewV1Schema.parse(candidate)
  if (
    review.path !== expected.path
    || review.assessmentMode !== expected.assessmentMode
    || !sameDigest(review.requestDigest, expected.requestDigest)
    || !sameDigest(review.subjectDigest, expected.subjectDigest)
    || !sameDigest(review.sourceDigest, expected.sourceDigest)
    || !sameDigest(review.redactionDigest, expected.redactionDigest)
    || !sameDigest(review.redactedDigest, expected.redactedDigest)
  ) {
    throw new TypeError('Source Slice secret review does not bind its expected redaction inputs')
  }
  if (
    review.redactionDigest.mediaType !== SOURCE_SLICE_REDACTION_MEDIA_TYPE
    || review.reviewEvidenceDigest.mediaType !== SOURCE_SLICE_SECRET_REVIEW_EVIDENCE_MEDIA_TYPE
    || review.independenceEvidenceDigest.mediaType !== SOURCE_SLICE_SECRET_REVIEW_INDEPENDENCE_MEDIA_TYPE
  ) {
    throw new TypeError('Source Slice secret review digest lineage is invalid')
  }
  if (
    review.decision === 'CLEAR'
      ? review.completion !== 'COMPLETE' || review.findingCount !== 0
      : review.decision === 'SECRET_FOUND'
        ? review.completion !== 'COMPLETE' || review.findingCount === 0
        : review.completion !== 'INCOMPLETE'
  ) {
    throw new TypeError('Source Slice secret review decision is invalid')
  }
  const { secretReviewDigest, ...core } = review
  const observedDigest = structuredDigest(SOURCE_SLICE_SECRET_REVIEW_MEDIA_TYPE, core)
  if (!sameDigest(secretReviewDigest, observedDigest)) {
    throw new TypeError('Source Slice secret review digest does not bind its canonical content')
  }
  return deepFreeze({ ...core, secretReviewDigest })
}
