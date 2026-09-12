import { z } from 'zod'
import type {
  AnalyzerContributionV1,
  AnalyzerPortfolioEntryV1,
} from '../analyzer.ts'
import type { DigestEnvelopeV1 } from '../contracts.ts'
import { digestEnvelopeV1Schema } from '../contracts.ts'
import type { RoleContextGrantV1 } from '../role-context-grant.ts'
import { parseRoleContextGrantV1 } from '../role-context-grant.ts'
import type {
  SourceSliceMaterialCheckV1,
  SourceSliceRequestV1,
} from '../source-slice-request.ts'
import { parseSourceSliceRequestV1 } from '../source-slice-request.ts'
import { canonicalJson, structuredDigest } from './canonical.ts'
import { deepFreeze } from './freeze.ts'
import {
  parseProtectedSourceSliceEgressReview,
  deriveProtectedSourceSliceEgressDisposition,
  redactProtectedSourceSliceSecrets,
  reviewProtectedSourceSliceEgress,
  SOURCE_SLICE_EGRESS_REVIEW_MEDIA_TYPE,
  SOURCE_SLICE_REDACTION_MEDIA_TYPE,
  type ProtectedSourceSliceEgressReasonV1,
} from './source-slice-protection.ts'
import {
  classifyProtectedSourceSliceSensitivity,
  deriveProtectedSourceSliceSensitivity,
  parseProtectedSourceSliceSensitivity,
  SOURCE_SLICE_SENSITIVITY_CLASSIFICATION_MEDIA_TYPE,
  SOURCE_SLICE_SENSITIVITY_CLASSIFIER_ID,
  SOURCE_SLICE_SENSITIVITY_CLASSIFIER_VERSION,
  type SourceSliceSensitivityCategoryV1,
  type SourceSliceSensitivityIndicatorV1,
} from './source-slice-sensitivity.ts'
import type { ProtectedSourceSliceSecretReviewV1 } from './source-slice-secret-review.ts'
import {
  admitQualifiedSourceSliceSecretReview,
  parseProtectedSourceSliceSecretReview,
  protectedSourceSliceSecretReviewV1Schema,
  SOURCE_SLICE_SECRET_REVIEW_MEDIA_TYPE,
} from './source-slice-secret-review.ts'
import { readVerifiedRequestedSourceSlice } from './subject-freeze.ts'

export const SOURCE_SLICE_MATERIAL_REVIEW_MEDIA_TYPE =
  'application/vnd.dsh.security.source-slice-material-review+json'

const MATERIAL_CHECKS = [
  'SUBJECT_CONTAINMENT',
  'SOURCE_DIGEST_INTEGRITY',
  'SENSITIVITY_CLASSIFICATION',
  'SECRET_REDACTION',
  'DATA_EGRESS',
  'ACTUAL_BUDGET',
  'ROLE_NEED',
] as const satisfies readonly SourceSliceMaterialCheckV1[]

export type ProtectedSourceSliceMaterialReviewStatusV1 =
  | 'SATISFIED'
  | 'REVIEW_REQUIRED'
  | 'REJECTED'

export type ProtectedSourceSliceMaterialReviewReasonV1 =
  | ProtectedSourceSliceEgressReasonV1
  | 'TOKEN_METERING_REQUIRED'
  | 'ROLE_NEED_VALIDATION_REQUIRED'

export interface ProtectedSourceSliceMaterialReviewCheckV1 {
  readonly check: SourceSliceMaterialCheckV1
  readonly status: ProtectedSourceSliceMaterialReviewStatusV1
  readonly reasonCodes: readonly ProtectedSourceSliceMaterialReviewReasonV1[]
}

export interface ProtectedSourceSliceMaterialReviewCoreV1 {
  readonly schemaVersion: 1
  readonly path: string
  readonly sensitivity: {
    readonly classifierId: typeof SOURCE_SLICE_SENSITIVITY_CLASSIFIER_ID
    readonly classifierVersion: typeof SOURCE_SLICE_SENSITIVITY_CLASSIFIER_VERSION
    readonly category: SourceSliceSensitivityCategoryV1
    readonly indicatorCodes: readonly SourceSliceSensitivityIndicatorV1[]
    readonly classificationDigest: DigestEnvelopeV1
  }
  readonly contextGrantDigest: DigestEnvelopeV1
  readonly requestDigest: DigestEnvelopeV1
  readonly subjectDigest: DigestEnvelopeV1
  readonly sourceDigest: DigestEnvelopeV1
  readonly secretInspectionDigest: DigestEnvelopeV1
  readonly redactionDigest: DigestEnvelopeV1
  readonly redactedDigest: DigestEnvelopeV1
  readonly egressReviewDigest: DigestEnvelopeV1
  readonly secretReview: ProtectedSourceSliceSecretReviewV1 | null
  readonly policies: {
    readonly detectorPolicyId: string
    readonly redactionPolicyId: string
    readonly dataEgressPolicyId: string
    readonly destinationId: string
    readonly categoryId: string
  }
  readonly observed: {
    readonly sourceBytes: number
    readonly redactedBytes: number
    readonly requestedContextBytes: number
    readonly requestedTokens: number
    readonly secretFindingCount: number
  }
  readonly redactionDecision: 'REDACTED_MATCHES_REVIEW_REQUIRED' | 'ADDITIONAL_REVIEW_REQUIRED'
  readonly egressDecision: 'REJECTED' | 'BROKER_REVIEW_REQUIRED'
  readonly decision: 'REJECTED' | 'ADDITIONAL_REVIEW_REQUIRED'
  readonly checks: readonly ProtectedSourceSliceMaterialReviewCheckV1[]
}

export interface ProtectedSourceSliceMaterialReviewV1
  extends ProtectedSourceSliceMaterialReviewCoreV1 {
  readonly materialReviewDigest: DigestEnvelopeV1
}

export interface ReviewRequestedSourceSliceMaterialOptionsV1 {
  readonly securityRoot: string
  readonly contextGrant: RoleContextGrantV1
  readonly request: SourceSliceRequestV1
  readonly fingerprintKey: Uint8Array
  readonly fingerprintKeyId: string
  readonly secretReview?: {
    readonly portfolioEntry: AnalyzerPortfolioEntryV1
    readonly contribution: AnalyzerContributionV1
  } | undefined
  readonly signal?: AbortSignal | undefined
}

export interface ProtectedSourceSliceMaterialReviewBindingsV1 {
  readonly contextGrantDigest: DigestEnvelopeV1
  readonly requestDigest: DigestEnvelopeV1
  readonly subjectDigest: DigestEnvelopeV1
  readonly secretReview?: ProtectedSourceSliceSecretReviewV1 | undefined
}

const reviewReasonV1Schema = z.enum([
  'POLICY_DENIES_EGRESS',
  'REDACTED_BYTE_BUDGET_EXCEEDED',
  'SECRET_REVIEW_INCOMPLETE',
  'RESIDUAL_SECRET_DETECTED',
  'BROKER_QUALIFICATION_REQUIRED',
  'DESTINATION_AUTHORIZATION_REQUIRED',
  'TOKEN_METERING_REQUIRED',
  'ROLE_NEED_VALIDATION_REQUIRED',
])
const boundedIdSchema = z.string().regex(/^[a-z0-9][a-z0-9._/-]{0,127}$/iu)
const subjectRelativePathSchema = z.string().min(1).max(1024).refine(path => (
  !path.startsWith('/')
  && !path.startsWith('\\')
  && !/^[a-z]:/iu.test(path)
  && !path.includes('\\')
  && path.split('/').every(segment => segment.length > 0 && segment !== '.' && segment !== '..')
), 'Source Slice material reviews require a canonical Subject-relative path')

const materialReviewV1Schema = z.strictObject({
  schemaVersion: z.literal(1),
  path: subjectRelativePathSchema,
  sensitivity: z.strictObject({
    classifierId: z.literal(SOURCE_SLICE_SENSITIVITY_CLASSIFIER_ID),
    classifierVersion: z.literal(SOURCE_SLICE_SENSITIVITY_CLASSIFIER_VERSION),
    category: z.enum(['PROTECTED_SOURCE', 'RESTRICTED_SOURCE', 'SECRET_BEARING_SOURCE']),
    indicatorCodes: z.array(z.enum([
      'BASELINE_SOURCE_PROTECTION',
      'SENSITIVE_PATH',
      'HIGH_CONFIDENCE_SECRET_MATCH',
    ])).length(1),
    classificationDigest: digestEnvelopeV1Schema,
  }),
  contextGrantDigest: digestEnvelopeV1Schema,
  requestDigest: digestEnvelopeV1Schema,
  subjectDigest: digestEnvelopeV1Schema,
  sourceDigest: digestEnvelopeV1Schema,
  secretInspectionDigest: digestEnvelopeV1Schema,
  redactionDigest: digestEnvelopeV1Schema,
  redactedDigest: digestEnvelopeV1Schema,
  egressReviewDigest: digestEnvelopeV1Schema,
  secretReview: protectedSourceSliceSecretReviewV1Schema.nullable(),
  policies: z.strictObject({
    detectorPolicyId: boundedIdSchema,
    redactionPolicyId: boundedIdSchema,
    dataEgressPolicyId: boundedIdSchema,
    destinationId: boundedIdSchema,
    categoryId: boundedIdSchema,
  }),
  observed: z.strictObject({
    sourceBytes: z.number().int().nonnegative().max(1024 * 1024),
    redactedBytes: z.number().int().nonnegative().max(2 * 1024 * 1024),
    requestedContextBytes: z.number().int().positive().max(64 * 1024 * 1024),
    requestedTokens: z.number().int().positive().max(4_000_000),
    secretFindingCount: z.number().int().nonnegative().max(4096),
  }),
  redactionDecision: z.enum(['REDACTED_MATCHES_REVIEW_REQUIRED', 'ADDITIONAL_REVIEW_REQUIRED']),
  egressDecision: z.enum(['REJECTED', 'BROKER_REVIEW_REQUIRED']),
  decision: z.enum(['REJECTED', 'ADDITIONAL_REVIEW_REQUIRED']),
  checks: z.array(z.strictObject({
    check: z.enum(MATERIAL_CHECKS),
    status: z.enum(['SATISFIED', 'REVIEW_REQUIRED', 'REJECTED']),
    reasonCodes: z.array(reviewReasonV1Schema).max(5),
  })).length(7),
  materialReviewDigest: digestEnvelopeV1Schema,
})

function sameDigest(left: DigestEnvelopeV1, right: DigestEnvelopeV1): boolean {
  return canonicalJson(left) === canonicalJson(right)
}

function materialChecks(
  secretReview: ProtectedSourceSliceSecretReviewV1 | null,
  egressDecision: ProtectedSourceSliceMaterialReviewCoreV1['egressDecision'],
  egressReasons: readonly ProtectedSourceSliceEgressReasonV1[],
): ProtectedSourceSliceMaterialReviewCheckV1[] {
  const byteBudgetExceeded = egressReasons.includes('REDACTED_BYTE_BUDGET_EXCEEDED')
  return [
    { check: 'SUBJECT_CONTAINMENT', status: 'SATISFIED', reasonCodes: [] },
    { check: 'SOURCE_DIGEST_INTEGRITY', status: 'SATISFIED', reasonCodes: [] },
    {
      check: 'SENSITIVITY_CLASSIFICATION',
      status: 'SATISFIED',
      reasonCodes: [],
    },
    secretReview?.decision === 'CLEAR'
      ? { check: 'SECRET_REDACTION', status: 'SATISFIED', reasonCodes: [] }
      : secretReview?.decision === 'SECRET_FOUND'
        ? {
            check: 'SECRET_REDACTION',
            status: 'REJECTED',
            reasonCodes: ['RESIDUAL_SECRET_DETECTED'],
          }
        : {
            check: 'SECRET_REDACTION',
            status: 'REVIEW_REQUIRED',
            reasonCodes: ['SECRET_REVIEW_INCOMPLETE'],
          },
    {
      check: 'DATA_EGRESS',
      status: egressDecision === 'REJECTED' ? 'REJECTED' : 'REVIEW_REQUIRED',
      reasonCodes: [...egressReasons],
    },
    byteBudgetExceeded
      ? {
          check: 'ACTUAL_BUDGET',
          status: 'REJECTED',
          reasonCodes: ['REDACTED_BYTE_BUDGET_EXCEEDED'],
        }
      : {
          check: 'ACTUAL_BUDGET',
          status: 'REVIEW_REQUIRED',
          reasonCodes: ['TOKEN_METERING_REQUIRED'],
        },
    {
      check: 'ROLE_NEED',
      status: 'REVIEW_REQUIRED',
      reasonCodes: ['ROLE_NEED_VALIDATION_REQUIRED'],
    },
  ]
}

function reviewDecision(
  checks: readonly ProtectedSourceSliceMaterialReviewCheckV1[],
): ProtectedSourceSliceMaterialReviewCoreV1['decision'] {
  return checks.some(check => check.status === 'REJECTED')
    ? 'REJECTED'
    : 'ADDITIONAL_REVIEW_REQUIRED'
}

/**
 * Re-run the protected local read, redaction and egress review as one deep
 * operation, then retain only a digest-bound review record without source text.
 */
export async function reviewRequestedSourceSliceMaterial(
  options: ReviewRequestedSourceSliceMaterialOptionsV1,
): Promise<ProtectedSourceSliceMaterialReviewV1> {
  const contextGrant = parseRoleContextGrantV1(options.contextGrant)
  const request = parseSourceSliceRequestV1(options.request)
  if (!(options.fingerprintKey instanceof Uint8Array) || options.fingerprintKey.byteLength < 32) {
    throw new TypeError('Secret fingerprint keys must contain at least 32 bytes')
  }
  const fingerprintKey = Buffer.from(options.fingerprintKey)
  try {
    const material = await readVerifiedRequestedSourceSlice({
      securityRoot: options.securityRoot,
      contextGrant,
      request,
      signal: options.signal,
    })
    const redaction = redactProtectedSourceSliceSecrets({
      material,
      fingerprintKey,
      fingerprintKeyId: options.fingerprintKeyId,
    })
    const classification = parseProtectedSourceSliceSensitivity(
      classifyProtectedSourceSliceSensitivity({ material, redaction }),
      { material, redaction },
    )
    const secretReview = options.secretReview === undefined
      ? null
      : admitQualifiedSourceSliceSecretReview({
          material,
          redaction,
          assessmentMode: contextGrant.purpose.assessmentMode,
          portfolioEntry: options.secretReview.portfolioEntry,
          contribution: options.secretReview.contribution,
        })
    const egressReview = reviewProtectedSourceSliceEgress({
      contextGrant,
      request,
      material,
      redaction,
      secretReview: secretReview ?? undefined,
    })
    const parsedEgressReview = parseProtectedSourceSliceEgressReview(egressReview, {
      contextGrantDigest: contextGrant.grantDigest,
      requestDigest: request.requestDigest,
      redactionDigest: redaction.redactionDigest,
      secretReview: secretReview ?? undefined,
    })
    const checks = materialChecks(
      secretReview,
      parsedEgressReview.decision,
      parsedEgressReview.reasonCodes,
    )
    const core: ProtectedSourceSliceMaterialReviewCoreV1 = {
      schemaVersion: 1,
      path: material.path,
      sensitivity: {
        classifierId: classification.classifierId,
        classifierVersion: classification.classifierVersion,
        category: classification.category,
        indicatorCodes: classification.indicatorCodes,
        classificationDigest: classification.classificationDigest,
      },
      contextGrantDigest: parsedEgressReview.contextGrantDigest,
      requestDigest: material.requestDigest,
      subjectDigest: material.subjectDigest,
      sourceDigest: material.digest,
      secretInspectionDigest: redaction.inspectionDigest,
      redactionDigest: redaction.redactionDigest,
      redactedDigest: redaction.redactedDigest,
      egressReviewDigest: parsedEgressReview.egressReviewDigest,
      secretReview,
      policies: {
        detectorPolicyId: redaction.detectorPolicyId,
        redactionPolicyId: redaction.redactionPolicyId,
        dataEgressPolicyId: parsedEgressReview.disclosure.dataEgressPolicyId,
        destinationId: parsedEgressReview.disclosure.destinationId,
        categoryId: parsedEgressReview.disclosure.categoryId,
      },
      observed: {
        sourceBytes: material.digest.byteLength,
        redactedBytes: redaction.redactedDigest.byteLength,
        requestedContextBytes: parsedEgressReview.requestedContextBytes,
        requestedTokens: request.budget.tokens,
        secretFindingCount: redaction.redactions.length,
      },
      redactionDecision: redaction.decision,
      egressDecision: parsedEgressReview.decision,
      decision: reviewDecision(checks),
      checks,
    }
    return deepFreeze({
      ...core,
      materialReviewDigest: structuredDigest(SOURCE_SLICE_MATERIAL_REVIEW_MEDIA_TYPE, core),
    })
  } finally {
    fingerprintKey.fill(0)
  }
}

/** Validate the canonical review matrix and exact upstream Grant, Request and Subject. */
export function parseProtectedSourceSliceMaterialReview(
  candidate: unknown,
  expectedBindings: ProtectedSourceSliceMaterialReviewBindingsV1,
): ProtectedSourceSliceMaterialReviewV1 {
  const review = materialReviewV1Schema.parse(candidate)
  if (
    !sameDigest(review.contextGrantDigest, expectedBindings.contextGrantDigest)
    || !sameDigest(review.requestDigest, expectedBindings.requestDigest)
    || !sameDigest(review.subjectDigest, expectedBindings.subjectDigest)
  ) {
    throw new TypeError('Source Slice material review does not bind its expected inputs')
  }
  if ((review.secretReview === null) !== (expectedBindings.secretReview === undefined)) {
    throw new TypeError('Source Slice material review does not bind its expected secret review')
  }
  if (review.secretReview !== null && expectedBindings.secretReview !== undefined) {
    const secretReviewBindings = {
      requestDigest: review.requestDigest,
      subjectDigest: review.subjectDigest,
      sourceDigest: review.sourceDigest,
      path: review.path,
      redactionDigest: review.redactionDigest,
      redactedDigest: review.redactedDigest,
      assessmentMode: review.secretReview.assessmentMode,
    }
    const embeddedSecretReview = parseProtectedSourceSliceSecretReview(
      review.secretReview,
      secretReviewBindings,
    )
    const expectedSecretReview = parseProtectedSourceSliceSecretReview(
      expectedBindings.secretReview,
      secretReviewBindings,
    )
    if (!sameDigest(embeddedSecretReview.secretReviewDigest, expectedSecretReview.secretReviewDigest)) {
      throw new TypeError('Source Slice material review secret review binding is invalid')
    }
  }
  if (
    review.redactionDigest.mediaType !== SOURCE_SLICE_REDACTION_MEDIA_TYPE
    || review.egressReviewDigest.mediaType !== SOURCE_SLICE_EGRESS_REVIEW_MEDIA_TYPE
    || review.sensitivity.classificationDigest.mediaType
      !== SOURCE_SLICE_SENSITIVITY_CLASSIFICATION_MEDIA_TYPE
    || (review.secretReview !== null
      && review.secretReview.secretReviewDigest.mediaType !== SOURCE_SLICE_SECRET_REVIEW_MEDIA_TYPE)
    || review.observed.sourceBytes !== review.sourceDigest.byteLength
    || review.observed.redactedBytes !== review.redactedDigest.byteLength
  ) {
    throw new TypeError('Source Slice material review digest lineage is invalid')
  }
  const egressCheck = review.checks.find(check => check.check === 'DATA_EGRESS')
  if (egressCheck === undefined) {
    throw new TypeError('Source Slice material review omits its Data Egress check')
  }
  const disposition = deriveProtectedSourceSliceEgressDisposition(
    review.policies.dataEgressPolicyId,
    review.observed.redactedBytes,
    review.observed.requestedContextBytes,
    review.secretReview?.decision ?? null,
  )
  if (
    review.egressDecision !== disposition.decision
    || canonicalJson(egressCheck.reasonCodes) !== canonicalJson(disposition.reasonCodes)
  ) {
    throw new TypeError('Source Slice material review Data Egress disposition is invalid')
  }
  const sensitivity = deriveProtectedSourceSliceSensitivity(
    review.path,
    review.observed.secretFindingCount,
  )
  if (
    review.sensitivity.category !== sensitivity.category
    || canonicalJson(review.sensitivity.indicatorCodes) !== canonicalJson(sensitivity.indicatorCodes)
  ) {
    throw new TypeError('Source Slice material review sensitivity classification is invalid')
  }
  const expectedChecks = materialChecks(
    review.secretReview,
    disposition.decision,
    disposition.reasonCodes,
  )
  const expectedDecision = reviewDecision(expectedChecks)
  if (
    review.decision !== expectedDecision
    || canonicalJson(review.checks) !== canonicalJson(expectedChecks)
  ) {
    throw new TypeError('Source Slice material review decision or check matrix is invalid')
  }
  const { materialReviewDigest, ...core } = review
  const observedDigest = structuredDigest(SOURCE_SLICE_MATERIAL_REVIEW_MEDIA_TYPE, core)
  if (!sameDigest(materialReviewDigest, observedDigest)) {
    throw new TypeError('Source Slice material review digest does not bind its canonical content')
  }
  return deepFreeze({ ...core, materialReviewDigest })
}
