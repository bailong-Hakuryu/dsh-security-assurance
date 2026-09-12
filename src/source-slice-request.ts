import { z } from 'zod'
import type { AssessmentId, DigestEnvelopeV1 } from './contracts.ts'
import { assessmentIdSchema, digestEnvelopeV1Schema } from './contracts.ts'
import { canonicalJson, structuredDigest } from './internal/canonical.ts'
import { deepFreeze } from './internal/freeze.ts'
import type { RoleContextGrantV1 } from './role-context-grant.ts'
import {
  parseRoleContextGrantV1,
  ROLE_CONTEXT_GRANT_MEDIA_TYPE,
} from './role-context-grant.ts'

export const SOURCE_SLICE_REQUEST_MEDIA_TYPE =
  'application/vnd.dsh.security.source-slice-request+json'
export const SOURCE_SLICE_REQUEST_PREFLIGHT_MEDIA_TYPE =
  'application/vnd.dsh.security.source-slice-request-preflight+json'

const SUBJECT_MANIFEST_MEDIA_TYPE = 'application/vnd.dsh.security.subject-manifest+json'
const SOURCE_BYTES_MEDIA_TYPE = 'application/octet-stream'
const boundedIdSchema = z.string().regex(/^[a-z0-9][a-z0-9._/-]{0,127}$/i)
const requestIdSchema = z.string().regex(/^slice-request-[0-9a-f-]{36}$/)
const roleAttemptIdSchema = z.string().regex(/^role-attempt-[0-9a-f-]{36}$/)
const subjectRelativePathSchema = z.string().min(1).max(1024).refine(path => (
  !path.startsWith('/')
  && !path.startsWith('\\')
  && !/^[a-z]:/iu.test(path)
  && !path.includes('\\')
  && path.split('/').every(segment => segment.length > 0 && segment !== '.' && segment !== '..')
), 'Source Slice Requests require a canonical Subject-relative path')

const contextGrantDigestSchema = digestEnvelopeV1Schema.refine(
  digest => digest.mediaType === ROLE_CONTEXT_GRANT_MEDIA_TYPE,
  'Source Slice Requests must bind a Role Context Grant digest',
)
const subjectDigestSchema = digestEnvelopeV1Schema.refine(
  digest => digest.mediaType === SUBJECT_MANIFEST_MEDIA_TYPE,
  'Source Slice Requests must bind a Subject Manifest digest',
)
const sourceBytesDigestSchema = digestEnvelopeV1Schema.refine(digest => (
  digest.mediaType === SOURCE_BYTES_MEDIA_TYPE
  && digest.canonicalization === 'raw-bytes'
), 'Source Slice Requests must bind raw source bytes')
const sourceSliceRequestDigestSchema = digestEnvelopeV1Schema.refine(
  digest => digest.mediaType === SOURCE_SLICE_REQUEST_MEDIA_TYPE,
  'Source Slice Request digests must use the request media type',
)

export interface SourceSliceRequestCoreV1 {
  readonly schemaVersion: 1
  readonly requestId: string
  readonly assessmentId: AssessmentId
  readonly roleAttemptId: string
  readonly contextGrantDigest: DigestEnvelopeV1
  readonly subjectDigest: DigestEnvelopeV1
  readonly purpose: {
    readonly purposeId: string
    readonly coverageObligationId: string
    readonly needId: string
  }
  readonly target: {
    readonly path: string
    readonly expectedSourceDigest: DigestEnvelopeV1
  }
  readonly disclosure: {
    readonly dataEgressPolicyId: string
    readonly destinationId: string
    readonly categoryId: string
  }
  readonly budget: {
    readonly contextBytes: number
    readonly tokens: number
  }
}

const sourceSliceRequestCoreV1Shape = {
  schemaVersion: z.literal(1),
  requestId: requestIdSchema,
  assessmentId: assessmentIdSchema,
  roleAttemptId: roleAttemptIdSchema,
  contextGrantDigest: contextGrantDigestSchema,
  subjectDigest: subjectDigestSchema,
  purpose: z.strictObject({
    purposeId: boundedIdSchema,
    coverageObligationId: boundedIdSchema,
    needId: boundedIdSchema,
  }),
  target: z.strictObject({
    path: subjectRelativePathSchema,
    expectedSourceDigest: sourceBytesDigestSchema,
  }),
  disclosure: z.strictObject({
    dataEgressPolicyId: boundedIdSchema,
    destinationId: boundedIdSchema,
    categoryId: boundedIdSchema,
  }),
  budget: z.strictObject({
    contextBytes: z.number().int().positive().max(64 * 1024 * 1024),
    tokens: z.number().int().positive().max(4_000_000),
  }),
} as const

export const sourceSliceRequestCoreV1Schema: z.ZodType<SourceSliceRequestCoreV1> =
  z.strictObject(sourceSliceRequestCoreV1Shape)

export interface SourceSliceRequestV1 extends SourceSliceRequestCoreV1 {
  readonly requestDigest: DigestEnvelopeV1
}

export const sourceSliceRequestV1Schema: z.ZodType<SourceSliceRequestV1> = z.strictObject({
  ...sourceSliceRequestCoreV1Shape,
  requestDigest: sourceSliceRequestDigestSchema,
})

/** Create immutable request metadata; this function reads no Subject and grants no capability. */
export function createSourceSliceRequestV1(candidate: unknown): SourceSliceRequestV1 {
  const core = sourceSliceRequestCoreV1Schema.parse(candidate)
  return deepFreeze({
    ...core,
    requestDigest: structuredDigest(SOURCE_SLICE_REQUEST_MEDIA_TYPE, core),
  })
}

/** Validate exact request content and detach it from the caller's mutable value. */
export function parseSourceSliceRequestV1(candidate: unknown): SourceSliceRequestV1 {
  const request = sourceSliceRequestV1Schema.parse(candidate)
  const { requestDigest, ...core } = request
  const parsedCore = sourceSliceRequestCoreV1Schema.parse(core)
  const observedDigest = structuredDigest(SOURCE_SLICE_REQUEST_MEDIA_TYPE, parsedCore)
  if (
    requestDigest.mediaType !== SOURCE_SLICE_REQUEST_MEDIA_TYPE
    || canonicalJson(requestDigest) !== canonicalJson(observedDigest)
  ) {
    throw new TypeError('Source Slice Request digest does not bind its canonical content')
  }
  return deepFreeze({ ...parsedCore, requestDigest })
}

function sameDigest(left: DigestEnvelopeV1, right: DigestEnvelopeV1): boolean {
  return canonicalJson(left) === canonicalJson(right)
}

export type SourceSliceRequestPreflightReasonV1 =
  | 'ASSESSMENT_MISMATCH'
  | 'ROLE_ATTEMPT_MISMATCH'
  | 'CONTEXT_GRANT_MISMATCH'
  | 'SUBJECT_MISMATCH'
  | 'PURPOSE_MISMATCH'
  | 'OBLIGATION_NOT_GRANTED'
  | 'EGRESS_POLICY_MISMATCH'
  | 'DESTINATION_MISMATCH'
  | 'DISCLOSURE_CATEGORY_NOT_GRANTED'
  | 'CONTEXT_BYTE_BUDGET_EXCEEDED'
  | 'TOKEN_BUDGET_EXCEEDED'

export type SourceSliceMaterialCheckV1 =
  | 'SUBJECT_CONTAINMENT'
  | 'SOURCE_DIGEST_INTEGRITY'
  | 'SENSITIVITY_CLASSIFICATION'
  | 'SECRET_REDACTION'
  | 'DATA_EGRESS'
  | 'ACTUAL_BUDGET'
  | 'ROLE_NEED'

const SOURCE_SLICE_REQUEST_PREFLIGHT_REASONS = [
  'ASSESSMENT_MISMATCH',
  'ROLE_ATTEMPT_MISMATCH',
  'CONTEXT_GRANT_MISMATCH',
  'SUBJECT_MISMATCH',
  'PURPOSE_MISMATCH',
  'OBLIGATION_NOT_GRANTED',
  'EGRESS_POLICY_MISMATCH',
  'DESTINATION_MISMATCH',
  'DISCLOSURE_CATEGORY_NOT_GRANTED',
  'CONTEXT_BYTE_BUDGET_EXCEEDED',
  'TOKEN_BUDGET_EXCEEDED',
] as const satisfies readonly SourceSliceRequestPreflightReasonV1[]
const sourceSliceRequestPreflightReasonV1Schema = z.enum(
  SOURCE_SLICE_REQUEST_PREFLIGHT_REASONS,
)
const sourceSliceMaterialCheckV1Schema = z.enum([
  'SUBJECT_CONTAINMENT',
  'SOURCE_DIGEST_INTEGRITY',
  'SENSITIVITY_CLASSIFICATION',
  'SECRET_REDACTION',
  'DATA_EGRESS',
  'ACTUAL_BUDGET',
  'ROLE_NEED',
])

const REQUIRED_MATERIAL_CHECKS: readonly SourceSliceMaterialCheckV1[] = [
  'SUBJECT_CONTAINMENT',
  'SOURCE_DIGEST_INTEGRITY',
  'SENSITIVITY_CLASSIFICATION',
  'SECRET_REDACTION',
  'DATA_EGRESS',
  'ACTUAL_BUDGET',
  'ROLE_NEED',
]

export interface SourceSliceRequestPreflightCoreV1 {
  readonly schemaVersion: 1
  readonly requestId: string
  readonly requestDigest: DigestEnvelopeV1
  readonly contextGrantDigest: DigestEnvelopeV1
  readonly decision: 'REJECTED' | 'MATERIAL_REVIEW_REQUIRED'
  readonly reasonCodes: readonly SourceSliceRequestPreflightReasonV1[]
  readonly budgetProjection: {
    readonly contextBytesRemaining: number
    readonly tokensRemaining: number
  } | null
  readonly requiredMaterialChecks: readonly SourceSliceMaterialCheckV1[]
}

const sourceSliceRequestPreflightCoreV1Shape = {
  schemaVersion: z.literal(1),
  requestId: requestIdSchema,
  requestDigest: sourceSliceRequestDigestSchema,
  contextGrantDigest: contextGrantDigestSchema,
  decision: z.enum(['REJECTED', 'MATERIAL_REVIEW_REQUIRED']),
  reasonCodes: z.array(sourceSliceRequestPreflightReasonV1Schema).max(11),
  budgetProjection: z.strictObject({
    contextBytesRemaining: z.number().int().nonnegative().max(64 * 1024 * 1024),
    tokensRemaining: z.number().int().nonnegative().max(4_000_000),
  }).nullable(),
  requiredMaterialChecks: z.array(sourceSliceMaterialCheckV1Schema).max(7),
} as const

function unique(values: readonly string[]): boolean {
  return new Set(values).size === values.length
}

function validateSourceSliceRequestPreflight(
  preflight: SourceSliceRequestPreflightCoreV1,
  context: z.RefinementCtx,
): void {
  if (!unique(preflight.reasonCodes) || !unique(preflight.requiredMaterialChecks)) {
    context.addIssue({ code: 'custom', message: 'Source Slice Request preflight arrays must be unique' })
  }
  const canonicalReasons = SOURCE_SLICE_REQUEST_PREFLIGHT_REASONS.filter(
    reason => preflight.reasonCodes.includes(reason),
  )
  if (canonicalJson(preflight.reasonCodes) !== canonicalJson(canonicalReasons)) {
    context.addIssue({
      code: 'custom',
      message: 'Source Slice Request preflight reasons must use canonical order',
    })
  }
  if (preflight.decision === 'MATERIAL_REVIEW_REQUIRED') {
    if (
      preflight.reasonCodes.length > 0
      || preflight.budgetProjection === null
      || canonicalJson(preflight.requiredMaterialChecks) !== canonicalJson(REQUIRED_MATERIAL_CHECKS)
    ) {
      context.addIssue({
        code: 'custom',
        message: 'Material review requires a clean static preflight and every protected check',
      })
    }
    return
  }
  if (
    preflight.reasonCodes.length === 0
    || preflight.budgetProjection !== null
    || preflight.requiredMaterialChecks.length > 0
  ) {
    context.addIssue({
      code: 'custom',
      message: 'Rejected Source Slice Requests must expose reasons without a budget projection',
    })
  }
}

export const sourceSliceRequestPreflightCoreV1Schema:
  z.ZodType<SourceSliceRequestPreflightCoreV1> = z.strictObject(
    sourceSliceRequestPreflightCoreV1Shape,
  ).superRefine(validateSourceSliceRequestPreflight)

export interface SourceSliceRequestPreflightV1 extends SourceSliceRequestPreflightCoreV1 {
  readonly preflightDigest: DigestEnvelopeV1
}

export const sourceSliceRequestPreflightV1Schema: z.ZodType<SourceSliceRequestPreflightV1> =
  z.strictObject({
    ...sourceSliceRequestPreflightCoreV1Shape,
    preflightDigest: digestEnvelopeV1Schema,
  }).superRefine(validateSourceSliceRequestPreflight)

export interface SourceSliceRequestPreflightInputV1 {
  readonly contextGrant: RoleContextGrantV1
  readonly request: SourceSliceRequestV1
}

export interface SourceSliceRequestPreflightBindingsV1 {
  readonly requestDigest: DigestEnvelopeV1
  readonly contextGrantDigest: DigestEnvelopeV1
}

/**
 * Perform only static admission checks. A successful result still requires
 * protected material review and never grants Subject content or capability.
 */
export function preflightSourceSliceRequestV1(
  candidate: SourceSliceRequestPreflightInputV1,
): SourceSliceRequestPreflightV1 {
  const contextGrant = parseRoleContextGrantV1(candidate.contextGrant)
  const request = parseSourceSliceRequestV1(candidate.request)
  const contextBytesRemaining =
    contextGrant.budget.contextBytes.limit - contextGrant.budget.contextBytes.granted
  const tokensRemaining = contextGrant.budget.tokens.limit - contextGrant.budget.tokens.granted
  const reasonCodes: SourceSliceRequestPreflightReasonV1[] = []
  if (request.assessmentId !== contextGrant.assessmentId) reasonCodes.push('ASSESSMENT_MISMATCH')
  if (request.roleAttemptId !== contextGrant.roleAttemptId) reasonCodes.push('ROLE_ATTEMPT_MISMATCH')
  if (!sameDigest(request.contextGrantDigest, contextGrant.grantDigest)) {
    reasonCodes.push('CONTEXT_GRANT_MISMATCH')
  }
  if (!sameDigest(request.subjectDigest, contextGrant.subject.digest)) reasonCodes.push('SUBJECT_MISMATCH')
  if (request.purpose.purposeId !== contextGrant.purpose.purposeId) reasonCodes.push('PURPOSE_MISMATCH')
  if (!contextGrant.purpose.coverageObligationIds.includes(request.purpose.coverageObligationId)) {
    reasonCodes.push('OBLIGATION_NOT_GRANTED')
  }
  if (request.disclosure.dataEgressPolicyId !== contextGrant.disclosure.dataEgressPolicyId) {
    reasonCodes.push('EGRESS_POLICY_MISMATCH')
  }
  if (request.disclosure.destinationId !== contextGrant.disclosure.destinationId) {
    reasonCodes.push('DESTINATION_MISMATCH')
  }
  if (!contextGrant.disclosure.categoryIds.includes(request.disclosure.categoryId)) {
    reasonCodes.push('DISCLOSURE_CATEGORY_NOT_GRANTED')
  }
  if (request.budget.contextBytes > contextBytesRemaining) {
    reasonCodes.push('CONTEXT_BYTE_BUDGET_EXCEEDED')
  }
  if (request.budget.tokens > tokensRemaining) reasonCodes.push('TOKEN_BUDGET_EXCEEDED')
  const materialReviewRequired = reasonCodes.length === 0
  const core: SourceSliceRequestPreflightCoreV1 = {
    schemaVersion: 1,
    requestId: request.requestId,
    requestDigest: request.requestDigest,
    contextGrantDigest: contextGrant.grantDigest,
    decision: materialReviewRequired ? 'MATERIAL_REVIEW_REQUIRED' : 'REJECTED',
    reasonCodes,
    budgetProjection: materialReviewRequired
      ? {
          contextBytesRemaining: contextBytesRemaining - request.budget.contextBytes,
          tokensRemaining: tokensRemaining - request.budget.tokens,
        }
      : null,
    requiredMaterialChecks: materialReviewRequired ? REQUIRED_MATERIAL_CHECKS : [],
  }
  return deepFreeze({
    ...core,
    preflightDigest: structuredDigest(SOURCE_SLICE_REQUEST_PREFLIGHT_MEDIA_TYPE, core),
  })
}

/** Validate a persisted preflight and bind it to the exact request and Context Grant. */
export function parseSourceSliceRequestPreflightV1(
  candidate: unknown,
  expectedBindings: SourceSliceRequestPreflightBindingsV1,
): SourceSliceRequestPreflightV1 {
  const preflight = sourceSliceRequestPreflightV1Schema.parse(candidate)
  const { preflightDigest, ...core } = preflight
  const parsedCore = sourceSliceRequestPreflightCoreV1Schema.parse(core)
  const observedDigest = structuredDigest(SOURCE_SLICE_REQUEST_PREFLIGHT_MEDIA_TYPE, parsedCore)
  if (
    preflightDigest.mediaType !== SOURCE_SLICE_REQUEST_PREFLIGHT_MEDIA_TYPE
    || !sameDigest(preflightDigest, observedDigest)
  ) {
    throw new TypeError('Source Slice Request preflight digest does not bind its canonical content')
  }
  const requestDigest = sourceSliceRequestDigestSchema.parse(expectedBindings.requestDigest)
  const contextGrantDigest = contextGrantDigestSchema.parse(expectedBindings.contextGrantDigest)
  if (
    !sameDigest(parsedCore.requestDigest, requestDigest)
    || !sameDigest(parsedCore.contextGrantDigest, contextGrantDigest)
  ) {
    throw new TypeError('Source Slice Request preflight binding does not match the expected request and Context Grant')
  }
  return deepFreeze({ ...parsedCore, preflightDigest })
}
