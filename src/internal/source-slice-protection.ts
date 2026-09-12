import { createHmac } from 'node:crypto'
import { z } from 'zod'
import type { DigestEnvelopeV1 } from '../contracts.ts'
import { digestEnvelopeV1Schema } from '../contracts.ts'
import type { RoleContextGrantV1 } from '../role-context-grant.ts'
import { parseRoleContextGrantV1 } from '../role-context-grant.ts'
import type { SourceSliceRequestV1 } from '../source-slice-request.ts'
import {
  parseSourceSliceRequestV1,
  preflightSourceSliceRequestV1,
} from '../source-slice-request.ts'
import { binaryDigest, canonicalJson, structuredDigest } from './canonical.ts'
import { deepFreeze } from './freeze.ts'
import type {
  ProtectedSourceSliceSecretReviewDecisionV1,
  ProtectedSourceSliceSecretReviewV1,
} from './source-slice-secret-review.ts'
import type { ProtectedSourceSliceMaterialV1 } from './subject-freeze.ts'

export const SOURCE_SLICE_SECRET_INSPECTION_MEDIA_TYPE =
  'application/vnd.dsh.security.source-slice-secret-inspection+json'
export const REDACTED_SOURCE_SLICE_MEDIA_TYPE =
  'application/vnd.dsh.security.redacted-source-slice+text'
export const SOURCE_SLICE_REDACTION_MEDIA_TYPE =
  'application/vnd.dsh.security.source-slice-redaction+json'
export const SOURCE_SLICE_EGRESS_REVIEW_MEDIA_TYPE =
  'application/vnd.dsh.security.source-slice-egress-review+json'
const QUALIFIED_SOURCE_SLICE_SECRET_REVIEW_MEDIA_TYPE =
  'application/vnd.dsh.security.qualified-source-slice-secret-review+json'

const SECRET_DETECTOR_POLICY_ID = 'security/high-confidence-secret-patterns-v1'
const SECRET_REDACTION_POLICY_ID = 'security/high-confidence-secret-redaction-v1'
const fingerprintKeyIdSchema = z.string().regex(/^[a-z0-9][a-z0-9._/-]{0,127}$/iu)
const subjectRelativePathSchema = z.string().min(1).max(1024).refine(path => (
  !path.startsWith('/')
  && !path.startsWith('\\')
  && !/^[a-z]:/iu.test(path)
  && !path.includes('\\')
  && path.split('/').every(segment => segment.length > 0 && segment !== '.' && segment !== '..')
), 'Protected Source Slice material requires a canonical Subject-relative path')

export type ProtectedSourceSliceSecretKindV1 =
  | 'ASSIGNMENT_SECRET'
  | 'BEARER_TOKEN'
  | 'PRIVATE_KEY'

export interface ProtectedSourceSliceSecretFindingV1 {
  readonly kind: ProtectedSourceSliceSecretKindV1
  readonly startOffset: number
  readonly endOffset: number
  readonly line: number
  readonly column: number
  readonly fingerprint: string
}

export interface ProtectedSourceSliceSecretInspectionCoreV1 {
  readonly schemaVersion: 1
  readonly requestDigest: DigestEnvelopeV1
  readonly subjectDigest: DigestEnvelopeV1
  readonly sourceDigest: DigestEnvelopeV1
  readonly path: string
  readonly detectorPolicyId: typeof SECRET_DETECTOR_POLICY_ID
  readonly fingerprintKeyId: string
  readonly decision: 'REDACTION_REQUIRED' | 'ADDITIONAL_REVIEW_REQUIRED'
  readonly findings: readonly ProtectedSourceSliceSecretFindingV1[]
}

export interface ProtectedSourceSliceSecretInspectionV1
  extends ProtectedSourceSliceSecretInspectionCoreV1 {
  readonly inspectionDigest: DigestEnvelopeV1
}

export interface InspectProtectedSourceSliceSecretsOptionsV1 {
  readonly material: ProtectedSourceSliceMaterialV1
  readonly fingerprintKey: Uint8Array
  readonly fingerprintKeyId: string
}

export interface ProtectedSourceSliceRedactionCoreV1 {
  readonly schemaVersion: 1
  readonly requestDigest: DigestEnvelopeV1
  readonly subjectDigest: DigestEnvelopeV1
  readonly sourceDigest: DigestEnvelopeV1
  readonly path: string
  readonly detectorPolicyId: typeof SECRET_DETECTOR_POLICY_ID
  readonly redactionPolicyId: typeof SECRET_REDACTION_POLICY_ID
  readonly fingerprintKeyId: string
  readonly inspectionDigest: DigestEnvelopeV1
  readonly decision: 'REDACTED_MATCHES_REVIEW_REQUIRED' | 'ADDITIONAL_REVIEW_REQUIRED'
  readonly redactions: readonly ProtectedSourceSliceSecretFindingV1[]
  readonly redactedText: string
  readonly redactedDigest: DigestEnvelopeV1
}

export interface ProtectedSourceSliceRedactionV1 extends ProtectedSourceSliceRedactionCoreV1 {
  readonly redactionDigest: DigestEnvelopeV1
}

export type ProtectedSourceSliceEgressReasonV1 =
  | 'POLICY_DENIES_EGRESS'
  | 'REDACTED_BYTE_BUDGET_EXCEEDED'
  | 'SECRET_REVIEW_INCOMPLETE'
  | 'RESIDUAL_SECRET_DETECTED'
  | 'BROKER_QUALIFICATION_REQUIRED'
  | 'DESTINATION_AUTHORIZATION_REQUIRED'

export interface ProtectedSourceSliceEgressSecretReviewSummaryV1 {
  readonly secretReviewDigest: DigestEnvelopeV1
  readonly decision: ProtectedSourceSliceSecretReviewDecisionV1
}

export interface ProtectedSourceSliceEgressReviewCoreV1 {
  readonly schemaVersion: 1
  readonly contextGrantDigest: DigestEnvelopeV1
  readonly requestDigest: DigestEnvelopeV1
  readonly subjectDigest: DigestEnvelopeV1
  readonly sourceDigest: DigestEnvelopeV1
  readonly redactionDigest: DigestEnvelopeV1
  readonly redactedDigest: DigestEnvelopeV1
  readonly secretReview: ProtectedSourceSliceEgressSecretReviewSummaryV1 | null
  readonly disclosure: {
    readonly dataEgressPolicyId: string
    readonly destinationId: string
    readonly categoryId: string
  }
  readonly observedRedactedBytes: number
  readonly requestedContextBytes: number
  readonly decision: 'REJECTED' | 'BROKER_REVIEW_REQUIRED'
  readonly reasonCodes: readonly ProtectedSourceSliceEgressReasonV1[]
}

export interface ProtectedSourceSliceEgressReviewV1
  extends ProtectedSourceSliceEgressReviewCoreV1 {
  readonly egressReviewDigest: DigestEnvelopeV1
}

export interface ReviewProtectedSourceSliceEgressOptionsV1 {
  readonly contextGrant: RoleContextGrantV1
  readonly request: SourceSliceRequestV1
  readonly material: ProtectedSourceSliceMaterialV1
  readonly redaction: ProtectedSourceSliceRedactionV1
  readonly secretReview?: ProtectedSourceSliceSecretReviewV1 | undefined
}

export interface ProtectedSourceSliceEgressReviewBindingsV1 {
  readonly contextGrantDigest: DigestEnvelopeV1
  readonly requestDigest: DigestEnvelopeV1
  readonly redactionDigest: DigestEnvelopeV1
  readonly secretReview?: ProtectedSourceSliceSecretReviewV1 | undefined
}

interface SecretCandidate {
  readonly kind: ProtectedSourceSliceSecretKindV1
  readonly startOffset: number
  readonly endOffset: number
  readonly secret: string
}

function sameDigest(left: DigestEnvelopeV1, right: DigestEnvelopeV1): boolean {
  return canonicalJson(left) === canonicalJson(right)
}

function parseProtectedMaterial(candidate: ProtectedSourceSliceMaterialV1): ProtectedSourceSliceMaterialV1 {
  const requestDigest = digestEnvelopeV1Schema.parse(candidate.requestDigest)
  const subjectDigest = digestEnvelopeV1Schema.parse(candidate.subjectDigest)
  const digest = digestEnvelopeV1Schema.parse(candidate.digest)
  const path = subjectRelativePathSchema.parse(candidate.path)
  const text = z.string().max(1024 * 1024).parse(candidate.text)
  if (
    requestDigest.mediaType !== 'application/vnd.dsh.security.source-slice-request+json'
    || subjectDigest.mediaType !== 'application/vnd.dsh.security.subject-manifest+json'
    || digest.mediaType !== 'application/octet-stream'
    || digest.canonicalization !== 'raw-bytes'
  ) {
    throw new TypeError('Protected Source Slice material has unsupported digest bindings')
  }
  const observedDigest = binaryDigest('application/octet-stream', Buffer.from(text, 'utf8'))
  if (!sameDigest(digest, observedDigest)) {
    throw new TypeError('Protected Source Slice material digest does not bind its text')
  }
  return deepFreeze({ requestDigest, subjectDigest, path, digest, text })
}

function assignmentCandidates(text: string): SecretCandidate[] {
  const pattern = /\b(?:api[_-]?key|access[_-]?token|auth[_-]?token|secret|password|credential)\b[ \t]*[:=][ \t]*(?:"([^"\r\n]{4,})"|'([^'\r\n]{4,})'|([^\s,;#]{4,}))/giu
  const candidates: SecretCandidate[] = []
  for (const match of text.matchAll(pattern)) {
    const secret = match[1] ?? match[2] ?? match[3]
    if (secret === undefined || match.index === undefined) continue
    const secretOffset = match[0].lastIndexOf(secret)
    const startOffset = match.index + secretOffset
    candidates.push({
      kind: 'ASSIGNMENT_SECRET',
      startOffset,
      endOffset: startOffset + secret.length,
      secret,
    })
  }
  return candidates
}

function bearerCandidates(text: string): SecretCandidate[] {
  const pattern = /\bBearer[ \t]+([A-Za-z0-9._~+/=-]{8,})/gu
  const candidates: SecretCandidate[] = []
  for (const match of text.matchAll(pattern)) {
    const secret = match[1]
    if (secret === undefined || match.index === undefined) continue
    const startOffset = match.index + match[0].lastIndexOf(secret)
    candidates.push({
      kind: 'BEARER_TOKEN',
      startOffset,
      endOffset: startOffset + secret.length,
      secret,
    })
  }
  return candidates
}

function privateKeyCandidates(text: string): SecretCandidate[] {
  const pattern = /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----/gu
  return [...text.matchAll(pattern)].flatMap(match => {
    if (match.index === undefined) return []
    return [{
      kind: 'PRIVATE_KEY' as const,
      startOffset: match.index,
      endOffset: match.index + match[0].length,
      secret: match[0],
    }]
  })
}

function secretCandidates(text: string): SecretCandidate[] {
  const candidates = [
    ...assignmentCandidates(text),
    ...bearerCandidates(text),
    ...privateKeyCandidates(text),
  ].sort((left, right) => (
    left.startOffset - right.startOffset
    || right.endOffset - left.endOffset
    || left.kind.localeCompare(right.kind)
  ))
  const nonOverlapping: SecretCandidate[] = []
  for (const candidate of candidates) {
    if (nonOverlapping.some(existing => (
      candidate.startOffset < existing.endOffset && candidate.endOffset > existing.startOffset
    ))) continue
    nonOverlapping.push(candidate)
  }
  return nonOverlapping
}

function location(text: string, offset: number): { readonly line: number; readonly column: number } {
  const prefix = text.slice(0, offset)
  const lines = prefix.split('\n')
  return { line: lines.length, column: (lines.at(-1)?.length ?? 0) + 1 }
}

function renderRedactedText(
  text: string,
  findings: readonly ProtectedSourceSliceSecretFindingV1[],
): string {
  let redacted = text
  for (const finding of [...findings].reverse()) {
    redacted = `${redacted.slice(0, finding.startOffset)}[REDACTED:${finding.kind}]${
      redacted.slice(finding.endOffset)
    }`
  }
  return redacted
}

/**
 * Detect only bounded high-confidence patterns in protected local text. Empty
 * findings never prove absence; raw matches and the fingerprint key are not retained.
 */
export function inspectProtectedSourceSliceSecrets(
  options: InspectProtectedSourceSliceSecretsOptionsV1,
): ProtectedSourceSliceSecretInspectionV1 {
  const material = parseProtectedMaterial(options.material)
  const fingerprintKeyId = fingerprintKeyIdSchema.parse(options.fingerprintKeyId)
  if (!(options.fingerprintKey instanceof Uint8Array) || options.fingerprintKey.byteLength < 32) {
    throw new TypeError('Secret fingerprint keys must contain at least 32 bytes')
  }
  const fingerprintKey = Buffer.from(options.fingerprintKey)
  try {
    const findings = secretCandidates(material.text).map(candidate => ({
      kind: candidate.kind,
      startOffset: candidate.startOffset,
      endOffset: candidate.endOffset,
      ...location(material.text, candidate.startOffset),
      fingerprint: `hmac-sha256:${createHmac('sha256', fingerprintKey)
        .update(candidate.secret, 'utf8')
        .digest('hex')}`,
    }))
    const core: ProtectedSourceSliceSecretInspectionCoreV1 = {
      schemaVersion: 1,
      requestDigest: material.requestDigest,
      subjectDigest: material.subjectDigest,
      sourceDigest: material.digest,
      path: material.path,
      detectorPolicyId: SECRET_DETECTOR_POLICY_ID,
      fingerprintKeyId,
      decision: findings.length > 0 ? 'REDACTION_REQUIRED' : 'ADDITIONAL_REVIEW_REQUIRED',
      findings,
    }
    return deepFreeze({
      ...core,
      inspectionDigest: structuredDigest(SOURCE_SLICE_SECRET_INSPECTION_MEDIA_TYPE, core),
    })
  } finally {
    fingerprintKey.fill(0)
  }
}

const secretFindingV1Schema = z.strictObject({
  kind: z.enum(['ASSIGNMENT_SECRET', 'BEARER_TOKEN', 'PRIVATE_KEY']),
  startOffset: z.number().int().nonnegative().max(1024 * 1024),
  endOffset: z.number().int().positive().max(1024 * 1024),
  line: z.number().int().positive().max(1024 * 1024),
  column: z.number().int().positive().max(1024 * 1024),
  fingerprint: z.string().regex(/^hmac-sha256:[0-9a-f]{64}$/u),
}).refine(finding => finding.endOffset > finding.startOffset, {
  message: 'Secret finding offsets must describe a non-empty range',
})

const sourceSliceRedactionV1Schema = z.strictObject({
  schemaVersion: z.literal(1),
  requestDigest: digestEnvelopeV1Schema,
  subjectDigest: digestEnvelopeV1Schema,
  sourceDigest: digestEnvelopeV1Schema,
  path: subjectRelativePathSchema,
  detectorPolicyId: z.literal(SECRET_DETECTOR_POLICY_ID),
  redactionPolicyId: z.literal(SECRET_REDACTION_POLICY_ID),
  fingerprintKeyId: fingerprintKeyIdSchema,
  inspectionDigest: digestEnvelopeV1Schema,
  decision: z.enum(['REDACTED_MATCHES_REVIEW_REQUIRED', 'ADDITIONAL_REVIEW_REQUIRED']),
  redactions: z.array(secretFindingV1Schema).max(4096),
  redactedText: z.string().max(2 * 1024 * 1024),
  redactedDigest: digestEnvelopeV1Schema,
  redactionDigest: digestEnvelopeV1Schema,
})

const SOURCE_SLICE_EGRESS_REASON_CODES = [
  'POLICY_DENIES_EGRESS',
  'REDACTED_BYTE_BUDGET_EXCEEDED',
  'SECRET_REVIEW_INCOMPLETE',
  'RESIDUAL_SECRET_DETECTED',
  'BROKER_QUALIFICATION_REQUIRED',
  'DESTINATION_AUTHORIZATION_REQUIRED',
] as const satisfies readonly ProtectedSourceSliceEgressReasonV1[]

const sourceSliceEgressReviewV1Schema = z.strictObject({
  schemaVersion: z.literal(1),
  contextGrantDigest: digestEnvelopeV1Schema,
  requestDigest: digestEnvelopeV1Schema,
  subjectDigest: digestEnvelopeV1Schema,
  sourceDigest: digestEnvelopeV1Schema,
  redactionDigest: digestEnvelopeV1Schema,
  redactedDigest: digestEnvelopeV1Schema,
  secretReview: z.strictObject({
    secretReviewDigest: digestEnvelopeV1Schema,
    decision: z.enum(['CLEAR', 'SECRET_FOUND', 'INDETERMINATE']),
  }).nullable(),
  disclosure: z.strictObject({
    dataEgressPolicyId: fingerprintKeyIdSchema,
    destinationId: fingerprintKeyIdSchema,
    categoryId: fingerprintKeyIdSchema,
  }),
  observedRedactedBytes: z.number().int().nonnegative().max(2 * 1024 * 1024),
  requestedContextBytes: z.number().int().positive().max(64 * 1024 * 1024),
  decision: z.enum(['REJECTED', 'BROKER_REVIEW_REQUIRED']),
  reasonCodes: z.array(z.enum(SOURCE_SLICE_EGRESS_REASON_CODES)).min(1).max(5),
  egressReviewDigest: digestEnvelopeV1Schema,
})

/** Replace every detected high-confidence match while preserving the fail-closed review state. */
export function redactProtectedSourceSliceSecrets(
  options: InspectProtectedSourceSliceSecretsOptionsV1,
): ProtectedSourceSliceRedactionV1 {
  const material = parseProtectedMaterial(options.material)
  const inspection = inspectProtectedSourceSliceSecrets({ ...options, material })
  const redactedText = renderRedactedText(material.text, inspection.findings)
  const redactedDigest = binaryDigest(
    REDACTED_SOURCE_SLICE_MEDIA_TYPE,
    Buffer.from(redactedText, 'utf8'),
  )
  const core: ProtectedSourceSliceRedactionCoreV1 = {
    schemaVersion: 1,
    requestDigest: material.requestDigest,
    subjectDigest: material.subjectDigest,
    sourceDigest: material.digest,
    path: material.path,
    detectorPolicyId: inspection.detectorPolicyId,
    redactionPolicyId: SECRET_REDACTION_POLICY_ID,
    fingerprintKeyId: inspection.fingerprintKeyId,
    inspectionDigest: inspection.inspectionDigest,
    decision: inspection.findings.length > 0
      ? 'REDACTED_MATCHES_REVIEW_REQUIRED'
      : 'ADDITIONAL_REVIEW_REQUIRED',
    redactions: inspection.findings,
    redactedText,
    redactedDigest,
  }
  return deepFreeze({
    ...core,
    redactionDigest: structuredDigest(SOURCE_SLICE_REDACTION_MEDIA_TYPE, core),
  })
}

/** Recompute redaction content and record digests against the exact protected material. */
export function parseProtectedSourceSliceRedaction(
  candidate: unknown,
  expectedMaterial: ProtectedSourceSliceMaterialV1,
): ProtectedSourceSliceRedactionV1 {
  const material = parseProtectedMaterial(expectedMaterial)
  const redaction = sourceSliceRedactionV1Schema.parse(candidate)
  if (
    !sameDigest(redaction.requestDigest, material.requestDigest)
    || !sameDigest(redaction.subjectDigest, material.subjectDigest)
    || !sameDigest(redaction.sourceDigest, material.digest)
    || redaction.path !== material.path
  ) {
    throw new TypeError('Source Slice redaction does not bind the expected protected material')
  }
  const expectedCandidates = secretCandidates(material.text).map(secret => ({
    kind: secret.kind,
    startOffset: secret.startOffset,
    endOffset: secret.endOffset,
    ...location(material.text, secret.startOffset),
  }))
  const declaredCandidates = redaction.redactions.map(({ fingerprint: _fingerprint, ...finding }) => finding)
  if (canonicalJson(expectedCandidates) !== canonicalJson(declaredCandidates)) {
    throw new TypeError('Source Slice redaction does not cover the detected secret locations')
  }
  const expectedDecision = redaction.redactions.length > 0
    ? 'REDACTED_MATCHES_REVIEW_REQUIRED'
    : 'ADDITIONAL_REVIEW_REQUIRED'
  const expectedText = renderRedactedText(material.text, redaction.redactions)
  const observedTextDigest = binaryDigest(
    REDACTED_SOURCE_SLICE_MEDIA_TYPE,
    Buffer.from(redaction.redactedText, 'utf8'),
  )
  if (
    redaction.decision !== expectedDecision
    || redaction.redactedText !== expectedText
    || redaction.inspectionDigest.mediaType !== SOURCE_SLICE_SECRET_INSPECTION_MEDIA_TYPE
    || !sameDigest(redaction.redactedDigest, observedTextDigest)
  ) {
    throw new TypeError('Source Slice redaction digest or review state is invalid')
  }
  const { redactionDigest, ...core } = redaction
  const observedRecordDigest = structuredDigest(SOURCE_SLICE_REDACTION_MEDIA_TYPE, core)
  if (!sameDigest(redactionDigest, observedRecordDigest)) {
    throw new TypeError('Source Slice redaction digest does not bind its canonical content')
  }
  return deepFreeze({ ...core, redactionDigest })
}

export function deriveProtectedSourceSliceEgressDisposition(
  policyId: string,
  observedRedactedBytes: number,
  requestedContextBytes: number,
  secretReviewDecision: ProtectedSourceSliceSecretReviewDecisionV1 | null = null,
): {
  readonly decision: ProtectedSourceSliceEgressReviewCoreV1['decision']
  readonly reasonCodes: readonly ProtectedSourceSliceEgressReasonV1[]
} {
  const reasons: ProtectedSourceSliceEgressReasonV1[] = []
  if (policyId === 'egress/deny-by-default') reasons.push('POLICY_DENIES_EGRESS')
  if (observedRedactedBytes > requestedContextBytes) {
    reasons.push('REDACTED_BYTE_BUDGET_EXCEEDED')
  }
  if (secretReviewDecision === 'SECRET_FOUND') reasons.push('RESIDUAL_SECRET_DETECTED')
  if (policyId !== 'egress/deny-by-default') {
    if (secretReviewDecision !== 'CLEAR' && secretReviewDecision !== 'SECRET_FOUND') {
      reasons.push('SECRET_REVIEW_INCOMPLETE')
    }
    reasons.push('BROKER_QUALIFICATION_REQUIRED', 'DESTINATION_AUTHORIZATION_REQUIRED')
  }
  return deepFreeze({
    decision: reasons.includes('POLICY_DENIES_EGRESS')
      || reasons.includes('REDACTED_BYTE_BUDGET_EXCEEDED')
      || reasons.includes('RESIDUAL_SECRET_DETECTED')
      ? 'REJECTED'
      : 'BROKER_REVIEW_REQUIRED',
    reasonCodes: reasons,
  })
}

function bindQualifiedSecretReviewToEgress(
  review: ProtectedSourceSliceSecretReviewV1,
  contextGrant: RoleContextGrantV1,
  request: SourceSliceRequestV1,
  material: ProtectedSourceSliceMaterialV1,
  redaction: ProtectedSourceSliceRedactionV1,
): ProtectedSourceSliceEgressSecretReviewSummaryV1 {
  if (
    review.schemaVersion !== 1
    || review.contractId !== 'dsh/security/source-slice-secret-review/v1'
    || review.path !== material.path
    || review.assessmentMode !== contextGrant.purpose.assessmentMode
    || !sameDigest(review.requestDigest, request.requestDigest)
    || !sameDigest(review.subjectDigest, material.subjectDigest)
    || !sameDigest(review.sourceDigest, material.digest)
    || !sameDigest(review.redactionDigest, redaction.redactionDigest)
    || !sameDigest(review.redactedDigest, redaction.redactedDigest)
    || review.secretReviewDigest.mediaType !== QUALIFIED_SOURCE_SLICE_SECRET_REVIEW_MEDIA_TYPE
  ) {
    throw new TypeError('Source Slice egress review does not bind its qualified secret review')
  }
  if (
    review.decision === 'CLEAR'
      ? review.completion !== 'COMPLETE' || review.findingCount !== 0
      : review.decision === 'SECRET_FOUND'
        ? review.completion !== 'COMPLETE' || review.findingCount === 0
        : review.completion !== 'INCOMPLETE'
  ) {
    throw new TypeError('Source Slice egress secret review decision is invalid')
  }
  const { secretReviewDigest, ...core } = review
  if (!sameDigest(
    secretReviewDigest,
    structuredDigest(QUALIFIED_SOURCE_SLICE_SECRET_REVIEW_MEDIA_TYPE, core),
  )) {
    throw new TypeError('Source Slice egress secret review digest is invalid')
  }
  return deepFreeze({ secretReviewDigest, decision: review.decision })
}

/**
 * Enforce local deny-by-default and identify remaining Host/Broker checks.
 * This function performs no network or Provider operation and cannot approve egress.
 */
export function reviewProtectedSourceSliceEgress(
  options: ReviewProtectedSourceSliceEgressOptionsV1,
): ProtectedSourceSliceEgressReviewV1 {
  const contextGrant = parseRoleContextGrantV1(options.contextGrant)
  const request = parseSourceSliceRequestV1(options.request)
  if (preflightSourceSliceRequestV1({ contextGrant, request }).decision !== 'MATERIAL_REVIEW_REQUIRED') {
    throw new TypeError('Source Slice egress review failed static preflight')
  }
  const material = parseProtectedMaterial(options.material)
  const redaction = parseProtectedSourceSliceRedaction(options.redaction, material)
  if (
    !sameDigest(material.requestDigest, request.requestDigest)
    || !sameDigest(material.subjectDigest, request.subjectDigest)
    || !sameDigest(material.digest, request.target.expectedSourceDigest)
  ) {
    throw new TypeError('Source Slice egress review does not bind the admitted request')
  }
  const observedRedactedBytes = Buffer.byteLength(redaction.redactedText, 'utf8')
  const secretReview = options.secretReview === undefined
    ? null
    : bindQualifiedSecretReviewToEgress(options.secretReview, contextGrant, request, material, redaction)
  const disposition = deriveProtectedSourceSliceEgressDisposition(
    request.disclosure.dataEgressPolicyId,
    observedRedactedBytes,
    request.budget.contextBytes,
    secretReview?.decision ?? null,
  )
  const core: ProtectedSourceSliceEgressReviewCoreV1 = {
    schemaVersion: 1,
    contextGrantDigest: contextGrant.grantDigest,
    requestDigest: request.requestDigest,
    subjectDigest: material.subjectDigest,
    sourceDigest: material.digest,
    redactionDigest: redaction.redactionDigest,
    redactedDigest: redaction.redactedDigest,
    secretReview,
    disclosure: request.disclosure,
    observedRedactedBytes,
    requestedContextBytes: request.budget.contextBytes,
    decision: disposition.decision,
    reasonCodes: disposition.reasonCodes,
  }
  return deepFreeze({
    ...core,
    egressReviewDigest: structuredDigest(SOURCE_SLICE_EGRESS_REVIEW_MEDIA_TYPE, core),
  })
}

/** Validate a persisted deny-by-default review against its exact upstream digests. */
export function parseProtectedSourceSliceEgressReview(
  candidate: unknown,
  expectedBindings: ProtectedSourceSliceEgressReviewBindingsV1,
): ProtectedSourceSliceEgressReviewV1 {
  const review = sourceSliceEgressReviewV1Schema.parse(candidate)
  if (
    !sameDigest(review.contextGrantDigest, expectedBindings.contextGrantDigest)
    || !sameDigest(review.requestDigest, expectedBindings.requestDigest)
    || !sameDigest(review.redactionDigest, expectedBindings.redactionDigest)
    || (review.secretReview === null) !== (expectedBindings.secretReview === undefined)
  ) {
    throw new TypeError('Source Slice egress review does not bind its expected inputs')
  }
  if (
    review.secretReview !== null
    && expectedBindings.secretReview !== undefined
    && (
      review.secretReview.decision !== expectedBindings.secretReview.decision
      || !sameDigest(
        review.secretReview.secretReviewDigest,
        expectedBindings.secretReview.secretReviewDigest,
      )
    )
  ) {
    throw new TypeError('Source Slice egress review does not bind its expected secret review')
  }
  const disposition = deriveProtectedSourceSliceEgressDisposition(
    review.disclosure.dataEgressPolicyId,
    review.observedRedactedBytes,
    review.requestedContextBytes,
    review.secretReview?.decision ?? null,
  )
  if (
    review.redactedDigest.mediaType !== REDACTED_SOURCE_SLICE_MEDIA_TYPE
    || review.redactionDigest.mediaType !== SOURCE_SLICE_REDACTION_MEDIA_TYPE
    || (review.secretReview !== null
      && review.secretReview.secretReviewDigest.mediaType
        !== QUALIFIED_SOURCE_SLICE_SECRET_REVIEW_MEDIA_TYPE)
    || review.decision !== disposition.decision
    || canonicalJson(review.reasonCodes) !== canonicalJson(disposition.reasonCodes)
  ) {
    throw new TypeError('Source Slice egress review decision or reasons are invalid')
  }
  const { egressReviewDigest, ...core } = review
  const observedDigest = structuredDigest(SOURCE_SLICE_EGRESS_REVIEW_MEDIA_TYPE, core)
  if (!sameDigest(egressReviewDigest, observedDigest)) {
    throw new TypeError('Source Slice egress review digest does not bind its canonical content')
  }
  return deepFreeze({ ...core, egressReviewDigest })
}
