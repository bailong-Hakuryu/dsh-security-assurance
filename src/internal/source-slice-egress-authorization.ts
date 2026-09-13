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
import { canonicalJson, structuredDigest } from './canonical.ts'
import { deepFreeze } from './freeze.ts'
import type { ProtectedSourceSliceRedactionV1 } from './source-slice-protection.ts'
import type { ProtectedSourceSliceSecretReviewV1 } from './source-slice-secret-review.ts'
import type { ProtectedSourceSliceMaterialV1 } from './subject-freeze.ts'

export const SOURCE_SLICE_EGRESS_BROKER_QUALIFICATION_MEDIA_TYPE =
  'application/vnd.dsh.security.egress-broker-qualification+json'
export const SOURCE_SLICE_EGRESS_BROKER_IMPLEMENTATION_MEDIA_TYPE =
  'application/vnd.dsh.security.egress-broker-implementation+json'
export const SOURCE_SLICE_DESTINATION_AUTHORIZATION_MEDIA_TYPE =
  'application/vnd.dsh.security.source-slice-destination-authorization+json'
export const SOURCE_SLICE_EGRESS_AUTHORIZATION_MEDIA_TYPE =
  'application/vnd.dsh.security.qualified-source-slice-egress-authorization+json'

const QUALIFIED_SOURCE_SLICE_SECRET_REVIEW_MEDIA_TYPE =
  'application/vnd.dsh.security.qualified-source-slice-secret-review+json'
const REDACTED_SOURCE_SLICE_MEDIA_TYPE =
  'application/vnd.dsh.security.redacted-source-slice+text'
const SOURCE_SLICE_REDACTION_MEDIA_TYPE =
  'application/vnd.dsh.security.source-slice-redaction+json'
const boundedIdSchema = z.string().regex(/^[a-z0-9][a-z0-9._/-]{0,127}$/iu)
const semanticVersionSchema = z.string().regex(/^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$/u)
const subjectRelativePathSchema = z.string().min(1).max(1024).refine(path => (
  !path.startsWith('/')
  && !path.startsWith('\\')
  && !/^[a-z]:/iu.test(path)
  && !path.includes('\\')
  && path.split('/').every(segment => segment.length > 0 && segment !== '.' && segment !== '..')
), 'Source Slice egress authorization requires a canonical Subject-relative path')

export interface SourceSliceEgressBrokerIdentityV1 {
  readonly brokerId: string
  readonly brokerVersion: string
  readonly implementationDigest: DigestEnvelopeV1
}

export interface SourceSliceEgressBrokerQualificationCoreV1 {
  readonly schemaVersion: 1
  readonly qualificationId: string
  readonly brokerIdentity: SourceSliceEgressBrokerIdentityV1
  readonly issuerId: string
  readonly level: 'HOST_ATTESTED'
  readonly providerIds: readonly string[]
  readonly dataEgressPolicyIds: readonly string[]
  readonly destinationIds: readonly string[]
  readonly categoryIds: readonly string[]
  readonly maximumRequestBytes: number
  readonly maximumRequestCount: number
  readonly maximumTimeoutMilliseconds: number
  readonly auditPolicyIds: readonly string[]
  readonly issuedAt: string
  readonly expiresAt: string
  readonly evidenceDigests: readonly DigestEnvelopeV1[]
  readonly limitations: readonly string[]
}

export interface SourceSliceEgressBrokerQualificationV1
  extends SourceSliceEgressBrokerQualificationCoreV1 {
  readonly qualificationDigest: DigestEnvelopeV1
}

export interface SourceSliceDestinationAuthorizationCoreV1 {
  readonly schemaVersion: 1
  readonly authorizationId: string
  readonly issuerId: string
  readonly level: 'HOST_AUTHORIZED'
  readonly contextGrantDigest: DigestEnvelopeV1
  readonly requestDigest: DigestEnvelopeV1
  readonly subjectDigest: DigestEnvelopeV1
  readonly sourceDigest: DigestEnvelopeV1
  readonly path: string
  readonly redactionDigest: DigestEnvelopeV1
  readonly redactedDigest: DigestEnvelopeV1
  readonly secretReviewDigest: DigestEnvelopeV1
  readonly brokerQualificationDigest: DigestEnvelopeV1
  readonly brokerId: string
  readonly providerId: string
  readonly credentialBindingId: string
  readonly dataEgressPolicyId: string
  readonly destinationId: string
  readonly categoryId: string
  readonly requestByteLimit: number
  readonly requestCountLimit: number
  readonly timeoutMilliseconds: number
  readonly auditPolicyId: string
  readonly authorizedAt: string
  readonly expiresAt: string
}

export interface SourceSliceDestinationAuthorizationV1
  extends SourceSliceDestinationAuthorizationCoreV1 {
  readonly authorizationDigest: DigestEnvelopeV1
}

export interface ProtectedSourceSliceEgressAuthorizationCoreV1 {
  readonly schemaVersion: 1
  readonly contextGrantDigest: DigestEnvelopeV1
  readonly requestDigest: DigestEnvelopeV1
  readonly subjectDigest: DigestEnvelopeV1
  readonly sourceDigest: DigestEnvelopeV1
  readonly path: string
  readonly redactionDigest: DigestEnvelopeV1
  readonly redactedDigest: DigestEnvelopeV1
  readonly secretReviewDigest: DigestEnvelopeV1
  readonly brokerIdentity: SourceSliceEgressBrokerIdentityV1
  readonly brokerQualificationId: string
  readonly brokerQualificationDigest: DigestEnvelopeV1
  readonly destinationAuthorizationId: string
  readonly destinationAuthorizationDigest: DigestEnvelopeV1
  readonly providerId: string
  readonly credentialBindingId: string
  readonly dataEgressPolicyId: string
  readonly destinationId: string
  readonly categoryId: string
  readonly requestByteLimit: number
  readonly requestCountLimit: 1
  readonly timeoutMilliseconds: number
  readonly auditPolicyId: string
  readonly evaluatedAt: string
}

export interface ProtectedSourceSliceEgressAuthorizationV1
  extends ProtectedSourceSliceEgressAuthorizationCoreV1 {
  readonly egressAuthorizationDigest: DigestEnvelopeV1
}

export interface AdmitProtectedSourceSliceEgressAuthorizationOptionsV1 {
  readonly contextGrant: RoleContextGrantV1
  readonly request: SourceSliceRequestV1
  readonly material: ProtectedSourceSliceMaterialV1
  readonly redaction: ProtectedSourceSliceRedactionV1
  readonly secretReview: ProtectedSourceSliceSecretReviewV1
  readonly brokerQualification: SourceSliceEgressBrokerQualificationV1
  readonly destinationAuthorization: SourceSliceDestinationAuthorizationV1
  readonly evaluatedAt: string
}

export interface ProtectedSourceSliceEgressAuthorizationBindingsV1 {
  readonly contextGrantDigest: DigestEnvelopeV1
  readonly requestDigest: DigestEnvelopeV1
  readonly subjectDigest: DigestEnvelopeV1
  readonly sourceDigest: DigestEnvelopeV1
  readonly path: string
  readonly redactionDigest: DigestEnvelopeV1
  readonly redactedDigest: DigestEnvelopeV1
  readonly secretReviewDigest: DigestEnvelopeV1
  readonly dataEgressPolicyId: string
  readonly destinationId: string
  readonly categoryId: string
  readonly requestedContextBytes: number
  readonly observedRedactedBytes: number
}

const brokerIdentityV1Schema: z.ZodType<SourceSliceEgressBrokerIdentityV1> = z.strictObject({
  brokerId: boundedIdSchema,
  brokerVersion: semanticVersionSchema,
  implementationDigest: digestEnvelopeV1Schema,
})

const brokerQualificationCoreV1Shape = {
  schemaVersion: z.literal(1),
  qualificationId: boundedIdSchema,
  brokerIdentity: brokerIdentityV1Schema,
  issuerId: boundedIdSchema,
  level: z.literal('HOST_ATTESTED'),
  providerIds: z.array(boundedIdSchema).min(1).max(32),
  dataEgressPolicyIds: z.array(boundedIdSchema).min(1).max(32),
  destinationIds: z.array(boundedIdSchema).min(1).max(64),
  categoryIds: z.array(boundedIdSchema).min(1).max(64),
  maximumRequestBytes: z.number().int().positive().max(64 * 1024 * 1024),
  maximumRequestCount: z.number().int().positive().max(1024),
  maximumTimeoutMilliseconds: z.number().int().positive().max(3_600_000),
  auditPolicyIds: z.array(boundedIdSchema).min(1).max(32),
  issuedAt: z.iso.datetime({ offset: true }),
  expiresAt: z.iso.datetime({ offset: true }),
  evidenceDigests: z.array(digestEnvelopeV1Schema).min(1).max(128),
  limitations: z.array(z.string().min(1).max(512)).max(64),
} as const

function validateBrokerQualification(
  qualification: SourceSliceEgressBrokerQualificationCoreV1,
  context: z.RefinementCtx,
): void {
  for (const values of [
    qualification.providerIds,
    qualification.dataEgressPolicyIds,
    qualification.destinationIds,
    qualification.categoryIds,
    qualification.auditPolicyIds,
  ]) {
    if (!isUniqueAndCanonical(values)) {
      context.addIssue({ code: 'custom', message: 'Broker qualification arrays must be unique and canonical' })
    }
  }
  if (!isUniqueDigestArray(qualification.evidenceDigests)) {
    context.addIssue({ code: 'custom', message: 'Broker qualification Evidence digests must be unique' })
  }
  if (Date.parse(qualification.issuedAt) >= Date.parse(qualification.expiresAt)) {
    context.addIssue({ code: 'custom', message: 'Broker qualification expiry must follow issuance' })
  }
}

export const sourceSliceEgressBrokerQualificationV1Schema:
  z.ZodType<SourceSliceEgressBrokerQualificationV1> = z.strictObject({
    ...brokerQualificationCoreV1Shape,
    qualificationDigest: digestEnvelopeV1Schema,
  }).superRefine(validateBrokerQualification)

const destinationAuthorizationCoreV1Shape = {
  schemaVersion: z.literal(1),
  authorizationId: boundedIdSchema,
  issuerId: boundedIdSchema,
  level: z.literal('HOST_AUTHORIZED'),
  contextGrantDigest: digestEnvelopeV1Schema,
  requestDigest: digestEnvelopeV1Schema,
  subjectDigest: digestEnvelopeV1Schema,
  sourceDigest: digestEnvelopeV1Schema,
  path: subjectRelativePathSchema,
  redactionDigest: digestEnvelopeV1Schema,
  redactedDigest: digestEnvelopeV1Schema,
  secretReviewDigest: digestEnvelopeV1Schema,
  brokerQualificationDigest: digestEnvelopeV1Schema,
  brokerId: boundedIdSchema,
  providerId: boundedIdSchema,
  credentialBindingId: boundedIdSchema,
  dataEgressPolicyId: boundedIdSchema,
  destinationId: boundedIdSchema,
  categoryId: boundedIdSchema,
  requestByteLimit: z.number().int().positive().max(64 * 1024 * 1024),
  requestCountLimit: z.number().int().positive().max(1024),
  timeoutMilliseconds: z.number().int().positive().max(3_600_000),
  auditPolicyId: boundedIdSchema,
  authorizedAt: z.iso.datetime({ offset: true }),
  expiresAt: z.iso.datetime({ offset: true }),
} as const

function destinationAuthorizationWindowIsValid(
  authorization: SourceSliceDestinationAuthorizationCoreV1,
): boolean {
  return Date.parse(authorization.authorizedAt) < Date.parse(authorization.expiresAt)
}

export const sourceSliceDestinationAuthorizationV1Schema:
  z.ZodType<SourceSliceDestinationAuthorizationV1> = z.strictObject({
    ...destinationAuthorizationCoreV1Shape,
    authorizationDigest: digestEnvelopeV1Schema,
  }).refine(
    destinationAuthorizationWindowIsValid,
    'Destination authorization expiry must follow authorization',
  )

const protectedSourceSliceEgressAuthorizationCoreV1Shape = {
  schemaVersion: z.literal(1),
  contextGrantDigest: digestEnvelopeV1Schema,
  requestDigest: digestEnvelopeV1Schema,
  subjectDigest: digestEnvelopeV1Schema,
  sourceDigest: digestEnvelopeV1Schema,
  path: subjectRelativePathSchema,
  redactionDigest: digestEnvelopeV1Schema,
  redactedDigest: digestEnvelopeV1Schema,
  secretReviewDigest: digestEnvelopeV1Schema,
  brokerIdentity: brokerIdentityV1Schema,
  brokerQualificationId: boundedIdSchema,
  brokerQualificationDigest: digestEnvelopeV1Schema,
  destinationAuthorizationId: boundedIdSchema,
  destinationAuthorizationDigest: digestEnvelopeV1Schema,
  providerId: boundedIdSchema,
  credentialBindingId: boundedIdSchema,
  dataEgressPolicyId: boundedIdSchema,
  destinationId: boundedIdSchema,
  categoryId: boundedIdSchema,
  requestByteLimit: z.number().int().positive().max(64 * 1024 * 1024),
  requestCountLimit: z.literal(1),
  timeoutMilliseconds: z.number().int().positive().max(3_600_000),
  auditPolicyId: boundedIdSchema,
  evaluatedAt: z.iso.datetime({ offset: true }),
} as const

export const protectedSourceSliceEgressAuthorizationV1Schema:
  z.ZodType<ProtectedSourceSliceEgressAuthorizationV1> = z.strictObject({
    ...protectedSourceSliceEgressAuthorizationCoreV1Shape,
    egressAuthorizationDigest: digestEnvelopeV1Schema,
  })

function sameDigest(left: DigestEnvelopeV1, right: DigestEnvelopeV1): boolean {
  return canonicalJson(left) === canonicalJson(right)
}

function isUniqueAndCanonical(values: readonly string[]): boolean {
  return values.every((value, index) => index === 0 || values[index - 1]! < value)
}

function isUniqueDigestArray(values: readonly DigestEnvelopeV1[]): boolean {
  const serialized = values.map(value => canonicalJson(value))
  return new Set(serialized).size === serialized.length
}

function parseBrokerQualification(candidate: unknown): SourceSliceEgressBrokerQualificationV1 {
  const qualification = sourceSliceEgressBrokerQualificationV1Schema.parse(candidate)
  const { qualificationDigest, ...core } = qualification
  if (
    qualificationDigest.mediaType !== SOURCE_SLICE_EGRESS_BROKER_QUALIFICATION_MEDIA_TYPE
    || qualification.brokerIdentity.implementationDigest.mediaType
      !== SOURCE_SLICE_EGRESS_BROKER_IMPLEMENTATION_MEDIA_TYPE
    || !sameDigest(
      qualificationDigest,
      structuredDigest(SOURCE_SLICE_EGRESS_BROKER_QUALIFICATION_MEDIA_TYPE, core),
    )
  ) {
    throw new TypeError('Egress Broker Qualification digest is invalid')
  }
  return deepFreeze({ ...core, qualificationDigest })
}

function parseDestinationAuthorization(candidate: unknown): SourceSliceDestinationAuthorizationV1 {
  const authorization = sourceSliceDestinationAuthorizationV1Schema.parse(candidate)
  const { authorizationDigest, ...core } = authorization
  if (
    authorizationDigest.mediaType !== SOURCE_SLICE_DESTINATION_AUTHORIZATION_MEDIA_TYPE
    || !sameDigest(
      authorizationDigest,
      structuredDigest(SOURCE_SLICE_DESTINATION_AUTHORIZATION_MEDIA_TYPE, core),
    )
  ) {
    throw new TypeError('Source Slice Destination Authorization digest is invalid')
  }
  return deepFreeze({ ...core, authorizationDigest })
}

function validateSecretReview(
  review: ProtectedSourceSliceSecretReviewV1,
  material: ProtectedSourceSliceMaterialV1,
  redaction: ProtectedSourceSliceRedactionV1,
  assessmentMode: RoleContextGrantV1['purpose']['assessmentMode'],
): void {
  const { secretReviewDigest, ...core } = review
  if (
    review.decision !== 'CLEAR'
    || review.completion !== 'COMPLETE'
    || review.findingCount !== 0
    || review.path !== material.path
    || review.assessmentMode !== assessmentMode
    || !sameDigest(review.requestDigest, material.requestDigest)
    || !sameDigest(review.subjectDigest, material.subjectDigest)
    || !sameDigest(review.sourceDigest, material.digest)
    || !sameDigest(review.redactionDigest, redaction.redactionDigest)
    || !sameDigest(review.redactedDigest, redaction.redactedDigest)
    || secretReviewDigest.mediaType !== QUALIFIED_SOURCE_SLICE_SECRET_REVIEW_MEDIA_TYPE
    || !sameDigest(
      secretReviewDigest,
      structuredDigest(QUALIFIED_SOURCE_SLICE_SECRET_REVIEW_MEDIA_TYPE, core),
    )
  ) {
    throw new TypeError('Source Slice egress authorization requires exact complete CLEAR secret review')
  }
}

/** Admit Host evidence for one exact, still-not-invoked governed Broker request. */
export function admitProtectedSourceSliceEgressAuthorization(
  options: AdmitProtectedSourceSliceEgressAuthorizationOptionsV1,
): ProtectedSourceSliceEgressAuthorizationV1 {
  const contextGrant = parseRoleContextGrantV1(options.contextGrant)
  const request = parseSourceSliceRequestV1(options.request)
  if (preflightSourceSliceRequestV1({ contextGrant, request }).decision !== 'MATERIAL_REVIEW_REQUIRED') {
    throw new TypeError('Source Slice egress authorization failed static preflight')
  }
  if (request.disclosure.dataEgressPolicyId === 'egress/deny-by-default') {
    throw new TypeError('Deny-by-default Source Slice egress cannot be authorized')
  }
  if (
    !sameDigest(options.material.requestDigest, request.requestDigest)
    || !sameDigest(options.material.subjectDigest, request.subjectDigest)
    || !sameDigest(options.material.digest, request.target.expectedSourceDigest)
    || options.redaction.path !== options.material.path
    || !sameDigest(options.redaction.requestDigest, request.requestDigest)
    || !sameDigest(options.redaction.subjectDigest, options.material.subjectDigest)
    || !sameDigest(options.redaction.sourceDigest, options.material.digest)
  ) {
    throw new TypeError('Source Slice egress authorization does not bind the admitted material')
  }
  validateSecretReview(
    options.secretReview,
    options.material,
    options.redaction,
    contextGrant.purpose.assessmentMode,
  )
  const qualification = parseBrokerQualification(options.brokerQualification)
  const authorization = parseDestinationAuthorization(options.destinationAuthorization)
  const evaluatedAt = Date.parse(z.iso.datetime({ offset: true }).parse(options.evaluatedAt))
  const observedRedactedBytes = Buffer.byteLength(options.redaction.redactedText, 'utf8')
  if (
    evaluatedAt < Date.parse(qualification.issuedAt)
    || evaluatedAt >= Date.parse(qualification.expiresAt)
    || evaluatedAt < Date.parse(authorization.authorizedAt)
    || evaluatedAt >= Date.parse(authorization.expiresAt)
    || authorization.issuerId !== qualification.issuerId
    || Date.parse(authorization.authorizedAt) < Date.parse(qualification.issuedAt)
    || Date.parse(authorization.expiresAt) > Date.parse(qualification.expiresAt)
  ) {
    throw new TypeError('Source Slice egress authorization is not valid at its evaluation instant')
  }
  if (
    !sameDigest(authorization.contextGrantDigest, contextGrant.grantDigest)
    || !sameDigest(authorization.requestDigest, request.requestDigest)
    || !sameDigest(authorization.subjectDigest, options.material.subjectDigest)
    || !sameDigest(authorization.sourceDigest, options.material.digest)
    || authorization.path !== options.material.path
    || !sameDigest(authorization.redactionDigest, options.redaction.redactionDigest)
    || !sameDigest(authorization.redactedDigest, options.redaction.redactedDigest)
    || !sameDigest(authorization.secretReviewDigest, options.secretReview.secretReviewDigest)
    || !sameDigest(authorization.brokerQualificationDigest, qualification.qualificationDigest)
    || authorization.brokerId !== qualification.brokerIdentity.brokerId
    || authorization.dataEgressPolicyId !== request.disclosure.dataEgressPolicyId
    || authorization.destinationId !== request.disclosure.destinationId
    || authorization.categoryId !== request.disclosure.categoryId
  ) {
    throw new TypeError('Source Slice egress authorization does not bind its exact inputs')
  }
  if (
    !qualification.providerIds.includes(authorization.providerId)
    || !qualification.dataEgressPolicyIds.includes(authorization.dataEgressPolicyId)
    || !qualification.destinationIds.includes(authorization.destinationId)
    || !qualification.categoryIds.includes(authorization.categoryId)
    || !qualification.auditPolicyIds.includes(authorization.auditPolicyId)
    || authorization.requestByteLimit > request.budget.contextBytes
    || observedRedactedBytes > authorization.requestByteLimit
    || authorization.requestByteLimit > qualification.maximumRequestBytes
    || authorization.requestCountLimit !== 1
    || authorization.requestCountLimit > qualification.maximumRequestCount
    || authorization.timeoutMilliseconds > qualification.maximumTimeoutMilliseconds
  ) {
    throw new TypeError('Source Slice egress authorization exceeds Broker qualification or Request bounds')
  }
  if (
    options.redaction.redactionDigest.mediaType !== SOURCE_SLICE_REDACTION_MEDIA_TYPE
    || options.redaction.redactedDigest.mediaType !== REDACTED_SOURCE_SLICE_MEDIA_TYPE
  ) {
    throw new TypeError('Source Slice egress authorization redaction lineage is invalid')
  }
  const core: ProtectedSourceSliceEgressAuthorizationCoreV1 = {
    schemaVersion: 1,
    contextGrantDigest: contextGrant.grantDigest,
    requestDigest: request.requestDigest,
    subjectDigest: options.material.subjectDigest,
    sourceDigest: options.material.digest,
    path: options.material.path,
    redactionDigest: options.redaction.redactionDigest,
    redactedDigest: options.redaction.redactedDigest,
    secretReviewDigest: options.secretReview.secretReviewDigest,
    brokerIdentity: qualification.brokerIdentity,
    brokerQualificationId: qualification.qualificationId,
    brokerQualificationDigest: qualification.qualificationDigest,
    destinationAuthorizationId: authorization.authorizationId,
    destinationAuthorizationDigest: authorization.authorizationDigest,
    providerId: authorization.providerId,
    credentialBindingId: authorization.credentialBindingId,
    dataEgressPolicyId: authorization.dataEgressPolicyId,
    destinationId: authorization.destinationId,
    categoryId: authorization.categoryId,
    requestByteLimit: authorization.requestByteLimit,
    requestCountLimit: 1,
    timeoutMilliseconds: authorization.timeoutMilliseconds,
    auditPolicyId: authorization.auditPolicyId,
    evaluatedAt: options.evaluatedAt,
  }
  return deepFreeze({
    ...core,
    egressAuthorizationDigest: structuredDigest(SOURCE_SLICE_EGRESS_AUTHORIZATION_MEDIA_TYPE, core),
  })
}

/** Recompute the admitted Host evidence summary against its exact Source Slice lineage. */
export function parseProtectedSourceSliceEgressAuthorization(
  candidate: unknown,
  expected: ProtectedSourceSliceEgressAuthorizationBindingsV1,
): ProtectedSourceSliceEgressAuthorizationV1 {
  const authorization = protectedSourceSliceEgressAuthorizationV1Schema.parse(candidate)
  if (
    authorization.path !== expected.path
    || authorization.dataEgressPolicyId !== expected.dataEgressPolicyId
    || authorization.destinationId !== expected.destinationId
    || authorization.categoryId !== expected.categoryId
    || authorization.requestByteLimit > expected.requestedContextBytes
    || authorization.requestByteLimit < expected.observedRedactedBytes
    || !sameDigest(authorization.contextGrantDigest, expected.contextGrantDigest)
    || !sameDigest(authorization.requestDigest, expected.requestDigest)
    || !sameDigest(authorization.subjectDigest, expected.subjectDigest)
    || !sameDigest(authorization.sourceDigest, expected.sourceDigest)
    || !sameDigest(authorization.redactionDigest, expected.redactionDigest)
    || !sameDigest(authorization.redactedDigest, expected.redactedDigest)
    || !sameDigest(authorization.secretReviewDigest, expected.secretReviewDigest)
  ) {
    throw new TypeError('Source Slice egress authorization does not bind its expected inputs')
  }
  if (
    authorization.redactionDigest.mediaType !== SOURCE_SLICE_REDACTION_MEDIA_TYPE
    || authorization.redactedDigest.mediaType !== REDACTED_SOURCE_SLICE_MEDIA_TYPE
    || authorization.secretReviewDigest.mediaType
      !== QUALIFIED_SOURCE_SLICE_SECRET_REVIEW_MEDIA_TYPE
    || authorization.brokerQualificationDigest.mediaType
      !== SOURCE_SLICE_EGRESS_BROKER_QUALIFICATION_MEDIA_TYPE
    || authorization.brokerIdentity.implementationDigest.mediaType
      !== SOURCE_SLICE_EGRESS_BROKER_IMPLEMENTATION_MEDIA_TYPE
    || authorization.destinationAuthorizationDigest.mediaType
      !== SOURCE_SLICE_DESTINATION_AUTHORIZATION_MEDIA_TYPE
  ) {
    throw new TypeError('Source Slice egress authorization digest lineage is invalid')
  }
  const { egressAuthorizationDigest, ...core } = authorization
  if (
    egressAuthorizationDigest.mediaType !== SOURCE_SLICE_EGRESS_AUTHORIZATION_MEDIA_TYPE
    || !sameDigest(
      egressAuthorizationDigest,
      structuredDigest(SOURCE_SLICE_EGRESS_AUTHORIZATION_MEDIA_TYPE, core),
    )
  ) {
    throw new TypeError('Source Slice egress authorization digest is invalid')
  }
  return deepFreeze({ ...core, egressAuthorizationDigest })
}
