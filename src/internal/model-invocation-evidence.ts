import { z } from 'zod'
import type {
  AssessmentId,
  DigestEnvelopeV1,
} from '../contracts.ts'
import {
  assessmentIdSchema,
  digestEnvelopeV1Schema,
  securitySubmissionJsonV1Schema,
} from '../contracts.ts'
import type { RoleContextGrantV1 } from '../role-context-grant.ts'
import { parseRoleContextGrantV1 } from '../role-context-grant.ts'
import { canonicalJson, structuredDigest } from './canonical.ts'
import {
  publishEvidenceSet,
  readPublishedEvidenceSet,
} from './evidence-persistence.ts'
import { deepFreeze } from './freeze.ts'
import type {
  ModelInvocationRecordBindingsV1,
  ModelInvocationRecordV1,
} from './model-invocation-settlement.ts'
import {
  MODEL_INVOCATION_RECORD_MEDIA_TYPE,
  parseModelInvocationRecordV1,
} from './model-invocation-settlement.ts'
import { SOURCE_SLICE_EGRESS_ATTEMPT_FENCE_MEDIA_TYPE } from './source-slice-egress-invocation.ts'

export const MODEL_INVOCATION_EVIDENCE_SCHEMA_ID =
  'dsh/security-model-invocation-record-v1'
export const MODEL_INVOCATION_EVIDENCE_PUBLICATION_RECEIPT_MEDIA_TYPE =
  'application/vnd.dsh.security.model-invocation-evidence-publication-receipt+json'

const MODEL_INVOCATION_ARTIFACT_ID = 'model-invocation-record'

function sameValue(left: unknown, right: unknown): boolean {
  return canonicalJson(left) === canonicalJson(right)
}

const attemptFenceDigestSchema = digestEnvelopeV1Schema.refine(
  digest => digest.mediaType === SOURCE_SLICE_EGRESS_ATTEMPT_FENCE_MEDIA_TYPE,
  'Model Invocation Evidence must bind an Attempt fence digest',
)
const invocationDigestSchema = digestEnvelopeV1Schema.refine(
  digest => (
    digest.mediaType === MODEL_INVOCATION_RECORD_MEDIA_TYPE
    && digest.canonicalization === 'dsh-canonical-json-v1'
  ),
  'Model Invocation Evidence must bind a canonical Model Invocation Record digest',
)
const publicationReceiptDigestSchema = digestEnvelopeV1Schema.refine(
  digest => digest.mediaType
    === MODEL_INVOCATION_EVIDENCE_PUBLICATION_RECEIPT_MEDIA_TYPE,
  'Model Invocation Evidence publication receipts must use the receipt media type',
)

export interface ModelInvocationEvidencePublicationReceiptCoreV1 {
  readonly schemaVersion: 1
  readonly assessmentId: AssessmentId
  readonly subjectDigest: DigestEnvelopeV1
  readonly artifactId: string
  readonly schemaId: typeof MODEL_INVOCATION_EVIDENCE_SCHEMA_ID
  readonly evidenceDigest: DigestEnvelopeV1
  readonly invocationId: string
  readonly parentAttempt: ModelInvocationRecordV1['parentAttempt']
  readonly recordDigest: DigestEnvelopeV1
}

export interface ModelInvocationEvidencePublicationReceiptV1
  extends ModelInvocationEvidencePublicationReceiptCoreV1 {
  readonly publicationReceiptDigest: DigestEnvelopeV1
}

const publicationReceiptCoreShape = {
  schemaVersion: z.literal(1),
  assessmentId: assessmentIdSchema,
  subjectDigest: digestEnvelopeV1Schema,
  artifactId: z.literal(MODEL_INVOCATION_ARTIFACT_ID),
  schemaId: z.literal(MODEL_INVOCATION_EVIDENCE_SCHEMA_ID),
  evidenceDigest: invocationDigestSchema,
  invocationId: z.string().regex(/^[a-z0-9][a-z0-9._/-]{0,127}$/iu),
  parentAttempt: z.strictObject({
    attemptId: z.string().regex(/^[a-z0-9][a-z0-9._/-]{0,127}$/iu),
    generation: z.number().int().positive().max(Number.MAX_SAFE_INTEGER),
    fenceDigest: attemptFenceDigestSchema,
  }),
  recordDigest: invocationDigestSchema,
} as const

const publicationReceiptV1Schema:
  z.ZodType<ModelInvocationEvidencePublicationReceiptV1> = z.strictObject({
    ...publicationReceiptCoreShape,
    publicationReceiptDigest: publicationReceiptDigestSchema,
  })

function parsePublicationReceipt(
  candidate: unknown,
): ModelInvocationEvidencePublicationReceiptV1 {
  const parsed = publicationReceiptV1Schema.parse(candidate)
  const { publicationReceiptDigest, ...core } = parsed
  if (
    parsed.artifactId !== MODEL_INVOCATION_ARTIFACT_ID
    || !sameValue(
      publicationReceiptDigest,
      structuredDigest(MODEL_INVOCATION_EVIDENCE_PUBLICATION_RECEIPT_MEDIA_TYPE, core),
    )
  ) {
    throw new TypeError('Model Invocation Evidence publication receipt is invalid')
  }
  return deepFreeze({ ...core, publicationReceiptDigest })
}

export interface PublishModelInvocationEvidenceOptionsV1 {
  readonly securityRoot: string
  readonly contextGrant: RoleContextGrantV1
  readonly record: ModelInvocationRecordV1
  readonly expected: ModelInvocationRecordBindingsV1
}

function exactPublicationContext(
  candidate: RoleContextGrantV1,
  expected: ModelInvocationRecordBindingsV1,
): RoleContextGrantV1 {
  const contextGrant = parseRoleContextGrantV1(candidate)
  if (
    contextGrant.roleAttemptId !== expected.attemptId
    || !sameValue(contextGrant.grantDigest, expected.contextGrantDigest)
  ) {
    throw new TypeError('Model Invocation Evidence does not bind the exact Context Grant')
  }
  return contextGrant
}

/**
 * Publish one protected record through the content-addressed Evidence layer.
 * The immutable object carries its exact parent Attempt; no path or Store handle escapes.
 */
export async function publishModelInvocationEvidenceV1(
  options: PublishModelInvocationEvidenceOptionsV1,
): Promise<ModelInvocationEvidencePublicationReceiptV1> {
  const contextGrant = exactPublicationContext(options.contextGrant, options.expected)
  const assessmentId = contextGrant.assessmentId
  const subjectDigest = contextGrant.subject.digest
  const record = parseModelInvocationRecordV1(options.record, options.expected)
  if (record.assessmentId !== assessmentId) {
    throw new TypeError('Model Invocation Evidence assessment binding is invalid')
  }
  const artifactId = MODEL_INVOCATION_ARTIFACT_ID
  const [evidenceReceipt] = await publishEvidenceSet(
    options.securityRoot,
    assessmentId,
    subjectDigest,
    [{
      artifactId,
      schemaId: MODEL_INVOCATION_EVIDENCE_SCHEMA_ID,
      mediaType: MODEL_INVOCATION_RECORD_MEDIA_TYPE,
      value: securitySubmissionJsonV1Schema.parse(record),
    }],
  )
  if (
    evidenceReceipt === undefined
    || evidenceReceipt.artifactId !== artifactId
    || evidenceReceipt.schemaId !== MODEL_INVOCATION_EVIDENCE_SCHEMA_ID
    || evidenceReceipt.digest.mediaType !== MODEL_INVOCATION_RECORD_MEDIA_TYPE
  ) {
    throw new Error('Model Invocation Evidence publication did not produce an exact receipt')
  }
  const core: ModelInvocationEvidencePublicationReceiptCoreV1 = {
    schemaVersion: 1,
    assessmentId,
    subjectDigest,
    artifactId,
    schemaId: MODEL_INVOCATION_EVIDENCE_SCHEMA_ID,
    evidenceDigest: evidenceReceipt.digest,
    invocationId: record.invocationId,
    parentAttempt: record.parentAttempt,
    recordDigest: record.recordDigest,
  }
  return parsePublicationReceipt({
    ...core,
    publicationReceiptDigest: structuredDigest(
      MODEL_INVOCATION_EVIDENCE_PUBLICATION_RECEIPT_MEDIA_TYPE,
      core,
    ),
  })
}

export interface ReadPublishedModelInvocationEvidenceOptionsV1 {
  readonly securityRoot: string
  readonly contextGrant: RoleContextGrantV1
  readonly receipt: ModelInvocationEvidencePublicationReceiptV1
  readonly expected: ModelInvocationRecordBindingsV1
}

/** Read one exact immutable record after rechecking its publication and Attempt lineage. */
export async function readPublishedModelInvocationEvidenceV1(
  options: ReadPublishedModelInvocationEvidenceOptionsV1,
): Promise<ModelInvocationRecordV1> {
  const contextGrant = exactPublicationContext(options.contextGrant, options.expected)
  const assessmentId = contextGrant.assessmentId
  const subjectDigest = contextGrant.subject.digest
  const receipt = parsePublicationReceipt(options.receipt)
  if (
    receipt.assessmentId !== assessmentId
    || !sameValue(receipt.subjectDigest, subjectDigest)
    || receipt.invocationId !== options.expected.invocationId
    || receipt.parentAttempt.attemptId !== options.expected.attemptId
    || receipt.parentAttempt.generation !== options.expected.attemptGeneration
    || !sameValue(receipt.parentAttempt.fenceDigest, options.expected.attemptFenceDigest)
  ) {
    throw new TypeError('Model Invocation Evidence does not bind the expected subject or Attempt')
  }
  const records = await readPublishedEvidenceSet(
    options.securityRoot,
    assessmentId,
    subjectDigest,
    [{
      schemaVersion: 1,
      artifactId: receipt.artifactId,
      schemaId: receipt.schemaId,
      digest: receipt.evidenceDigest,
    }],
  )
  const [stored] = records
  if (
    stored === undefined
    || records.length !== 1
    || stored.artifactId !== receipt.artifactId
    || stored.schemaId !== MODEL_INVOCATION_EVIDENCE_SCHEMA_ID
    || stored.mediaType !== MODEL_INVOCATION_RECORD_MEDIA_TYPE
  ) {
    throw new Error('Model Invocation Evidence read did not resolve one exact record')
  }
  const record = parseModelInvocationRecordV1(stored.value, options.expected)
  if (
    record.assessmentId !== assessmentId
    || record.invocationId !== receipt.invocationId
    || !sameValue(record.parentAttempt, receipt.parentAttempt)
    || !sameValue(record.recordDigest, receipt.recordDigest)
    || !sameValue(
      structuredDigest(MODEL_INVOCATION_RECORD_MEDIA_TYPE, record),
      receipt.evidenceDigest,
    )
  ) {
    throw new Error('Model Invocation Evidence failed its publication binding')
  }
  return record
}
