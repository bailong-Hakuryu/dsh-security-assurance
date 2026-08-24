import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto'
import { z } from 'zod'
import {
  assessmentIdSchema,
  assessmentListPageV1Schema,
} from '../contracts.ts'
import type {
  AssessmentListItemV1,
  AssessmentListPageV1,
  ListAssessmentsRequest,
} from '../contracts.ts'
import type {
  AssessmentListKey,
  SecurityPersistence,
} from './persistence.ts'
import type { InternalAssessmentRecordV1 } from './assessment-record.ts'
import { canonicalJson, sha256Hex } from './canonical.ts'

const listKeySchema = z.strictObject({
  createdAt: z.iso.datetime({ offset: true }),
  assessmentId: assessmentIdSchema,
})

const watermarkPayloadSchema = z.strictObject({
  schemaVersion: z.literal(1),
  authorityDigest: z.string().length(64).regex(/^[0-9a-f]+$/),
  upperInclusive: listKeySchema.nullable(),
})

const cursorPayloadSchema = z.strictObject({
  schemaVersion: z.literal(1),
  authorityDigest: z.string().length(64).regex(/^[0-9a-f]+$/),
  limit: z.number().int().min(1).max(100),
  consistencyWatermark: z.string().min(1).max(4096),
  afterExclusive: listKeySchema,
})

type WatermarkPayload = z.infer<typeof watermarkPayloadSchema>
export class AssessmentListCursorError extends Error {}

export interface AssessmentListAuthority {
  readonly kind: 'harness-session' | 'host-operator' | 'control-plane'
  readonly principalId: string
}

function authorityDigest(authority: AssessmentListAuthority): string {
  return sha256Hex(canonicalJson(authority))
}

function project(record: InternalAssessmentRecordV1): AssessmentListItemV1 {
  return {
    schemaVersion: 1,
    assessmentId: record.assessmentId,
    assessmentRevision: record.assessmentRevision,
    state: record.state,
    repository: {
      repositoryId: record.repository.repositoryId,
      repositoryRevision: record.repository.repositoryRevision,
    },
    subjectKind: record.subject.source.kind,
    policyId: record.contract.policy.policyId,
    coverageStatus: record.coverage.status,
    verdict: record.verdict,
    createdAt: record.createdAt,
    updatedAt: record.updatedAt,
  }
}

/** Deep query Module owning redaction, keyset stability, and authority-bound opaque cursors. */
export class AssessmentListQueryModule {
  readonly #cursorKey = randomBytes(32)

  list(
    persistence: SecurityPersistence,
    request: ListAssessmentsRequest,
    authority: AssessmentListAuthority,
  ): AssessmentListPageV1 {
    const digest = authorityDigest(authority)
    let watermark: WatermarkPayload
    let consistencyWatermark: string
    let afterExclusive: AssessmentListKey | null = null

    if (request.cursor === undefined) {
      watermark = {
        schemaVersion: 1,
        authorityDigest: digest,
        upperInclusive: persistence.getAssessmentListWatermark(),
      }
      consistencyWatermark = this.#encode(watermarkPayloadSchema, watermark)
    } else {
      const cursor = this.#decode(cursorPayloadSchema, request.cursor)
      if (cursor.authorityDigest !== digest || cursor.limit !== request.limit) {
        throw new AssessmentListCursorError('Assessment list cursor does not match this query')
      }
      consistencyWatermark = cursor.consistencyWatermark
      watermark = this.#decode(watermarkPayloadSchema, consistencyWatermark)
      if (watermark.authorityDigest !== digest) {
        throw new AssessmentListCursorError('Assessment list watermark does not match this authority')
      }
      afterExclusive = cursor.afterExclusive
    }

    const records = watermark.upperInclusive === null
      ? []
      : persistence.listAssessmentRecordsPage({
          upperInclusive: watermark.upperInclusive,
          afterExclusive,
          limit: request.limit + 1,
        })
    const page = records.slice(0, request.limit)
    const last = page.at(-1)
    const nextCursor = records.length > request.limit && last !== undefined
      ? this.#encode(cursorPayloadSchema, {
          schemaVersion: 1,
          authorityDigest: digest,
          limit: request.limit,
          consistencyWatermark,
          afterExclusive: {
            createdAt: last.createdAt,
            assessmentId: last.assessmentId,
          },
        })
      : null

    return assessmentListPageV1Schema.parse({
      schemaVersion: 1,
      consistencyWatermark,
      assessments: page.map(project),
      nextCursor,
    })
  }

  #encode<T>(schema: z.ZodType<T>, payload: T): string {
    const body = Buffer.from(canonicalJson(schema.parse(payload)), 'utf8').toString('base64url')
    const signature = createHmac('sha256', this.#cursorKey).update(body).digest('base64url')
    return `${body}.${signature}`
  }

  #decode<T>(schema: z.ZodType<T>, value: string): T {
    try {
      const parts = value.split('.')
      if (parts.length !== 2) throw new Error('invalid framing')
      const [body, encodedSignature] = parts
      if (body === undefined || encodedSignature === undefined) throw new Error('invalid framing')
      const actual = Buffer.from(encodedSignature, 'base64url')
      const expected = createHmac('sha256', this.#cursorKey).update(body).digest()
      if (actual.length !== expected.length || !timingSafeEqual(actual, expected)) {
        throw new Error('invalid signature')
      }
      const decoded: unknown = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'))
      return schema.parse(decoded)
    } catch {
      throw new AssessmentListCursorError('Assessment list cursor is invalid')
    }
  }
}
