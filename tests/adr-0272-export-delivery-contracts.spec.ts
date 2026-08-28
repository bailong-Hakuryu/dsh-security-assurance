import { describe, expect, it } from 'vitest'
import {
  exportRequestReceiptV1Schema,
  exportStatusV1Schema,
  requestExportRequestSchema,
} from '../src/index.ts'

const assessmentId = 'asm-00000000-0000-0000-0000-000000000272'
const exportId = `export-${'2'.repeat(64)}`
const digest = {
  schemaVersion: 1 as const,
  algorithm: 'sha256' as const,
  mediaType: 'application/vnd.dsh.security.export+json',
  byteLength: 128,
  canonicalization: 'raw-bytes' as const,
  value: '2'.repeat(64),
}

describe('ADR 0272 Host-registered Export delivery', () => {
  it('accepts named destinations and rejects caller-controlled delivery authority', () => {
    const request = {
      schemaVersion: 1,
      contractVersion: 1 as const,
      idempotencyKey: 'adr-0272-export',
      assessmentId,
      expectedAssessmentRevision: 9,
      exportProfileId: 'security/export/internal-json-v1',
      deliveryDestinationId: 'delivery/local-audit',
    }
    expect(requestExportRequestSchema.safeParse(request).success).toBe(true)
    for (const forbidden of [
      { absolutePath: 'C:/private/export.json' },
      { url: 'https://example.invalid/upload' },
      { credential: 'secret' },
      { shellCommand: 'copy bundle' },
      { browserStoreLocation: 'downloads/export.json' },
    ]) {
      expect(requestExportRequestSchema.safeParse({ ...request, ...forbidden }).success).toBe(false)
    }
  })

  it('returns a durable Receipt and a path-free status projection', () => {
    const receipt = {
      schemaVersion: 1,
      operation: 'request_export',
      exportId,
      assessmentId,
      assessmentRevision: 9,
      idempotencyKey: 'adr-0272-export',
      acceptedState: 'PENDING',
      acceptedAt: '2026-08-28T00:00:00.000Z',
      correlationId: 'sec-00000000-0000-0000-0000-000000000272',
    }
    expect(exportRequestReceiptV1Schema.safeParse(receipt).success).toBe(true)

    const status = {
      schemaVersion: 1,
      kind: 'STATUS',
      exportId,
      assessmentId,
      assessmentRevision: 9,
      status: 'DELIVERED',
      profile: {
        exportProfileId: 'security/export/internal-json-v1',
        audience: 'INTERNAL',
        artifactFormat: 'JSON',
        mediaType: 'application/vnd.dsh.security.export+json',
        includedCategories: ['SUBJECT'],
        redactions: ['PRIVATE_STORE_PATHS'],
      },
      destination: {
        deliveryDestinationId: 'delivery/local-audit',
        kind: 'HOST_REGISTERED_LOCAL_AUDIT',
        summary: 'Host-managed local audit delivery',
      },
      artifact: { artifactId: `${exportId}/artifact`, digest },
      expiresAt: '2026-08-29T00:00:00.000Z',
      retention: { status: 'RETAINED' },
      delivery: {
        attemptCount: 1,
        lastAttemptAt: '2026-08-28T00:00:01.000Z',
        lastFailureAt: null,
        lastFailureCode: null,
        nextRetryAt: null,
      },
      accessAction: {
        kind: 'ONE_USE_DOWNLOAD',
        action: 'REQUEST_ONE_USE_DOWNLOAD',
        capabilityExpiresAfterSeconds: 60,
        maxByteLength: 16 * 1024 * 1024,
      },
      failure: null,
      createdAt: '2026-08-28T00:00:00.000Z',
      updatedAt: '2026-08-28T00:00:01.000Z',
    }
    expect(exportStatusV1Schema.safeParse(status).success).toBe(true)
    expect(exportStatusV1Schema.safeParse({
      ...status,
      destination: { ...status.destination, path: 'private/delivery/export.json' },
    }).success).toBe(false)
  })
})
