import { describe, expect, it } from 'vitest'
import {
  INTERNAL_JSON_EXPORT_PROFILE_ID,
  LOCAL_AUDIT_DELIVERY_DESTINATION_ID,
  requestExportRequestSchema,
} from '../src/index.ts'
import { buildExportPreview } from '../src/internal/export-delivery.ts'

const assessmentId = 'asm-00000000-0000-0000-0000-000000000291'

describe('ADR 0291 Service-derived Export Preview and Delivery', () => {
  it('projects the fixed Profile, redactions, registered destination summary, expiry, and warnings', () => {
    const preview = buildExportPreview({
      assessmentId,
      assessmentRevision: 7,
      sealId: 'seal-00000000-0000-0000-0000-000000000291',
      deliveryDestinationId: LOCAL_AUDIT_DELIVERY_DESTINATION_ID,
    })

    expect(preview).toMatchObject({
      kind: 'PREVIEW',
      assessmentId,
      assessmentRevision: 7,
      profile: {
        exportProfileId: INTERNAL_JSON_EXPORT_PROFILE_ID,
        artifactFormat: 'JSON',
        redactions: expect.arrayContaining([
          'ORIGINAL_CREDENTIAL_VALUES',
          'HOST_CREDENTIALS',
          'PRIVATE_STORE_PATHS',
        ]),
      },
      destination: {
        deliveryDestinationId: LOCAL_AUDIT_DELIVERY_DESTINATION_ID,
        kind: 'HOST_REGISTERED_LOCAL_AUDIT',
        summary: 'Host-registered local audit delivery',
      },
      expiresAfterSeconds: 86_400,
    })
    expect(preview?.profile.includedCategories).toEqual(expect.arrayContaining([
      'SUBJECT',
      'FINDINGS',
      'EVIDENCE',
      'PROVENANCE',
      'SEAL',
    ]))
    expect(preview?.warnings.length).toBeGreaterThan(0)
    expect(JSON.stringify(preview)).not.toMatch(/[A-Z]:\\|file:\/\/|https?:\/\//u)
  })

  it('admits only a named Profile and registered destination identity, never an arbitrary target', () => {
    const request = {
      schemaVersion: 1,
      contractVersion: 1,
      idempotencyKey: 'adr-0291-export-v1',
      assessmentId,
      expectedAssessmentRevision: 7,
      exportProfileId: INTERNAL_JSON_EXPORT_PROFILE_ID,
      deliveryDestinationId: LOCAL_AUDIT_DELIVERY_DESTINATION_ID,
    }
    expect(requestExportRequestSchema.safeParse(request).success).toBe(true)
    for (const forbidden of [
      { path: 'C:\\private\\report.json' },
      { url: 'https://example.invalid/report' },
      { credential: 'secret' },
      { command: 'write-report' },
      { artifactBytes: 'canonical-report' },
    ]) {
      expect(requestExportRequestSchema.safeParse({ ...request, ...forbidden }).success).toBe(false)
    }
  })
})
