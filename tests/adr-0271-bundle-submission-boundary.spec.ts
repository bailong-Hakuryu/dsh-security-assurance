import { describe, expect, it } from 'vitest'
import {
  bundleManifestV1Schema,
  getAssuranceSubmissionRequestSchema,
  getBundleManifestRequestSchema,
  securityAssuranceSubmissionV1Schema,
} from '../src/index.ts'

const assessmentId = 'asm-00000000-0000-0000-0000-000000000271'
const digest = {
  schemaVersion: 1 as const,
  algorithm: 'sha256' as const,
  mediaType: 'application/vnd.dsh.canonical-json',
  byteLength: 1,
  canonicalization: 'dsh-canonical-json-v1' as const,
  value: '1'.repeat(64),
}

function objectShape(schema: unknown): Record<string, unknown> {
  return (schema as { readonly shape: Record<string, unknown> }).shape
}

describe('ADR 0271 Bundle Manifest and self-contained Submission', () => {
  it('keeps Bundle reads identity-only and the Manifest path-free', () => {
    const request = { schemaVersion: 1, assessmentId }
    expect(getBundleManifestRequestSchema.safeParse(request).success).toBe(true)
    expect(getAssuranceSubmissionRequestSchema.safeParse(request).success).toBe(true)
    for (const forbidden of [
      { path: 'private/bundles/manifest.json' },
      { regenerateFromMarkdown: true },
      { uncheckedBytes: 'opaque' },
    ]) {
      expect(getBundleManifestRequestSchema.safeParse({ ...request, ...forbidden }).success).toBe(false)
      expect(getAssuranceSubmissionRequestSchema.safeParse({ ...request, ...forbidden }).success).toBe(false)
    }

    const manifest = {
      schemaVersion: 1,
      assessmentId,
      assessmentRevision: 9,
      verdict: 'SATISFIED',
      seal: {
        schemaVersion: 1,
        sealId: 'seal-00000000-0000-0000-0000-000000000271',
        assessmentRevision: 9,
        verdict: 'SATISFIED',
        digest,
        sealedAt: '2026-08-28T00:00:00.000Z',
      },
      records: [{
        recordId: 'findings',
        schemaId: 'dsh/security-findings',
        schemaVersion: 1,
        classification: 'CONTROL_PLANE',
        digest,
      }],
      omissions: [{
        schemaId: 'dsh/security-threat-model',
        reason: 'NO_ELIGIBLE_ANALYZER',
      }],
      digest,
    }
    expect(bundleManifestV1Schema.safeParse(manifest).success).toBe(true)
    for (const forbidden of [
      { path: 'private/bundles/manifest.json' },
      { storeHandle: { transactionId: 'private' } },
      { records: [{ ...manifest.records[0], value: { secret: true } }] },
    ]) {
      expect(bundleManifestV1Schema.safeParse({ ...manifest, ...forbidden }).success).toBe(false)
    }
  })

  it('requires the complete digest-bound Submission value instead of a Store reference', () => {
    const submissionShape = objectShape(securityAssuranceSubmissionV1Schema)
    const payloadKeys = Object.keys(objectShape(submissionShape.payload)).sort()
    expect(payloadKeys).toEqual([
      'assessment',
      'binding',
      'coverage',
      'evidence',
      'findings',
      'provenance',
      'providerComposition',
      'providerPolicy',
      'riskDecisions',
      'sourceSeal',
    ])
    expect(Object.keys(submissionShape).sort()).toEqual([
      'digest',
      'payload',
      'schemaVersion',
    ])
    expect(securityAssuranceSubmissionV1Schema.safeParse({
      schemaVersion: 1,
      submissionId: 'store-reference-only',
      digest,
    }).success).toBe(false)
  })
})
