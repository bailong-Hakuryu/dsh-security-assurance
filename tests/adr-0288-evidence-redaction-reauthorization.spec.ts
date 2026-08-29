import { describe, expect, it } from 'vitest'
import { evidenceViewV1Schema } from '../src/index.ts'

const digest = {
  schemaVersion: 1 as const,
  algorithm: 'sha256' as const,
  mediaType: 'application/vnd.dsh.canonical-json',
  byteLength: 128,
  canonicalization: 'dsh-canonical-json-v1' as const,
  value: '8'.repeat(64),
}

const metadata = {
  schemaVersion: 1 as const,
  assessmentId: 'asm-00000000-0000-0000-0000-000000000288',
  assessmentRevision: 4,
  context: {
    kind: 'finding' as const,
    recordId: `finding-${'8'.repeat(64)}`,
    recordRevision: 1,
  },
  evidence: {
    artifactId: 'validation-evidence',
    schemaId: 'security/validation-evidence',
    digest,
    classification: 'CONTROL_PLANE' as const,
  },
  link: {
    purpose: 'VALIDATION_EVIDENCE' as const,
    eligibilityDecision: 'ELIGIBLE' as const,
    eligibilityDecisionArtifactId: 'validation-eligibility',
  },
  producerLineage: {
    status: 'VERIFIED' as const,
    producer: {
      analyzerId: 'security/reference-analyzer',
      analyzerVersion: '1.2.0',
      buildDigest: { ...digest, value: 'b'.repeat(64) },
    },
    lineageArtifactId: 'validation-eligibility',
  },
  redactedSummary: {
    kind: 'SCHEMA_METADATA' as const,
    byteLength: digest.byteLength,
    contentStatus: 'REDACTED' as const,
  },
  purpose: 'FINDING_TRIAGE' as const,
  viewProfileId: 'security/evidence-view/metadata-only-v1' as const,
  protection: { policyId: 'evidence/local-protected', status: 'AVAILABLE' as const },
  retention: { status: 'RETAINED' as const },
  egress: { policyId: 'egress/deny-by-default', status: 'LOCAL_ONLY' as const },
  content: { kind: 'REDACTED' as const, reason: 'PROFILE_METADATA_ONLY' as const },
}

describe('ADR 0288 Evidence starts redacted and reauthorizes disclosure', () => {
  it('requires safe metadata, producer lineage, and an explicit redacted summary', () => {
    expect(evidenceViewV1Schema.parse(metadata)).toMatchObject({
      producerLineage: { status: 'VERIFIED', lineageArtifactId: 'validation-eligibility' },
      redactedSummary: { contentStatus: 'REDACTED', byteLength: 128 },
      content: { kind: 'REDACTED', reason: 'PROFILE_METADATA_ONLY' },
    })
    for (const forbidden of [
      { storeDirectory: 'private/evidence' },
      { decryptionCapability: 'durable-secret' },
      { preloadedValue: { sensitive: true } },
    ]) expect(evidenceViewV1Schema.safeParse({ ...metadata, ...forbidden }).success).toBe(false)
  })

  it('admits sensitive content only through the purpose-bound expiring profile', () => {
    const value = { proof: 'bounded' }
    const byteLength = Buffer.byteLength(JSON.stringify(value), 'utf8')
    const disclosed = {
      ...metadata,
      purpose: 'VALIDATION_REVIEW',
      viewProfileId: 'security/evidence-view/bounded-json-v1',
      content: {
        kind: 'BOUNDED_JSON',
        byteLength,
        expiresAt: '2026-08-29T12:05:00.000Z',
        value,
      },
    }
    expect(evidenceViewV1Schema.safeParse(disclosed).success).toBe(true)
    expect(evidenceViewV1Schema.safeParse({
      ...disclosed,
      purpose: 'FINDING_TRIAGE',
    }).success).toBe(false)
  })
})
