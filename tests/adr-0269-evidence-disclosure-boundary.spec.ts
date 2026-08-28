import { describe, expect, it } from 'vitest'
import {
  evidenceViewV1Schema,
  getEvidenceViewRequestSchema,
} from '../src/index.ts'

const assessmentId = 'asm-00000000-0000-0000-0000-000000000269'
const recordId = `finding-${'9'.repeat(64)}`
const digest = {
  schemaVersion: 1 as const,
  algorithm: 'sha256' as const,
  mediaType: 'application/vnd.dsh.canonical-json',
  byteLength: 1,
  canonicalization: 'dsh-canonical-json-v1' as const,
  value: '9'.repeat(64),
}

describe('ADR 0269 purpose- and Profile-bound Evidence disclosure', () => {
  it('requires exact Evidence, consuming Finding, purpose, and named Profile identities', () => {
    const request = {
      schemaVersion: 1,
      assessmentId,
      assessmentRevision: 7,
      context: { kind: 'finding', recordId, recordRevision: 1 },
      evidenceArtifactId: 'validation-evidence',
      evidenceDigest: digest,
      purpose: 'VALIDATION_REVIEW',
      viewProfileId: 'security/evidence-view/bounded-json-v1',
    }
    expect(getEvidenceViewRequestSchema.safeParse(request).success).toBe(true)
    for (const invalid of [
      { ...request, evidenceDigest: undefined },
      { ...request, context: undefined },
      { ...request, purpose: undefined },
      { ...request, viewProfileId: 'security/evidence-view/unrestricted-v1' },
      { ...request, storePath: 'private/evidence/record.json' },
    ]) {
      expect(getEvidenceViewRequestSchema.safeParse(invalid).success).toBe(false)
    }
  })

  it('admits only bounded content or structured redaction without storage authority', () => {
    const view = {
      schemaVersion: 1,
      assessmentId,
      assessmentRevision: 7,
      context: { kind: 'finding', recordId, recordRevision: 1 },
      evidence: {
        artifactId: 'validation-evidence',
        schemaId: 'security/validation-evidence',
        digest,
        classification: 'CONTROL_PLANE',
      },
      link: {
        purpose: 'VALIDATION_EVIDENCE',
        eligibilityDecision: 'ELIGIBLE',
        eligibilityDecisionArtifactId: 'eligibility-decision',
      },
      purpose: 'FINDING_TRIAGE',
      viewProfileId: 'security/evidence-view/metadata-only-v1',
      protection: { policyId: 'evidence/local-protected', status: 'AVAILABLE' },
      retention: { status: 'RETAINED' },
      egress: { policyId: 'egress/deny-by-default', status: 'LOCAL_ONLY' },
      content: { kind: 'REDACTED', reason: 'PROFILE_METADATA_ONLY' },
    }
    expect(evidenceViewV1Schema.safeParse(view).success).toBe(true)
    for (const forbidden of [
      { path: 'private/evidence/record.json' },
      { encryptionKey: 'secret' },
      { capability: { kind: 'REUSABLE' } },
    ]) {
      expect(evidenceViewV1Schema.safeParse({ ...view, ...forbidden }).success).toBe(false)
    }
    expect(evidenceViewV1Schema.safeParse({
      ...view,
      purpose: 'VALIDATION_REVIEW',
      viewProfileId: 'security/evidence-view/bounded-json-v1',
      content: {
        kind: 'BOUNDED_JSON',
        byteLength: 32 * 1024 + 1,
        expiresAt: '2026-08-28T01:00:00.000Z',
        value: { secret: 'x' },
      },
    }).success).toBe(false)
  })
})
