import { describe, expect, it } from 'vitest'
import type { ProtectedSourceSliceMaterialV1 } from '../src/internal/subject-freeze.ts'
import { binaryDigest, structuredDigest } from '../src/internal/canonical.ts'
import {
  parseProtectedSourceSliceRedaction,
  redactProtectedSourceSliceSecrets,
} from '../src/internal/source-slice-protection.ts'

const fingerprintKey = new Uint8Array(32).fill(11)

function protectedMaterial(text: string): ProtectedSourceSliceMaterialV1 {
  return {
    requestDigest: structuredDigest(
      'application/vnd.dsh.security.source-slice-request+json',
      { requestId: 'slice-request-0110' },
    ),
    subjectDigest: structuredDigest(
      'application/vnd.dsh.security.subject-manifest+json',
      { subjectId: 'subject-0110' },
    ),
    path: 'src/provider.ts',
    digest: binaryDigest('application/octet-stream', Buffer.from(text, 'utf8')),
    text,
  }
}

describe('ADR 0110 protected Source Slice redaction', () => {
  it('replaces detected values without retaining raw secrets', () => {
    const password = 'correct-horse-battery-staple'
    const bearer = 'eyJhbGciOiJIUzI1NiJ9.payload.signature'
    const material = protectedMaterial([
      `password = "${password}"`,
      `Authorization: Bearer ${bearer}`,
    ].join('\n'))

    const redaction = redactProtectedSourceSliceSecrets({
      material,
      fingerprintKey,
      fingerprintKeyId: 'host/secret-fingerprint-key-1',
    })

    expect(redaction.decision).toBe('REDACTED_MATCHES_REVIEW_REQUIRED')
    expect(redaction.redactedText).toBe([
      'password = "[REDACTED:ASSIGNMENT_SECRET]"',
      'Authorization: Bearer [REDACTED:BEARER_TOKEN]',
    ].join('\n'))
    expect(JSON.stringify(redaction)).not.toContain(password)
    expect(JSON.stringify(redaction)).not.toContain(bearer)
    expect(redaction.redactedDigest).toEqual(binaryDigest(
      'application/vnd.dsh.security.redacted-source-slice+text',
      Buffer.from(redaction.redactedText, 'utf8'),
    ))
    expect(Object.isFrozen(redaction)).toBe(true)
    expect(Object.isFrozen(redaction.redactions)).toBe(true)
  })

  it('redacts a complete private-key block as one bounded match', () => {
    const privateKey = [
      '-----BEGIN PRIVATE KEY-----',
      'cHJpdmF0ZS1rZXktbWF0ZXJpYWw=',
      '-----END PRIVATE KEY-----',
    ].join('\n')
    const redaction = redactProtectedSourceSliceSecrets({
      material: protectedMaterial(privateKey),
      fingerprintKey,
      fingerprintKeyId: 'host/secret-fingerprint-key-1',
    })

    expect(redaction.redactedText).toBe('[REDACTED:PRIVATE_KEY]')
    expect(redaction.redactions).toHaveLength(1)
    expect(JSON.stringify(redaction)).not.toContain('cHJpdmF0ZS1rZXktbWF0ZXJpYWw=')
  })

  it('is deterministic but keeps no-match text under additional review', () => {
    const material = protectedMaterial('export const answer = 42\n')
    const first = redactProtectedSourceSliceSecrets({
      material,
      fingerprintKey,
      fingerprintKeyId: 'host/secret-fingerprint-key-1',
    })
    const repeated = redactProtectedSourceSliceSecrets({
      material,
      fingerprintKey,
      fingerprintKeyId: 'host/secret-fingerprint-key-1',
    })

    expect(repeated).toEqual(first)
    expect(first.decision).toBe('ADDITIONAL_REVIEW_REQUIRED')
    expect(first.redactedText).toBe(material.text)
    expect(first.redactions).toEqual([])
  })

  it('recomputes both digests and exact source bindings when parsing', () => {
    const material = protectedMaterial('api_key = "sk-live-1234567890"\n')
    const redaction = redactProtectedSourceSliceSecrets({
      material,
      fingerprintKey,
      fingerprintKeyId: 'host/secret-fingerprint-key-1',
    })

    expect(parseProtectedSourceSliceRedaction(redaction, material)).toEqual(redaction)
    expect(() => parseProtectedSourceSliceRedaction({
      ...redaction,
      redactedText: `${redaction.redactedText}drift`,
    }, material)).toThrow(/digest/iu)
    expect(() => parseProtectedSourceSliceRedaction({
      ...redaction,
      path: 'src/other.ts',
    }, material)).toThrow(/bind/iu)
  })

  it('keeps redaction outside the package root interface', async () => {
    const packageRoot = await import('../src/index.ts')

    expect(packageRoot).not.toHaveProperty('redactProtectedSourceSliceSecrets')
    expect(packageRoot).not.toHaveProperty('parseProtectedSourceSliceRedaction')
  })
})
