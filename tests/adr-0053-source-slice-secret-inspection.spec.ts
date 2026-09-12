import { describe, expect, it } from 'vitest'
import type { ProtectedSourceSliceMaterialV1 } from '../src/internal/subject-freeze.ts'
import { binaryDigest, structuredDigest } from '../src/internal/canonical.ts'
import { inspectProtectedSourceSliceSecrets } from '../src/internal/source-slice-protection.ts'

const fingerprintKey = new Uint8Array(32).fill(7)

function protectedMaterial(text: string): ProtectedSourceSliceMaterialV1 {
  return {
    requestDigest: structuredDigest(
      'application/vnd.dsh.security.source-slice-request+json',
      { requestId: 'slice-request-0053' },
    ),
    subjectDigest: structuredDigest(
      'application/vnd.dsh.security.subject-manifest+json',
      { subjectId: 'subject-0053' },
    ),
    path: 'src/config.ts',
    digest: binaryDigest('application/octet-stream', Buffer.from(text, 'utf8')),
    text,
  }
}

describe('ADR 0053 protected Source Slice secret inspection', () => {
  it('retains only type, location and keyed irreversible fingerprints', () => {
    const apiKey = 'sk-live-1234567890'
    const bearer = 'eyJhbGciOiJIUzI1NiJ9.payload.signature'
    const report = inspectProtectedSourceSliceSecrets({
      material: protectedMaterial([
        `const apiKey = "${apiKey}"`,
        `Authorization: Bearer ${bearer}`,
      ].join('\n')),
      fingerprintKey,
      fingerprintKeyId: 'host/secret-fingerprint-key-1',
    })

    expect(report.decision).toBe('REDACTION_REQUIRED')
    expect(report.findings.map(finding => finding.kind)).toEqual([
      'ASSIGNMENT_SECRET',
      'BEARER_TOKEN',
    ])
    for (const finding of report.findings) {
      expect(finding).toEqual(expect.objectContaining({
        startOffset: expect.any(Number),
        endOffset: expect.any(Number),
        line: expect.any(Number),
        column: expect.any(Number),
        fingerprint: expect.stringMatching(/^hmac-sha256:[0-9a-f]{64}$/u),
      }))
    }
    expect(JSON.stringify(report)).not.toContain(apiKey)
    expect(JSON.stringify(report)).not.toContain(bearer)
    expect(Object.isFrozen(report)).toBe(true)
    expect(Object.isFrozen(report.findings)).toBe(true)
  })

  it('is deterministic for one key and separates fingerprints across keys', () => {
    const material = protectedMaterial('password = "correct-horse-battery-staple"\n')
    const first = inspectProtectedSourceSliceSecrets({
      material,
      fingerprintKey,
      fingerprintKeyId: 'host/secret-fingerprint-key-1',
    })
    const repeated = inspectProtectedSourceSliceSecrets({
      material,
      fingerprintKey,
      fingerprintKeyId: 'host/secret-fingerprint-key-1',
    })
    const rotated = inspectProtectedSourceSliceSecrets({
      material,
      fingerprintKey: new Uint8Array(32).fill(9),
      fingerprintKeyId: 'host/secret-fingerprint-key-2',
    })

    expect(repeated).toEqual(first)
    expect(rotated.findings[0]?.fingerprint).not.toBe(first.findings[0]?.fingerprint)
  })

  it('does not claim that a bounded high-confidence scan proves absence', () => {
    const report = inspectProtectedSourceSliceSecrets({
      material: protectedMaterial('export const answer = 42\n'),
      fingerprintKey,
      fingerprintKeyId: 'host/secret-fingerprint-key-1',
    })

    expect(report.decision).toBe('ADDITIONAL_REVIEW_REQUIRED')
    expect(report.findings).toEqual([])
  })

  it('rejects weak fingerprint keys and tampered protected material', () => {
    const material = protectedMaterial('secret = "sufficiently-long-value"\n')
    expect(() => inspectProtectedSourceSliceSecrets({
      material,
      fingerprintKey: new Uint8Array(31),
      fingerprintKeyId: 'host/secret-fingerprint-key-1',
    })).toThrow(/at least 32 bytes/iu)

    expect(() => inspectProtectedSourceSliceSecrets({
      material: { ...material, text: `${material.text}drift` },
      fingerprintKey,
      fingerprintKeyId: 'host/secret-fingerprint-key-1',
    })).toThrow(/digest/iu)
  })

  it('keeps the secret inspection seam outside the package root', async () => {
    const packageRoot = await import('../src/index.ts')

    expect(packageRoot).not.toHaveProperty('inspectProtectedSourceSliceSecrets')
  })
})
