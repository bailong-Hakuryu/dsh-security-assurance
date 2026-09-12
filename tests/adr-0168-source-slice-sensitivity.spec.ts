import { describe, expect, it } from 'vitest'
import { binaryDigest, structuredDigest } from '../src/internal/canonical.ts'
import {
  classifyProtectedSourceSliceSensitivity,
  parseProtectedSourceSliceSensitivity,
  SOURCE_SLICE_SENSITIVITY_CLASSIFICATION_MEDIA_TYPE,
} from '../src/internal/source-slice-sensitivity.ts'
import { redactProtectedSourceSliceSecrets } from '../src/internal/source-slice-protection.ts'
import type { ProtectedSourceSliceMaterialV1 } from '../src/internal/subject-freeze.ts'

const fingerprintKey = new Uint8Array(32).fill(19)

function protectedMaterial(path: string, text: string): ProtectedSourceSliceMaterialV1 {
  return {
    requestDigest: structuredDigest(
      'application/vnd.dsh.security.source-slice-request+json',
      { requestId: 'slice-request-sensitivity-0168' },
    ),
    subjectDigest: structuredDigest(
      'application/vnd.dsh.security.subject-manifest+json',
      { subjectId: 'subject-sensitivity-0168' },
    ),
    path,
    digest: binaryDigest('application/octet-stream', Buffer.from(text, 'utf8')),
    text,
  }
}

function classify(path: string, text: string) {
  const material = protectedMaterial(path, text)
  const redaction = redactProtectedSourceSliceSecrets({
    material,
    fingerprintKey,
    fingerprintKeyId: 'host/secret-fingerprint-key-1',
  })
  return {
    material,
    redaction,
    classification: classifyProtectedSourceSliceSensitivity({ material, redaction }),
  }
}

describe('ADR 0168 protected Source Slice sensitivity classification', () => {
  it('classifies a detected secret as secret-bearing without retaining its value', () => {
    const secret = 'correct-horse-battery-staple'
    const { classification } = classify('src/config.ts', `password = "${secret}"\n`)

    expect(classification.category).toBe('SECRET_BEARING_SOURCE')
    expect(classification.indicatorCodes).toEqual(['HIGH_CONFIDENCE_SECRET_MATCH'])
    expect(classification.secretFindingCount).toBe(1)
    expect(JSON.stringify(classification)).not.toContain(secret)
    expect(Object.isFrozen(classification)).toBe(true)
    expect(Object.isFrozen(classification.indicatorCodes)).toBe(true)
  })

  it.each([
    '.env.production',
    'config/credentials.json',
    'certificates/client.pem',
    'home/.npmrc',
  ])('classifies the sensitive path %s as restricted without asserting a secret match', path => {
    const { classification } = classify(path, 'export const answer = 42\n')

    expect(classification.category).toBe('RESTRICTED_SOURCE')
    expect(classification.indicatorCodes).toEqual(['SENSITIVE_PATH'])
    expect(classification.secretFindingCount).toBe(0)
  })

  it('keeps ordinary source protected instead of inventing a public category', () => {
    const { classification } = classify('src/answer.ts', 'export const answer = 42\n')

    expect(classification.category).toBe('PROTECTED_SOURCE')
    expect(classification.indicatorCodes).toEqual(['BASELINE_SOURCE_PROTECTION'])
    expect(JSON.stringify(classification)).not.toMatch(/PUBLIC|LOW_SENSITIVITY/iu)
  })

  it('parses exact bindings and rejects a digest-valid downgrade', () => {
    const fixture = classify('src/config.ts', 'api_key = "sk-live-1234567890"\n')
    const bindings = { material: fixture.material, redaction: fixture.redaction }

    expect(parseProtectedSourceSliceSensitivity(fixture.classification, bindings))
      .toEqual(fixture.classification)
    const { classificationDigest: _classificationDigest, ...classificationCore } =
      fixture.classification
    const downgradedCore = {
      ...classificationCore,
      category: 'PROTECTED_SOURCE' as const,
      indicatorCodes: ['BASELINE_SOURCE_PROTECTION' as const],
    }
    expect(() => parseProtectedSourceSliceSensitivity({
      ...downgradedCore,
      classificationDigest: structuredDigest(
        SOURCE_SLICE_SENSITIVITY_CLASSIFICATION_MEDIA_TYPE,
        downgradedCore,
      ),
    }, bindings)).toThrow(/classification/iu)
  })

  it('keeps sensitivity classification outside the package root', async () => {
    const packageRoot = await import('../src/index.ts')

    expect(packageRoot).not.toHaveProperty('classifyProtectedSourceSliceSensitivity')
    expect(packageRoot).not.toHaveProperty('parseProtectedSourceSliceSensitivity')
  })
})
