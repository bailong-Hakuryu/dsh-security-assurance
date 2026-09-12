import { describe, expect, it } from 'vitest'
import {
  createRoleContextGrantV1,
  createSourceSliceRequestV1,
} from '../src/index.ts'
import type { ProtectedSourceSliceMaterialV1 } from '../src/internal/subject-freeze.ts'
import { binaryDigest, structuredDigest } from '../src/internal/canonical.ts'
import {
  parseProtectedSourceSliceEgressReview,
  redactProtectedSourceSliceSecrets,
  reviewProtectedSourceSliceEgress,
} from '../src/internal/source-slice-protection.ts'

const fingerprintKey = new Uint8Array(32).fill(13)

function egressFixture(options: {
  readonly policyId?: string
  readonly requestDestinationId?: string
  readonly contextBytes?: number
  readonly text?: string
} = {}) {
  const text = options.text ?? 'password = "correct-horse-battery-staple"\n'
  const sourceDigest = binaryDigest('application/octet-stream', Buffer.from(text, 'utf8'))
  const subjectDigest = structuredDigest(
    'application/vnd.dsh.security.subject-manifest+json',
    { subjectId: 'subject-0161' },
  )
  const policyId = options.policyId ?? 'egress/deny-by-default'
  const contextGrant = createRoleContextGrantV1({
    schemaVersion: 1,
    assessmentId: 'asm-00000000-0000-0000-0000-000000000161',
    roleAttemptId: 'role-attempt-00000000-0000-0000-0000-000000000161',
    roleDefinition: {
      roleId: 'discovery-analyst',
      roleVersion: '1.0.0',
      definitionDigest: structuredDigest(
        'application/vnd.dsh.security.role-definition+json',
        { role: 'discovery-analyst' },
      ),
    },
    purpose: {
      purposeId: 'security/deep-discovery',
      assessmentMode: 'TARGETED',
      assessmentProfileId: 'security/deep',
      targetDigest: structuredDigest(
        'application/vnd.dsh.security.target-selector+json',
        { kind: 'targeted', relativePaths: ['src/provider.ts'] },
      ),
      coverageObligationIds: ['security/source-review'],
      constraintIds: ['security/read-only'],
      peerContributionVisibility: 'NONE',
    },
    subject: {
      digest: subjectDigest,
      inventory: [{
        artifactId: 'inventory-source-egress-0161',
        schemaId: 'dsh/security-subject-inventory',
        digest: structuredDigest(
          'application/vnd.dsh.security.subject-inventory+json',
          { inventory: 'source-egress-0161' },
        ),
        disclosureCategoryId: 'security/subject-inventory',
      }],
      sourceSlices: [],
    },
    evidenceProjections: [],
    disclosure: {
      dataEgressPolicyId: policyId,
      destinationId: 'provider/reference',
      categoryIds: ['security/source-slice', 'security/subject-inventory'],
    },
    budget: {
      contextBytes: { limit: 65_536, granted: 0 },
      tokens: { limit: 8_192, granted: 0 },
    },
  })
  const request = createSourceSliceRequestV1({
    schemaVersion: 1,
    requestId: 'slice-request-00000000-0000-0000-0000-000000000161',
    assessmentId: contextGrant.assessmentId,
    roleAttemptId: contextGrant.roleAttemptId,
    contextGrantDigest: contextGrant.grantDigest,
    subjectDigest,
    purpose: {
      purposeId: contextGrant.purpose.purposeId,
      coverageObligationId: 'security/source-review',
      needId: 'security/trace-data-flow',
    },
    target: { path: 'src/provider.ts', expectedSourceDigest: sourceDigest },
    disclosure: {
      dataEgressPolicyId: policyId,
      destinationId: options.requestDestinationId ?? 'provider/reference',
      categoryId: 'security/source-slice',
    },
    budget: {
      contextBytes: options.contextBytes ?? Buffer.byteLength(text, 'utf8') + 128,
      tokens: 128,
    },
  })
  const material: ProtectedSourceSliceMaterialV1 = {
    requestDigest: request.requestDigest,
    subjectDigest,
    path: request.target.path,
    digest: sourceDigest,
    text,
  }
  const redaction = redactProtectedSourceSliceSecrets({
    material,
    fingerprintKey,
    fingerprintKeyId: 'host/secret-fingerprint-key-1',
  })
  return { contextGrant, request, material, redaction }
}

describe('ADR 0161 protected Source Slice Data Egress review', () => {
  it('enforces the deny-by-default policy without invoking a Provider', () => {
    const fixture = egressFixture()
    const review = reviewProtectedSourceSliceEgress(fixture)

    expect(review.decision).toBe('REJECTED')
    expect(review.reasonCodes).toEqual(['POLICY_DENIES_EGRESS'])
    expect(review.disclosure).toEqual({
      dataEgressPolicyId: 'egress/deny-by-default',
      destinationId: 'provider/reference',
      categoryId: 'security/source-slice',
    })
    expect(JSON.stringify(review)).not.toMatch(/APPROVED|AUTHORIZED|GRANTED/iu)
    expect(Object.isFrozen(review)).toBe(true)
  })

  it('requires broker, destination and secret review for a non-deny policy', () => {
    const fixture = egressFixture({ policyId: 'egress/host-qualified-v1' })
    const review = reviewProtectedSourceSliceEgress(fixture)

    expect(review.decision).toBe('BROKER_REVIEW_REQUIRED')
    expect(review.reasonCodes).toEqual([
      'SECRET_REVIEW_INCOMPLETE',
      'BROKER_QUALIFICATION_REQUIRED',
      'DESTINATION_AUTHORIZATION_REQUIRED',
    ])
  })

  it('rejects redacted output that expands beyond the requested byte budget', () => {
    const fixture = egressFixture({
      policyId: 'egress/host-qualified-v1',
      text: 'secret=xxyy',
      contextBytes: 11,
    })
    const review = reviewProtectedSourceSliceEgress(fixture)

    expect(review.decision).toBe('REJECTED')
    expect(review.reasonCodes).toContain('REDACTED_BYTE_BUDGET_EXCEEDED')
    expect(review.observedRedactedBytes).toBeGreaterThan(review.requestedContextBytes)
  })

  it('repeats static admission and parses exact digest bindings', () => {
    const expanded = egressFixture({ requestDestinationId: 'provider/unapproved' })
    expect(() => reviewProtectedSourceSliceEgress(expanded)).toThrow(/static preflight/iu)

    const fixture = egressFixture()
    const review = reviewProtectedSourceSliceEgress(fixture)
    expect(parseProtectedSourceSliceEgressReview(review, {
      contextGrantDigest: fixture.contextGrant.grantDigest,
      requestDigest: fixture.request.requestDigest,
      redactionDigest: fixture.redaction.redactionDigest,
    })).toEqual(review)
    expect(() => parseProtectedSourceSliceEgressReview({
      ...review,
      destinationId: 'provider/other',
    }, {
      contextGrantDigest: fixture.contextGrant.grantDigest,
      requestDigest: fixture.request.requestDigest,
      redactionDigest: fixture.redaction.redactionDigest,
    })).toThrow()
  })

  it('keeps Data Egress review outside the package root interface', async () => {
    const packageRoot = await import('../src/index.ts')

    expect(packageRoot).not.toHaveProperty('reviewProtectedSourceSliceEgress')
    expect(packageRoot).not.toHaveProperty('parseProtectedSourceSliceEgressReview')
  })
})
