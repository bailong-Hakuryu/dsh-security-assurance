import { describe, expect, it } from 'vitest'
import {
  createRoleContextGrantV1,
  createSourceSliceRequestV1,
  parseSourceSliceRequestPreflightV1,
  parseSourceSliceRequestV1,
  preflightSourceSliceRequestV1,
  sourceSliceRequestPreflightV1Schema,
} from '../src/index.ts'

const digest = (value: string, mediaType: string) => ({
  schemaVersion: 1 as const,
  algorithm: 'sha256' as const,
  mediaType,
  byteLength: 1,
  canonicalization: 'dsh-canonical-json-v1' as const,
  value: value.repeat(64),
})

const rawDigest = (value: string) => ({
  ...digest(value, 'application/octet-stream'),
  canonicalization: 'raw-bytes' as const,
})

const requestCore = {
  schemaVersion: 1 as const,
  requestId: 'slice-request-00000000-0000-0000-0000-000000000168',
  assessmentId: 'asm-00000000-0000-0000-0000-000000000168',
  roleAttemptId: 'role-attempt-00000000-0000-0000-0000-000000000168',
  contextGrantDigest: digest('1', 'application/vnd.dsh.security.role-context-grant+json'),
  subjectDigest: digest('2', 'application/vnd.dsh.security.subject-manifest+json'),
  purpose: {
    purposeId: 'security/deep-discovery',
    coverageObligationId: 'security/source-review',
    needId: 'security/trace-data-flow',
  },
  target: {
    path: 'src/auth/session.ts',
    expectedSourceDigest: rawDigest('3'),
  },
  disclosure: {
    dataEgressPolicyId: 'egress/deny-by-default',
    destinationId: 'provider/reference',
    categoryId: 'security/source-slice',
  },
  budget: {
    contextBytes: 8_192,
    tokens: 2_048,
  },
}

const grantCore = {
  schemaVersion: 1 as const,
  assessmentId: requestCore.assessmentId,
  roleAttemptId: requestCore.roleAttemptId,
  roleDefinition: {
    roleId: 'discovery-analyst' as const,
    roleVersion: '1.0.0',
    definitionDigest: digest('a', 'application/vnd.dsh.security.role-definition+json'),
  },
  purpose: {
    purposeId: requestCore.purpose.purposeId,
    assessmentMode: 'REPOSITORY' as const,
    assessmentProfileId: 'security/deep',
    targetDigest: digest('b', 'application/vnd.dsh.security.target-selector+json'),
    coverageObligationIds: [requestCore.purpose.coverageObligationId],
    constraintIds: ['security/read-only'],
    peerContributionVisibility: 'NONE' as const,
  },
  subject: {
    digest: requestCore.subjectDigest,
    inventory: [{
      artifactId: 'inventory-role-0168',
      schemaId: 'dsh/security-subject-inventory',
      digest: digest('c', 'application/vnd.dsh.security.subject-inventory+json'),
      disclosureCategoryId: 'security/subject-inventory',
    }],
    sourceSlices: [],
  },
  evidenceProjections: [],
  disclosure: {
    dataEgressPolicyId: requestCore.disclosure.dataEgressPolicyId,
    destinationId: requestCore.disclosure.destinationId,
    categoryIds: ['security/source-slice', 'security/subject-inventory'],
  },
  budget: {
    contextBytes: { limit: 65_536, granted: 12_288 },
    tokens: { limit: 8_192, granted: 4_096 },
  },
}

describe('ADR 0168 structured Source Slice Requests', () => {
  it('creates deterministic immutable authority-free request metadata', () => {
    const request = createSourceSliceRequestV1(requestCore)

    expect(request).toEqual({
      ...requestCore,
      requestDigest: {
        schemaVersion: 1,
        algorithm: 'sha256',
        mediaType: 'application/vnd.dsh.security.source-slice-request+json',
        byteLength: 1_305,
        canonicalization: 'dsh-canonical-json-v1',
        value: 'fb9fdd0fe194c9a139d3f448852359ddfb97c2c4e979e0863ac4d16ad19d18a8',
      },
    })
    expect(Object.isFrozen(request)).toBe(true)
    expect(Object.isFrozen(request.target)).toBe(true)
    expect(JSON.stringify(request)).not.toMatch(
      /workspaceRoot|conversation|credential|sourceText|service|cordis|capability/iu,
    )
  })

  it('parses only exact digest-bound canonical Subject targets', () => {
    const request = createSourceSliceRequestV1(requestCore)

    expect(parseSourceSliceRequestV1(request)).toEqual(request)
    expect(() => parseSourceSliceRequestV1({
      ...request,
      target: { ...request.target, path: 'src/auth/admin.ts' },
    })).toThrow(/digest/iu)
    expect(() => createSourceSliceRequestV1({
      ...requestCore,
      target: { ...requestCore.target, path: '../outside.ts' },
    })).toThrow(/relative path/iu)
  })

  it('requires protected material review without granting source authority', () => {
    const contextGrant = createRoleContextGrantV1(grantCore)
    const request = createSourceSliceRequestV1({
      ...requestCore,
      contextGrantDigest: contextGrant.grantDigest,
    })

    const preflight = preflightSourceSliceRequestV1({ contextGrant, request })

    expect(preflight).toMatchObject({
      schemaVersion: 1,
      requestId: request.requestId,
      requestDigest: request.requestDigest,
      contextGrantDigest: contextGrant.grantDigest,
      decision: 'MATERIAL_REVIEW_REQUIRED',
      reasonCodes: [],
      budgetProjection: {
        contextBytesRemaining: 45_056,
        tokensRemaining: 2_048,
      },
      requiredMaterialChecks: [
        'SUBJECT_CONTAINMENT',
        'SOURCE_DIGEST_INTEGRITY',
        'SENSITIVITY_CLASSIFICATION',
        'SECRET_REDACTION',
        'DATA_EGRESS',
        'ACTUAL_BUDGET',
        'ROLE_NEED',
      ],
      preflightDigest: {
        schemaVersion: 1,
        algorithm: 'sha256',
        mediaType: 'application/vnd.dsh.security.source-slice-request-preflight+json',
        byteLength: 905,
        canonicalization: 'dsh-canonical-json-v1',
        value: '2780603e1fda48eb4589c04d0baf0c1e16d767c70b34bc94000ae7f34430477e',
      },
    })
    expect(Object.isFrozen(preflight)).toBe(true)
    expect(Object.isFrozen(preflight.requiredMaterialChecks)).toBe(true)
    expect(JSON.stringify(preflight)).not.toMatch(/GRANTED|AUTHORIZED|sourceText|artifactId/iu)
  })

  it('rejects stale bindings, scope expansion, egress drift and budget overruns together', () => {
    const contextGrant = createRoleContextGrantV1(grantCore)
    const request = createSourceSliceRequestV1({
      ...requestCore,
      assessmentId: 'asm-00000000-0000-0000-0000-000000000999',
      roleAttemptId: 'role-attempt-00000000-0000-0000-0000-000000000999',
      subjectDigest: digest('9', 'application/vnd.dsh.security.subject-manifest+json'),
      purpose: {
        purposeId: 'security/expanded-discovery',
        coverageObligationId: 'security/ungranted-review',
        needId: 'security/trace-data-flow',
      },
      disclosure: {
        dataEgressPolicyId: 'egress/permissive',
        destinationId: 'provider/unapproved',
        categoryId: 'security/unapproved-source',
      },
      budget: {
        contextBytes: 60_000,
        tokens: 5_000,
      },
    })

    const preflight = preflightSourceSliceRequestV1({ contextGrant, request })
    expect(preflight).toMatchObject({
      decision: 'REJECTED',
      reasonCodes: [
        'ASSESSMENT_MISMATCH',
        'ROLE_ATTEMPT_MISMATCH',
        'CONTEXT_GRANT_MISMATCH',
        'SUBJECT_MISMATCH',
        'PURPOSE_MISMATCH',
        'OBLIGATION_NOT_GRANTED',
        'EGRESS_POLICY_MISMATCH',
        'DESTINATION_MISMATCH',
        'DISCLOSURE_CATEGORY_NOT_GRANTED',
        'CONTEXT_BYTE_BUDGET_EXCEEDED',
        'TOKEN_BUDGET_EXCEEDED',
      ],
      budgetProjection: null,
      requiredMaterialChecks: [],
    })
    expect(sourceSliceRequestPreflightV1Schema.safeParse({
      ...preflight,
      reasonCodes: [...preflight.reasonCodes].reverse(),
    }).success).toBe(false)
  })

  it('rejects tampered preflights and replay against another Context Grant', () => {
    const contextGrant = createRoleContextGrantV1(grantCore)
    const request = createSourceSliceRequestV1({
      ...requestCore,
      contextGrantDigest: contextGrant.grantDigest,
    })
    const preflight = preflightSourceSliceRequestV1({ contextGrant, request })
    const expectedBindings = {
      requestDigest: request.requestDigest,
      contextGrantDigest: contextGrant.grantDigest,
    }

    expect(parseSourceSliceRequestPreflightV1(preflight, expectedBindings)).toEqual(preflight)
    expect(() => parseSourceSliceRequestPreflightV1({
      ...preflight,
      budgetProjection: {
        ...preflight.budgetProjection,
        contextBytesRemaining: 45_057,
      },
    }, expectedBindings)).toThrow(/digest/iu)

    const otherGrant = createRoleContextGrantV1({
      ...grantCore,
      purpose: { ...grantCore.purpose, constraintIds: ['security/no-network'] },
    })
    expect(() => parseSourceSliceRequestPreflightV1(preflight, {
      ...expectedBindings,
      contextGrantDigest: otherGrant.grantDigest,
    })).toThrow(/binding/iu)
    expect(sourceSliceRequestPreflightV1Schema.safeParse({
      ...preflight,
      decision: 'REJECTED',
    }).success).toBe(false)
  })
})
