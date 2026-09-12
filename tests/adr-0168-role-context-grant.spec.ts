import { describe, expect, it } from 'vitest'
import {
  createRoleContextGrantV1,
  parseRoleContextGrantV1,
  roleContextGrantV1Schema,
} from '../src/index.ts'

const digest = (value: string, mediaType: string) => ({
  schemaVersion: 1 as const,
  algorithm: 'sha256' as const,
  mediaType,
  byteLength: 1,
  canonicalization: 'dsh-canonical-json-v1' as const,
  value: value.repeat(64),
})

const grantCore = {
  schemaVersion: 1 as const,
  assessmentId: 'asm-00000000-0000-0000-0000-000000000168',
  roleAttemptId: 'role-attempt-00000000-0000-0000-0000-000000000168',
  roleDefinition: {
    roleId: 'discovery-analyst' as const,
    roleVersion: '1.0.0',
    definitionDigest: digest('a', 'application/vnd.dsh.security.role-definition+json'),
  },
  purpose: {
    purposeId: 'security/deep-discovery',
    assessmentMode: 'REPOSITORY' as const,
    assessmentProfileId: 'security/deep',
    targetDigest: digest('b', 'application/vnd.dsh.security.target-selector+json'),
    coverageObligationIds: ['security/dependency-review', 'security/source-review'],
    constraintIds: ['security/no-peer-contributions', 'security/read-only'],
    peerContributionVisibility: 'NONE' as const,
  },
  subject: {
    digest: digest('c', 'application/vnd.dsh.security.subject-manifest+json'),
    inventory: [{
      artifactId: 'inventory-role-0168',
      schemaId: 'dsh/security-subject-inventory',
      digest: digest('d', 'application/vnd.dsh.security.subject-inventory+json'),
      disclosureCategoryId: 'security/subject-inventory',
    }],
    sourceSlices: [{
      artifactId: 'source-role-0168',
      schemaId: 'dsh/security-source-slice',
      digest: digest('e', 'application/vnd.dsh.security.source-slice+json'),
      disclosureCategoryId: 'security/source-slice',
    }],
  },
  evidenceProjections: [{
    artifactId: 'evidence-role-0168',
    schemaId: 'dsh/security-finding-evidence',
    digest: digest('f', 'application/vnd.dsh.security.finding-evidence+json'),
    disclosureCategoryId: 'security/evidence-projection',
  }],
  disclosure: {
    dataEgressPolicyId: 'egress/deny-by-default',
    destinationId: 'provider/reference',
    categoryIds: [
      'security/evidence-projection',
      'security/source-slice',
      'security/subject-inventory',
    ],
  },
  budget: {
    contextBytes: { limit: 65_536, granted: 12_288 },
    tokens: { limit: 8_192, granted: 4_096 },
  },
}

describe('ADR 0168 minimal Role Context Grants', () => {
  it('creates one deterministic immutable grant from bounded governed references', () => {
    const grant = createRoleContextGrantV1(grantCore)

    expect(grant).toEqual({
      ...grantCore,
      grantDigest: {
        schemaVersion: 1,
        algorithm: 'sha256',
        mediaType: 'application/vnd.dsh.security.role-context-grant+json',
        byteLength: 2_768,
        canonicalization: 'dsh-canonical-json-v1',
        value: '19635a33fc64404067f99fc2e5e2222f6119907a0df709efea5d67529abbbd1c',
      },
    })
    expect(Object.isFrozen(grant)).toBe(true)
    expect(Object.isFrozen(grant.subject.sourceSlices[0])).toBe(true)
    expect(JSON.stringify(grant)).not.toMatch(
      /workspaceRoot|conversation|credential|sourceText|service|cordis/iu,
    )
  })

  it('recomputes the grant digest and rejects tampered context', () => {
    const grant = createRoleContextGrantV1(grantCore)

    expect(parseRoleContextGrantV1(grant)).toEqual(grant)
    expect(() => parseRoleContextGrantV1({
      ...grant,
      purpose: { ...grant.purpose, purposeId: 'security/expanded-discovery' },
    })).toThrow(/digest/iu)
  })

  it('rejects Context Grants that exceed a frozen resource limit', () => {
    for (const budget of [{
      ...grantCore.budget,
      contextBytes: { ...grantCore.budget.contextBytes, granted: 65_537 },
    }, {
      ...grantCore.budget,
      tokens: { ...grantCore.budget.tokens, granted: 8_193 },
    }]) {
      expect(() => createRoleContextGrantV1({ ...grantCore, budget })).toThrow(/budget/iu)
    }

    const grant = createRoleContextGrantV1(grantCore)
    expect(roleContextGrantV1Schema.safeParse({
      ...grant,
      budget: {
        ...grant.budget,
        tokens: { ...grant.budget.tokens, granted: 8_193 },
      },
    }).success).toBe(false)
  })

  it('rejects undisclosed categories and ambiguous duplicate references', () => {
    expect(() => createRoleContextGrantV1({
      ...grantCore,
      subject: {
        ...grantCore.subject,
        sourceSlices: [{
          ...grantCore.subject.sourceSlices[0],
          disclosureCategoryId: 'security/unapproved-source',
        }],
      },
    })).toThrow(/disclosure/iu)

    expect(() => createRoleContextGrantV1({
      ...grantCore,
      evidenceProjections: [{
        ...grantCore.evidenceProjections[0],
        artifactId: grantCore.subject.sourceSlices[0]!.artifactId,
      }],
    })).toThrow(/unique/iu)

    expect(() => createRoleContextGrantV1({
      ...grantCore,
      purpose: {
        ...grantCore.purpose,
        coverageObligationIds: ['security/source-review', 'security/source-review'],
      },
    })).toThrow(/unique/iu)
  })
})
