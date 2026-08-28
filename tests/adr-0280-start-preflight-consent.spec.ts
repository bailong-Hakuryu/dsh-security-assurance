import { describe, expect, it } from 'vitest'
import {
  startAssessmentRequestSchema,
  startPreflightV1Schema,
} from '../src/index.ts'

const digest = {
  schemaVersion: 1 as const,
  algorithm: 'sha256' as const,
  mediaType: 'application/vnd.dsh.security.start-preflight+json',
  byteLength: 1,
  canonicalization: 'dsh-canonical-json-v1' as const,
  value: 'b'.repeat(64),
}
const selection = {
  schemaVersion: 1 as const,
  repositoryId: 'repo-00000000-0000-0000-0000-000000000280',
  subject: { kind: 'workspace_snapshot' as const },
  assessmentMode: 'REPOSITORY' as const,
  assessmentProfileId: 'security/standard',
  target: { kind: 'repository' as const },
  requestedStrongerControlIds: [] as const,
}
const preflight = {
  schemaVersion: 1 as const,
  repository: {
    repositoryId: selection.repositoryId,
    repositoryRevision: 4,
    displayName: 'Registered repository',
  },
  selection,
  effectivePolicyId: 'security/node-package-lifecycle',
  effectiveProfileId: 'security/standard',
  providerComposition: [{
    providerId: 'dsh-security-assurance',
    analyzerId: 'dsh/builtin-node-package-lifecycle',
    analyzerVersion: '1.0.0',
    executionClass: 'PURE' as const,
    eligibility: 'ELIGIBLE' as const,
    reason: null,
    supportedEcosystemIds: ['node-package'],
    supportedPlatforms: ['win32' as const],
    coverageObligationIds: ['security/sast'],
  }],
  dataEgress: {
    policyId: 'egress/deny-by-default',
    destinationIds: [],
    categories: ['NONE' as const],
  },
  evidenceProtection: { policyId: 'evidence/local-protected' },
  maximumBudget: { status: 'NOT_REPORTED' as const },
  unsupportedConditions: [],
  claimLimitations: ['Analyzer claims remain proposals.'],
  coverageLimitations: ['Only registered obligations are evaluated.'],
  admissible: true,
  proposalDigest: digest,
}

describe('ADR 0280 immutable Start Preflight consent', () => {
  it('requires the complete effective contract disclosure and rejects undeclared facts', () => {
    expect(startPreflightV1Schema.parse(preflight)).toEqual(preflight)
    for (const missing of [
      'repository',
      'selection',
      'effectivePolicyId',
      'effectiveProfileId',
      'providerComposition',
      'dataEgress',
      'evidenceProtection',
      'maximumBudget',
      'unsupportedConditions',
      'claimLimitations',
      'coverageLimitations',
      'proposalDigest',
    ] as const) {
      const candidate = { ...preflight } as Record<string, unknown>
      delete candidate[missing]
      expect(startPreflightV1Schema.safeParse(candidate).success).toBe(false)
    }
    expect(startPreflightV1Schema.safeParse({ ...preflight, editable: true }).success).toBe(false)
  })

  it('binds confirmation to the proposal digest without accepting a mutable preflight copy', () => {
    const request = {
      ...selection,
      contractVersion: 1 as const,
      idempotencyKey: 'confirmed-preflight-0280',
      startPreflightDigest: preflight.proposalDigest,
    }
    expect(startAssessmentRequestSchema.parse(request)).toEqual(request)
    expect(startAssessmentRequestSchema.safeParse({
      ...request,
      startPreflight: preflight,
    }).success).toBe(false)
    expect(startAssessmentRequestSchema.safeParse({
      ...request,
      confirmed: true,
    }).success).toBe(false)
  })
})
