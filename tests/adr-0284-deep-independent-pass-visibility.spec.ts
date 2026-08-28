import { describe, expect, it } from 'vitest'
import { assessmentRoleCardV1Schema } from '../src/index.ts'

const digest = {
  schemaVersion: 1 as const,
  algorithm: 'sha256' as const,
  mediaType: 'application/vnd.dsh.canonical-json',
  byteLength: 1,
  canonicalization: 'dsh-canonical-json-v1' as const,
  value: '4'.repeat(64),
}
const pendingDeepPass = {
  schemaVersion: 1 as const,
  roleDefinition: {
    roleId: 'discovery-analyst' as const,
    roleVersion: '1.0.0',
    definitionDigest: digest,
    independenceClass: 'DISTINCT_PROVIDER_OR_MODEL_FAMILY' as const,
  },
  attempt: {
    attemptId: 'role-attempt-00000000-0000-0000-0000-000000000284',
    parentAttemptId: null,
    lifecycleState: 'RUNNING' as const,
    startedAt: '2026-08-24T00:01:00.000Z',
    completedAt: null,
  },
  provider: {
    providerId: 'provider/deep-a',
    modelId: 'model/deep-a',
    movingProvider: false,
  },
  budget: {
    status: 'REPORTED' as const,
    requestLimit: 8,
    requestsUsed: 2,
    tokenLimit: 16_000,
    tokensUsed: 4_000,
  },
  milestones: [{ milestoneId: 'CONTEXT_GRANTED', state: 'REACHED' as const, recordedAt: '2026-08-24T00:01:00.000Z' }],
  evidenceCount: 0,
  candidateCount: 0,
  completionDisposition: 'NOT_AVAILABLE' as const,
  challengeRelations: [],
  analysisLane: {
    kind: 'DEEP_INDEPENDENT' as const,
    passId: 'deep/pass-a',
    initialContributionState: 'PENDING' as const,
    executionPeerVisibility: 'HIDDEN' as const,
    currentPhase: 'INDEPENDENT_ANALYSIS' as const,
  },
  detail: {
    schemaVersion: 1 as const,
    status: 'NOT_PUBLISHED' as const,
    transcript: { status: 'NOT_AVAILABLE' as const },
  },
}

describe('ADR 0284 Deep independent pass visibility', () => {
  it('shows non-semantic pass facts while keeping live peer outputs absent', () => {
    expect(assessmentRoleCardV1Schema.parse(pendingDeepPass)).toEqual(pendingDeepPass)
    expect(JSON.stringify(pendingDeepPass)).not.toMatch(/peerOutput|peerContribution|consensus/iu)
  })

  it('rejects peer visibility or Challenge phase before the initial Contribution freezes', () => {
    expect(assessmentRoleCardV1Schema.safeParse({
      ...pendingDeepPass,
      analysisLane: {
        ...pendingDeepPass.analysisLane,
        executionPeerVisibility: 'FROZEN_CONTRIBUTIONS_ONLY',
      },
    }).success).toBe(false)
    expect(assessmentRoleCardV1Schema.safeParse({
      ...pendingDeepPass,
      analysisLane: { ...pendingDeepPass.analysisLane, currentPhase: 'CHALLENGE' },
    }).success).toBe(false)
    expect(assessmentRoleCardV1Schema.safeParse({
      ...pendingDeepPass,
      detail: { ...pendingDeepPass.detail, status: 'PUBLISHED' },
    }).success).toBe(false)
  })
})
