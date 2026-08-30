import { describe, expect, it } from 'vitest'
import {
  assessmentRoleCardV1Schema,
  assessmentSnapshotV1Schema,
} from '../src/index.ts'

const digest = {
  schemaVersion: 1 as const,
  algorithm: 'sha256' as const,
  mediaType: 'application/vnd.dsh.canonical-json',
  byteLength: 1,
  canonicalization: 'dsh-canonical-json-v1' as const,
  value: 'd'.repeat(64),
}
const roleCard = {
  schemaVersion: 1 as const,
  roleDefinition: {
    roleId: 'validation-analyst' as const,
    roleVersion: '1.0.0',
    definitionDigest: digest,
    independenceClass: 'DISTINCT_ATTEMPT' as const,
  },
  attempt: {
    attemptId: 'role-attempt-00000000-0000-0000-0000-000000000282',
    parentAttemptId: 'role-attempt-00000000-0000-0000-0000-000000000281',
    lifecycleState: 'COMPLETED' as const,
    startedAt: '2026-08-24T00:01:00.000Z',
    completedAt: '2026-08-24T00:02:00.000Z',
  },
  provider: {
    providerId: 'provider/reference',
    modelId: 'model/reference-v1',
    movingProvider: false,
  },
  budget: {
    status: 'REPORTED' as const,
    requestLimit: 4,
    requestsUsed: 2,
    tokenLimit: 8_000,
    tokensUsed: 3_200,
  },
  milestones: [{
    milestoneId: 'INITIAL_CONTRIBUTION_FROZEN',
    state: 'REACHED' as const,
    recordedAt: '2026-08-24T00:02:00.000Z',
  }],
  evidenceCount: 3,
  candidateCount: 1,
  completionDisposition: 'COMPLETE' as const,
  challengeRelations: [{
    relatedAttemptId: 'role-attempt-00000000-0000-0000-0000-000000000283',
    relation: 'CHALLENGED_BY' as const,
  }],
}

describe('ADR 0282 governed Role Cards', () => {
  it('accepts exact role, attempt lineage, lifecycle, provider, budget, milestone, count, disposition, and challenge facts', () => {
    expect(assessmentRoleCardV1Schema.parse(roleCard)).toEqual(roleCard)
  })

  it('rejects chat authority, conversational confidence, transcripts, and polished answers', () => {
    for (const forbidden of [
      { approved: true },
      { authority: 'FINAL_DECISION_MAKER' },
      { confidence: 0.99 },
      { typing: true },
      { transcript: 'protected conversation' },
      { answer: 'This assessment is approved.' },
    ]) {
      expect(assessmentRoleCardV1Schema.safeParse({ ...roleCard, ...forbidden }).success).toBe(false)
    }
  })

  it('rejects contradictory lifecycle, milestone, and budget claims', () => {
    expect(assessmentRoleCardV1Schema.safeParse({
      ...roleCard,
      completionDisposition: 'NOT_AVAILABLE',
    }).success).toBe(false)
    expect(assessmentRoleCardV1Schema.safeParse({
      ...roleCard,
      budget: { ...roleCard.budget, requestsUsed: 5 },
    }).success).toBe(false)
    expect(assessmentRoleCardV1Schema.safeParse({
      ...roleCard,
      milestones: [{ ...roleCard.milestones[0], state: 'PENDING' }],
    }).success).toBe(false)
  })

  it('keeps Role activity a separate bounded Snapshot projection', () => {
    const base = {
      schemaVersion: 1 as const,
      assessmentId: 'asm-00000000-0000-0000-0000-000000000282',
      assessmentRevision: 3,
      state: 'RUNNING' as const,
      repository: {
        repositoryId: 'repo-00000000-0000-0000-0000-000000000282',
        repositoryRevision: 1,
      },
      subject: { kind: 'workspace_snapshot' as const, digest },
      contract: {
        schemaVersion: 1 as const,
        assessmentMode: 'REPOSITORY' as const,
        assessmentProfileId: 'security/standard',
        target: { kind: 'repository' as const },
        targetDigest: digest,
        requestedStrongerControlIds: [],
      },
      policy: { policyId: 'security/standard', digest },
      coverage: {
        status: 'PENDING' as const,
        mandatoryObligations: 1,
        satisfiedObligations: 0,
        gapObligations: 0,
        resolutions: [],
        digest,
      },
      blockedRecovery: null,
      availableActions: [],
      roleCards: [roleCard],
      verdict: null,
      seal: null,
      createdAt: '2026-08-24T00:00:00.000Z',
      updatedAt: '2026-08-24T00:03:00.000Z',
    }
    expect(assessmentSnapshotV1Schema.parse(base).roleCards).toEqual([roleCard])
    expect(assessmentSnapshotV1Schema.safeParse({ ...base, roleCards: Array.from({ length: 129 }, () => roleCard) }).success).toBe(false)
  })
})
