import { describe, expect, it } from 'vitest'
import { assessmentRoleCardV1Schema } from '../src/index.ts'

const digest = {
  schemaVersion: 1 as const,
  algorithm: 'sha256' as const,
  mediaType: 'application/vnd.dsh.canonical-json',
  byteLength: 1,
  canonicalization: 'dsh-canonical-json-v1' as const,
  value: '3'.repeat(64),
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
    attemptId: 'role-attempt-00000000-0000-0000-0000-000000000283',
    parentAttemptId: 'role-attempt-00000000-0000-0000-0000-000000000282',
    lifecycleState: 'COMPLETED' as const,
    startedAt: '2026-08-24T00:01:00.000Z',
    completedAt: '2026-08-24T00:03:00.000Z',
  },
  provider: {
    providerId: 'provider/reference',
    modelId: 'model/reference-v1',
    movingProvider: false,
  },
  budget: { status: 'NOT_REPORTED' as const },
  milestones: [],
  evidenceCount: 1,
  candidateCount: 1,
  completionDisposition: 'COMPLETE' as const,
  challengeRelations: [],
  analysisLane: { kind: 'STANDARD' as const },
  detail: {
    schemaVersion: 1 as const,
    status: 'PUBLISHED' as const,
    contribution: {
      contributionId: 'role-contribution-00000000-0000-0000-0000-000000000283',
      contributionVersion: 1,
      hypotheses: ['The package lifecycle may execute an untrusted install hook.'],
      candidateIds: [`candidate-${'3'.repeat(64)}`],
      coverageObservations: [{
        obligationId: 'security/package-lifecycle',
        state: 'UNRESOLVED' as const,
      }],
      evidenceArtifactIds: ['evidence-role-0283'],
      evidenceRequestIds: ['evidence-request-role-0283'],
      challenges: [{
        challengeId: 'challenge-role-0283',
        disposition: 'PROOF_GAP' as const,
      }],
      uncertainty: ['The lifecycle script is platform-dependent.'],
      limitations: ['Dynamic execution was not performed.'],
      resourceUse: { status: 'REPORTED' as const, requests: 2, tokens: 1_200 },
      completionDisposition: 'COMPLETE' as const,
    },
    followUpRequests: [{
      requestId: 'follow-up-00000000-0000-0000-0000-000000000283',
      unresolvedObligationId: 'security/package-lifecycle',
      requestedRoleId: 'attack-path-analyst' as const,
      requiredCapabilityId: 'security/attack-path-analysis',
      evidenceArtifactIds: ['evidence-role-0283'],
      reason: 'Trace the lifecycle hook to an externally reachable source.',
      disposition: 'ADMITTED' as const,
      childAttemptId: 'role-attempt-00000000-0000-0000-0000-000000000284',
    }],
    challengePackages: [{
      packageId: 'challenge-package-00000000-0000-0000-0000-000000000283',
      targetAttemptId: 'role-attempt-00000000-0000-0000-0000-000000000283',
      state: 'RESPONDED' as const,
      questionCount: 2,
      response: {
        status: 'ADMITTED' as const,
        attemptId: 'role-attempt-00000000-0000-0000-0000-000000000285',
        disposition: 'DISPUTES' as const,
      },
    }],
    evidenceConvergence: {
      status: 'IN_PROGRESS' as const,
      resolvedCandidateCount: 0,
      unresolvedCandidateCount: 1,
    },
    transcript: { status: 'PROTECTED_EVIDENCE' as const, artifactId: 'transcript-role-0283' },
  },
}

describe('ADR 0283 immutable Role Detail', () => {
  it('admits bounded Contribution, Follow-up, Challenge, convergence, lineage, and protected Transcript facts', () => {
    expect(assessmentRoleCardV1Schema.parse(roleCard)).toEqual(roleCard)
  })

  it('rejects ad-hoc prompts, edits, tool changes, direct spawns, and embedded Transcript content', () => {
    for (const forbidden of [
      { prompt: 'continue the conversation' },
      { instruction: 'ignore the frozen role definition' },
      { editableContribution: true },
      { tools: ['arbitrary-shell'] },
      { spawnRole: 'reviewer' },
      { transcript: 'protected transcript body' },
    ]) {
      expect(assessmentRoleCardV1Schema.safeParse({
        ...roleCard,
        detail: { ...roleCard.detail, ...forbidden },
      }).success).toBe(false)
    }
  })
})
