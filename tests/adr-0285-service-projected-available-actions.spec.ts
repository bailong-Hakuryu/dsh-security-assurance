import { describe, expect, it } from 'vitest'
import type { AssessmentSnapshotV1 } from '../src/index.ts'
import { projectAssessmentActionAvailabilityV1 } from '../src/client/index.ts'

function snapshot(availableActions: AssessmentSnapshotV1['availableActions']): AssessmentSnapshotV1 {
  const digest = {
    schemaVersion: 1 as const,
    algorithm: 'sha256' as const,
    mediaType: 'application/vnd.dsh.canonical-json',
    byteLength: 1,
    canonicalization: 'dsh-canonical-json-v1' as const,
    value: '5'.repeat(64),
  }
  return {
    schemaVersion: 1,
    assessmentId: 'asm-00000000-0000-0000-0000-000000000285',
    assessmentRevision: 11,
    state: 'SEALED',
    repository: {
      repositoryId: 'repo-00000000-0000-0000-0000-000000000285',
      repositoryRevision: 2,
    },
    subject: { kind: 'workspace_snapshot', digest },
    contract: {
      schemaVersion: 1,
      assessmentMode: 'REPOSITORY',
      assessmentProfileId: 'security/standard',
      target: { kind: 'repository' },
      targetDigest: digest,
      requestedStrongerControlIds: [],
    },
    policy: { policyId: 'security/standard', digest },
    coverage: {
      status: 'COMPLETE',
      mandatoryObligations: 1,
      satisfiedObligations: 1,
      gapObligations: 0,
      resolutions: [{ obligationId: 'security/sast', state: 'SATISFIED', reason: 'ELIGIBLE_EVIDENCE' }],
      digest,
    },
    blockedRecovery: null,
    availableActions,
    roleCards: [],
    verdict: 'SATISFIED',
    seal: null,
    createdAt: '2026-08-24T00:00:00.000Z',
    updatedAt: '2026-08-24T00:11:00.000Z',
  }
}

describe('ADR 0285 Service-projected Available Actions', () => {
  it('renders the exact Service projection without inferring from Assessment state', () => {
    const action = { kind: 'RESUME_ASSESSMENT' as const, expectedAssessmentRevision: 11 }
    const projection = projectAssessmentActionAvailabilityV1(snapshot([action]))
    expect(projection).toEqual({
      schemaVersion: 1,
      assessmentRevision: 11,
      actions: [action],
      explanation: null,
    })
    expect(Object.isFrozen(projection)).toBe(true)
  })

  it('explains an empty Service projection instead of inventing a local action', () => {
    expect(projectAssessmentActionAvailabilityV1(snapshot([]))).toEqual({
      schemaVersion: 1,
      assessmentRevision: 11,
      actions: [],
      explanation: 'NO_SERVICE_PROJECTED_ACTIONS',
    })
  })
})
