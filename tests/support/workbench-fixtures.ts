import type { AssessmentId, AssessmentSnapshotV1 } from '../../src/contracts.ts'

/** A minimal, schema-valid Assessment Snapshot for Workbench client tests. */
export function assessmentSnapshot(
  id: AssessmentId,
  revision: number,
  state: AssessmentSnapshotV1['state'],
): AssessmentSnapshotV1 {
  const digest = {
    schemaVersion: 1 as const,
    algorithm: 'sha256' as const,
    mediaType: 'application/vnd.dsh.canonical-json',
    byteLength: 1,
    canonicalization: 'dsh-canonical-json-v1' as const,
    value: '0'.repeat(64),
  }
  return {
    schemaVersion: 1,
    assessmentId: id,
    assessmentRevision: revision,
    state,
    repository: {
      repositoryId: 'repo-00000000-0000-0000-0000-000000000001',
      repositoryRevision: 1,
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
      resolutions: [],
      digest,
    },
    blockedRecovery: null,
    availableActions: [],
    verdict: null,
    seal: null,
    createdAt: '2026-09-26T00:00:00.000Z',
    updatedAt: '2026-09-26T00:01:00.000Z',
  }
}
