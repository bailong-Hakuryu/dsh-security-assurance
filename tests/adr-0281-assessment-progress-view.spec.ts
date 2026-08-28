import { describe, expect, it } from 'vitest'
import type { AssessmentSnapshotV1 } from '../src/index.ts'
import { projectAssessmentProgressViewV1 } from '../src/client/index.ts'

function snapshot(state: AssessmentSnapshotV1['state']): AssessmentSnapshotV1 {
  const digest = {
    schemaVersion: 1 as const,
    algorithm: 'sha256' as const,
    mediaType: 'application/vnd.dsh.canonical-json',
    byteLength: 1,
    canonicalization: 'dsh-canonical-json-v1' as const,
    value: 'c'.repeat(64),
  }
  return {
    schemaVersion: 1,
    assessmentId: 'asm-00000000-0000-0000-0000-000000000281',
    assessmentRevision: 9,
    state,
    repository: {
      repositoryId: 'repo-00000000-0000-0000-0000-000000000281',
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
      status: state === 'SEALED' ? 'COMPLETE' : 'GAP',
      mandatoryObligations: 2,
      satisfiedObligations: state === 'SEALED' ? 2 : 1,
      gapObligations: state === 'SEALED' ? 0 : 1,
      resolutions: state === 'SEALED'
        ? [
            { obligationId: 'security/sast', state: 'SATISFIED', reason: 'ELIGIBLE_EVIDENCE' },
            { obligationId: 'security/secrets', state: 'SATISFIED', reason: 'ELIGIBLE_EVIDENCE' },
          ]
        : [{ obligationId: 'security/sast', state: 'GAP', reason: 'ANALYZER_INCOMPLETE' }],
      digest,
    },
    blockedRecovery: state === 'BLOCKED'
      ? {
          schemaVersion: 1,
          blocker: {
            code: 'ASSESSMENT_EXECUTION_FAILED',
            phase: 'ASSESSMENT_EXECUTION',
            interruption: 'FAILED',
            affectedObligations: [{ obligationId: 'security/sast', reason: 'ANALYZER_INCOMPLETE' }],
          },
          evidence: { status: 'RETAINED', publishedArtifactCount: null },
          recovery: {
            requiredCondition: 'EXPLICIT_RESUME_REQUIRED',
            remainingExecutionBudget: { status: 'NOT_REPORTED' },
            coverageReconciliation: { required: true, possibleVerdict: 'INDETERMINATE' },
          },
        }
      : null,
    availableActions: [],
    roleCards: [],
    verdict: state === 'SEALED' ? 'SATISFIED' : null,
    seal: null,
    createdAt: '2026-08-24T00:00:00.000Z',
    updatedAt: '2026-08-24T00:09:00.000Z',
  }
}

describe('ADR 0281 revision-bound Assessment progress', () => {
  it('projects durable phases, dependencies, coverage, milestones, budget, and blocker from one Snapshot', () => {
    const view = projectAssessmentProgressViewV1(snapshot('BLOCKED'))
    expect(view).toMatchObject({
      schemaVersion: 1,
      assessmentId: 'asm-00000000-0000-0000-0000-000000000281',
      assessmentRevision: 9,
      terminalStatus: 'BLOCKED',
      budget: { status: 'NOT_REPORTED' },
      blocker: { code: 'ASSESSMENT_EXECUTION_FAILED', phase: 'ASSESSMENT_EXECUTION' },
      coverage: { status: 'GAP', pendingObligationCount: 1 },
    })
    expect(view.phaseNodes.map(node => [node.phaseId, node.dependsOn, node.attemptState])).toEqual([
      ['SUBJECT_FREEZE', [], 'COMPLETED'],
      ['ASSESSMENT_EXECUTION', ['SUBJECT_FREEZE'], 'BLOCKED'],
      ['VERDICT_AND_SEAL', ['ASSESSMENT_EXECUTION'], 'NOT_STARTED'],
    ])
    expect(view.milestones.map(milestone => [milestone.milestoneId, milestone.state])).toEqual([
      ['SUBJECT_FROZEN', 'REACHED'],
      ['COVERAGE_RESOLVED', 'REACHED'],
      ['VERDICT_RECORDED', 'PENDING'],
      ['ASSESSMENT_SEALED', 'PENDING'],
    ])
  })

  it('is frozen, revision-labeled, and contains no log, heartbeat, animation, or estimated completion fields', () => {
    const view = projectAssessmentProgressViewV1(snapshot('SEALED'))
    expect(view.terminalStatus).toBe('SEALED')
    expect(view.phaseNodes.every(node => node.attemptState === 'COMPLETED')).toBe(true)
    expect(Object.isFrozen(view)).toBe(true)
    expect(JSON.stringify(view)).not.toMatch(/log|heartbeat|animation|percent|estimate/iu)
  })
})
