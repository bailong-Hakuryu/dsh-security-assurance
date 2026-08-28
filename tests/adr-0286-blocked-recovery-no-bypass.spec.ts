import { describe, expect, it } from 'vitest'
import { assessmentBlockedRecoveryV1Schema } from '../src/index.ts'

const recovery = {
  schemaVersion: 1 as const,
  blocker: {
    code: 'ASSESSMENT_EXECUTION_FAILED',
    phase: 'ASSESSMENT_EXECUTION' as const,
    interruption: 'FAILED' as const,
    affectedObligations: [{ obligationId: 'security/sast', reason: 'ANALYZER_INCOMPLETE' as const }],
  },
  attempt: {
    status: 'IDENTIFIED' as const,
    attemptId: 'asm-00000000-0000-0000-0000-000000000286:assessment-execution:2',
    attemptKind: 'ASSESSMENT_EXECUTION' as const,
    lifecycleState: 'FAILED' as const,
  },
  evidence: { status: 'RETAINED' as const, publishedArtifactCount: 1 },
  recovery: {
    remainingExecutionBudget: { status: 'NOT_REPORTED' as const },
    requiredCondition: 'EXPLICIT_RESUME_REQUIRED' as const,
    remainingEligibility: {
      status: 'ELIGIBLE_FOR_CALLER' as const,
      actionKinds: ['RESUME_ASSESSMENT' as const, 'CANCEL_ASSESSMENT' as const],
    },
    coverageReconciliation: { required: true, possibleVerdict: 'INDETERMINATE' as const },
  },
}

describe('ADR 0286 BLOCKED recovery without bypass', () => {
  it('admits exact blocker, Attempt, Evidence, budget, eligibility, condition, and reconciliation facts', () => {
    expect(assessmentBlockedRecoveryV1Schema.parse(recovery)).toEqual(recovery)
  })

  it('rejects ignore, force-complete, mark-covered, composition, Verdict, and Seal bypasses', () => {
    for (const forbidden of [
      { ignoreFailure: true },
      { forceComplete: true },
      { markCovered: true },
      { providerComposition: ['replacement'] },
      { verdict: 'SATISFIED' },
      { seal: true },
    ]) {
      expect(assessmentBlockedRecoveryV1Schema.safeParse({ ...recovery, ...forbidden }).success).toBe(false)
    }
  })
})
