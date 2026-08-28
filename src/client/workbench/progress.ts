import type {
  AssessmentCoverageResolutionV1,
  AssessmentId,
  AssessmentSnapshotV1,
} from '../../contracts.ts'

export type AssessmentProgressPhaseIdV1 =
  | 'SUBJECT_FREEZE'
  | 'ASSESSMENT_EXECUTION'
  | 'VERDICT_AND_SEAL'

export type AssessmentProgressAttemptStateV1 =
  | 'NOT_STARTED'
  | 'RUNNING'
  | 'BLOCKED'
  | 'COMPLETED'
  | 'CANCELED'

export interface AssessmentProgressPhaseNodeV1 {
  readonly phaseId: AssessmentProgressPhaseIdV1
  readonly dependsOn: readonly AssessmentProgressPhaseIdV1[]
  readonly attemptState: AssessmentProgressAttemptStateV1
}

export interface AssessmentProgressMilestoneV1 {
  readonly milestoneId:
    | 'SUBJECT_FROZEN'
    | 'COVERAGE_RESOLVED'
    | 'VERDICT_RECORDED'
    | 'ASSESSMENT_SEALED'
  readonly state: 'PENDING' | 'REACHED'
}

/**
 * Read-only progress facts derived exclusively from one durable Assessment
 * Snapshot. This view deliberately has no stream, heartbeat, estimate, or log
 * surface: a revision signal can only cause the caller to fetch a new Snapshot.
 */
export interface AssessmentProgressViewV1 {
  readonly schemaVersion: 1
  readonly assessmentId: AssessmentId
  readonly assessmentRevision: number
  readonly phaseNodes: readonly AssessmentProgressPhaseNodeV1[]
  readonly coverage: {
    readonly status: AssessmentSnapshotV1['coverage']['status']
    readonly resolutions: readonly AssessmentCoverageResolutionV1[]
    readonly pendingObligationCount: number
  }
  readonly milestones: readonly AssessmentProgressMilestoneV1[]
  readonly budget: { readonly status: 'NOT_REPORTED' }
  readonly blocker: null | {
    readonly code: string
    readonly phase: NonNullable<AssessmentSnapshotV1['blockedRecovery']>['blocker']['phase']
    readonly interruption: NonNullable<AssessmentSnapshotV1['blockedRecovery']>['blocker']['interruption']
  }
  readonly terminalStatus: 'ACTIVE' | 'BLOCKED' | 'SEALED' | 'CANCELED'
}

/** Project the complete public progress view from exactly one Snapshot revision. */
export function projectAssessmentProgressViewV1(
  snapshot: AssessmentSnapshotV1,
): AssessmentProgressViewV1 {
  const executionState: AssessmentProgressAttemptStateV1 = snapshot.state === 'CREATED'
    ? 'NOT_STARTED'
    : snapshot.state === 'RUNNING'
      ? 'RUNNING'
      : snapshot.state === 'BLOCKED'
        ? 'BLOCKED'
        : snapshot.state === 'SEALED'
          ? 'COMPLETED'
          : 'CANCELED'
  const verdictState: AssessmentProgressAttemptStateV1 = snapshot.state === 'SEALED'
    ? 'COMPLETED'
    : snapshot.state === 'CANCELED'
      ? 'CANCELED'
      : 'NOT_STARTED'
  const recovery = snapshot.blockedRecovery
  const pendingObligationCount = Math.max(
    0,
    snapshot.coverage.mandatoryObligations - snapshot.coverage.resolutions.length,
  )
  return deepFreeze({
    schemaVersion: 1,
    assessmentId: snapshot.assessmentId,
    assessmentRevision: snapshot.assessmentRevision,
    phaseNodes: [
      { phaseId: 'SUBJECT_FREEZE', dependsOn: [], attemptState: 'COMPLETED' },
      {
        phaseId: 'ASSESSMENT_EXECUTION',
        dependsOn: ['SUBJECT_FREEZE'],
        attemptState: executionState,
      },
      {
        phaseId: 'VERDICT_AND_SEAL',
        dependsOn: ['ASSESSMENT_EXECUTION'],
        attemptState: verdictState,
      },
    ],
    coverage: {
      status: snapshot.coverage.status,
      resolutions: snapshot.coverage.resolutions.map(resolution => ({ ...resolution })),
      pendingObligationCount,
    },
    milestones: [
      { milestoneId: 'SUBJECT_FROZEN', state: 'REACHED' },
      {
        milestoneId: 'COVERAGE_RESOLVED',
        state: snapshot.coverage.status === 'PENDING' ? 'PENDING' : 'REACHED',
      },
      { milestoneId: 'VERDICT_RECORDED', state: snapshot.verdict === null ? 'PENDING' : 'REACHED' },
      { milestoneId: 'ASSESSMENT_SEALED', state: snapshot.seal === null ? 'PENDING' : 'REACHED' },
    ],
    budget: { status: 'NOT_REPORTED' },
    blocker: recovery === null
      ? null
      : {
          code: recovery.blocker.code,
          phase: recovery.blocker.phase,
          interruption: recovery.blocker.interruption,
        },
    terminalStatus: snapshot.state === 'BLOCKED'
      ? 'BLOCKED'
      : snapshot.state === 'SEALED'
        ? 'SEALED'
        : snapshot.state === 'CANCELED'
          ? 'CANCELED'
          : 'ACTIVE',
  })
}

function deepFreeze<T>(value: T): T {
  if (value !== null && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const nested of Object.values(value)) deepFreeze(nested)
    Object.freeze(value)
  }
  return value
}
