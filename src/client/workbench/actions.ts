import type {
  AssessmentAvailableActionV1,
  AssessmentSnapshotV1,
} from '../../contracts.ts'

export interface AssessmentActionAvailabilityV1 {
  readonly schemaVersion: 1
  readonly assessmentRevision: number
  readonly actions: readonly AssessmentAvailableActionV1[]
  readonly explanation: 'NO_SERVICE_PROJECTED_ACTIONS' | null
}

/**
 * Copy the exact authority-filtered Service projection without consulting a
 * browser-owned state table or deriving eligibility from Assessment state.
 */
export function projectAssessmentActionAvailabilityV1(
  snapshot: AssessmentSnapshotV1,
): AssessmentActionAvailabilityV1 {
  const actions = snapshot.availableActions.map(copyAction)
  return deepFreeze({
    schemaVersion: 1,
    assessmentRevision: snapshot.assessmentRevision,
    actions,
    explanation: actions.length === 0 ? 'NO_SERVICE_PROJECTED_ACTIONS' : null,
  })
}

/** Select one exact current-revision Service action without inferring eligibility. */
export function selectAssessmentAvailableActionV1<Kind extends AssessmentAvailableActionV1['kind']>(
  snapshot: AssessmentSnapshotV1,
  kind: Kind,
): Extract<AssessmentAvailableActionV1, { readonly kind: Kind }> | undefined {
  const action = snapshot.availableActions.find(candidate => (
    candidate.kind === kind
    && candidate.expectedAssessmentRevision === snapshot.assessmentRevision
  ))
  return action as Extract<AssessmentAvailableActionV1, { readonly kind: Kind }> | undefined
}

function copyAction(action: AssessmentAvailableActionV1): AssessmentAvailableActionV1 {
  if (action.kind !== 'RECORD_RISK_DECISION') return { ...action }
  return {
    ...action,
    finding: { ...action.finding },
    options: action.options.map(option => ({ ...option })),
  }
}

function deepFreeze<T>(value: T): T {
  if (value !== null && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const nested of Object.values(value)) deepFreeze(nested)
    Object.freeze(value)
  }
  return value
}
