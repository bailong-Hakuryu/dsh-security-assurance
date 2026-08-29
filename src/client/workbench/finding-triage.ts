import type { FindingSummaryV1 } from '../../contracts.ts'

export type FindingTriageDimensionV1 =
  | 'policySignificance'
  | 'technicalSeverity'
  | 'validationOutcome'
  | 'evidenceConfidence'
  | 'weakness'
  | 'component'
  | 'sensitivity'
  | 'coverageRelation'

export const FINDING_TRIAGE_DIMENSIONS: readonly FindingTriageDimensionV1[] = Object.freeze([
  'policySignificance',
  'technicalSeverity',
  'validationOutcome',
  'evidenceConfidence',
  'weakness',
  'component',
  'sensitivity',
  'coverageRelation',
])

/** Project one domain dimension without collapsing it into an aggregate score. */
export function findingTriageValues(
  item: FindingSummaryV1,
  dimension: FindingTriageDimensionV1,
): readonly string[] {
  switch (dimension) {
    case 'policySignificance': return [item.policySignificance ?? 'PENDING']
    case 'technicalSeverity': return [item.technicalSeverity ?? 'PENDING']
    case 'validationOutcome': return [item.validationState]
    case 'evidenceConfidence': return [item.evidenceConfidence ?? 'PENDING']
    case 'weakness': return [item.weaknessClassification.primary, ...item.weaknessClassification.secondary]
    case 'component': return [item.component]
    case 'sensitivity': return [item.sensitivity]
    case 'coverageRelation': return item.coverageRelations.length === 0
      ? ['NO_RELATION']
      : item.coverageRelations.map(relation => `${relation.state}:${relation.obligationId}`)
  }
}
