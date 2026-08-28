import type { SecurityAssuranceWorkbenchStateV1 } from '../index.ts'

/** Reviewed v0.1 Workbench views. Adding a value requires a Service-contract review. */
export const WORKBENCH_INFORMATION_ARCHITECTURE_V1 = Object.freeze([
  'overview',
  'repositories',
  'new-assessment',
  'assessment-detail',
  'findings',
  'evidence',
  'risk-decisions',
  'exports',
  'runtime-health',
] as const)

export type WorkbenchViewIdV1 = typeof WORKBENCH_INFORMATION_ARCHITECTURE_V1[number]

/** Minimal browser-route projection. Authority and domain payloads are deliberately absent. */
export interface WorkbenchRouteStateV1 {
  readonly schemaVersion: 1
  readonly viewId: WorkbenchViewIdV1
}

/** Decode untrusted browser history without admitting additional payload fields. */
export function decodeWorkbenchRouteStateV1(value: unknown): WorkbenchRouteStateV1 | null {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return null
  const record = value as Record<string, unknown>
  if (
    Object.keys(record).length !== 2
    || record.schemaVersion !== 1
    || typeof record.viewId !== 'string'
    || !isWorkbenchViewIdV1(record.viewId)
  ) return null
  return Object.freeze({ schemaVersion: 1, viewId: record.viewId })
}

/** Project transient Controller state to the only state safe for navigation surfaces. */
export function projectWorkbenchRouteStateV1(
  state: SecurityAssuranceWorkbenchStateV1,
): WorkbenchRouteStateV1 {
  return Object.freeze({ schemaVersion: 1, viewId: viewIdForState(state) })
}

function isWorkbenchViewIdV1(value: string): value is WorkbenchViewIdV1 {
  return (WORKBENCH_INFORMATION_ARCHITECTURE_V1 as readonly string[]).includes(value)
}

function viewIdForState(state: SecurityAssuranceWorkbenchStateV1): WorkbenchViewIdV1 {
  switch (state.kind) {
    case 'CLOSED':
    case 'SELECTION_LOADING':
    case 'SELECTION_READY':
    case 'SELECTION_LOADING_MORE':
      return 'overview'
    case 'REPOSITORIES_LOADING':
    case 'REPOSITORIES_READY':
      return 'repositories'
    case 'CATALOG_LOADING':
    case 'PREFLIGHT_LOADING':
    case 'WIZARD_READY':
      return 'new-assessment'
    case 'HEALTH_LOADING':
    case 'HEALTH_READY':
      return 'runtime-health'
    case 'BUNDLE_LOADING':
    case 'BUNDLE_READY':
      return 'exports'
    case 'LOADING':
      return 'assessment-detail'
    case 'FAILED':
      return state.assessmentId === null ? 'overview' : 'assessment-detail'
    case 'READY': {
      if (state.findings.kind === 'NOT_LOADED') return 'assessment-detail'
      if (state.findings.kind !== 'DETAIL_READY') return 'findings'
      if (state.findings.evidence.kind !== 'NOT_LOADED') return 'evidence'
      if (state.findings.riskDecisionSubmission.kind !== 'IDLE') return 'risk-decisions'
      return 'findings'
    }
  }
}
