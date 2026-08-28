import { describe, expect, it } from 'vitest'
import type { SecurityAssuranceWorkbenchStateV1 } from '../src/client/index.ts'
import {
  projectWorkbenchRouteStateV1,
  WORKBENCH_INFORMATION_ARCHITECTURE_V1,
} from '../src/client/index.ts'
import { en, zh } from '../src/client/workbench/locales.ts'

describe('ADR 0277 fixed Workbench information architecture', () => {
  it('publishes the exact nine v0.1 views in stable order', () => {
    expect(WORKBENCH_INFORMATION_ARCHITECTURE_V1).toEqual([
      'overview',
      'repositories',
      'new-assessment',
      'assessment-detail',
      'findings',
      'evidence',
      'risk-decisions',
      'exports',
      'runtime-health',
    ])
    expect(Object.isFrozen(WORKBENCH_INFORMATION_ARCHITECTURE_V1)).toBe(true)
    expect(en['selection.title']).toBe('Overview')
    expect(zh['selection.title']).toBe('概览')
  })

  it('projects existing Controller states onto the reviewed view catalog', () => {
    const cases = [
      [{ kind: 'SELECTION_LOADING' }, 'overview'],
      [{ kind: 'REPOSITORIES_LOADING' }, 'repositories'],
      [{ kind: 'CATALOG_LOADING', repository: {} }, 'new-assessment'],
      [{ kind: 'LOADING', assessmentId: 'opaque' }, 'assessment-detail'],
      [{ kind: 'READY', findings: { kind: 'LIST_LOADING' } }, 'findings'],
      [{ kind: 'READY', findings: {
        kind: 'DETAIL_READY',
        evidence: { kind: 'METADATA_LOADING' },
        riskDecisionSubmission: { kind: 'IDLE' },
      } }, 'evidence'],
      [{ kind: 'READY', findings: {
        kind: 'DETAIL_READY',
        evidence: { kind: 'NOT_LOADED' },
        riskDecisionSubmission: { kind: 'SUBMITTING' },
      } }, 'risk-decisions'],
      [{ kind: 'BUNDLE_LOADING', assessmentId: 'opaque' }, 'exports'],
      [{ kind: 'HEALTH_LOADING' }, 'runtime-health'],
    ] as const

    for (const [state, viewId] of cases) {
      expect(projectWorkbenchRouteStateV1(
        state as unknown as SecurityAssuranceWorkbenchStateV1,
      ).viewId).toBe(viewId)
    }
  })
})
