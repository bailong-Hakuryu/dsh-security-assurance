import { createElement } from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import { describe, expect, it } from 'vitest'
import type { AssessmentId, AssessmentListItemV1 } from '../src/contracts.ts'
import type { SecurityAssuranceWorkbenchStateV1 } from '../src/web-client/workbench/controller.ts'
import { zh, type WorkbenchKey } from '../src/web-client/workbench/locales.ts'
import {
  WorkbenchOverlay,
  type WorkbenchOverlayProps,
} from '../src/web-client/workbench/WorkbenchOverlay.tsx'

function translate(key: WorkbenchKey, params: Record<string, unknown> = {}): string {
  return zh[key].replace(/\{(\w+)\}/gu, (_match, name: string) => String(params[name] ?? `{${name}}`))
}

/**
 * Render the overlay with the props the slot framework derives from one
 * presentation/assessment snapshot pair. Command callbacks are bound only as
 * event handlers, so static markup never needs them.
 */
function render(state: SecurityAssuranceWorkbenchStateV1, open = true): string {
  const props = {
    t: translate,
    usePresentation: <S>(select: (snapshot: { readonly open: boolean }) => S) => select({ open }),
    useAssessment: <S>(select: (snapshot: SecurityAssuranceWorkbenchStateV1) => S) => select(state),
  } as unknown as WorkbenchOverlayProps
  return renderToStaticMarkup(createElement(WorkbenchOverlay, props))
}

const listed: AssessmentListItemV1 = {
  schemaVersion: 1,
  assessmentId: 'asm-00000000-0000-0000-0000-000000000321' as AssessmentId,
  assessmentRevision: 4,
  state: 'SEALED',
  repository: {
    repositoryId: 'repo-00000000-0000-0000-0000-000000000321',
    repositoryRevision: 1,
  } as AssessmentListItemV1['repository'],
  subjectKind: 'workspace_snapshot',
  policyId: 'security/standard',
  coverageStatus: 'COMPLETE',
  verdict: 'SATISFIED',
  createdAt: '2026-09-26T00:00:00.000Z',
  updatedAt: '2026-09-26T00:01:00.000Z',
}

describe('ADR 0321 local Workbench overlay', () => {
  it('renders nothing until the launcher shows it', () => {
    expect(render({ kind: 'CLOSED' }, false)).toBe('')
  })

  it('tells the operator the local authority is reading their Assessments', () => {
    const markup = render({ kind: 'SELECTION_LOADING' })
    expect(markup).toContain(zh['dialog.title'])
    expect(markup).toContain(zh['selection.loadingTitle'])
    expect(markup).toContain('role="dialog"')
  })

  it('lists visible Assessments beside the repository and health entry points', () => {
    const markup = render({
      kind: 'SELECTION_READY',
      consistencyWatermark: 'local.signature',
      assessments: [listed],
      nextCursor: null,
    })
    expect(markup).toContain(listed.assessmentId)
    expect(markup).toContain(zh['selection.open'])
    expect(markup).toContain(zh['repositories.open'])
    expect(markup).toContain(zh['health.open'])
    expect(markup).not.toContain(zh['riskDecision.title'])
  })

  it('keeps the Host-integration guidance when no local authority is exported', () => {
    expect(render({ kind: 'CLOSED' })).toContain(zh['empty.body'])
  })

  it('reports a failed local context by source and code only', () => {
    const markup = render({
      kind: 'FAILED',
      assessmentId: null,
      failure: {
        source: 'CLIENT',
        code: 'LOCAL_CONTEXT_PROTOCOL_VIOLATION',
        message: 'The local Workbench authority returned an unusable context.',
        retryable: false,
      },
    })
    expect(markup).toContain(zh['failure.title'])
    expect(markup).toContain('CLIENT/LOCAL_CONTEXT_PROTOCOL_VIOLATION')
    expect(markup).toContain('role="alert"')
  })
})
