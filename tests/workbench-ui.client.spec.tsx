// @vitest-environment jsdom
import { act, cleanup, fireEvent } from '@testing-library/react'
import TypertRegistry from '@deepseek-ai/dsh-typert-registry'
import { afterEach, describe, expect, it } from 'vitest'
import { SlotTestRuntime } from '@deepseek-ai/dsh-client-test-runtime'
import {
  apply as applyClientRemote,
  inject as clientRemoteInject,
} from '../../deepseek-harness-master/packages/api/gateway/lib/types/client/index.js'
import { LocaleRuntime } from '@deepseek-ai/dsh-client-locale/client'
import type {} from '@deepseek-ai/dsh-client-ui-layout/client'
import type {} from '@deepseek-ai/dsh-client-ui-sidebar/client'
import type {
  AssessmentId,
  AssessmentListItemV1,
  AssessmentSnapshotV1,
  FindingDetailViewV1,
  FindingSummaryV1,
} from '../src/contracts.ts'
import {
  apply as applyWorkbenchClient,
  inject as workbenchClientInject,
  type SecurityAssuranceWorkbenchController,
  type WorkbenchAuthorityContextId,
} from '../src/client/index.ts'

afterEach(() => { cleanup() })

async function bench(call: (
  path: string,
  endpoint: string,
  payload: unknown,
  signal: AbortSignal,
) => Promise<unknown> = () => Promise.reject(new Error('The empty Workbench must not call Remote.'))) {
  const runtime = await SlotTestRuntime.create()
  await runtime.ctx.plugin(TypertRegistry)
  runtime.provide('connection', {
    rpc: {
      call,
    },
  } as never)
  const gateway = await runtime.mount({ inject: clientRemoteInject, apply: applyClientRemote })

  const locale = new LocaleRuntime(runtime.ctx)
  locale.setLocale('zh')
  runtime.provide('locale', locale)
  runtime.slots.installLocale(locale)
  await runtime.declare({
    'sidebar.footer.action': { kind: 'list', scope: 'root' },
    'shell.overlay': { kind: 'list', scope: 'root' },
  })
  const feature = await runtime.mount({
    inject: [...workbenchClientInject],
    apply: applyWorkbenchClient,
  })
  return {
    runtime,
    locale,
    feature,
    gateway,
    controller: runtime.ctx.get('securityAssuranceWorkbench') as SecurityAssuranceWorkbenchController,
  }
}

function assessmentId(value: string): AssessmentId {
  return value as AssessmentId
}

function authorityContextId(value: string): WorkbenchAuthorityContextId {
  return value as WorkbenchAuthorityContextId
}

function readySnapshot(id: AssessmentId): AssessmentSnapshotV1 {
  const digest = {
    schemaVersion: 1 as const,
    algorithm: 'sha256' as const,
    mediaType: 'application/vnd.dsh.canonical-json',
    byteLength: 1,
    canonicalization: 'dsh-canonical-json-v1' as const,
    value: 'a'.repeat(64),
  }
  return {
    schemaVersion: 1,
    assessmentId: id,
    assessmentRevision: 7,
    state: 'BLOCKED',
    repository: {
      repositoryId: 'repo-00000000-0000-0000-0000-000000000007',
      repositoryRevision: 3,
    },
    subject: { kind: 'workspace_snapshot', digest },
    policy: { policyId: 'security/standard', digest },
    coverage: {
      status: 'GAP',
      mandatoryObligations: 2,
      satisfiedObligations: 0,
      gapObligations: 2,
      resolutions: [
        { obligationId: 'security/sast', state: 'GAP', reason: 'ANALYZER_INCOMPLETE' },
        { obligationId: 'security/secrets', state: 'GAP', reason: 'EVIDENCE_INELIGIBLE' },
      ],
      digest,
    },
    availableActions: [
      { kind: 'RESUME_ASSESSMENT', expectedAssessmentRevision: 7 },
      { kind: 'CANCEL_ASSESSMENT', expectedAssessmentRevision: 7 },
    ],
    verdict: null,
    seal: null,
    createdAt: '2026-08-24T00:00:00.000Z',
    updatedAt: '2026-08-24T00:07:00.000Z',
  }
}

function selectionItem(id: AssessmentId, ordinal: number): AssessmentListItemV1 {
  return {
    schemaVersion: 1,
    assessmentId: id,
    assessmentRevision: ordinal,
    state: 'SEALED',
    repository: {
      repositoryId: `repo-00000000-0000-0000-0000-${String(ordinal).padStart(12, '0')}`,
      repositoryRevision: 1,
    } as AssessmentListItemV1['repository'],
    subjectKind: 'workspace_snapshot',
    policyId: 'security/standard',
    coverageStatus: 'COMPLETE',
    verdict: 'SATISFIED',
    createdAt: `2026-08-24T00:0${ordinal}:00.000Z`,
    updatedAt: `2026-08-24T00:0${ordinal}:30.000Z`,
  }
}

function findingSummaryItem(id: AssessmentId): FindingSummaryV1 {
  return {
    schemaVersion: 1,
    assessmentId: id,
    assessmentRevision: 7,
    recordKind: 'FINDING',
    recordId: `finding-${'f'.repeat(64)}`,
    candidateId: `candidate-${'f'.repeat(64)}`,
    recordRevision: 1,
    validationState: 'VALIDATED',
    validationContractId: 'security/validation/reference-v1',
    weaknessClassification: { primary: 'cwe/79', secondary: [] },
    technicalSeverity: 'HIGH',
    evidenceConfidence: 'HIGH',
    policySignificance: 'BLOCKING',
    hasProtectedDetail: true,
  }
}

function findingDetailView(summary: FindingSummaryV1): FindingDetailViewV1 {
  const digest = {
    schemaVersion: 1 as const,
    algorithm: 'sha256' as const,
    mediaType: 'application/vnd.dsh.canonical-json',
    byteLength: 42,
    canonicalization: 'dsh-canonical-json-v1' as const,
    value: 'e'.repeat(64),
  }
  return {
    schemaVersion: 1,
    assessmentId: summary.assessmentId,
    assessmentRevision: summary.assessmentRevision,
    recordKind: summary.recordKind,
    recordId: summary.recordId,
    candidateId: summary.candidateId,
    recordRevision: summary.recordRevision,
    revisionChain: [{ recordRevision: 1, supersedesRecordRevision: null, isCurrent: true }],
    weaknessClassification: summary.weaknessClassification,
    affectedControlId: 'security/control/output-encoding',
    sourceAnchor: {
      path: 'src/render.ts',
      fileDigest: digest,
      locator: { kind: 'JSON_POINTER', value: '/render/html' },
    },
    validation: {
      state: 'VALIDATED',
      contractId: 'security/validation/reference-v1',
      contractVersion: 1,
      outcomeArtifactId: 'validation/outcome/reference',
      rejectionCondition: null,
      proofGaps: [],
      negativeControls: ['security/negative-control/encoded-output'],
    },
    technicalSeverity: {
      value: 'HIGH',
      methodVersion: 'security/severity/v1',
      inputs: [{ dimension: 'impact', value: 'account-takeover' }],
    },
    evidenceConfidence: {
      value: 'HIGH',
      methodVersion: 'security/confidence/v1',
      rubric: [{ dimension: 'reproducible', value: true }],
    },
    policySignificance: 'BLOCKING',
    coverageRelations: [{
      obligationId: 'security/output-encoding',
      state: 'SATISFIED',
      reason: 'ELIGIBLE_EVIDENCE',
    }],
    riskDecision: { state: 'NOT_RECORDED' },
    evidenceLinks: [{
      artifactId: 'evidence/reference-output-encoding',
      schemaId: 'security/evidence/reference-v1',
      digest,
      purpose: 'VALIDATION_EVIDENCE',
      eligibilityDecision: 'ELIGIBLE',
      eligibilityDecisionArtifactId: 'eligibility/reference-output-encoding',
    }],
    attackPath: { state: 'NOT_AVAILABLE' },
  }
}

describe('Security Assurance Workbench UI', () => {
  it('navigates from multidimensional Finding triage to revision-bound Detail and back', async () => {
    const id = assessmentId('asm-00000000-0000-0000-0000-000000000071')
    const snapshot = readySnapshot(id)
    const summary = findingSummaryItem(id)
    const unresolved: FindingSummaryV1 = {
      ...summary,
      recordKind: 'UNRESOLVED_CANDIDATE',
      recordId: `candidate-${'1'.repeat(64)}`,
      candidateId: `candidate-${'1'.repeat(64)}`,
      validationState: 'UNRESOLVED',
      technicalSeverity: null,
      evidenceConfidence: 'LOW',
      policySignificance: null,
      hasProtectedDetail: false,
    }
    const detail = findingDetailView(summary)
    let findingPage = 0
    const b = await bench((_path, endpoint, _payload, signal) => {
      if (endpoint === 'securityAssuranceWorkbench/getAssessment') {
        return Promise.resolve({ ok: true, value: { ok: true, value: snapshot } })
      }
      if (endpoint === 'securityAssuranceWorkbench/waitForAssessmentRevision') {
        return new Promise(resolve => {
          signal.addEventListener('abort', () => {
            resolve({ ok: false, error: { code: 'aborted' } })
          }, { once: true })
        })
      }
      if (endpoint === 'securityAssuranceWorkbench/listFindings') {
        findingPage += 1
        return Promise.resolve({
          ok: true,
          value: {
            ok: true,
            value: {
              schemaVersion: 1,
              assessmentId: id,
              assessmentRevision: 7,
              findings: [findingPage === 1 ? summary : unresolved],
              nextCursor: findingPage === 1 ? 'finding.cursor' : null,
            },
          },
        })
      }
      if (endpoint === 'securityAssuranceWorkbench/getFinding') {
        return Promise.resolve({ ok: true, value: { ok: true, value: detail } })
      }
      return Promise.reject(new Error(`Unexpected endpoint: ${endpoint}`))
    })
    const launcher = b.runtime.renderSlot('sidebar.footer.action', { wide: true })
    const overlay = b.runtime.renderSlot('shell.overlay', {})
    await act(async () => {
      fireEvent.click(launcher.view.getByRole('button', { name: '打开安全保障工作台' }))
      await b.controller.openAssessment({
        securityAssuranceWorkbenchContextId: authorityContextId('workbench-session-finding-ui'),
        assessmentId: id,
      })
    })

    await act(async () => {
      fireEvent.click(overlay.view.getByRole('button', { name: '查看 Findings' }))
    })
    expect(overlay.view.getByRole('heading', { name: 'Findings' })).toBeTruthy()
    expect(overlay.view.getByText('cwe/79')).toBeTruthy()
    expect(overlay.view.getAllByText('HIGH').length).toBeGreaterThanOrEqual(2)
    expect(overlay.view.getByText('BLOCKING')).toBeTruthy()
    expect(overlay.view.getByText('VALIDATED')).toBeTruthy()
    expect(overlay.view.getByText('包含受保护详情')).toBeTruthy()
    expect(overlay.view.queryByText('src/render.ts')).toBeNull()

    await act(async () => {
      fireEvent.click(overlay.view.getByRole('button', { name: '加载更多 Findings' }))
    })
    expect(overlay.view.getByText(unresolved.recordId)).toBeTruthy()
    expect(overlay.view.getByText('UNRESOLVED_CANDIDATE')).toBeTruthy()
    expect(overlay.view.getByText('UNRESOLVED')).toBeTruthy()
    expect(overlay.view.queryByRole('button', { name: '加载更多 Findings' })).toBeNull()

    await act(async () => {
      fireEvent.click(overlay.view.getByRole('button', {
        name: `打开 Finding ${summary.recordId}`,
      }))
    })
    expect(overlay.view.getByRole('heading', { name: 'Finding 详情' })).toBeTruthy()
    expect(overlay.view.getByText('src/render.ts')).toBeTruthy()
    expect(overlay.view.getByText('/render/html')).toBeTruthy()
    expect(overlay.view.getByText('evidence/reference-output-encoding')).toBeTruthy()
    expect(overlay.view.getByText('NOT_RECORDED')).toBeTruthy()
    expect(overlay.view.queryByText('contentBase64')).toBeNull()

    await act(async () => {
      fireEvent.click(overlay.view.getByRole('button', { name: '返回 Finding 列表' }))
    })
    expect(overlay.view.getByRole('button', {
      name: `打开 Finding ${summary.recordId}`,
    })).toBeTruthy()

    await b.feature.dispose()
    await b.gateway.dispose()
    await b.runtime.dispose()
  })

  it('loads the next Assessment page once without rendering authority or cursor material', async () => {
    const firstId = assessmentId('asm-00000000-0000-0000-0000-000000000051')
    const secondId = assessmentId('asm-00000000-0000-0000-0000-000000000052')
    let calls = 0
    let resolveContinuation: ((value: unknown) => void) | undefined
    const b = await bench((_path, endpoint) => {
      if (endpoint !== 'securityAssuranceWorkbench/listAssessments') {
        return Promise.reject(new Error(`Unexpected endpoint: ${endpoint}`))
      }
      calls += 1
      if (calls === 1) {
        return Promise.resolve({
          ok: true,
          value: {
            ok: true,
            value: {
              schemaVersion: 1,
              consistencyWatermark: 'stable.signature',
              assessments: [selectionItem(firstId, 1)],
              nextCursor: 'cursor.signature',
            },
          },
        })
      }
      return new Promise(resolve => { resolveContinuation = resolve })
    })
    const launcher = b.runtime.renderSlot('sidebar.footer.action', { wide: true })
    const overlay = b.runtime.renderSlot('shell.overlay', {})
    const authorityId = authorityContextId('workbench-session-pagination-ui')
    await act(async () => {
      await b.controller.openAssessmentSelection({
        securityAssuranceWorkbenchContextId: authorityId,
      })
      fireEvent.click(launcher.view.getByRole('button', { name: '打开安全保障工作台' }))
    })

    expect(overlay.view.getByText(firstId)).toBeTruthy()
    const loadMore = overlay.view.getByRole('button', { name: '加载更多 Assessment' })
    await act(async () => { fireEvent.click(loadMore) })
    expect(overlay.view.getByRole<HTMLButtonElement>(
      'button',
      { name: '正在加载更多 Assessment' },
    ).disabled).toBe(true)
    expect(calls).toBe(2)

    await act(async () => {
      resolveContinuation?.({
        ok: true,
        value: {
          ok: true,
          value: {
            schemaVersion: 1,
            consistencyWatermark: 'stable.signature',
            assessments: [selectionItem(secondId, 2)],
            nextCursor: null,
          },
        },
      })
      await Promise.resolve()
    })
    expect(overlay.view.getByText(firstId)).toBeTruthy()
    expect(overlay.view.getByText(secondId)).toBeTruthy()
    expect(overlay.view.queryByRole('button', { name: '加载更多 Assessment' })).toBeNull()
    expect(overlay.view.queryByText('cursor.signature')).toBeNull()
    expect(overlay.view.queryByText(authorityId)).toBeNull()

    await b.feature.dispose()
    await b.gateway.dispose()
    await b.runtime.dispose()
  })

  it('renders an authority-scoped Assessment selector without credential inputs', async () => {
    const id = assessmentId('asm-00000000-0000-0000-0000-000000000011')
    const snapshot = readySnapshot(id)
    const b = await bench((_path, endpoint, _payload, signal) => {
      if (endpoint === 'securityAssuranceWorkbench/listAssessments') {
        return Promise.resolve({
          ok: true,
          value: {
            ok: true,
            value: {
              schemaVersion: 1,
              consistencyWatermark: 'watermark.signature',
              assessments: [{
                schemaVersion: 1,
                assessmentId: id,
                assessmentRevision: snapshot.assessmentRevision,
                state: snapshot.state,
                repository: snapshot.repository,
                subjectKind: snapshot.subject.kind,
                policyId: snapshot.policy.policyId,
                coverageStatus: snapshot.coverage.status,
                verdict: snapshot.verdict,
                createdAt: snapshot.createdAt,
                updatedAt: snapshot.updatedAt,
              }],
              nextCursor: null,
            },
          },
        })
      }
      if (endpoint === 'securityAssuranceWorkbench/getAssessment') {
        return Promise.resolve({ ok: true, value: { ok: true, value: snapshot } })
      }
      if (endpoint === 'securityAssuranceWorkbench/waitForAssessmentRevision') {
        return new Promise(resolve => {
          signal.addEventListener('abort', () => {
            resolve({ ok: false, error: { code: 'aborted' } })
          }, { once: true })
        })
      }
      return Promise.reject(new Error(`Unexpected endpoint: ${endpoint}`))
    })
    const launcher = b.runtime.renderSlot('sidebar.footer.action', { wide: true })
    const overlay = b.runtime.renderSlot('shell.overlay', {})
    await act(async () => {
      await b.controller.openAssessmentSelection({
        securityAssuranceWorkbenchContextId: authorityContextId('workbench-session-selector'),
      })
      fireEvent.click(launcher.view.getByRole('button', { name: '打开安全保障工作台' }))
    })

    expect(overlay.view.getByRole('heading', { name: '选择 Assessment' })).toBeTruthy()
    expect(overlay.view.getByText(id)).toBeTruthy()
    expect(overlay.view.queryByRole('textbox')).toBeNull()
    expect(overlay.view.queryByText('workbench-session-selector')).toBeNull()
    const selectionButton = overlay.view.getByRole('button', { name: `打开 ${id}` })
    fireEvent.keyDown(overlay.view.getByRole('dialog'), { key: 'Tab', shiftKey: true })
    expect(document.activeElement).toBe(selectionButton)
    await act(async () => {
      fireEvent.click(selectionButton)
    })
    expect(overlay.view.getByText('security/standard')).toBeTruthy()
    await act(async () => {
      fireEvent.click(overlay.view.getByRole('button', { name: '关闭工作台' }))
    })
    expect(b.controller.getState()).toEqual({ kind: 'CLOSED' })
    expect(overlay.view.queryByRole('dialog')).toBeNull()

    await b.feature.dispose()
    await b.gateway.dispose()
    await b.runtime.dispose()
  })

  it('opens a bilingual empty dialog from the additive Host slots and returns focus on close', async () => {
    const b = await bench()
    const launcher = b.runtime.renderSlot('sidebar.footer.action', { wide: true })
    const overlay = b.runtime.renderSlot('shell.overlay', {})

    const open = launcher.view.getByRole('button', { name: '打开安全保障工作台' })
    open.focus()
    await act(async () => { fireEvent.click(open) })
    expect(overlay.view.getByRole('dialog', { name: '安全保障工作台' })).toBeTruthy()
    expect(overlay.view.getByText('尚未选择评估')).toBeTruthy()
    expect(overlay.view.getByText('请通过已认证的宿主集成打开一个 Assessment。')).toBeTruthy()

    act(() => { b.locale.setLocale('en') })
    expect(overlay.view.getByRole('dialog', { name: 'Security Assurance Workbench' })).toBeTruthy()
    expect(overlay.view.getByText('No assessment selected')).toBeTruthy()

    const close = overlay.view.getByRole('button', { name: 'Close Workbench' })
    expect(document.activeElement).toBe(close)
    await act(async () => { fireEvent.click(close) })
    expect(overlay.view.queryByRole('dialog')).toBeNull()
    expect(document.activeElement).toBe(open)
    expect(b.controller.getState()).toEqual({ kind: 'CLOSED' })

    await b.feature.dispose()
    expect(b.runtime.slots.entries('sidebar.footer.action')).toHaveLength(0)
    expect(b.runtime.slots.entries('shell.overlay')).toHaveLength(0)
    await b.gateway.dispose()
    await b.runtime.dispose()
  })

  it('renders the Controller Snapshot and service-projected actions without exposing mutations', async () => {
    const id = assessmentId('asm-00000000-0000-0000-0000-000000000007')
    const snapshot = readySnapshot(id)
    const b = await bench((_path, endpoint, _payload, signal) => {
      if (endpoint === 'securityAssuranceWorkbench/getAssessment') {
        return Promise.resolve({ ok: true, value: { ok: true, value: snapshot } })
      }
      if (endpoint === 'securityAssuranceWorkbench/waitForAssessmentRevision') {
        return new Promise(resolve => {
          signal.addEventListener('abort', () => { resolve({ ok: false, error: { code: 'aborted' } }) }, { once: true })
        })
      }
      return Promise.reject(new Error(`Unexpected endpoint: ${endpoint}`))
    })
    const launcher = b.runtime.renderSlot('sidebar.footer.action', { wide: true })
    const overlay = b.runtime.renderSlot('shell.overlay', {})
    await act(async () => {
      fireEvent.click(launcher.view.getByRole('button', { name: '打开安全保障工作台' }))
      await b.controller.openAssessment({
        securityAssuranceWorkbenchContextId: authorityContextId('workbench-session-reviewer'),
        assessmentId: id,
      })
    })

    expect(overlay.view.getByText(id)).toBeTruthy()
    expect(overlay.view.getAllByText('BLOCKED')).toHaveLength(2)
    expect(overlay.view.getByText('GAP')).toBeTruthy()
    expect(overlay.view.getByText('0 / 2')).toBeTruthy()
    expect(overlay.view.getByText('security/standard')).toBeTruthy()
    expect(overlay.view.getAllByText('尚未生成')).toHaveLength(2)
    expect(overlay.view.getByText('RESUME_ASSESSMENT')).toBeTruthy()
    expect(overlay.view.getByText('CANCEL_ASSESSMENT')).toBeTruthy()
    expect(overlay.view.getByText('可用操作由 Security Service 快照决定；当前工作台为只读。')).toBeTruthy()
    expect(overlay.view.getByRole('button', { name: '查看 Findings' })).toBeTruthy()
    expect(overlay.view.queryByRole('button', { name: 'RESUME_ASSESSMENT' })).toBeNull()
    expect(overlay.view.queryByRole('button', { name: 'CANCEL_ASSESSMENT' })).toBeNull()

    await b.feature.dispose()
    await b.gateway.dispose()
    await b.runtime.dispose()
  })
})
