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
import type { AssessmentId, AssessmentSnapshotV1 } from '../src/contracts.ts'
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

describe('Security Assurance Workbench UI', () => {
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
    expect(overlay.view.getAllByRole('button')).toHaveLength(1)

    await b.feature.dispose()
    await b.gateway.dispose()
    await b.runtime.dispose()
  })
})
