import { IconCloseOutline16, IconDataOutline16 } from '@deepseek-ai/dsh-client-ui-primitives'
import type {
  HostObservable,
  PropsHooks,
  PropsLocale,
  PropsRuntime,
} from '@deepseek-ai/dsh-client-ui-slots'
import { useEffect, useRef } from 'react'
import type { KeyboardEvent, MouseEvent } from 'react'
import type { SecurityAssuranceWorkbenchStateV1 } from '../index.ts'
import type { AssessmentAvailableActionV1, AssessmentSnapshotV1 } from '../../contracts.ts'
import type { WORKBENCH_LOCALE_NAMESPACE } from './locales.ts'
import type { WorkbenchPresentationSnapshotV1 } from './presentation.ts'

export type WorkbenchOverlaySources = {
  readonly presentation: HostObservable<WorkbenchPresentationSnapshotV1>
  readonly assessment: HostObservable<SecurityAssuranceWorkbenchStateV1>
}

export interface WorkbenchOverlayInjected {
  readonly hooks: WorkbenchOverlaySources
  readonly closeWorkbench: () => void
}

export type WorkbenchOverlayProps =
  & PropsRuntime<'shell.overlay'>
  & PropsLocale<typeof WORKBENCH_LOCALE_NAMESPACE>
  & PropsHooks<WorkbenchOverlaySources>
  & Omit<WorkbenchOverlayInjected, 'hooks'>

/** Frame-wide, authority-free shell. Assessment content always arrives from the Controller snapshot. */
export function WorkbenchOverlay({
  t,
  usePresentation,
  useAssessment,
  closeWorkbench,
}: WorkbenchOverlayProps) {
  const open = usePresentation(snapshot => snapshot.open)
  const state = useAssessment(snapshot => snapshot)
  const closeRef = useRef<HTMLButtonElement>(null)

  useEffect(() => {
    if (open) closeRef.current?.focus()
  }, [open])

  if (!open) return null

  const onBackdrop = (event: MouseEvent<HTMLDivElement>): void => {
    if (event.target === event.currentTarget) closeWorkbench()
  }
  const onKeyDown = (event: KeyboardEvent<HTMLDivElement>): void => {
    if (event.key === 'Escape') {
      event.preventDefault()
      closeWorkbench()
      return
    }
    if (event.key === 'Tab') {
      event.preventDefault()
      closeRef.current?.focus()
    }
  }

  return (
    <div className="dsh-security-backdrop" onMouseDown={onBackdrop} onKeyDown={onKeyDown}>
      <section
        className="dsh-security-dialog"
        role="dialog"
        aria-modal="true"
        aria-labelledby="dsh-security-workbench-title"
      >
        <header className="dsh-security-dialog__header">
          <h1 id="dsh-security-workbench-title" className="dsh-security-dialog__title">
            {t('dialog.title')}
          </h1>
          <button
            ref={closeRef}
            type="button"
            className="dsh-security-dialog__close"
            aria-label={t('dialog.close')}
            onClick={closeWorkbench}
          >
            <IconCloseOutline16 />
          </button>
        </header>
        <div className="dsh-security-dialog__body">
          {state.kind === 'CLOSED' && <MessageState title={t('empty.title')} body={t('empty.body')} />}
          {state.kind === 'LOADING' && (
            <MessageState
              title={t('loading.title')}
              body={t('loading.body')}
              detail={state.assessmentId}
              role="status"
            />
          )}
          {state.kind === 'FAILED' && (
            <MessageState
              title={t('failure.title')}
              body={t('failure.body')}
              detail={`${t('label.failureCode')}: ${state.failure.source}/${state.failure.code}`}
              role="alert"
            />
          )}
          {state.kind === 'READY' && <AssessmentDetail snapshot={state.snapshot} t={t} />}
        </div>
      </section>
    </div>
  )
}

function MessageState({
  title,
  body,
  detail,
  role,
}: {
  readonly title: string
  readonly body: string
  readonly detail?: string
  readonly role?: 'status' | 'alert'
}) {
  return (
    <div className="dsh-security-empty" role={role} aria-live={role === 'status' ? 'polite' : undefined}>
      <span className="dsh-security-empty__icon" aria-hidden="true">
        <IconDataOutline16 />
      </span>
      <h2>{title}</h2>
      <p>{body}</p>
      {detail !== undefined && <code className="dsh-security-message__detail">{detail}</code>}
    </div>
  )
}

function AssessmentDetail({
  snapshot,
  t,
}: {
  readonly snapshot: AssessmentSnapshotV1
  readonly t: WorkbenchOverlayProps['t']
}) {
  return (
    <div className="dsh-security-assessment">
      <div className="dsh-security-assessment__heading">
        <div>
          <span className="dsh-security-eyebrow">{t('label.assessment')}</span>
          <code className="dsh-security-assessment__id">{snapshot.assessmentId}</code>
        </div>
        <div className="dsh-security-badges" aria-label={t('label.state')}>
          <MachineBadge value={snapshot.state} />
          <MachineBadge value={snapshot.verdict ?? t('value.pending')} />
        </div>
      </div>

      <dl className="dsh-security-facts">
        <Fact label={t('label.revision')} value={String(snapshot.assessmentRevision)} />
        <Fact label={t('label.state')} value={snapshot.state} machine />
        <Fact label={t('label.verdict')} value={snapshot.verdict ?? t('value.pending')} machine={snapshot.verdict !== null} />
        <Fact label={t('label.repository')} value={`${snapshot.repository.repositoryId} @ ${snapshot.repository.repositoryRevision}`} machine />
        <Fact label={t('label.subject')} value={snapshot.subject.kind} machine />
        <Fact label={t('label.policy')} value={snapshot.policy.policyId} machine />
        <Fact label={t('label.updated')} value={snapshot.updatedAt} machine />
      </dl>

      <section className="dsh-security-section" aria-labelledby="dsh-security-coverage-title">
        <div className="dsh-security-section__header">
          <h2 id="dsh-security-coverage-title">{t('label.coverage')}</h2>
          <MachineBadge value={snapshot.coverage.status} />
        </div>
        <div className="dsh-security-metrics">
          <Metric
            label={t('label.satisfied')}
            value={`${snapshot.coverage.satisfiedObligations} / ${snapshot.coverage.mandatoryObligations}`}
          />
          <Metric label={t('label.gaps')} value={String(snapshot.coverage.gapObligations)} />
        </div>
      </section>

      <section className="dsh-security-section" aria-labelledby="dsh-security-actions-title">
        <div className="dsh-security-section__header">
          <h2 id="dsh-security-actions-title">{t('label.availableActions')}</h2>
        </div>
        <p className="dsh-security-readonly-note">{t('actions.readOnly')}</p>
        {snapshot.availableActions.length === 0
          ? <p className="dsh-security-muted">{t('value.noActions')}</p>
          : (
              <ul className="dsh-security-actions">
                {snapshot.availableActions.map(action => (
                  <li key={actionKey(action)}>
                    <code>{action.kind}</code>
                    <span>{actionDescription(action, t)}</span>
                    <small>revision {action.expectedAssessmentRevision}</small>
                  </li>
                ))}
              </ul>
            )}
      </section>
    </div>
  )
}

function Fact({ label, value, machine = false }: {
  readonly label: string
  readonly value: string
  readonly machine?: boolean
}) {
  return (
    <div>
      <dt>{label}</dt>
      <dd>{machine ? <code>{value}</code> : value}</dd>
    </div>
  )
}

function Metric({ label, value }: { readonly label: string; readonly value: string }) {
  return <div className="dsh-security-metric"><span>{label}</span><strong>{value}</strong></div>
}

function MachineBadge({ value }: { readonly value: string }) {
  return <span className="dsh-security-badge" data-value={value}>{value}</span>
}

function actionKey(action: AssessmentAvailableActionV1): string {
  return action.kind === 'RECORD_RISK_DECISION'
    ? `${action.kind}:${action.finding.recordId}:${action.finding.recordRevision}`
    : action.kind
}

function actionDescription(
  action: AssessmentAvailableActionV1,
  t: WorkbenchOverlayProps['t'],
): string {
  switch (action.kind) {
    case 'RESUME_ASSESSMENT': return t('action.resume')
    case 'CANCEL_ASSESSMENT': return t('action.cancel')
    case 'RECORD_RISK_DECISION': return t('action.riskDecision')
  }
}
