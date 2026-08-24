import { IconCloseOutline16, IconDataOutline16 } from '@deepseek-ai/dsh-client-ui-primitives'
import type {
  HostObservable,
  PropsHooks,
  PropsLocale,
  PropsRuntime,
} from '@deepseek-ai/dsh-client-ui-slots'
import { useEffect, useRef } from 'react'
import type { KeyboardEvent, MouseEvent } from 'react'
import type {
  SecurityAssuranceWorkbenchStateV1,
  WorkbenchFindingsStateV1,
} from '../index.ts'
import type {
  AssessmentAvailableActionV1,
  AssessmentId,
  AssessmentListItemV1,
  AssessmentSnapshotV1,
  FindingDetailViewV1,
  FindingSummaryV1,
} from '../../contracts.ts'
import type { WORKBENCH_LOCALE_NAMESPACE } from './locales.ts'
import type { WorkbenchPresentationSnapshotV1 } from './presentation.ts'

export type WorkbenchOverlaySources = {
  readonly presentation: HostObservable<WorkbenchPresentationSnapshotV1>
  readonly assessment: HostObservable<SecurityAssuranceWorkbenchStateV1>
}

export interface WorkbenchOverlayInjected {
  readonly hooks: WorkbenchOverlaySources
  readonly closeWorkbench: () => void
  readonly loadMoreAssessments: () => void
  readonly loadMoreFindings: () => void
  readonly openFindings: () => void
  readonly backToFindingList: () => void
  readonly selectAssessment: (assessmentId: AssessmentId) => void
  readonly selectFinding: (recordId: string) => void
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
  loadMoreAssessments,
  loadMoreFindings,
  openFindings,
  backToFindingList,
  selectAssessment,
  selectFinding,
}: WorkbenchOverlayProps) {
  const open = usePresentation(snapshot => snapshot.open)
  const state = useAssessment(snapshot => snapshot)
  const closeRef = useRef<HTMLButtonElement>(null)
  const dialogRef = useRef<HTMLElement>(null)

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
      const focusable = [...(dialogRef.current?.querySelectorAll<HTMLButtonElement>(
        'button:not([disabled])',
      ) ?? [])]
      const first = focusable.at(0)
      const last = focusable.at(-1)
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault()
        last?.focus()
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault()
        first?.focus()
      }
    }
  }

  return (
    <div className="dsh-security-backdrop" onMouseDown={onBackdrop} onKeyDown={onKeyDown}>
      <section
        ref={dialogRef}
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
          {state.kind === 'SELECTION_LOADING' && (
            <MessageState title={t('selection.loadingTitle')} body={t('selection.loadingBody')} role="status" />
          )}
          {(state.kind === 'SELECTION_READY' || state.kind === 'SELECTION_LOADING_MORE') && (
            <AssessmentSelection
              assessments={state.assessments}
              hasMore={state.nextCursor !== null}
              loadingMore={state.kind === 'SELECTION_LOADING_MORE'}
              loadMoreAssessments={loadMoreAssessments}
              selectAssessment={selectAssessment}
              t={t}
            />
          )}
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
          {state.kind === 'READY' && (
            <AssessmentDetail
              snapshot={state.snapshot}
              findings={state.findings}
              openFindings={openFindings}
              loadMoreFindings={loadMoreFindings}
              selectFinding={selectFinding}
              backToFindingList={backToFindingList}
              t={t}
            />
          )}
        </div>
      </section>
    </div>
  )
}

function AssessmentSelection({
  assessments,
  hasMore,
  loadingMore,
  loadMoreAssessments,
  selectAssessment,
  t,
}: {
  readonly assessments: readonly AssessmentListItemV1[]
  readonly hasMore: boolean
  readonly loadingMore: boolean
  readonly loadMoreAssessments: () => void
  readonly selectAssessment: (assessmentId: AssessmentId) => void
  readonly t: WorkbenchOverlayProps['t']
}) {
  return (
    <section className="dsh-security-selection" aria-labelledby="dsh-security-selection-title">
      <div>
        <h2 id="dsh-security-selection-title">{t('selection.title')}</h2>
        <p>{t('selection.body')}</p>
      </div>
      {assessments.length === 0
        ? <p className="dsh-security-muted">{t('selection.empty')}</p>
        : (
            <ul className="dsh-security-selection__list">
              {assessments.map(item => (
                <li key={item.assessmentId}>
                  <button
                    type="button"
                    aria-label={`${t('selection.open')} ${item.assessmentId}`}
                    disabled={loadingMore}
                    onClick={() => { selectAssessment(item.assessmentId) }}
                  >
                    <span className="dsh-security-selection__identity">
                      <code>{item.assessmentId}</code>
                      <small>{item.repository.repositoryId} @ {item.repository.repositoryRevision}</small>
                    </span>
                    <span className="dsh-security-badges">
                      <MachineBadge value={item.state} />
                      <MachineBadge value={item.verdict ?? t('value.pending')} />
                    </span>
                  </button>
                </li>
              ))}
            </ul>
          )}
      {hasMore && (
        <button
          type="button"
          className="dsh-security-selection__load-more"
          aria-label={loadingMore ? t('selection.loadingMore') : t('selection.loadMore')}
          disabled={loadingMore}
          onClick={loadMoreAssessments}
        >
          {loadingMore ? t('selection.loadingMore') : t('selection.loadMore')}
        </button>
      )}
    </section>
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
  findings,
  openFindings,
  loadMoreFindings,
  selectFinding,
  backToFindingList,
  t,
}: {
  readonly snapshot: AssessmentSnapshotV1
  readonly findings: WorkbenchFindingsStateV1
  readonly openFindings: () => void
  readonly loadMoreFindings: () => void
  readonly selectFinding: (recordId: string) => void
  readonly backToFindingList: () => void
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

      <FindingPanel
        state={findings}
        openFindings={openFindings}
        loadMoreFindings={loadMoreFindings}
        selectFinding={selectFinding}
        backToFindingList={backToFindingList}
        t={t}
      />
    </div>
  )
}

function FindingPanel({
  state,
  openFindings,
  loadMoreFindings,
  selectFinding,
  backToFindingList,
  t,
}: {
  readonly state: WorkbenchFindingsStateV1
  readonly openFindings: () => void
  readonly loadMoreFindings: () => void
  readonly selectFinding: (recordId: string) => void
  readonly backToFindingList: () => void
  readonly t: WorkbenchOverlayProps['t']
}) {
  if (state.kind === 'DETAIL_READY') {
    return <FindingDetail detail={state.detail} backToFindingList={backToFindingList} t={t} />
  }
  return (
    <section className="dsh-security-section dsh-security-findings" aria-labelledby="dsh-security-findings-title">
      <div className="dsh-security-section__header">
        <h2 id="dsh-security-findings-title">{t('findings.title')}</h2>
        {state.kind === 'NOT_LOADED' && (
          <button type="button" className="dsh-security-secondary-action" onClick={openFindings}>
            {t('findings.open')}
          </button>
        )}
      </div>
      {state.kind === 'NOT_LOADED' && (
        <p className="dsh-security-readonly-note">{t('findings.description')}</p>
      )}
      {(state.kind === 'LIST_LOADING' || state.kind === 'DETAIL_LOADING') && (
        <p className="dsh-security-muted" role="status" aria-live="polite">
          {state.kind === 'LIST_LOADING' ? t('findings.loading') : t('findingDetail.loading')}
        </p>
      )}
      {(state.kind === 'LIST_READY' || state.kind === 'LIST_LOADING_MORE') && (
        <FindingList
          items={state.items}
          hasMore={state.nextCursor !== null}
          loadingMore={state.kind === 'LIST_LOADING_MORE'}
          loadMoreFindings={loadMoreFindings}
          selectFinding={selectFinding}
          t={t}
        />
      )}
    </section>
  )
}

function FindingList({
  items,
  hasMore,
  loadingMore,
  loadMoreFindings,
  selectFinding,
  t,
}: {
  readonly items: readonly FindingSummaryV1[]
  readonly hasMore: boolean
  readonly loadingMore: boolean
  readonly loadMoreFindings: () => void
  readonly selectFinding: (recordId: string) => void
  readonly t: WorkbenchOverlayProps['t']
}) {
  if (items.length === 0) return <p className="dsh-security-muted">{t('findings.empty')}</p>
  return (
    <>
      <ul className="dsh-security-finding-list">
        {items.map(item => (
          <li key={`${item.recordId}:${item.recordRevision}`}>
            <button
              type="button"
              aria-label={`${t('findings.openItem')} ${item.recordId}`}
              disabled={loadingMore}
              onClick={() => { selectFinding(item.recordId) }}
            >
              <span className="dsh-security-finding-list__identity">
                <code>{item.recordId}</code>
                <small>{item.weaknessClassification.primary}</small>
              </span>
              <span className="dsh-security-finding-list__dimensions">
                <MachineBadge value={item.recordKind} />
                <MachineBadge value={item.validationState} />
                <MachineBadge value={item.technicalSeverity ?? t('value.pending')} />
                <MachineBadge value={item.evidenceConfidence ?? t('value.pending')} />
                <MachineBadge value={item.policySignificance ?? t('value.pending')} />
                {item.hasProtectedDetail && <span>{t('findings.protected')}</span>}
              </span>
            </button>
          </li>
        ))}
      </ul>
      {hasMore && (
        <button
          type="button"
          className="dsh-security-selection__load-more"
          disabled={loadingMore}
          onClick={loadMoreFindings}
        >
          {loadingMore ? t('findings.loadingMore') : t('findings.loadMore')}
        </button>
      )}
    </>
  )
}

function FindingDetail({
  detail,
  backToFindingList,
  t,
}: {
  readonly detail: FindingDetailViewV1
  readonly backToFindingList: () => void
  readonly t: WorkbenchOverlayProps['t']
}) {
  return (
    <section className="dsh-security-section dsh-security-finding-detail" aria-labelledby="dsh-security-finding-detail-title">
      <div className="dsh-security-section__header">
        <h2 id="dsh-security-finding-detail-title">{t('findingDetail.title')}</h2>
        <button type="button" className="dsh-security-secondary-action" onClick={backToFindingList}>
          {t('findingDetail.back')}
        </button>
      </div>
      <code className="dsh-security-finding-detail__id">{detail.recordId}</code>
      <dl className="dsh-security-facts">
        <Fact label={t('findingDetail.recordKind')} value={detail.recordKind} machine />
        <Fact label={t('findingDetail.validation')} value={detail.validation.state} machine />
        <Fact label={t('findingDetail.severity')} value={detail.technicalSeverity?.value ?? t('value.pending')} machine={detail.technicalSeverity !== null} />
        <Fact label={t('findingDetail.confidence')} value={detail.evidenceConfidence?.value ?? t('value.pending')} machine={detail.evidenceConfidence !== null} />
        <Fact label={t('findingDetail.significance')} value={detail.policySignificance ?? t('value.pending')} machine={detail.policySignificance !== null} />
        <Fact label={t('findingDetail.weakness')} value={detail.weaknessClassification.primary} machine />
        <Fact label={t('findingDetail.affectedControl')} value={detail.affectedControlId ?? t('value.notAvailable')} machine={detail.affectedControlId !== null} />
        <Fact label={t('findingDetail.riskDecision')} value={detail.riskDecision.state} machine />
        <Fact label={t('findingDetail.attackPath')} value={detail.attackPath.state} machine />
      </dl>
      <div className="dsh-security-finding-detail__anchor">
        <strong>{t('findingDetail.sourceAnchor')}</strong>
        <code>{detail.sourceAnchor.path}</code>
        <code>{detail.sourceAnchor.locator.value}</code>
      </div>
      <div>
        <strong>{t('findingDetail.coverage')}</strong>
        {detail.coverageRelations.length === 0
          ? <p className="dsh-security-muted">{t('value.notAvailable')}</p>
          : (
              <ul className="dsh-security-metadata-list">
                {detail.coverageRelations.map(relation => (
                  <li key={relation.obligationId}>
                    <code>{relation.obligationId}</code>
                    <MachineBadge value={relation.state} />
                    <code>{relation.reason}</code>
                  </li>
                ))}
              </ul>
            )}
      </div>
      <div>
        <strong>{t('findingDetail.evidenceLinks')}</strong>
        {detail.evidenceLinks.length === 0
          ? <p className="dsh-security-muted">{t('value.notAvailable')}</p>
          : (
              <ul className="dsh-security-metadata-list">
                {detail.evidenceLinks.map(link => (
                  <li key={`${link.artifactId}:${link.digest.value}`}>
                    <code>{link.artifactId}</code>
                    <span>{link.purpose}</span>
                    <MachineBadge value={link.eligibilityDecision} />
                  </li>
                ))}
              </ul>
            )}
      </div>
    </section>
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
