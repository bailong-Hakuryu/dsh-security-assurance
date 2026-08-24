import { IconCloseOutline16, IconDataOutline16 } from '@deepseek-ai/dsh-client-ui-primitives'
import type {
  HostObservable,
  PropsHooks,
  PropsLocale,
  PropsRuntime,
} from '@deepseek-ai/dsh-client-ui-slots'
import { useEffect, useRef, useState } from 'react'
import type { FormEvent, KeyboardEvent, MouseEvent, RefObject } from 'react'
import type {
  SecurityAssuranceWorkbenchStateV1,
  WorkbenchEvidenceStateV1,
  WorkbenchFindingsStateV1,
  WorkbenchRiskDecisionSubmissionStateV1,
  WorkbenchRiskDecisionSubmissionV1,
} from '../index.ts'
import type {
  WorkbenchEvidenceDisclosureViewV1,
  WorkbenchEvidenceMetadataViewV1,
} from '../../workbench-remote.ts'
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
  readonly recordRiskDecision: (submission: WorkbenchRiskDecisionSubmissionV1) => void
  readonly backToFindingList: () => void
  readonly backToFindingDetail: () => void
  readonly discloseEvidence: () => void
  readonly hideEvidenceDisclosure: () => void
  readonly selectAssessment: (assessmentId: AssessmentId) => void
  readonly selectEvidence: (artifactId: string) => void
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
  recordRiskDecision,
  backToFindingList,
  backToFindingDetail,
  discloseEvidence,
  hideEvidenceDisclosure,
  selectAssessment,
  selectEvidence,
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
      const focusable = [...(dialogRef.current?.querySelectorAll<HTMLElement>(
        'button:not([disabled]),input:not([disabled]),textarea:not([disabled]),select:not([disabled])',
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
              recordRiskDecision={recordRiskDecision}
              loadMoreFindings={loadMoreFindings}
              selectFinding={selectFinding}
              backToFindingList={backToFindingList}
              selectEvidence={selectEvidence}
              backToFindingDetail={backToFindingDetail}
              discloseEvidence={discloseEvidence}
              hideEvidenceDisclosure={hideEvidenceDisclosure}
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
  recordRiskDecision,
  loadMoreFindings,
  selectFinding,
  backToFindingList,
  selectEvidence,
  backToFindingDetail,
  discloseEvidence,
  hideEvidenceDisclosure,
  t,
}: {
  readonly snapshot: AssessmentSnapshotV1
  readonly findings: WorkbenchFindingsStateV1
  readonly openFindings: () => void
  readonly recordRiskDecision: (submission: WorkbenchRiskDecisionSubmissionV1) => void
  readonly loadMoreFindings: () => void
  readonly selectFinding: (recordId: string) => void
  readonly backToFindingList: () => void
  readonly selectEvidence: (artifactId: string) => void
  readonly backToFindingDetail: () => void
  readonly discloseEvidence: () => void
  readonly hideEvidenceDisclosure: () => void
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
        availableActions={snapshot.availableActions}
        openFindings={openFindings}
        recordRiskDecision={recordRiskDecision}
        loadMoreFindings={loadMoreFindings}
        selectFinding={selectFinding}
        backToFindingList={backToFindingList}
        selectEvidence={selectEvidence}
        backToFindingDetail={backToFindingDetail}
        discloseEvidence={discloseEvidence}
        hideEvidenceDisclosure={hideEvidenceDisclosure}
        t={t}
      />
    </div>
  )
}

function FindingPanel({
  state,
  availableActions,
  openFindings,
  recordRiskDecision,
  loadMoreFindings,
  selectFinding,
  backToFindingList,
  selectEvidence,
  backToFindingDetail,
  discloseEvidence,
  hideEvidenceDisclosure,
  t,
}: {
  readonly state: WorkbenchFindingsStateV1
  readonly availableActions: AssessmentSnapshotV1['availableActions']
  readonly openFindings: () => void
  readonly recordRiskDecision: (submission: WorkbenchRiskDecisionSubmissionV1) => void
  readonly loadMoreFindings: () => void
  readonly selectFinding: (recordId: string) => void
  readonly backToFindingList: () => void
  readonly selectEvidence: (artifactId: string) => void
  readonly backToFindingDetail: () => void
  readonly discloseEvidence: () => void
  readonly hideEvidenceDisclosure: () => void
  readonly t: WorkbenchOverlayProps['t']
}) {
  const evidenceBackRef = useRef<HTMLButtonElement>(null)
  const disclosureActionRef = useRef<HTMLButtonElement>(null)
  const disclosureExitRef = useRef<HTMLButtonElement>(null)
  const evidenceTriggerArtifactId = useRef<string | null>(null)
  const evidenceTriggers = useRef(new Map<string, HTMLButtonElement>())
  const previousEvidenceKind = useRef<WorkbenchEvidenceStateV1['kind'] | null>(null)

  useEffect(() => {
    if (state.kind !== 'DETAIL_READY') {
      previousEvidenceKind.current = null
      evidenceTriggerArtifactId.current = null
      return
    }
    const currentKind = state.evidence.kind
    if (currentKind === 'NOT_LOADED') {
      if (
        previousEvidenceKind.current !== null
        && previousEvidenceKind.current !== 'NOT_LOADED'
      ) {
        const artifactId = evidenceTriggerArtifactId.current
        if (artifactId !== null) evidenceTriggers.current.get(artifactId)?.focus()
        evidenceTriggerArtifactId.current = null
      }
    } else if (
      currentKind === 'METADATA_READY'
      && (
        previousEvidenceKind.current === 'DISCLOSURE_LOADING'
        || previousEvidenceKind.current === 'DISCLOSURE_READY'
      )
    ) {
      disclosureActionRef.current?.focus()
    } else if (
      (currentKind === 'DISCLOSURE_LOADING' || currentKind === 'DISCLOSURE_READY')
      && previousEvidenceKind.current !== currentKind
    ) {
      disclosureExitRef.current?.focus()
    } else if (previousEvidenceKind.current !== currentKind) {
      evidenceBackRef.current?.focus()
    }
    previousEvidenceKind.current = currentKind
  }, [state])

  if (state.kind === 'DETAIL_READY') {
    if (state.evidence.kind === 'METADATA_LOADING') {
      return (
        <EvidenceLoading
          backButtonRef={evidenceBackRef}
          backToFindingDetail={backToFindingDetail}
          t={t}
        />
      )
    }
    if (state.evidence.kind === 'METADATA_READY') {
      return (
        <EvidenceMetadata
          view={state.evidence.view}
          disclosureStatus={state.evidence.disclosureStatus}
          backButtonRef={evidenceBackRef}
          disclosureActionRef={disclosureActionRef}
          backToFindingDetail={backToFindingDetail}
          discloseEvidence={discloseEvidence}
          t={t}
        />
      )
    }
    if (state.evidence.kind === 'DISCLOSURE_LOADING') {
      return (
        <EvidenceDisclosureLoading
          metadata={state.evidence.metadata}
          exitButtonRef={disclosureExitRef}
          hideEvidenceDisclosure={hideEvidenceDisclosure}
          t={t}
        />
      )
    }
    if (state.evidence.kind === 'DISCLOSURE_READY') {
      return (
        <EvidenceDisclosure
          view={state.evidence.view}
          exitButtonRef={disclosureExitRef}
          hideEvidenceDisclosure={hideEvidenceDisclosure}
          t={t}
        />
      )
    }
    return (
      <FindingDetail
        detail={state.detail}
        riskDecisionAction={availableActions.find((action): action is RiskDecisionActionV1 => (
          action.kind === 'RECORD_RISK_DECISION'
          && action.finding.recordId === state.detail.recordId
          && action.finding.recordRevision === state.detail.recordRevision
        ))}
        riskDecisionSubmission={state.riskDecisionSubmission}
        recordRiskDecision={recordRiskDecision}
        backToFindingList={backToFindingList}
        selectEvidence={artifactId => {
          evidenceTriggerArtifactId.current = artifactId
          selectEvidence(artifactId)
        }}
        setEvidenceTrigger={(artifactId, trigger) => {
          if (trigger === null) evidenceTriggers.current.delete(artifactId)
          else evidenceTriggers.current.set(artifactId, trigger)
        }}
        t={t}
      />
    )
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
  riskDecisionAction,
  riskDecisionSubmission,
  recordRiskDecision,
  backToFindingList,
  selectEvidence,
  setEvidenceTrigger,
  t,
}: {
  readonly detail: FindingDetailViewV1
  readonly riskDecisionAction: RiskDecisionActionV1 | undefined
  readonly riskDecisionSubmission: WorkbenchRiskDecisionSubmissionStateV1
  readonly recordRiskDecision: (submission: WorkbenchRiskDecisionSubmissionV1) => void
  readonly backToFindingList: () => void
  readonly selectEvidence: (artifactId: string) => void
  readonly setEvidenceTrigger: (artifactId: string, trigger: HTMLButtonElement | null) => void
  readonly t: WorkbenchOverlayProps['t']
}) {
  return (
    <section className="dsh-security-section dsh-security-finding-detail" aria-labelledby="dsh-security-finding-detail-title">
      <div className="dsh-security-section__header">
        <h2 id="dsh-security-finding-detail-title">{t('findingDetail.title')}</h2>
        <button
          type="button"
          className="dsh-security-secondary-action"
          disabled={riskDecisionSubmission.kind === 'SUBMITTING'}
          onClick={backToFindingList}
        >
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
      {detail.riskDecision.state !== 'NOT_RECORDED' && (
        <RecordedRiskDecision detail={detail} t={t} />
      )}
      {riskDecisionAction !== undefined && (
        <RiskDecisionForm
          key={actionKey(riskDecisionAction)}
          action={riskDecisionAction}
          detail={detail}
          submissionState={riskDecisionSubmission}
          recordRiskDecision={recordRiskDecision}
          t={t}
        />
      )}
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
                    <button
                      ref={trigger => { setEvidenceTrigger(link.artifactId, trigger) }}
                      type="button"
                      className="dsh-security-evidence-link"
                      aria-label={`${t('evidence.open')} ${link.artifactId}`}
                      disabled={riskDecisionSubmission.kind === 'SUBMITTING'}
                      onClick={() => { selectEvidence(link.artifactId) }}
                    >
                      <code>{link.artifactId}</code>
                      <span>{link.purpose}</span>
                      <MachineBadge value={link.eligibilityDecision} />
                    </button>
                  </li>
                ))}
              </ul>
            )}
      </div>
    </section>
  )
}

type RiskDecisionActionV1 = Extract<AssessmentAvailableActionV1, {
  readonly kind: 'RECORD_RISK_DECISION'
}>

function RiskDecisionForm({
  action,
  detail,
  submissionState,
  recordRiskDecision,
  t,
}: {
  readonly action: RiskDecisionActionV1
  readonly detail: FindingDetailViewV1
  readonly submissionState: WorkbenchRiskDecisionSubmissionStateV1
  readonly recordRiskDecision: (submission: WorkbenchRiskDecisionSubmissionV1) => void
  readonly t: WorkbenchOverlayProps['t']
}) {
  const exactOption = action.options.find(option => (
    option.decision === 'ACCEPT' && option.exactMatchRequired
  ))
  const onlyOption = action.options.length === 1 ? action.options[0] : undefined
  const [decision, setDecision] = useState<'' | WorkbenchRiskDecisionSubmissionV1['decision']>(
    exactOption?.decision ?? onlyOption?.decision ?? '',
  )
  const [rationale, setRationale] = useState('')
  const [controls, setControls] = useState('')
  const [expiresAt, setExpiresAt] = useState('')
  const option = action.options.find(candidate => candidate.decision === decision)
  const exactMatch = option?.decision === 'ACCEPT' && option.exactMatchRequired
  const pending = exactMatch && detail.riskDecision.state === 'PENDING_DUAL_AUTHORITY'
    ? detail.riskDecision
    : undefined
  const submitting = submissionState.kind === 'SUBMITTING'

  const submit = (event: FormEvent<HTMLFormElement>): void => {
    event.preventDefault()
    if (option === undefined) return
    let submission: WorkbenchRiskDecisionSubmissionV1
    if (option.decision === 'DENY') {
      submission = {
        decision: 'DENY',
        rationale,
        compensatingControls: [],
        expiresAt: null,
      }
    } else if (pending !== undefined) {
      submission = {
        decision: 'ACCEPT',
        rationale: pending.rationale,
        compensatingControls: pending.compensatingControls,
        expiresAt: pending.expiresAt,
      }
    } else {
      const parsedExpiry = Date.parse(expiresAt)
      if (!Number.isFinite(parsedExpiry)) return
      submission = {
        decision: 'ACCEPT',
        rationale,
        compensatingControls: controls
          .split(/\r?\n/u)
          .map(control => control.trim())
          .filter(control => control.length > 0),
        expiresAt: new Date(parsedExpiry).toISOString(),
      }
    }
    recordRiskDecision(submission)
    setRationale('')
    setControls('')
    setExpiresAt('')
  }

  return (
    <section className="dsh-security-risk-decision" aria-labelledby="dsh-security-risk-decision-title">
      <div className="dsh-security-section__header">
        <h2 id="dsh-security-risk-decision-title">{t('riskDecision.title')}</h2>
        <MachineBadge value={`revision:${action.expectedAssessmentRevision}`} />
      </div>
      <p className="dsh-security-readonly-note">{t('riskDecision.immutable')}</p>
      <dl className="dsh-security-facts">
        <Fact label={t('riskDecision.finding')} value={`${action.finding.recordId} @ ${action.finding.recordRevision}`} machine />
        <Fact label={t('riskDecision.authority')} value={t('riskDecision.authorityDerived')} />
      </dl>
      <form className="dsh-security-risk-decision__form" onSubmit={submit}>
        <fieldset disabled={submitting || exactMatch}>
          <legend>{t('riskDecision.decision')}</legend>
          <div className="dsh-security-risk-decision__options">
            {action.options.map(candidate => (
              <label key={`${candidate.decision}:${candidate.consequence}`}>
                <input
                  type="radio"
                  name={`risk-decision-${action.finding.recordId}`}
                  value={candidate.decision}
                  checked={decision === candidate.decision}
                  required
                  onChange={() => { setDecision(candidate.decision) }}
                />
                <span>{candidate.decision === 'DENY' ? t('riskDecision.deny') : t('riskDecision.accept')}</span>
                <code>{candidate.consequence}</code>
              </label>
            ))}
          </div>
        </fieldset>

        {option?.decision === 'ACCEPT' && (
          <dl className="dsh-security-facts">
            <Fact label={t('riskDecision.authorizationMode')} value={option.authorizationMode} machine />
            <Fact label={t('riskDecision.minimumControls')} value={String(option.minimumCompensatingControls)} />
            <Fact label={t('riskDecision.maximumLifetime')} value={String(option.maximumLifetimeSeconds)} machine />
            <Fact label={t('riskDecision.attestations')} value={`${option.completedAttestations} / ${option.requiredAttestations}`} />
            <Fact label={t('riskDecision.exactMatch')} value={String(option.exactMatchRequired)} machine />
          </dl>
        )}

        <label className="dsh-security-risk-decision__field">
          <span>{t('riskDecision.rationale')}</span>
          <textarea
            value={pending?.rationale ?? rationale}
            readOnly={pending !== undefined}
            required
            minLength={20}
            maxLength={2_000}
            rows={4}
            onChange={event => { setRationale(event.currentTarget.value) }}
          />
        </label>

        {option?.decision === 'ACCEPT' && (
          <>
            <label className="dsh-security-risk-decision__field">
              <span>{t('riskDecision.controls')}</span>
              <textarea
                value={pending?.compensatingControls.join('\n') ?? controls}
                readOnly={pending !== undefined}
                required
                rows={3}
                onChange={event => { setControls(event.currentTarget.value) }}
              />
              <small>{t('riskDecision.controlsHint')}</small>
            </label>
            <label className="dsh-security-risk-decision__field">
              <span>{t('riskDecision.expiry')}</span>
              {pending === undefined
                ? (
                    <input
                      type="datetime-local"
                      value={expiresAt}
                      required
                      onChange={event => { setExpiresAt(event.currentTarget.value) }}
                    />
                  )
                : <code>{pending.expiresAt}</code>}
            </label>
          </>
        )}

        <p className="dsh-security-risk-decision__consequence">
          <strong>{t('riskDecision.consequence')}</strong>
          <code>{option?.consequence ?? t('riskDecision.choose')}</code>
        </p>
        {exactMatch && <p className="dsh-security-risk-decision__warning">{t('riskDecision.secondAuthority')}</p>}
        <button
          type="submit"
          className="dsh-security-risk-decision__submit"
          disabled={submitting || option === undefined}
        >
          {submitting
            ? t('riskDecision.submitting')
            : exactMatch
              ? t('riskDecision.attest')
              : t('riskDecision.submit')}
        </button>
      </form>
    </section>
  )
}

function RecordedRiskDecision({
  detail,
  t,
}: {
  readonly detail: FindingDetailViewV1
  readonly t: WorkbenchOverlayProps['t']
}) {
  const decision = detail.riskDecision
  if (decision.state === 'NOT_RECORDED') return null
  return (
    <section className="dsh-security-risk-decision" aria-labelledby="dsh-security-recorded-risk-decision-title">
      <div className="dsh-security-section__header">
        <h2 id="dsh-security-recorded-risk-decision-title">{t('riskDecision.recordedTitle')}</h2>
        <MachineBadge value={decision.state} />
      </div>
      <dl className="dsh-security-facts">
        <Fact label={t('riskDecision.authorizationMode')} value={decision.authorizationMode ?? 'SINGLE_AUTHORITY'} machine />
        <Fact label={t('riskDecision.recordedAt')} value={decision.recordedAt} machine />
        <Fact label={t('riskDecision.expiry')} value={decision.expiresAt ?? t('value.notAvailable')} machine={decision.expiresAt !== null} />
        <Fact label={t('riskDecision.rationale')} value={decision.rationale} />
      </dl>
      {decision.compensatingControls.length > 0 && (
        <ul className="dsh-security-metadata-list">
          {decision.compensatingControls.map(control => <li key={control}>{control}</li>)}
        </ul>
      )}
      {(decision.attestations ?? []).map(attestation => (
        <div className="dsh-security-risk-decision__attestation" key={attestation.sequence}>
          <strong>{t('riskDecision.attestation')} {attestation.sequence}</strong>
          <code>{attestation.decisionMaker.principalId}</code>
          <code>{attestation.attestedAt}</code>
        </div>
      ))}
    </section>
  )
}

function EvidenceLoading({
  backButtonRef,
  backToFindingDetail,
  t,
}: {
  readonly backButtonRef: RefObject<HTMLButtonElement>
  readonly backToFindingDetail: () => void
  readonly t: WorkbenchOverlayProps['t']
}) {
  return (
    <section className="dsh-security-section dsh-security-finding-detail" aria-labelledby="dsh-security-evidence-title">
      <div className="dsh-security-section__header">
        <h2 id="dsh-security-evidence-title">{t('evidence.title')}</h2>
        <button
          ref={backButtonRef}
          type="button"
          className="dsh-security-secondary-action"
          onClick={backToFindingDetail}
        >
          {t('evidence.back')}
        </button>
      </div>
      <p className="dsh-security-muted" role="status" aria-live="polite">
        {t('evidence.loading')}
      </p>
    </section>
  )
}

function EvidenceMetadata({
  view,
  disclosureStatus,
  backButtonRef,
  disclosureActionRef,
  backToFindingDetail,
  discloseEvidence,
  t,
}: {
  readonly view: WorkbenchEvidenceMetadataViewV1
  readonly disclosureStatus: 'NOT_REQUESTED' | 'EXPIRED'
  readonly backButtonRef: RefObject<HTMLButtonElement>
  readonly disclosureActionRef: RefObject<HTMLButtonElement>
  readonly backToFindingDetail: () => void
  readonly discloseEvidence: () => void
  readonly t: WorkbenchOverlayProps['t']
}) {
  return (
    <section className="dsh-security-section dsh-security-finding-detail" aria-labelledby="dsh-security-evidence-title">
      <div className="dsh-security-section__header">
        <h2 id="dsh-security-evidence-title">{t('evidence.title')}</h2>
        <button
          ref={backButtonRef}
          type="button"
          className="dsh-security-secondary-action"
          onClick={backToFindingDetail}
        >
          {t('evidence.back')}
        </button>
      </div>
      <code className="dsh-security-finding-detail__id">{view.evidence.artifactId}</code>
      <dl className="dsh-security-facts">
        <Fact label={t('evidence.artifact')} value={view.evidence.artifactId} machine />
        <Fact label={t('evidence.schema')} value={view.evidence.schemaId} machine />
        <Fact label={t('evidence.digest')} value={view.evidence.digest.value} machine />
        <Fact
          label={t('evidence.digestSchemaVersion')}
          value={String(view.evidence.digest.schemaVersion)}
          machine
        />
        <Fact label={t('evidence.digestAlgorithm')} value={view.evidence.digest.algorithm} machine />
        <Fact label={t('evidence.digestMediaType')} value={view.evidence.digest.mediaType} machine />
        <Fact
          label={t('evidence.digestByteLength')}
          value={String(view.evidence.digest.byteLength)}
          machine
        />
        <Fact label={t('evidence.digestCanonicalization')} value={view.evidence.digest.canonicalization} machine />
        <Fact label={t('evidence.classification')} value={view.evidence.classification} machine />
        <Fact label={t('evidence.linkPurpose')} value={view.link.purpose} machine />
        <Fact label={t('evidence.eligibility')} value={view.link.eligibilityDecision} machine />
        <Fact label={t('evidence.eligibilityArtifact')} value={view.link.eligibilityDecisionArtifactId} machine />
        <Fact label={t('evidence.protectionPolicy')} value={view.protection.policyId} machine />
        <Fact label={t('evidence.protectionStatus')} value={view.protection.status} machine />
        <Fact label={t('evidence.retention')} value={view.retention.status} machine />
        <Fact label={t('evidence.egressPolicy')} value={view.egress.policyId} machine />
        <Fact label={t('evidence.egressStatus')} value={view.egress.status} machine />
        <Fact label={t('evidence.requestPurpose')} value={view.purpose} machine />
        <Fact label={t('evidence.profile')} value={view.viewProfileId} machine />
        <Fact label={t('evidence.content')} value={view.content.kind} machine />
        <Fact label={t('evidence.redactionReason')} value={view.content.reason} machine />
      </dl>
      {disclosureStatus === 'EXPIRED' && (
        <p className="dsh-security-evidence-expired" role="status" aria-live="polite">
          {t('evidence.expired')}
        </p>
      )}
      <button
        ref={disclosureActionRef}
        type="button"
        className="dsh-security-evidence-disclosure-action"
        onClick={discloseEvidence}
      >
        {t('evidence.disclosureAction')}
      </button>
    </section>
  )
}

function EvidenceDisclosureLoading({
  metadata,
  exitButtonRef,
  hideEvidenceDisclosure,
  t,
}: {
  readonly metadata: WorkbenchEvidenceMetadataViewV1
  readonly exitButtonRef: RefObject<HTMLButtonElement>
  readonly hideEvidenceDisclosure: () => void
  readonly t: WorkbenchOverlayProps['t']
}) {
  return (
    <section
      className="dsh-security-section dsh-security-evidence-disclosure"
      aria-labelledby="dsh-security-evidence-sensitive-title"
    >
      <div className="dsh-security-section__header">
        <h2 id="dsh-security-evidence-sensitive-title">{t('evidence.sensitiveTitle')}</h2>
        <button
          ref={exitButtonRef}
          type="button"
          className="dsh-security-secondary-action"
          onClick={hideEvidenceDisclosure}
        >
          {t('evidence.hideDisclosure')}
        </button>
      </div>
      <SensitivityWarning t={t} />
      <code className="dsh-security-finding-detail__id">{metadata.evidence.artifactId}</code>
      <p className="dsh-security-muted" role="status" aria-live="polite">
        {t('evidence.disclosureLoading')}
      </p>
    </section>
  )
}

function EvidenceDisclosure({
  view,
  exitButtonRef,
  hideEvidenceDisclosure,
  t,
}: {
  readonly view: WorkbenchEvidenceDisclosureViewV1
  readonly exitButtonRef: RefObject<HTMLButtonElement>
  readonly hideEvidenceDisclosure: () => void
  readonly t: WorkbenchOverlayProps['t']
}) {
  return (
    <section
      className="dsh-security-section dsh-security-evidence-disclosure"
      aria-labelledby="dsh-security-evidence-sensitive-title"
    >
      <div className="dsh-security-section__header">
        <h2 id="dsh-security-evidence-sensitive-title">{t('evidence.sensitiveTitle')}</h2>
        <button
          ref={exitButtonRef}
          type="button"
          className="dsh-security-secondary-action"
          onClick={hideEvidenceDisclosure}
        >
          {t('evidence.hideDisclosure')}
        </button>
      </div>
      <SensitivityWarning t={t} />
      <code className="dsh-security-finding-detail__id">{view.evidence.artifactId}</code>
      <dl className="dsh-security-facts">
        <Fact label={t('evidence.artifact')} value={view.evidence.artifactId} machine />
        <Fact label={t('evidence.classification')} value={view.evidence.classification} machine />
        <Fact label={t('evidence.requestPurpose')} value={view.purpose} machine />
        <Fact label={t('evidence.profile')} value={view.viewProfileId} machine />
        <Fact label={t('evidence.content')} value={view.content.kind} machine />
        {view.content.kind === 'BOUNDED_JSON' && (
          <>
            <Fact label={t('evidence.byteLength')} value={String(view.content.byteLength)} machine />
            <Fact label={t('evidence.expiresAt')} value={view.content.expiresAt} machine />
          </>
        )}
        {view.content.kind === 'REDACTED' && (
          <Fact label={t('evidence.redactionReason')} value={view.content.reason} machine />
        )}
      </dl>
      {view.content.kind === 'BOUNDED_JSON'
        ? (
            <pre className="dsh-security-evidence-disclosure__json">
              <code>{JSON.stringify(view.content.value, null, 2)}</code>
            </pre>
          )
        : (
            <p className="dsh-security-evidence-expired" role="status">
              {t('evidence.disclosureRedacted')}
            </p>
          )}
    </section>
  )
}

function SensitivityWarning({ t }: { readonly t: WorkbenchOverlayProps['t'] }) {
  return (
    <p className="dsh-security-evidence-sensitivity">
      <strong>{t('evidence.sensitiveTitle')}</strong>
      <span>{t('evidence.sensitiveWarning')}</span>
    </p>
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
