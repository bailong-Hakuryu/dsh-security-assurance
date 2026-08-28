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
  WorkbenchAssessmentCommandReasonV1,
  WorkbenchAssessmentCommandStateV1,
  WorkbenchEvidenceStateV1,
  WorkbenchExportStateV1,
  WorkbenchFindingsStateV1,
  WorkbenchRiskDecisionSubmissionStateV1,
  WorkbenchRiskDecisionSubmissionV1,
  WorkbenchStartSubmissionStateV1,
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
  BundleManifestV1,
  FindingDetailViewV1,
  FindingSummaryV1,
  RepositorySnapshotV1,
  RuntimeHealthSnapshot,
  SecurityCatalogSnapshotV1,
  StartAssessmentSelectionV1,
  StartPreflightV1,
} from '../../contracts.ts'
import type { WORKBENCH_LOCALE_NAMESPACE } from './locales.ts'
import { projectWorkbenchRouteStateV1 } from './navigation.ts'
import type { WorkbenchPresentationSnapshotV1 } from './presentation.ts'

export type WorkbenchOverlaySources = {
  readonly presentation: HostObservable<WorkbenchPresentationSnapshotV1>
  readonly assessment: HostObservable<SecurityAssuranceWorkbenchStateV1>
}

export interface WorkbenchOverlayInjected {
  readonly hooks: WorkbenchOverlaySources
  readonly closeWorkbench: () => void
  readonly backToAssessmentDetail: () => void
  readonly backToAssessmentSelection: () => void
  readonly cancelStartPreflight: () => void
  readonly cancelAssessment: (reason: WorkbenchAssessmentCommandReasonV1) => void
  readonly confirmStartAssessment: () => void
  readonly downloadExport: () => void
  readonly loadMoreAssessments: () => void
  readonly loadMoreFindings: () => void
  readonly openFindings: () => void
  readonly openBundle: () => void
  readonly openRepositories: () => void
  readonly openRuntimeHealth: () => void
  readonly previewExport: (deliveryDestinationId: string) => void
  readonly refreshExportStatus: () => void
  readonly requestExport: () => void
  readonly recordRiskDecision: (submission: WorkbenchRiskDecisionSubmissionV1) => void
  readonly refreshRuntimeHealth: () => void
  readonly resumeAssessment: (reason: WorkbenchAssessmentCommandReasonV1) => void
  readonly backToFindingList: () => void
  readonly backToFindingDetail: () => void
  readonly discloseEvidence: () => void
  readonly hideEvidenceDisclosure: () => void
  readonly selectAssessment: (assessmentId: AssessmentId) => void
  readonly selectRepository: (repositoryId: RepositorySnapshotV1['repositoryId']) => void
  readonly requestStartPreflight: (selection: StartAssessmentSelectionV1) => void
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
  backToAssessmentDetail,
  backToAssessmentSelection,
  cancelStartPreflight,
  cancelAssessment,
  confirmStartAssessment,
  downloadExport,
  loadMoreAssessments,
  loadMoreFindings,
  openFindings,
  openBundle,
  openRepositories,
  openRuntimeHealth,
  previewExport,
  refreshExportStatus,
  requestExport,
  recordRiskDecision,
  refreshRuntimeHealth,
  resumeAssessment,
  backToFindingList,
  backToFindingDetail,
  discloseEvidence,
  hideEvidenceDisclosure,
  selectAssessment,
  selectRepository,
  requestStartPreflight,
  selectEvidence,
  selectFinding,
}: WorkbenchOverlayProps) {
  const open = usePresentation(snapshot => snapshot.open)
  const state = useAssessment(snapshot => snapshot)
  const route = projectWorkbenchRouteStateV1(state)
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
        <div
          className="dsh-security-dialog__body"
          data-workbench-route-version={route.schemaVersion}
          data-workbench-view={route.viewId}
        >
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
              openRepositories={openRepositories}
              openRuntimeHealth={openRuntimeHealth}
              selectAssessment={selectAssessment}
              t={t}
            />
          )}
          {state.kind === 'HEALTH_LOADING' && (
            <MessageState title={t('health.loadingTitle')} body={t('health.loadingBody')} role="status" />
          )}
          {state.kind === 'HEALTH_READY' && (
            <RuntimeHealthView
              health={state.health}
              backToAssessmentSelection={backToAssessmentSelection}
              refreshRuntimeHealth={refreshRuntimeHealth}
              t={t}
            />
          )}
          {state.kind === 'BUNDLE_LOADING' && (
            <MessageState
              title={t('exports.loadingTitle')}
              body={t('exports.loadingBody')}
              detail={state.assessmentId}
              role="status"
            />
          )}
          {state.kind === 'BUNDLE_READY' && (
            <BundleExportView
              manifest={state.manifest}
              deliveryDestinationIds={state.deliveryDestinationIds}
              exportState={state.export}
              backToAssessmentDetail={backToAssessmentDetail}
              downloadExport={downloadExport}
              previewExport={previewExport}
              refreshExportStatus={refreshExportStatus}
              requestExport={requestExport}
              t={t}
            />
          )}
          {state.kind === 'REPOSITORIES_LOADING' && (
            <MessageState title={t('repositories.loadingTitle')} body={t('repositories.loadingBody')} role="status" />
          )}
          {state.kind === 'REPOSITORIES_READY' && (
            <RepositorySelection
              repositories={state.repositories}
              truncated={state.truncated}
              backToAssessmentSelection={backToAssessmentSelection}
              selectRepository={selectRepository}
              t={t}
            />
          )}
          {(state.kind === 'CATALOG_LOADING' || state.kind === 'PREFLIGHT_LOADING') && (
            <MessageState
              title={state.kind === 'CATALOG_LOADING'
                ? t('wizard.catalogLoadingTitle')
                : t('wizard.preflightLoadingTitle')}
              body={state.kind === 'CATALOG_LOADING'
                ? t('wizard.catalogLoadingBody')
                : t('wizard.preflightLoadingBody')}
              detail={state.repository.displayName}
              role="status"
            />
          )}
          {state.kind === 'WIZARD_READY' && (
            <NewAssessmentWizard
              repository={state.repository}
              catalog={state.catalog}
              startPreflight={state.startPreflight}
              startSubmission={state.startSubmission}
              backToAssessmentSelection={backToAssessmentSelection}
              cancelStartPreflight={cancelStartPreflight}
              confirmStartAssessment={confirmStartAssessment}
              requestStartPreflight={requestStartPreflight}
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
              assessmentCommand={state.assessmentCommand}
              openBundle={openBundle}
              cancelAssessment={cancelAssessment}
              openFindings={openFindings}
              recordRiskDecision={recordRiskDecision}
              resumeAssessment={resumeAssessment}
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
  openRepositories,
  openRuntimeHealth,
  selectAssessment,
  t,
}: {
  readonly assessments: readonly AssessmentListItemV1[]
  readonly hasMore: boolean
  readonly loadingMore: boolean
  readonly loadMoreAssessments: () => void
  readonly openRepositories: () => void
  readonly openRuntimeHealth: () => void
  readonly selectAssessment: (assessmentId: AssessmentId) => void
  readonly t: WorkbenchOverlayProps['t']
}) {
  return (
    <section className="dsh-security-selection" aria-labelledby="dsh-security-selection-title">
      <div>
        <div className="dsh-security-view-heading">
          <h2 id="dsh-security-selection-title">{t('selection.title')}</h2>
          <div className="dsh-security-view-heading__actions">
            <button type="button" className="dsh-security-secondary-action" onClick={openRuntimeHealth}>
              {t('health.open')}
            </button>
            <button type="button" className="dsh-security-secondary-action" onClick={openRepositories}>
              {t('repositories.open')}
            </button>
          </div>
        </div>
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

function RuntimeHealthView({
  health,
  backToAssessmentSelection,
  refreshRuntimeHealth,
  t,
}: {
  readonly health: RuntimeHealthSnapshot
  readonly backToAssessmentSelection: () => void
  readonly refreshRuntimeHealth: () => void
  readonly t: WorkbenchOverlayProps['t']
}) {
  const admissions = [
    [t('health.queries'), health.admission.queries],
    [t('health.mutations'), health.admission.mutations],
    [t('health.sealedExports'), health.admission.sealedExports],
  ] as const
  return (
    <section className="dsh-security-health" aria-labelledby="dsh-security-health-title">
      <div className="dsh-security-view-heading">
        <div>
          <span className="dsh-security-eyebrow">{t('health.eyebrow')}</span>
          <h2 id="dsh-security-health-title">{t('health.title')}</h2>
        </div>
        <MachineBadge value={health.state} />
      </div>
      <p className="dsh-security-readonly-note">{t('health.immutable')}</p>
      <div className="dsh-security-view-heading__actions dsh-security-health__actions">
        <button type="button" className="dsh-security-secondary-action" onClick={backToAssessmentSelection}>
          {t('health.back')}
        </button>
        <button type="button" className="dsh-security-secondary-action" onClick={refreshRuntimeHealth}>
          {t('health.refresh')}
        </button>
      </div>
      <dl className="dsh-security-facts">
        <Fact label={t('health.product')} value={health.product.name} machine />
        <Fact label={t('health.version')} value={health.product.version} machine />
        <Fact label={t('label.state')} value={health.state} machine />
        <Fact label={t('health.targetHarness')} value={health.compatibility.targetHarnessVersion} machine />
        <Fact label={t('health.requiredNode')} value={health.compatibility.requiredNodeRange} machine />
        <Fact label={t('health.actualNode')} value={health.compatibility.actualNodeVersion} machine />
        <Fact label={t('health.harnessVerification')} value={health.compatibility.harnessVerification} machine />
      </dl>
      <section className="dsh-security-section" aria-labelledby="dsh-security-health-admission-title">
        <div className="dsh-security-section__header">
          <h2 id="dsh-security-health-admission-title">{t('health.admission')}</h2>
        </div>
        <ul className="dsh-security-health__admission">
          {admissions.map(([label, admitted]) => (
            <li key={label}>
              <span>{label}</span>
              <MachineBadge value={String(admitted)} />
            </li>
          ))}
        </ul>
      </section>
      <section className="dsh-security-section" aria-labelledby="dsh-security-health-checks-title">
        <div className="dsh-security-section__header">
          <h2 id="dsh-security-health-checks-title">{t('health.checks')}</h2>
        </div>
        <ul className="dsh-security-health__checks">
          {health.checks.map(check => (
            <li key={check.id}>
              <div className="dsh-security-health__check-heading">
                <code>{check.id}</code>
                <div className="dsh-security-badges">
                  <span className="dsh-security-health__requirement">
                    {check.required ? t('health.required') : t('health.optional')}
                  </span>
                  <MachineBadge value={check.status} />
                </div>
              </div>
              <p>{check.message}</p>
            </li>
          ))}
        </ul>
      </section>
    </section>
  )
}

function RepositorySelection({
  repositories,
  truncated,
  backToAssessmentSelection,
  selectRepository,
  t,
}: {
  readonly repositories: readonly RepositorySnapshotV1[]
  readonly truncated: boolean
  readonly backToAssessmentSelection: () => void
  readonly selectRepository: (repositoryId: RepositorySnapshotV1['repositoryId']) => void
  readonly t: WorkbenchOverlayProps['t']
}) {
  return (
    <section className="dsh-security-selection" aria-labelledby="dsh-security-repositories-title">
      <div>
        <button type="button" className="dsh-security-secondary-action" onClick={backToAssessmentSelection}>
          {t('repositories.back')}
        </button>
        <div className="dsh-security-view-heading">
          <div>
            <h2 id="dsh-security-repositories-title">{t('repositories.title')}</h2>
            <p>{t('repositories.body')}</p>
          </div>
        </div>
      </div>
      {repositories.length === 0
        ? <p className="dsh-security-muted">{t('repositories.empty')}</p>
        : (
            <ul className="dsh-security-repository-list">
              {repositories.map(repository => (
                <li key={repository.repositoryId}>
                  <div className="dsh-security-repository-list__heading">
                    <div>
                      <strong>{repository.displayName}</strong>
                      <code>{repository.repositoryId} @ {repository.repositoryRevision}</code>
                    </div>
                    <MachineBadge value={repository.state} />
                  </div>
                  <dl className="dsh-security-facts">
                    <Fact label={t('label.policy')} value={repository.bindings.policyId} machine />
                    <Fact label={t('wizard.profile')} value={repository.bindings.assessmentProfileId} machine />
                    <Fact label={t('wizard.evidenceProtection')} value={repository.bindings.evidenceProtectionId} machine />
                    <Fact label={t('wizard.egress')} value={repository.bindings.dataEgressPolicyId} machine />
                  </dl>
                  <button
                    type="button"
                    className="dsh-security-risk-decision__submit"
                    disabled={repository.state !== 'ENABLED'}
                    onClick={() => { selectRepository(repository.repositoryId) }}
                  >
                    {repository.state === 'ENABLED' ? t('repositories.newAssessment') : t('repositories.disabled')}
                  </button>
                </li>
              ))}
            </ul>
          )}
      {truncated && <p className="dsh-security-muted">{t('repositories.truncated')}</p>}
    </section>
  )
}

function NewAssessmentWizard({
  repository,
  catalog,
  startPreflight,
  startSubmission,
  backToAssessmentSelection,
  cancelStartPreflight,
  confirmStartAssessment,
  requestStartPreflight,
  t,
}: {
  readonly repository: RepositorySnapshotV1
  readonly catalog: SecurityCatalogSnapshotV1
  readonly startPreflight: StartPreflightV1 | null
  readonly startSubmission: WorkbenchStartSubmissionStateV1
  readonly backToAssessmentSelection: () => void
  readonly cancelStartPreflight: () => void
  readonly confirmStartAssessment: () => void
  readonly requestStartPreflight: (selection: StartAssessmentSelectionV1) => void
  readonly t: WorkbenchOverlayProps['t']
}) {
  const supportedModes = catalog.assessmentModes.filter(mode => mode.support === 'SUPPORTED')
  const [mode, setMode] = useState(supportedModes[0]?.assessmentMode ?? 'REPOSITORY')
  const activeMode = catalog.assessmentModes.find(candidate => candidate.assessmentMode === mode)
  const [subjectKind, setSubjectKind] = useState<'git_revision' | 'change' | 'workspace_snapshot'>(
    activeMode?.subjectKinds[0] ?? 'workspace_snapshot',
  )
  const [commit, setCommit] = useState('')
  const [baseCommit, setBaseCommit] = useState('')
  const [headCommit, setHeadCommit] = useState('')
  const [relativePaths, setRelativePaths] = useState('')
  const [controls, setControls] = useState<readonly string[]>([])
  const profile = catalog.assessmentProfiles[0]

  if (startPreflight !== null) {
    return (
      <StartPreflightPanel
        preflight={startPreflight}
        submitting={startSubmission.kind === 'SUBMITTING'}
        cancelStartPreflight={cancelStartPreflight}
        confirmStartAssessment={confirmStartAssessment}
        backToAssessmentSelection={backToAssessmentSelection}
        t={t}
      />
    )
  }

  const subject = subjectKind === 'git_revision'
    ? { kind: 'git_revision' as const, commit: commit.trim() }
    : subjectKind === 'change'
      ? { kind: 'change' as const, baseCommit: baseCommit.trim(), headCommit: headCommit.trim() }
      : { kind: 'workspace_snapshot' as const }
  const paths = relativePaths.split(/\r?\n/u).map(path => path.trim()).filter(Boolean)
  const target = mode === 'CHANGE'
    ? { kind: 'change' as const, baseCommit: baseCommit.trim(), headCommit: headCommit.trim(), impactCone: 'POLICY_DEFAULT' as const }
    : mode === 'TARGETED'
      ? { kind: 'targeted' as const, relativePaths: paths }
      : { kind: 'repository' as const }
  const commitsValid = subjectKind === 'git_revision'
    ? /^[0-9a-f]{40}$/u.test(commit.trim())
    : subjectKind === 'change'
      ? /^[0-9a-f]{40}$/u.test(baseCommit.trim()) && /^[0-9a-f]{40}$/u.test(headCommit.trim())
      : true
  const pathsValid = mode !== 'TARGETED' || (
    paths.length >= 1
    && paths.length <= 128
    && paths.every(path => (
      !path.startsWith('/')
      && !path.startsWith('\\')
      && !/^[a-z]:/iu.test(path)
      && !path.includes('\\')
      && path.split('/').every(segment => segment.length > 0 && segment !== '.' && segment !== '..')
    ))
  )
  const formValid = activeMode?.support === 'SUPPORTED'
    && activeMode.subjectKinds.includes(subjectKind)
    && profile !== undefined
    && commitsValid
    && pathsValid

  const submit = (event: FormEvent<HTMLFormElement>): void => {
    event.preventDefault()
    if (!formValid || profile === undefined) return
    requestStartPreflight({
      schemaVersion: 1,
      repositoryId: repository.repositoryId,
      subject,
      assessmentMode: mode,
      assessmentProfileId: profile.assessmentProfileId,
      target,
      requestedStrongerControlIds: controls,
    })
  }
  return (
    <section className="dsh-security-wizard" aria-labelledby="dsh-security-wizard-title">
      <button type="button" className="dsh-security-secondary-action" onClick={backToAssessmentSelection}>
        {t('wizard.cancel')}
      </button>
      <div>
        <span className="dsh-security-eyebrow">{t('wizard.repository')}</span>
        <h2 id="dsh-security-wizard-title">{t('wizard.title')}</h2>
        <strong>{repository.displayName}</strong>
        <code className="dsh-security-wizard__repository">{repository.repositoryId} @ {repository.repositoryRevision}</code>
      </div>
      <p className="dsh-security-readonly-note">{t('wizard.boundary')}</p>
      <form className="dsh-security-wizard__form" onSubmit={submit}>
        <label className="dsh-security-risk-decision__field">
          <span>{t('wizard.mode')}</span>
          <select
            aria-label={t('wizard.mode')}
            value={mode}
            onChange={event => {
              const next = event.currentTarget.value as typeof mode
              const definition = catalog.assessmentModes.find(candidate => candidate.assessmentMode === next)
              setMode(next)
              setSubjectKind(definition?.subjectKinds[0] ?? 'workspace_snapshot')
            }}
          >
            {supportedModes.map(candidate => (
              <option key={candidate.assessmentMode} value={candidate.assessmentMode}>
                {catalogLabel(candidate.label, t)} ({candidate.assessmentMode})
              </option>
            ))}
          </select>
        </label>
        <label className="dsh-security-risk-decision__field">
          <span>{t('wizard.profile')}</span>
          <select aria-label={t('wizard.profile')} value={profile?.assessmentProfileId ?? ''} disabled>
            {catalog.assessmentProfiles.map(candidate => (
              <option key={candidate.assessmentProfileId} value={candidate.assessmentProfileId}>
                {catalogLabel(candidate.label, t)} ({candidate.assessmentProfileId})
              </option>
            ))}
          </select>
        </label>
        <label className="dsh-security-risk-decision__field">
          <span>{t('wizard.subject')}</span>
          <select
            aria-label={t('wizard.subject')}
            value={subjectKind}
            onChange={event => { setSubjectKind(event.currentTarget.value as typeof subjectKind) }}
          >
            {activeMode?.subjectKinds.map(kind => <option key={kind} value={kind}>{kind}</option>)}
          </select>
        </label>
        {subjectKind === 'git_revision' && (
          <label className="dsh-security-risk-decision__field">
            <span>{t('wizard.commit')}</span>
            <input aria-label={t('wizard.commit')} value={commit} maxLength={40} onChange={event => { setCommit(event.currentTarget.value) }} />
          </label>
        )}
        {subjectKind === 'change' && (
          <>
            <label className="dsh-security-risk-decision__field">
              <span>{t('wizard.baseCommit')}</span>
              <input aria-label={t('wizard.baseCommit')} value={baseCommit} maxLength={40} onChange={event => { setBaseCommit(event.currentTarget.value) }} />
            </label>
            <label className="dsh-security-risk-decision__field">
              <span>{t('wizard.headCommit')}</span>
              <input aria-label={t('wizard.headCommit')} value={headCommit} maxLength={40} onChange={event => { setHeadCommit(event.currentTarget.value) }} />
            </label>
          </>
        )}
        {mode === 'TARGETED' && (
          <label className="dsh-security-risk-decision__field">
            <span>{t('wizard.paths')}</span>
            <textarea aria-label={t('wizard.paths')} rows={5} value={relativePaths} onChange={event => { setRelativePaths(event.currentTarget.value) }} />
            <small>{t('wizard.pathsHint')}</small>
          </label>
        )}
        <fieldset className="dsh-security-wizard__controls">
          <legend>{t('wizard.strongerControls')}</legend>
          {catalog.strongerControls.map(control => {
            const checked = controls.includes(control.controlId)
            const dependenciesMet = control.requiresControlIds.every(required => controls.includes(required))
            return (
              <label key={control.controlId}>
                <input
                  type="checkbox"
                  checked={checked}
                  disabled={!checked && !dependenciesMet}
                  onChange={event => {
                    setControls(event.currentTarget.checked
                      ? [...controls, control.controlId]
                      : controls.filter(candidate => (
                          candidate !== control.controlId
                          && !catalog.strongerControls.some(other => (
                            other.controlId === candidate
                            && other.requiresControlIds.includes(control.controlId)
                          ))
                        )))
                  }}
                />
                <span>{catalogLabel(control.label, t)}</span>
                <code>{control.controlId}</code>
              </label>
            )
          })}
        </fieldset>
        <button type="submit" className="dsh-security-risk-decision__submit" disabled={!formValid}>
          {t('wizard.reviewPreflight')}
        </button>
      </form>
    </section>
  )
}

function StartPreflightPanel({
  preflight,
  submitting,
  cancelStartPreflight,
  confirmStartAssessment,
  backToAssessmentSelection,
  t,
}: {
  readonly preflight: StartPreflightV1
  readonly submitting: boolean
  readonly cancelStartPreflight: () => void
  readonly confirmStartAssessment: () => void
  readonly backToAssessmentSelection: () => void
  readonly t: WorkbenchOverlayProps['t']
}) {
  return (
    <section className="dsh-security-wizard dsh-security-preflight" aria-labelledby="dsh-security-preflight-title">
      <h2 id="dsh-security-preflight-title">{t('preflight.title')}</h2>
      <p className="dsh-security-readonly-note">{t('preflight.immutable')}</p>
      <dl className="dsh-security-facts">
        <Fact label={t('wizard.repository')} value={`${preflight.repository.displayName} @ ${preflight.repository.repositoryRevision}`} />
        <Fact label={t('wizard.subject')} value={preflight.selection.subject.kind} machine />
        <Fact label={t('wizard.target')} value={JSON.stringify(preflight.selection.target)} machine />
        <Fact label={t('label.policy')} value={preflight.effectivePolicyId} machine />
        <Fact label={t('wizard.profile')} value={preflight.effectiveProfileId} machine />
        <Fact label={t('wizard.evidenceProtection')} value={preflight.evidenceProtection.policyId} machine />
        <Fact label={t('wizard.egress')} value={`${preflight.dataEgress.policyId} / ${preflight.dataEgress.categories.join(', ')}`} machine />
        <Fact label={t('wizard.maximumBudget')} value={preflight.maximumBudget.status} machine />
      </dl>
      <div>
        <strong className="dsh-security-recovery__label">{t('preflight.providers')}</strong>
        <ul className="dsh-security-metadata-list">
          {preflight.providerComposition.map(provider => (
            <li key={`${provider.analyzerId}@${provider.analyzerVersion}`}>
              <code>{provider.analyzerId}@{provider.analyzerVersion}</code>
              <MachineBadge value={provider.eligibility} />
              <span>{provider.coverageObligationIds.join(', ')}</span>
            </li>
          ))}
        </ul>
      </div>
      <PreflightLimitations title={t('preflight.unsupported')} values={preflight.unsupportedConditions} empty={t('preflight.none')} />
      <PreflightLimitations title={t('preflight.claimLimitations')} values={preflight.claimLimitations} empty={t('preflight.none')} />
      <PreflightLimitations title={t('preflight.coverageLimitations')} values={preflight.coverageLimitations} empty={t('preflight.none')} />
      <div className="dsh-security-preflight__digest">
        <strong>{t('preflight.digest')}</strong>
        <code>{preflight.proposalDigest.value}</code>
      </div>
      <div className="dsh-security-recovery__actions">
        <button type="button" className="dsh-security-secondary-action" disabled={submitting} onClick={cancelStartPreflight}>
          {t('preflight.editSelection')}
        </button>
        <button type="button" className="dsh-security-secondary-action" disabled={submitting} onClick={backToAssessmentSelection}>
          {t('wizard.cancel')}
        </button>
        <button
          type="button"
          className="dsh-security-risk-decision__submit"
          disabled={!preflight.admissible || submitting}
          onClick={confirmStartAssessment}
        >
          {submitting ? t('preflight.starting') : t('preflight.confirm')}
        </button>
      </div>
    </section>
  )
}

function PreflightLimitations({ title, values, empty }: {
  readonly title: string
  readonly values: readonly string[]
  readonly empty: string
}) {
  return (
    <div>
      <strong className="dsh-security-recovery__label">{title}</strong>
      {values.length === 0
        ? <p className="dsh-security-muted">{empty}</p>
        : <ul className="dsh-security-preflight__limitations">{values.map(value => <li key={value}>{value}</li>)}</ul>}
    </div>
  )
}

function catalogLabel(label: { readonly en: string; readonly zhCN: string }, t: WorkbenchOverlayProps['t']): string {
  return t('catalog.locale') === 'zhCN' ? label.zhCN : label.en
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

function BundleExportView({
  manifest,
  deliveryDestinationIds,
  exportState,
  backToAssessmentDetail,
  downloadExport,
  previewExport,
  refreshExportStatus,
  requestExport,
  t,
}: {
  readonly manifest: BundleManifestV1
  readonly deliveryDestinationIds: readonly string[]
  readonly exportState: WorkbenchExportStateV1
  readonly backToAssessmentDetail: () => void
  readonly downloadExport: () => void
  readonly previewExport: (deliveryDestinationId: string) => void
  readonly refreshExportStatus: () => void
  readonly requestExport: () => void
  readonly t: WorkbenchOverlayProps['t']
}) {
  return (
    <section className="dsh-security-exports" aria-labelledby="dsh-security-exports-title">
      <button type="button" className="dsh-security-secondary-action" onClick={backToAssessmentDetail}>
        {t('exports.back')}
      </button>
      <div className="dsh-security-view-heading">
        <div>
          <span className="dsh-security-eyebrow">{t('exports.eyebrow')}</span>
          <h2 id="dsh-security-exports-title">{t('exports.title')}</h2>
        </div>
        <MachineBadge value={manifest.verdict} />
      </div>
      <p className="dsh-security-readonly-note">{t('exports.immutable')}</p>
      <dl className="dsh-security-facts">
        <Fact label={t('label.assessment')} value={manifest.assessmentId} machine />
        <Fact label={t('label.revision')} value={String(manifest.assessmentRevision)} />
        <Fact label={t('label.verdict')} value={manifest.verdict} machine />
        <Fact label={t('exports.seal')} value={manifest.seal.sealId} machine />
        <Fact label={t('exports.sealedAt')} value={manifest.seal.sealedAt} machine />
        <Fact label={t('exports.manifestDigest')} value={manifest.digest.value} machine />
        <Fact label={t('exports.digestMediaType')} value={manifest.digest.mediaType} machine />
        <Fact label={t('exports.digestByteLength')} value={String(manifest.digest.byteLength)} />
      </dl>
      <section className="dsh-security-section" aria-labelledby="dsh-security-bundle-records-title">
        <div className="dsh-security-section__header">
          <h2 id="dsh-security-bundle-records-title">{t('exports.records')}</h2>
          <span className="dsh-security-health__requirement">{manifest.records.length}</span>
        </div>
        <ul className="dsh-security-export-list">
          {manifest.records.map(record => (
            <li key={record.recordId}>
              <div className="dsh-security-export-list__heading">
                <code>{record.recordId}</code>
                <MachineBadge value={record.classification} />
              </div>
              <span><code>{record.schemaId}@{record.schemaVersion}</code></span>
              <small>{record.digest.mediaType} · {record.digest.byteLength} B</small>
              <code className="dsh-security-export-list__digest">{record.digest.value}</code>
            </li>
          ))}
        </ul>
      </section>
      <section className="dsh-security-section" aria-labelledby="dsh-security-bundle-omissions-title">
        <div className="dsh-security-section__header">
          <h2 id="dsh-security-bundle-omissions-title">{t('exports.omissions')}</h2>
        </div>
        {manifest.omissions.length === 0
          ? <p className="dsh-security-muted">{t('exports.noOmissions')}</p>
          : (
              <ul className="dsh-security-export-list">
                {manifest.omissions.map(omission => (
                  <li key={omission.schemaId}>
                    <code>{omission.schemaId}</code>
                    <MachineBadge value={omission.reason} />
                  </li>
                ))}
              </ul>
            )}
      </section>
      <section className="dsh-security-section" aria-labelledby="dsh-security-destinations-title">
        <div className="dsh-security-section__header">
          <h2 id="dsh-security-destinations-title">{t('exports.destinations')}</h2>
        </div>
        <p className="dsh-security-readonly-note">{t('exports.destinationBoundary')}</p>
        {deliveryDestinationIds.length === 0
          ? <p className="dsh-security-muted">{t('exports.noDestinations')}</p>
          : (
              <ul className="dsh-security-export-list dsh-security-export-list--destinations">
                {deliveryDestinationIds.map(destinationId => (
                  <li key={destinationId}>
                    <code>{destinationId}</code>
                    <button
                      type="button"
                      className="dsh-security-secondary-action"
                      disabled={exportState.kind === 'PREVIEW_LOADING' || exportState.kind === 'REQUESTING'}
                      onClick={() => { previewExport(destinationId) }}
                    >
                      {t('exports.previewAction')}
                    </button>
                  </li>
                ))}
              </ul>
            )}
      </section>
      {exportState.kind === 'PREVIEW_LOADING' && (
        <MessageState
          title={t('exports.previewLoadingTitle')}
          body={t('exports.previewLoadingBody')}
          detail={exportState.deliveryDestinationId}
          role="status"
        />
      )}
      {(exportState.kind === 'PREVIEW_READY'
        || exportState.kind === 'REQUESTING'
        || exportState.kind === 'STATUS_READY') && (
        <section className="dsh-security-section" aria-labelledby="dsh-security-export-preview-title">
          <div className="dsh-security-section__header">
            <h2 id="dsh-security-export-preview-title">{t('exports.previewTitle')}</h2>
            <MachineBadge value={exportState.kind === 'STATUS_READY' ? exportState.status.status : 'PREVIEW'} />
          </div>
          <p className="dsh-security-readonly-note">{t('exports.previewBoundary')}</p>
          <dl className="dsh-security-facts">
            <Fact label={t('exports.profile')} value={exportState.preview.profile.exportProfileId} machine />
            <Fact label={t('exports.audience')} value={exportState.preview.profile.audience} machine />
            <Fact label={t('exports.format')} value={exportState.preview.profile.artifactFormat} machine />
            <Fact label={t('exports.mediaType')} value={exportState.preview.profile.mediaType} machine />
            <Fact
              label={t('exports.destination')}
              value={exportState.preview.destination.deliveryDestinationId}
              machine
            />
            <Fact
              label={t('exports.expiryWindow')}
              value={`${exportState.preview.expiresAfterSeconds} s`}
            />
          </dl>
          <PreflightLimitations
            title={t('exports.includedCategories')}
            values={exportState.preview.profile.includedCategories}
            empty={t('value.notAvailable')}
          />
          <PreflightLimitations
            title={t('exports.redactions')}
            values={exportState.preview.profile.redactions}
            empty={t('value.notAvailable')}
          />
          <PreflightLimitations
            title={t('exports.warnings')}
            values={exportState.preview.warnings}
            empty={t('value.notAvailable')}
          />
          {exportState.kind !== 'STATUS_READY' && (
            <button
              type="button"
              className="dsh-security-primary-action"
              disabled={exportState.kind === 'REQUESTING'}
              onClick={requestExport}
            >
              {exportState.kind === 'REQUESTING' ? t('exports.requesting') : t('exports.requestAction')}
            </button>
          )}
          {exportState.kind === 'STATUS_READY' && (
            <dl className="dsh-security-facts">
              <Fact label={t('exports.exportId')} value={exportState.status.exportId} machine />
              <Fact label={t('exports.status')} value={exportState.status.status} machine />
              <Fact label={t('exports.retentionStatus')} value={exportState.status.retention.status} machine />
              {(exportState.status.retention.status === 'PURGE_PENDING'
                || exportState.status.retention.status === 'PURGED') && (
                <>
                  <Fact
                    label={t('exports.tombstoneDigest')}
                    value={exportState.status.retention.tombstone.digest.value}
                    machine
                  />
                  <Fact
                    label={t('exports.purgeReason')}
                    value={exportState.status.retention.tombstone.reason}
                    machine
                  />
                  <Fact
                    label={t('exports.purgeRequestedAt')}
                    value={exportState.status.retention.purgeRequestedAt}
                  />
                  <Fact
                    label={t('exports.purgedAt')}
                    value={exportState.status.retention.purgedAt ?? t('value.notAvailable')}
                  />
                </>
              )}
              <Fact label={t('exports.attemptCount')} value={String(exportState.status.delivery.attemptCount)} />
              <Fact
                label={t('exports.lastAttemptAt')}
                value={exportState.status.delivery.lastAttemptAt ?? t('value.notAvailable')}
              />
              <Fact
                label={t('exports.lastFailure')}
                value={exportState.status.delivery.lastFailureCode ?? t('value.notAvailable')}
                machine={exportState.status.delivery.lastFailureCode !== null}
              />
              <Fact
                label={t('exports.lastFailureAt')}
                value={exportState.status.delivery.lastFailureAt ?? t('value.notAvailable')}
              />
              <Fact
                label={t('exports.nextRetryAt')}
                value={exportState.status.delivery.nextRetryAt ?? t('value.notAvailable')}
              />
              <Fact label={t('exports.receiptCorrelation')} value={exportState.receipt.correlationId} machine />
              <Fact label={t('exports.acceptedAt')} value={exportState.receipt.acceptedAt} />
              <Fact label={t('exports.expiresAt')} value={exportState.status.expiresAt ?? t('value.notAvailable')} />
              <Fact
                label={t('exports.artifactDigest')}
                value={exportState.status.artifact?.digest.value ?? t('value.notAvailable')}
                machine={exportState.status.artifact !== null}
              />
              <Fact label={t('exports.accessAction')} value={exportState.status.accessAction.kind} machine />
            </dl>
          )}
          {exportState.kind === 'STATUS_READY'
            && exportState.status.accessAction.kind === 'ONE_USE_DOWNLOAD' && (
            <div className="dsh-security-section__action">
              <button
                type="button"
                className="dsh-security-primary-action"
                disabled={exportState.download.kind === 'DOWNLOADING'}
                onClick={downloadExport}
              >
                {exportState.download.kind === 'DOWNLOADING'
                  ? t('exports.downloadAuthorizing')
                  : t('exports.downloadAction')}
              </button>
              <p className="dsh-security-readonly-note">{t('exports.downloadBoundary')}</p>
            </div>
          )}
          {exportState.kind === 'STATUS_READY' && (
            <div className="dsh-security-section__action">
              <button
                type="button"
                className="dsh-security-secondary-action"
                onClick={refreshExportStatus}
              >
                {t('exports.refreshStatus')}
              </button>
              <p className="dsh-security-readonly-note">{t('exports.retryBoundary')}</p>
            </div>
          )}
          {exportState.kind === 'STATUS_READY' && exportState.download.kind === 'COMPLETE' && (
            <div role="status" className="dsh-security-preflight__digest">
              <strong>{t('exports.downloadComplete')}</strong>
              <code>{exportState.download.fileName}</code>
              <code>{exportState.download.digest}</code>
              <span>{exportState.download.byteLength} B · {exportState.download.consumedAt}</span>
            </div>
          )}
        </section>
      )}
    </section>
  )
}

function AssessmentDetail({
  snapshot,
  findings,
  assessmentCommand,
  openBundle,
  cancelAssessment,
  openFindings,
  recordRiskDecision,
  resumeAssessment,
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
  readonly assessmentCommand: WorkbenchAssessmentCommandStateV1
  readonly openBundle: () => void
  readonly cancelAssessment: (reason: WorkbenchAssessmentCommandReasonV1) => void
  readonly openFindings: () => void
  readonly recordRiskDecision: (submission: WorkbenchRiskDecisionSubmissionV1) => void
  readonly resumeAssessment: (reason: WorkbenchAssessmentCommandReasonV1) => void
  readonly loadMoreFindings: () => void
  readonly selectFinding: (recordId: string) => void
  readonly backToFindingList: () => void
  readonly selectEvidence: (artifactId: string) => void
  readonly backToFindingDetail: () => void
  readonly discloseEvidence: () => void
  readonly hideEvidenceDisclosure: () => void
  readonly t: WorkbenchOverlayProps['t']
}) {
  const bundleAvailable = snapshot.state === 'SEALED'
    && snapshot.seal !== null
    && snapshot.verdict !== null
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

      <section className="dsh-security-section" aria-labelledby="dsh-security-exports-launcher-title">
        <div className="dsh-security-section__header">
          <h2 id="dsh-security-exports-launcher-title">{t('exports.title')}</h2>
          {bundleAvailable && <MachineBadge value="SEALED" />}
        </div>
        <p className="dsh-security-readonly-note">
          {bundleAvailable ? t('exports.available') : t('exports.unavailable')}
        </p>
        {bundleAvailable && (
          <button type="button" className="dsh-security-secondary-action dsh-security-section__action" onClick={openBundle}>
            {t('exports.open')}
          </button>
        )}
      </section>

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

      {snapshot.blockedRecovery !== null && (
        <BlockedRecoveryPanel
          snapshot={snapshot}
          recovery={snapshot.blockedRecovery}
          commandState={assessmentCommand}
          cancelAssessment={cancelAssessment}
          resumeAssessment={resumeAssessment}
          t={t}
        />
      )}

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

function BlockedRecoveryPanel({
  snapshot,
  recovery,
  commandState,
  cancelAssessment,
  resumeAssessment,
  t,
}: {
  readonly snapshot: AssessmentSnapshotV1
  readonly recovery: NonNullable<AssessmentSnapshotV1['blockedRecovery']>
  readonly commandState: WorkbenchAssessmentCommandStateV1
  readonly cancelAssessment: (reason: WorkbenchAssessmentCommandReasonV1) => void
  readonly resumeAssessment: (reason: WorkbenchAssessmentCommandReasonV1) => void
  readonly t: WorkbenchOverlayProps['t']
}) {
  const [reasonCode, setReasonCode] = useState('')
  const [reasonSummary, setReasonSummary] = useState('')
  const resumeAction = snapshot.availableActions.find(action => action.kind === 'RESUME_ASSESSMENT')
  const cancelAction = snapshot.availableActions.find(action => action.kind === 'CANCEL_ASSESSMENT')
  const normalizedReason = {
    code: reasonCode.trim(),
    summary: reasonSummary.trim(),
  }
  const reasonValid = /^[A-Z][A-Z0-9_]{0,63}$/.test(normalizedReason.code)
    && normalizedReason.summary.length >= 1
    && normalizedReason.summary.length <= 512
  const submitting = commandState.kind === 'SUBMITTING'
  return (
    <section className="dsh-security-section dsh-security-recovery" aria-labelledby="dsh-security-recovery-title">
      <div className="dsh-security-section__header">
        <h2 id="dsh-security-recovery-title">{t('recovery.title')}</h2>
        <MachineBadge value={recovery.blocker.interruption} />
      </div>
      <p className="dsh-security-readonly-note">{t('recovery.immutable')}</p>
      <dl className="dsh-security-facts">
        <Fact label={t('recovery.blocker')} value={recovery.blocker.code} machine />
        <Fact label={t('recovery.phase')} value={recovery.blocker.phase} machine />
        <Fact label={t('recovery.condition')} value={recovery.recovery.requiredCondition} machine />
        <Fact label={t('recovery.evidence')} value={recovery.evidence.status} machine />
        <Fact
          label={t('recovery.evidenceCount')}
          value={recovery.evidence.publishedArtifactCount === null
            ? t('value.notAvailable')
            : String(recovery.evidence.publishedArtifactCount)}
        />
        <Fact
          label={t('recovery.budget')}
          value={recovery.recovery.remainingExecutionBudget.status}
          machine
        />
        <Fact
          label={t('recovery.reconciliation')}
          value={recovery.recovery.coverageReconciliation.required
            ? t('value.required')
            : t('value.notRequired')}
        />
        <Fact
          label={t('recovery.possibleVerdict')}
          value={recovery.recovery.coverageReconciliation.possibleVerdict ?? t('value.notAvailable')}
          machine={recovery.recovery.coverageReconciliation.possibleVerdict !== null}
        />
      </dl>
      <div>
        <strong className="dsh-security-recovery__label">{t('recovery.obligations')}</strong>
        {recovery.blocker.affectedObligations.length === 0
          ? <p className="dsh-security-muted">{t('recovery.noObligations')}</p>
          : (
              <ul className="dsh-security-metadata-list">
                {recovery.blocker.affectedObligations.map(obligation => (
                  <li key={obligation.obligationId}>
                    <code>{obligation.obligationId}</code>
                    <MachineBadge value={obligation.reason} />
                  </li>
                ))}
              </ul>
            )}
      </div>
      {(resumeAction !== undefined || cancelAction !== undefined) && (
        <div className="dsh-security-recovery__form">
          <label className="dsh-security-risk-decision__field">
            <span>{t('recovery.reasonCode')}</span>
            <input
              aria-label={t('recovery.reasonCode')}
              autoComplete="off"
              maxLength={64}
              pattern="[A-Z][A-Z0-9_]{0,63}"
              value={reasonCode}
              disabled={submitting}
              onChange={event => { setReasonCode(event.currentTarget.value) }}
            />
          </label>
          <label className="dsh-security-risk-decision__field">
            <span>{t('recovery.reasonSummary')}</span>
            <textarea
              aria-label={t('recovery.reasonSummary')}
              maxLength={512}
              rows={3}
              value={reasonSummary}
              disabled={submitting}
              onChange={event => { setReasonSummary(event.currentTarget.value) }}
            />
          </label>
          <p className="dsh-security-readonly-note">{t('recovery.commandBoundary')}</p>
          <div className="dsh-security-recovery__actions">
            {resumeAction !== undefined && (
              <button
                type="button"
                className="dsh-security-risk-decision__submit"
                disabled={!reasonValid || submitting}
                onClick={() => { resumeAssessment(normalizedReason) }}
              >
                {commandState.kind === 'SUBMITTING' && commandState.command === 'RESUME'
                  ? t('recovery.resuming')
                  : t('recovery.resume')}
              </button>
            )}
            {cancelAction !== undefined && (
              <button
                type="button"
                className="dsh-security-secondary-action dsh-security-recovery__cancel"
                disabled={!reasonValid || submitting}
                onClick={() => { cancelAssessment(normalizedReason) }}
              >
                {commandState.kind === 'SUBMITTING' && commandState.command === 'CANCEL'
                  ? t('recovery.canceling')
                  : t('recovery.cancel')}
              </button>
            )}
          </div>
        </div>
      )}
    </section>
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
