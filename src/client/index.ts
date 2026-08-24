/**
 * Browser half of the Security Assurance Workbench. It mounts the package-owned
 * strict Remote contribution and owns one transient Assessment view session.
 */
import { Service, type Context } from '@deepseek-ai/cordis'
import type { ClientContext } from '@deepseek-ai/dsh-client-runtime/client'
import type { HostObservable } from '@deepseek-ai/dsh-client-ui-slots'
import type {} from '@deepseek-ai/dsh-client-locale/client'
import type {} from '@deepseek-ai/dsh-client-ui-layout/client'
import type {} from '@deepseek-ai/dsh-client-ui-sidebar/client'
import type {
  RemoteFailure,
  RemoteResult,
  TypertClientRemote,
} from '@deepseek-ai/dsh-typert-protocol'
import workbenchRemote from 'dsh-security-assurance/remote'
import type {
  AssessmentId,
  AssessmentListItemV1,
  AssessmentListPageV1,
  AssessmentRevisionSignalV1,
  AssessmentSnapshotV1,
  FindingDetailViewV1,
  FindingListPageV1,
  FindingSummaryV1,
  PublicSecurityError,
  SecurityResult,
} from '../contracts.ts'
import type {
  WorkbenchAuthorityContextId,
  WorkbenchEvidenceMetadataViewV1,
} from 'dsh-security-assurance/workbench-remote'
import {
  en,
  WORKBENCH_LOCALE_NAMESPACE,
  zh,
  type WorkbenchKey,
} from './workbench/locales.ts'
import { WorkbenchPresentation } from './workbench/presentation.ts'
import { installWorkbenchStyles } from './workbench/styles.ts'
import {
  WorkbenchLauncher,
  type WorkbenchLauncherInjected,
} from './workbench/WorkbenchLauncher.tsx'
import {
  WorkbenchOverlay,
  type WorkbenchOverlayInjected,
} from './workbench/WorkbenchOverlay.tsx'

export type { WorkbenchAuthorityContextId } from 'dsh-security-assurance/workbench-remote'

declare module '@deepseek-ai/cordis' {
  interface Context {
    /** Generated Client Remote namespaces selected by the active Client assembly. */
    remote: TypertClientRemote
    /** One transient, authority-bound Security Assessment Workbench session. */
    securityAssuranceWorkbench: SecurityAssuranceWorkbenchController
  }
}

declare module '@deepseek-ai/dsh-client-ui-slots' {
  interface LocaleNamespaceMap {
    /** Security Assurance Workbench presentation copy. */
    'security-assurance-workbench': WorkbenchKey
  }
}

/** Public request for opening one in-memory Assessment view session. */
export interface OpenAssessmentWorkbenchRequestV1 {
  readonly securityAssuranceWorkbenchContextId: WorkbenchAuthorityContextId
  readonly assessmentId: AssessmentId
}

/** Authenticated Host request for opening an in-memory Assessment selection session. */
export interface OpenAssessmentSelectionRequestV1 {
  readonly securityAssuranceWorkbenchContextId: WorkbenchAuthorityContextId
}

/** Presentation-safe failure retained after sensitive session state is erased. */
export interface WorkbenchClientFailureV1 {
  readonly source: 'TRANSPORT' | 'SECURITY' | 'CLIENT'
  readonly code: string
  readonly message: string
  readonly retryable: boolean
}

/** Transient metadata disclosure nested under one exact Finding Detail. */
export type WorkbenchEvidenceStateV1 =
  | { readonly kind: 'NOT_LOADED' }
  | { readonly kind: 'METADATA_LOADING'; readonly artifactId: string }
  | { readonly kind: 'METADATA_READY'; readonly view: WorkbenchEvidenceMetadataViewV1 }

/** Transient Finding projection nested under one revision-bound Assessment view. */
export type WorkbenchFindingsStateV1 =
  | { readonly kind: 'NOT_LOADED' }
  | { readonly kind: 'LIST_LOADING' }
  | {
    readonly kind: 'LIST_READY'
    readonly assessmentRevision: number
    readonly items: readonly FindingSummaryV1[]
    readonly nextCursor: string | null
  }
  | {
    readonly kind: 'LIST_LOADING_MORE'
    readonly assessmentRevision: number
    readonly items: readonly FindingSummaryV1[]
    readonly nextCursor: string
  }
  | {
    readonly kind: 'DETAIL_LOADING'
    readonly assessmentRevision: number
    readonly items: readonly FindingSummaryV1[]
    readonly nextCursor: string | null
    readonly recordId: string
  }
  | {
    readonly kind: 'DETAIL_READY'
    readonly assessmentRevision: number
    readonly items: readonly FindingSummaryV1[]
    readonly nextCursor: string | null
    readonly detail: FindingDetailViewV1
    readonly evidence: WorkbenchEvidenceStateV1
  }

/** Immutable observable state of the browser-owned Workbench session. */
export type SecurityAssuranceWorkbenchStateV1 =
  | { readonly kind: 'CLOSED' }
  | { readonly kind: 'SELECTION_LOADING' }
  | {
    readonly kind: 'SELECTION_READY'
    readonly consistencyWatermark: string
    readonly assessments: readonly AssessmentListItemV1[]
    readonly nextCursor: string | null
  }
  | {
    readonly kind: 'SELECTION_LOADING_MORE'
    readonly consistencyWatermark: string
    readonly assessments: readonly AssessmentListItemV1[]
    readonly nextCursor: string
  }
  | { readonly kind: 'LOADING'; readonly assessmentId: AssessmentId }
  | {
    readonly kind: 'READY'
    readonly assessmentId: AssessmentId
    readonly snapshot: AssessmentSnapshotV1
    readonly findings: WorkbenchFindingsStateV1
  }
  | {
    readonly kind: 'FAILED'
    readonly assessmentId: AssessmentId | null
    readonly failure: WorkbenchClientFailureV1
  }

/** Observer of the current immutable Workbench state. */
export type SecurityAssuranceWorkbenchListener = (
  state: SecurityAssuranceWorkbenchStateV1,
) => void

interface LiveAssessmentSession {
  readonly generation: number
  readonly contextId: WorkbenchAuthorityContextId
  assessmentId: AssessmentId | undefined
  readonly abort: AbortController
}

const CLOSED_STATE: SecurityAssuranceWorkbenchStateV1 = Object.freeze({ kind: 'CLOSED' })
const FINDINGS_NOT_LOADED: WorkbenchFindingsStateV1 = Object.freeze({ kind: 'NOT_LOADED' })
const EVIDENCE_NOT_LOADED: WorkbenchEvidenceStateV1 = Object.freeze({ kind: 'NOT_LOADED' })
const LONG_POLL_TIMEOUT_MS = 25_000

/**
 * Deep Client module hiding nested Remote results, revision long-polling,
 * cancellation, stale-response fencing, and sensitive in-memory cleanup.
 */
export class SecurityAssuranceWorkbenchController extends Service {
  static inject = ['remote', 'remote.securityAssuranceWorkbench']

  private readonly ownerCtx: Context
  private readonly listeners = new Set<SecurityAssuranceWorkbenchListener>()
  private state: SecurityAssuranceWorkbenchStateV1 = CLOSED_STATE
  private session: LiveAssessmentSession | undefined
  private nextGeneration = 0
  private evidenceRequestGeneration = 0

  constructor(ctx: Context) {
    super(ctx, 'securityAssuranceWorkbench')
    this.ownerCtx = ctx
    ctx.effect(() => () => {
      this.eraseSession()
      this.listeners.clear()
    }, 'security-assurance-workbench: transient session')
  }

  /** Open one Host-authenticated selector without accepting browser-entered credentials. */
  async openAssessmentSelection(
    request: OpenAssessmentSelectionRequestV1,
  ): Promise<SecurityAssuranceWorkbenchStateV1> {
    this.eraseSession()
    const session: LiveAssessmentSession = {
      generation: ++this.nextGeneration,
      contextId: request.securityAssuranceWorkbenchContextId,
      assessmentId: undefined,
      abort: new AbortController(),
    }
    this.session = session
    this.publish(Object.freeze({ kind: 'SELECTION_LOADING' }))

    let result: RemoteResult<SecurityResult<AssessmentListPageV1>>
    try {
      result = await this.ownerCtx.remote.securityAssuranceWorkbench.listAssessments(
        session.contextId,
        { schemaVersion: 1, limit: 50 },
        session.abort.signal,
      )
    } catch (error) {
      return this.failClient(session, error)
    }
    if (!this.isActive(session)) return this.state
    const page = this.readRemoteResult(session, result)
    if (page === undefined) return this.state
    return this.publishSelection(page)
  }

  /** Append the next page from the current authority-bound consistency window. */
  async loadMoreAssessments(): Promise<SecurityAssuranceWorkbenchStateV1> {
    const session = this.session
    const current = this.state
    if (
      session === undefined
      || current.kind !== 'SELECTION_READY'
      || current.nextCursor === null
    ) return current
    this.publish(Object.freeze({
      kind: 'SELECTION_LOADING_MORE',
      consistencyWatermark: current.consistencyWatermark,
      assessments: current.assessments,
      nextCursor: current.nextCursor,
    }))

    let result: RemoteResult<SecurityResult<AssessmentListPageV1>>
    try {
      result = await this.ownerCtx.remote.securityAssuranceWorkbench.listAssessments(
        session.contextId,
        { schemaVersion: 1, limit: 50, cursor: current.nextCursor },
        session.abort.signal,
      )
    } catch (error) {
      return this.failClient(session, error)
    }
    if (!this.isActive(session)) return this.state
    const page = this.readRemoteResult(session, result)
    if (page === undefined) return this.state
    if (page.consistencyWatermark !== current.consistencyWatermark) {
      return this.fail(session, {
        source: 'CLIENT',
        code: 'SELECTION_PROTOCOL_VIOLATION',
        message: 'The Assessment continuation left its first-page consistency window.',
        retryable: false,
      })
    }
    return this.publishSelection({
      ...page,
      assessments: [...current.assessments, ...page.assessments],
    })
  }

  /** Select one identity from the current authority-projected page. */
  async selectAssessment(assessmentId: AssessmentId): Promise<SecurityAssuranceWorkbenchStateV1> {
    const session = this.session
    if (
      session === undefined
      || this.state.kind !== 'SELECTION_READY'
      || !this.state.assessments.some(item => item.assessmentId === assessmentId)
    ) {
      return this.failSelection({
        source: 'CLIENT',
        code: 'ASSESSMENT_NOT_LISTED',
        message: 'The Assessment is not present in the current authority-scoped selection.',
        retryable: false,
      })
    }
    session.assessmentId = assessmentId
    return this.loadAssessment(session, assessmentId)
  }

  /** Load the first redacted Finding page for the exact rendered Assessment revision. */
  async openFindings(): Promise<SecurityAssuranceWorkbenchStateV1> {
    const session = this.session
    const current = this.state
    if (
      session === undefined
      || current.kind !== 'READY'
      || current.findings.kind !== 'NOT_LOADED'
    ) return current

    this.publishReady(current.assessmentId, current.snapshot, Object.freeze({
      kind: 'LIST_LOADING',
    }))
    let result: RemoteResult<SecurityResult<FindingListPageV1>>
    try {
      result = await this.ownerCtx.remote.securityAssuranceWorkbench.listFindings(
        session.contextId,
        { schemaVersion: 1, assessmentId: current.assessmentId, limit: 50 },
        session.abort.signal,
      )
    } catch (error) {
      return this.failClient(session, error)
    }
    if (
      !this.isActive(session)
      || this.state.kind !== 'READY'
      || this.state.snapshot.assessmentRevision !== current.snapshot.assessmentRevision
      || this.state.findings.kind !== 'LIST_LOADING'
    ) return this.state
    const page = this.readRemoteResult(session, result)
    if (page === undefined) return this.state
    if (
      page.assessmentId !== current.assessmentId
      || page.assessmentRevision !== current.snapshot.assessmentRevision
      || page.findings.some(item =>
        item.assessmentId !== page.assessmentId
        || item.assessmentRevision !== page.assessmentRevision)
    ) {
      return this.fail(session, {
        source: 'CLIENT',
        code: 'FINDING_PROTOCOL_VIOLATION',
        message: 'The Finding page is not bound to the rendered Assessment revision.',
        retryable: false,
      })
    }
    return this.publishReady(current.assessmentId, current.snapshot, Object.freeze({
      kind: 'LIST_READY',
      assessmentRevision: page.assessmentRevision,
      items: Object.freeze([...page.findings]),
      nextCursor: page.nextCursor,
    }))
  }

  /** Append one cursor-bound Finding page while preserving the exact Assessment revision. */
  async loadMoreFindings(): Promise<SecurityAssuranceWorkbenchStateV1> {
    const session = this.session
    const current = this.state
    if (
      session === undefined
      || current.kind !== 'READY'
      || current.findings.kind !== 'LIST_READY'
    ) return current
    const currentFindings = current.findings
    const nextCursor = currentFindings.nextCursor
    if (nextCursor === null) return current
    this.publishReady(current.assessmentId, current.snapshot, Object.freeze({
      kind: 'LIST_LOADING_MORE',
      assessmentRevision: currentFindings.assessmentRevision,
      items: currentFindings.items,
      nextCursor,
    }))

    let result: RemoteResult<SecurityResult<FindingListPageV1>>
    try {
      result = await this.ownerCtx.remote.securityAssuranceWorkbench.listFindings(
        session.contextId,
        {
          schemaVersion: 1,
          assessmentId: current.assessmentId,
          limit: 50,
          cursor: nextCursor,
        },
        session.abort.signal,
      )
    } catch (error) {
      return this.failClient(session, error)
    }
    if (
      !this.isActive(session)
      || this.state.kind !== 'READY'
      || this.state.snapshot.assessmentRevision !== current.snapshot.assessmentRevision
      || this.state.findings.kind !== 'LIST_LOADING_MORE'
    ) return this.state
    const page = this.readRemoteResult(session, result)
    if (page === undefined) return this.state
    if (
      page.assessmentId !== current.assessmentId
      || page.assessmentRevision !== currentFindings.assessmentRevision
      || page.findings.some(item =>
        item.assessmentId !== page.assessmentId
        || item.assessmentRevision !== page.assessmentRevision)
    ) {
      return this.fail(session, {
        source: 'CLIENT',
        code: 'FINDING_PROTOCOL_VIOLATION',
        message: 'The Finding continuation left its Assessment revision.',
        retryable: false,
      })
    }
    return this.publishReady(current.assessmentId, current.snapshot, Object.freeze({
      kind: 'LIST_READY',
      assessmentRevision: currentFindings.assessmentRevision,
      items: Object.freeze([...currentFindings.items, ...page.findings]),
      nextCursor: page.nextCursor,
    }))
  }

  /** Open one exact Finding revision selected from the current redacted list. */
  async selectFinding(recordId: string): Promise<SecurityAssuranceWorkbenchStateV1> {
    const session = this.session
    const current = this.state
    if (session === undefined || current.kind !== 'READY') return current
    if (current.findings.kind !== 'LIST_READY') return current
    const summary = current.findings.items.find(item => item.recordId === recordId)
    if (summary === undefined) {
      return this.fail(session, {
        source: 'CLIENT',
        code: 'FINDING_NOT_LISTED',
        message: 'The Finding is not present in the current revision-bound list.',
        retryable: false,
      })
    }
    const currentFindings = current.findings
    this.publishReady(current.assessmentId, current.snapshot, Object.freeze({
      kind: 'DETAIL_LOADING',
      assessmentRevision: currentFindings.assessmentRevision,
      items: currentFindings.items,
      nextCursor: currentFindings.nextCursor,
      recordId,
    }))

    let result: RemoteResult<SecurityResult<FindingDetailViewV1>>
    try {
      result = await this.ownerCtx.remote.securityAssuranceWorkbench.getFinding(
        session.contextId,
        {
          schemaVersion: 1,
          assessmentId: current.assessmentId,
          assessmentRevision: summary.assessmentRevision,
          recordId: summary.recordId,
          recordRevision: summary.recordRevision,
        },
        session.abort.signal,
      )
    } catch (error) {
      return this.failClient(session, error)
    }
    if (
      !this.isActive(session)
      || this.state.kind !== 'READY'
      || this.state.snapshot.assessmentRevision !== current.snapshot.assessmentRevision
      || this.state.findings.kind !== 'DETAIL_LOADING'
      || this.state.findings.recordId !== recordId
    ) return this.state
    const detail = this.readRemoteResult(session, result)
    if (detail === undefined) return this.state
    if (
      detail.assessmentId !== summary.assessmentId
      || detail.assessmentRevision !== summary.assessmentRevision
      || detail.recordId !== summary.recordId
      || detail.recordRevision !== summary.recordRevision
    ) {
      return this.fail(session, {
        source: 'CLIENT',
        code: 'FINDING_PROTOCOL_VIOLATION',
        message: 'The Finding Detail does not match the selected revision.',
        retryable: false,
      })
    }
    return this.publishReady(current.assessmentId, current.snapshot, Object.freeze({
      kind: 'DETAIL_READY',
      assessmentRevision: currentFindings.assessmentRevision,
      items: currentFindings.items,
      nextCursor: currentFindings.nextCursor,
      detail,
      evidence: EVIDENCE_NOT_LOADED,
    }))
  }

  /** Open metadata for one Evidence Link retained by the exact Finding Detail. */
  async selectEvidence(evidenceArtifactId: string): Promise<SecurityAssuranceWorkbenchStateV1> {
    const session = this.session
    const current = this.state
    if (
      session === undefined
      || current.kind !== 'READY'
      || current.findings.kind !== 'DETAIL_READY'
      || current.findings.evidence.kind !== 'NOT_LOADED'
    ) return current
    const link = current.findings.detail.evidenceLinks.find(candidate =>
      candidate.artifactId === evidenceArtifactId)
    if (link === undefined) {
      return this.fail(session, {
        source: 'CLIENT',
        code: 'EVIDENCE_NOT_LISTED',
        message: 'The Evidence is not present in the current revision-bound Finding Detail.',
        retryable: false,
      })
    }
    const currentFindings = current.findings
    const evidenceRequestGeneration = ++this.evidenceRequestGeneration
    this.publishReady(current.assessmentId, current.snapshot, Object.freeze({
      ...currentFindings,
      evidence: Object.freeze({
        kind: 'METADATA_LOADING' as const,
        artifactId: evidenceArtifactId,
      }),
    }))

    let result: RemoteResult<SecurityResult<WorkbenchEvidenceMetadataViewV1>>
    try {
      result = await this.ownerCtx.remote.securityAssuranceWorkbench.getEvidenceView(
        session.contextId,
        {
          schemaVersion: 1,
          assessmentId: current.assessmentId,
          assessmentRevision: currentFindings.detail.assessmentRevision,
          context: {
            kind: 'finding',
            recordId: currentFindings.detail.recordId,
            recordRevision: currentFindings.detail.recordRevision,
          },
          evidenceArtifactId: link.artifactId,
          evidenceDigest: link.digest,
          purpose: 'FINDING_TRIAGE',
          viewProfileId: 'security/evidence-view/metadata-only-v1',
        },
        session.abort.signal,
      )
    } catch (error) {
      if (!this.isActiveEvidenceRequest(
        session,
        current.snapshot.assessmentRevision,
        evidenceArtifactId,
        evidenceRequestGeneration,
      )) return this.state
      return this.failClient(session, error)
    }
    if (!this.isActiveEvidenceRequest(
      session,
      current.snapshot.assessmentRevision,
      evidenceArtifactId,
      evidenceRequestGeneration,
    )) return this.state
    const view = this.readRemoteResult(session, result)
    if (view === undefined) return this.state
    if (!matchesEvidenceMetadata(currentFindings.detail, link, view)) {
      return this.fail(session, {
        source: 'CLIENT',
        code: 'EVIDENCE_PROTOCOL_VIOLATION',
        message: 'The Evidence metadata does not match the selected revision-bound Link.',
        retryable: false,
      })
    }
    return this.publishReady(current.assessmentId, current.snapshot, Object.freeze({
      ...currentFindings,
      evidence: Object.freeze({ kind: 'METADATA_READY' as const, view }),
    }))
  }

  /** Return from Evidence metadata and discard the protected View. */
  backToFindingDetail(): SecurityAssuranceWorkbenchStateV1 {
    const current = this.state
    if (current.kind !== 'READY' || current.findings.kind !== 'DETAIL_READY') return current
    this.evidenceRequestGeneration += 1
    return this.publishReady(current.assessmentId, current.snapshot, Object.freeze({
      ...current.findings,
      evidence: EVIDENCE_NOT_LOADED,
    }))
  }

  /** Return from Finding Detail to the already authorized redacted list. */
  backToFindingList(): SecurityAssuranceWorkbenchStateV1 {
    const current = this.state
    if (current.kind !== 'READY' || current.findings.kind !== 'DETAIL_READY') return current
    return this.publishReady(current.assessmentId, current.snapshot, Object.freeze({
      kind: 'LIST_READY',
      assessmentRevision: current.findings.assessmentRevision,
      items: current.findings.items,
      nextCursor: current.findings.nextCursor,
    }))
  }

  /** Open one Assessment, replacing and erasing any prior in-memory session. */
  async openAssessment(
    request: OpenAssessmentWorkbenchRequestV1,
  ): Promise<SecurityAssuranceWorkbenchStateV1> {
    this.eraseSession()
    const session: LiveAssessmentSession = {
      generation: ++this.nextGeneration,
      contextId: request.securityAssuranceWorkbenchContextId,
      assessmentId: request.assessmentId,
      abort: new AbortController(),
    }
    this.session = session
    return this.loadAssessment(session, request.assessmentId)
  }

  private async loadAssessment(
    session: LiveAssessmentSession,
    assessmentId: AssessmentId,
  ): Promise<SecurityAssuranceWorkbenchStateV1> {
    this.publish(Object.freeze({ kind: 'LOADING', assessmentId }))

    let result: RemoteResult<SecurityResult<AssessmentSnapshotV1>>
    try {
      result = await this.ownerCtx.remote.securityAssuranceWorkbench.getAssessment(
        session.contextId,
        { schemaVersion: 1, assessmentId },
        session.abort.signal,
      )
    } catch (error) {
      return this.failClient(session, error)
    }
    if (!this.isActive(session)) return this.state
    const snapshot = this.readRemoteResult(session, result)
    if (snapshot === undefined) return this.state

    const ready = this.publishReady(assessmentId, snapshot)
    if (!isTerminal(snapshot)) void this.monitor(session, assessmentId, snapshot.assessmentRevision)
    return ready
  }

  /** Erase the authority context and every retained Assessment payload. */
  closeAssessment(): void {
    this.eraseSession()
    this.publish(CLOSED_STATE)
  }

  /** Read the current immutable presentation state. */
  getState(): SecurityAssuranceWorkbenchStateV1 {
    return this.state
  }

  /** Observe state changes; the registration belongs to the calling Cordis fiber. */
  subscribe(listener: SecurityAssuranceWorkbenchListener): () => void {
    const owned = this.ctx.effect(() => {
      this.listeners.add(listener)
      this.notify(listener, this.state)
      return () => { this.listeners.delete(listener) }
    }, 'security-assurance-workbench: state observer')
    return () => { void owned() }
  }

  private async monitor(
    session: LiveAssessmentSession,
    assessmentId: AssessmentId,
    firstRevision: number,
  ): Promise<void> {
    let afterRevision = firstRevision
    while (this.isActive(session)) {
      let waited: RemoteResult<SecurityResult<AssessmentRevisionSignalV1>>
      try {
        waited = await this.ownerCtx.remote.securityAssuranceWorkbench.waitForAssessmentRevision(
          session.contextId,
          {
            schemaVersion: 1,
            assessmentId,
            afterRevision,
            timeoutMs: LONG_POLL_TIMEOUT_MS,
          },
          session.abort.signal,
        )
      } catch (error) {
        this.failClient(session, error)
        return
      }
      if (!this.isActive(session)) return
      const signal = this.readRemoteResult(session, waited)
      if (signal === undefined) return
      if (signal.kind === 'TIMED_OUT') continue

      let refreshed: RemoteResult<SecurityResult<AssessmentSnapshotV1>>
      try {
        refreshed = await this.ownerCtx.remote.securityAssuranceWorkbench.getAssessment(
          session.contextId,
          { schemaVersion: 1, assessmentId },
          session.abort.signal,
        )
      } catch (error) {
        this.failClient(session, error)
        return
      }
      if (!this.isActive(session)) return
      const snapshot = this.readRemoteResult(session, refreshed)
      if (snapshot === undefined) return
      if (snapshot.assessmentRevision <= afterRevision) {
        this.fail(session, {
          source: 'CLIENT',
          code: 'REVISION_PROTOCOL_VIOLATION',
          message: 'The refreshed Assessment did not advance beyond the observed revision.',
          retryable: false,
        })
        return
      }
      afterRevision = snapshot.assessmentRevision
      this.publishReady(assessmentId, snapshot)
      if (isTerminal(snapshot)) {
        return
      }
    }
  }

  private readRemoteResult<T>(
    session: LiveAssessmentSession,
    result: RemoteResult<SecurityResult<T>>,
  ): T | undefined {
    if (!result.ok) {
      this.fail(session, remoteFailure(result.error))
      return undefined
    }
    if (!result.value.ok) {
      this.fail(session, securityFailure(result.value.error))
      return undefined
    }
    return result.value.value
  }

  private publishReady(
    assessmentId: AssessmentId,
    snapshot: AssessmentSnapshotV1,
    findings: WorkbenchFindingsStateV1 = FINDINGS_NOT_LOADED,
  ): SecurityAssuranceWorkbenchStateV1 {
    const ready = Object.freeze({
      kind: 'READY' as const,
      assessmentId,
      snapshot,
      findings,
    })
    this.publish(ready)
    return ready
  }

  private failClient(
    session: LiveAssessmentSession,
    error: unknown,
  ): SecurityAssuranceWorkbenchStateV1 {
    return this.fail(session, {
      source: 'CLIENT',
      code: 'REMOTE_INVOCATION_FAILED',
      message: error instanceof Error ? error.message : 'The Workbench Remote invocation failed.',
      retryable: true,
    })
  }

  private fail(
    session: LiveAssessmentSession,
    failure: WorkbenchClientFailureV1,
  ): SecurityAssuranceWorkbenchStateV1 {
    if (!this.isActive(session)) return this.state
    this.retireAuthority(session)
    const failed = Object.freeze({
      kind: 'FAILED' as const,
      assessmentId: session.assessmentId ?? null,
      failure: Object.freeze(failure),
    })
    this.publish(failed)
    return failed
  }

  private publishSelection(
    page: AssessmentListPageV1,
  ): SecurityAssuranceWorkbenchStateV1 {
    const ready = Object.freeze({
      kind: 'SELECTION_READY' as const,
      consistencyWatermark: page.consistencyWatermark,
      assessments: Object.freeze([...page.assessments]),
      nextCursor: page.nextCursor,
    })
    this.publish(ready)
    return ready
  }

  private failSelection(
    failure: WorkbenchClientFailureV1,
  ): SecurityAssuranceWorkbenchStateV1 {
    this.eraseSession()
    const failed = Object.freeze({
      kind: 'FAILED' as const,
      assessmentId: null,
      failure: Object.freeze(failure),
    })
    this.publish(failed)
    return failed
  }

  private retireAuthority(session: LiveAssessmentSession): void {
    if (!this.isActive(session)) return
    this.session = undefined
    session.abort.abort()
  }

  private eraseSession(): void {
    const active = this.session
    this.session = undefined
    active?.abort.abort()
  }

  private isActive(session: LiveAssessmentSession): boolean {
    return this.session === session && !session.abort.signal.aborted
  }

  private isActiveEvidenceRequest(
    session: LiveAssessmentSession,
    assessmentRevision: number,
    evidenceArtifactId: string,
    requestGeneration: number,
  ): boolean {
    return this.isActive(session)
      && this.evidenceRequestGeneration === requestGeneration
      && this.state.kind === 'READY'
      && this.state.snapshot.assessmentRevision === assessmentRevision
      && this.state.findings.kind === 'DETAIL_READY'
      && this.state.findings.evidence.kind === 'METADATA_LOADING'
      && this.state.findings.evidence.artifactId === evidenceArtifactId
  }

  private publish(state: SecurityAssuranceWorkbenchStateV1): void {
    this.state = state
    for (const listener of [...this.listeners]) this.notify(listener, state)
  }

  private notify(
    listener: SecurityAssuranceWorkbenchListener,
    state: SecurityAssuranceWorkbenchStateV1,
  ): void {
    try {
      listener(state)
    } catch (error) {
      console.error('security-assurance-workbench: state listener failed', error)
    }
  }
}

function isTerminal(snapshot: AssessmentSnapshotV1): boolean {
  return snapshot.state === 'SEALED' || snapshot.state === 'CANCELED'
}

function matchesEvidenceMetadata(
  detail: FindingDetailViewV1,
  link: FindingDetailViewV1['evidenceLinks'][number],
  view: WorkbenchEvidenceMetadataViewV1,
): boolean {
  return view.assessmentId === detail.assessmentId
    && view.assessmentRevision === detail.assessmentRevision
    && view.context.kind === 'finding'
    && view.context.recordId === detail.recordId
    && view.context.recordRevision === detail.recordRevision
    && view.evidence.artifactId === link.artifactId
    && view.evidence.schemaId === link.schemaId
    && sameDigest(view.evidence.digest, link.digest)
    && view.link.purpose === link.purpose
    && view.link.eligibilityDecision === link.eligibilityDecision
    && view.link.eligibilityDecisionArtifactId === link.eligibilityDecisionArtifactId
    && view.purpose === 'FINDING_TRIAGE'
    && view.viewProfileId === 'security/evidence-view/metadata-only-v1'
    && view.content.kind === 'REDACTED'
    && view.content.reason === 'PROFILE_METADATA_ONLY'
}

function sameDigest(
  left: WorkbenchEvidenceMetadataViewV1['evidence']['digest'],
  right: WorkbenchEvidenceMetadataViewV1['evidence']['digest'],
): boolean {
  return left.schemaVersion === right.schemaVersion
    && left.algorithm === right.algorithm
    && left.mediaType === right.mediaType
    && left.byteLength === right.byteLength
    && left.canonicalization === right.canonicalization
    && left.value === right.value
}

function remoteFailure(error: RemoteFailure): WorkbenchClientFailureV1 {
  return Object.freeze({
    source: 'TRANSPORT',
    code: error.code,
    message: error.message,
    retryable: true,
  })
}

function securityFailure(error: PublicSecurityError): WorkbenchClientFailureV1 {
  return Object.freeze({
    source: 'SECURITY',
    code: error.code,
    message: error.message,
    retryable: error.retryable,
  })
}

/** Required Client services: Remote transport plus the Host-owned UI assembly seams. */
export const inject = ['remote', 'slots', 'locale']

/** Mount the strict contribution and install the transient Workbench Controller. */
export async function apply(ctx: Context): Promise<() => Promise<void>> {
  const unmount = await ctx.remote.$mount(workbenchRemote)
  const controller = ctx.plugin(SecurityAssuranceWorkbenchController)
  let uninstallUi: (() => void) | undefined
  try {
    await controller
    uninstallUi = installWorkbenchUi(
      ctx as ClientContext,
      ctx.get('securityAssuranceWorkbench') as SecurityAssuranceWorkbenchController,
    )
  } catch (error) {
    uninstallUi?.()
    await controller.dispose()
    await unmount()
    throw error
  }
  return async () => {
    uninstallUi?.()
    await controller.dispose()
    await unmount()
  }
}

/** Register the additive launcher/overlay pair around one presentation machine. */
function installWorkbenchUi(
  ctx: ClientContext,
  controller: SecurityAssuranceWorkbenchController,
): () => void {
  const presentation = new WorkbenchPresentation(controller)
  const assessment: HostObservable<SecurityAssuranceWorkbenchStateV1> = {
    getSnapshot: () => controller.getState(),
    subscribe: listener => controller.subscribe(() => { listener() }),
  }
  const removeStyles = installWorkbenchStyles()
  const removeDictionary = ctx.locale.register(WORKBENCH_LOCALE_NAMESPACE, { zh, en })

  let removeLauncher: (() => void) | undefined
  let removeOverlay: (() => void) | undefined
  try {
    removeLauncher = ctx.slots.inject('sidebar.footer.action', () => ctx.slots.register({
      name: 'sidebar.footer.action',
      id: 'security-assurance-workbench-launcher',
      locale: WORKBENCH_LOCALE_NAMESPACE,
      inject: (): WorkbenchLauncherInjected => ({
        showWorkbench: returnFocus => { presentation.show(returnFocus) },
      }),
    }, WorkbenchLauncher))
    removeOverlay = ctx.slots.inject('shell.overlay', () => ctx.slots.register({
      name: 'shell.overlay',
      id: 'security-assurance-workbench-overlay',
      locale: WORKBENCH_LOCALE_NAMESPACE,
      inject: (): WorkbenchOverlayInjected => ({
        hooks: { presentation, assessment },
        backToFindingDetail: () => { controller.backToFindingDetail() },
        backToFindingList: () => { controller.backToFindingList() },
        closeWorkbench: () => { presentation.hide() },
        loadMoreAssessments: () => { void controller.loadMoreAssessments() },
        loadMoreFindings: () => { void controller.loadMoreFindings() },
        openFindings: () => { void controller.openFindings() },
        selectAssessment: assessmentId => { void controller.selectAssessment(assessmentId) },
        selectEvidence: artifactId => { void controller.selectEvidence(artifactId) },
        selectFinding: recordId => { void controller.selectFinding(recordId) },
      }),
    }, WorkbenchOverlay))
  } catch (error) {
    removeOverlay?.()
    removeLauncher?.()
    removeDictionary()
    removeStyles()
    presentation.dispose()
    throw error
  }

  return () => {
    removeOverlay?.()
    removeLauncher?.()
    removeDictionary()
    removeStyles()
    presentation.dispose()
  }
}
