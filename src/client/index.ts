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
  PublicSecurityError,
  SecurityResult,
} from '../contracts.ts'
import type { WorkbenchAuthorityContextId } from 'dsh-security-assurance/workbench-remote'
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
    if (isTerminal(snapshot)) this.retireAuthority(session)
    else void this.monitor(session, assessmentId, snapshot.assessmentRevision)
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
        this.retireAuthority(session)
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
  ): SecurityAssuranceWorkbenchStateV1 {
    const ready = Object.freeze({
      kind: 'READY' as const,
      assessmentId,
      snapshot,
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
        closeWorkbench: () => { presentation.hide() },
        loadMoreAssessments: () => { void controller.loadMoreAssessments() },
        selectAssessment: assessmentId => { void controller.selectAssessment(assessmentId) },
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
