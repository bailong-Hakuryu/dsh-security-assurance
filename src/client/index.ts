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
  AssessmentCancellationReceiptV1,
  AssessmentId,
  AssessmentListItemV1,
  AssessmentListPageV1,
  AssessmentRevisionSignalV1,
  AssessmentResumeReceiptV1,
  AssessmentReceiptV1,
  AssessmentSnapshotV1,
  BundleManifestV1,
  DigestEnvelopeV1,
  ExportDownloadV1,
  ExportDeliveryStatusV1,
  ExportPreviewV1,
  ExportRequestReceiptV1,
  ExportStatusV1,
  FindingDetailViewV1,
  FindingListPageV1,
  FindingSummaryV1,
  PublicSecurityError,
  RiskDecisionKindV1,
  RiskDecisionReceiptV1,
  RepositorySnapshotV1,
  RuntimeHealthSnapshot,
  SecurityCatalogSnapshotV1,
  SecurityResult,
  StartAssessmentSelectionV1,
  StartPreflightV1,
} from '../contracts.ts'
import { INTERNAL_JSON_EXPORT_PROFILE_ID } from '../contracts.ts'
import type {
  WorkbenchAuthorityContextId,
  WorkbenchEvidenceDisclosureViewV1,
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

/** Sensitive browser-authored fields for one Service-projected Risk Decision option. */
export interface WorkbenchRiskDecisionSubmissionV1 {
  readonly decision: RiskDecisionKindV1
  readonly rationale: string
  readonly compensatingControls: readonly string[]
  readonly expiresAt: string | null
}

/** Browser-authored reason fields for one exact Service-projected Assessment command. */
export interface WorkbenchAssessmentCommandReasonV1 {
  readonly code: string
  readonly summary: string
}

/** Non-sensitive progress for a Resume or Cancel command at one Snapshot revision. */
export type WorkbenchAssessmentCommandStateV1 =
  | { readonly kind: 'IDLE' }
  | { readonly kind: 'SUBMITTING'; readonly command: 'RESUME' | 'CANCEL' }

/** Non-sensitive progress for confirming one exact Start Preflight. */
export type WorkbenchStartSubmissionStateV1 =
  | { readonly kind: 'IDLE' }
  | { readonly kind: 'SUBMITTING' }

/** Transient Service-owned Export Preview, Receipt, and Delivery status. */
export type WorkbenchExportStateV1 =
  | { readonly kind: 'IDLE' }
  | { readonly kind: 'PREVIEW_LOADING'; readonly deliveryDestinationId: string }
  | { readonly kind: 'PREVIEW_READY'; readonly preview: ExportPreviewV1 }
  | { readonly kind: 'REQUESTING'; readonly preview: ExportPreviewV1 }
  | {
      readonly kind: 'STATUS_READY'
      readonly preview: ExportPreviewV1
      readonly receipt: ExportRequestReceiptV1
      readonly status: ExportStatusV1
      readonly download: WorkbenchExportDownloadStateV1
    }

export type WorkbenchExportDownloadStateV1 =
  | { readonly kind: 'IDLE' }
  | { readonly kind: 'DOWNLOADING' }
  | {
      readonly kind: 'COMPLETE'
      readonly fileName: string
      readonly byteLength: number
      readonly digest: string
      readonly consumedAt: string
    }

/** Non-sensitive command progress retained beside one exact Finding revision. */
export type WorkbenchRiskDecisionSubmissionStateV1 =
  | { readonly kind: 'IDLE' }
  | { readonly kind: 'SUBMITTING'; readonly decision: RiskDecisionKindV1 }

/** Transient metadata disclosure nested under one exact Finding Detail. */
export type WorkbenchEvidenceStateV1 =
  | { readonly kind: 'NOT_LOADED' }
  | { readonly kind: 'METADATA_LOADING'; readonly artifactId: string }
  | {
      readonly kind: 'METADATA_READY'
      readonly view: WorkbenchEvidenceMetadataViewV1
      readonly disclosureStatus: 'NOT_REQUESTED' | 'EXPIRED'
    }
  | {
      readonly kind: 'DISCLOSURE_LOADING'
      readonly metadata: WorkbenchEvidenceMetadataViewV1
    }
  | {
      readonly kind: 'DISCLOSURE_READY'
      readonly metadata: WorkbenchEvidenceMetadataViewV1
      readonly view: WorkbenchEvidenceDisclosureViewV1
    }

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
    readonly riskDecisionSubmission: WorkbenchRiskDecisionSubmissionStateV1
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
  | { readonly kind: 'HEALTH_LOADING' }
  | {
    readonly kind: 'HEALTH_READY'
    readonly health: RuntimeHealthSnapshot
  }
  | { readonly kind: 'BUNDLE_LOADING'; readonly assessmentId: AssessmentId }
  | {
    readonly kind: 'BUNDLE_READY'
    readonly assessmentId: AssessmentId
    readonly manifest: BundleManifestV1
    readonly deliveryDestinationIds: readonly string[]
    readonly export: WorkbenchExportStateV1
  }
  | { readonly kind: 'REPOSITORIES_LOADING' }
  | {
    readonly kind: 'REPOSITORIES_READY'
    readonly repositories: readonly RepositorySnapshotV1[]
    readonly truncated: boolean
  }
  | {
    readonly kind: 'CATALOG_LOADING'
    readonly repository: RepositorySnapshotV1
  }
  | {
    readonly kind: 'PREFLIGHT_LOADING'
    readonly repository: RepositorySnapshotV1
    readonly catalog: SecurityCatalogSnapshotV1
  }
  | {
    readonly kind: 'WIZARD_READY'
    readonly repository: RepositorySnapshotV1
    readonly catalog: SecurityCatalogSnapshotV1
    readonly startPreflight: StartPreflightV1 | null
    readonly startSubmission: WorkbenchStartSubmissionStateV1
  }
  | { readonly kind: 'LOADING'; readonly assessmentId: AssessmentId }
  | {
    readonly kind: 'READY'
    readonly assessmentId: AssessmentId
    readonly snapshot: AssessmentSnapshotV1
    readonly findings: WorkbenchFindingsStateV1
    readonly assessmentCommand: WorkbenchAssessmentCommandStateV1
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
  monitorGeneration: number
  evidenceExpiryTimer: ReturnType<typeof setTimeout> | undefined
  evidenceAbort: AbortController | undefined
}

const CLOSED_STATE: SecurityAssuranceWorkbenchStateV1 = Object.freeze({ kind: 'CLOSED' })
const FINDINGS_NOT_LOADED: WorkbenchFindingsStateV1 = Object.freeze({ kind: 'NOT_LOADED' })
const EVIDENCE_NOT_LOADED: WorkbenchEvidenceStateV1 = Object.freeze({ kind: 'NOT_LOADED' })
const RISK_DECISION_IDLE: WorkbenchRiskDecisionSubmissionStateV1 = Object.freeze({ kind: 'IDLE' })
const ASSESSMENT_COMMAND_IDLE: WorkbenchAssessmentCommandStateV1 = Object.freeze({ kind: 'IDLE' })
const START_SUBMISSION_IDLE: WorkbenchStartSubmissionStateV1 = Object.freeze({ kind: 'IDLE' })
const EXPORT_IDLE: WorkbenchExportStateV1 = Object.freeze({ kind: 'IDLE' })
const EXPORT_DOWNLOAD_IDLE: WorkbenchExportDownloadStateV1 = Object.freeze({ kind: 'IDLE' })
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
      monitorGeneration: 0,
      evidenceExpiryTimer: undefined,
      evidenceAbort: undefined,
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

  /** Open the authority-visible Repository Registry from the current Workbench session. */
  async openRepositories(): Promise<SecurityAssuranceWorkbenchStateV1> {
    const session = this.session
    if (session === undefined) return this.state
    session.monitorGeneration += 1
    this.evidenceRequestGeneration += 1
    this.cancelEvidenceRequest(session)
    this.clearEvidenceExpiry(session)
    session.assessmentId = undefined
    this.publish(Object.freeze({ kind: 'REPOSITORIES_LOADING' }))
    let result: RemoteResult<SecurityResult<import('../contracts.ts').RepositoryListSnapshotV1>>
    try {
      result = await this.ownerCtx.remote.securityAssuranceWorkbench.listRepositories(
        session.contextId,
        { schemaVersion: 1, limit: 100 },
        session.abort.signal,
      )
    } catch (error) {
      return this.failClient(session, error)
    }
    if (!this.isActive(session) || this.state.kind !== 'REPOSITORIES_LOADING') return this.state
    const repositories = this.readRemoteResult(session, result)
    if (repositories === undefined) return this.state
    const ready = Object.freeze({
      kind: 'REPOSITORIES_READY' as const,
      repositories: Object.freeze([...repositories.repositories]),
      truncated: repositories.truncated,
    })
    this.publish(ready)
    return ready
  }

  /** Open the Service-owned Runtime Health projection with current Host authority. */
  async openRuntimeHealth(): Promise<SecurityAssuranceWorkbenchStateV1> {
    const session = this.session
    if (session === undefined) return this.state
    session.monitorGeneration += 1
    this.evidenceRequestGeneration += 1
    this.cancelEvidenceRequest(session)
    this.clearEvidenceExpiry(session)
    session.assessmentId = undefined
    return this.loadRuntimeHealth(session)
  }

  /** Reauthorize and refresh Runtime Health without deriving browser-side health. */
  async refreshRuntimeHealth(): Promise<SecurityAssuranceWorkbenchStateV1> {
    const session = this.session
    if (session === undefined || this.state.kind !== 'HEALTH_READY') return this.state
    return this.loadRuntimeHealth(session)
  }

  /** Open the verified SEALED Bundle and its path-free registered export destinations. */
  async openBundle(): Promise<SecurityAssuranceWorkbenchStateV1> {
    const session = this.session
    const current = this.state
    if (
      session === undefined
      || current.kind !== 'READY'
      || current.snapshot.state !== 'SEALED'
      || current.snapshot.seal === null
      || current.snapshot.verdict === null
    ) return current
    session.monitorGeneration += 1
    this.evidenceRequestGeneration += 1
    this.cancelEvidenceRequest(session)
    this.clearEvidenceExpiry(session)
    const assessmentId = current.assessmentId
    const snapshot = current.snapshot
    this.publish(Object.freeze({ kind: 'BUNDLE_LOADING', assessmentId }))

    let manifestResult: RemoteResult<SecurityResult<BundleManifestV1>>
    try {
      manifestResult = await this.ownerCtx.remote.securityAssuranceWorkbench.getBundleManifest(
        session.contextId,
        { schemaVersion: 1, assessmentId },
        session.abort.signal,
      )
    } catch (error) {
      return this.failClient(session, error)
    }
    if (!this.isActive(session) || this.state.kind !== 'BUNDLE_LOADING') return this.state
    const manifest = this.readRemoteResult(session, manifestResult)
    if (manifest === undefined) return this.state
    if (!matchesBundleManifest(snapshot, manifest)) {
      return this.fail(session, {
        source: 'CLIENT',
        code: 'BUNDLE_PROTOCOL_VIOLATION',
        message: 'The Bundle Manifest does not match the retained SEALED Assessment Snapshot.',
        retryable: false,
      })
    }

    let repositoryResult: RemoteResult<SecurityResult<RepositorySnapshotV1>>
    try {
      repositoryResult = await this.ownerCtx.remote.securityAssuranceWorkbench.getRepository(
        session.contextId,
        { schemaVersion: 1, repositoryId: snapshot.repository.repositoryId },
        session.abort.signal,
      )
    } catch (error) {
      return this.failClient(session, error)
    }
    if (!this.isActive(session) || this.state.kind !== 'BUNDLE_LOADING') return this.state
    const repository = this.readRemoteResult(session, repositoryResult)
    if (repository === undefined) return this.state
    if (
      repository.repositoryId !== snapshot.repository.repositoryId
      || repository.repositoryRevision !== snapshot.repository.repositoryRevision
    ) {
      return this.fail(session, {
        source: 'CLIENT',
        code: 'BUNDLE_REPOSITORY_PROTOCOL_VIOLATION',
        message: 'The Repository binding does not match the SEALED Assessment Snapshot.',
        retryable: false,
      })
    }
    const ready = Object.freeze({
      kind: 'BUNDLE_READY' as const,
      assessmentId,
      manifest,
      deliveryDestinationIds: Object.freeze([...repository.bindings.deliveryDestinationIds]),
      export: EXPORT_IDLE,
    })
    this.publish(ready)
    return ready
  }

  /** Ask the Service to preview one exact frozen Profile and registered Destination. */
  async previewExport(deliveryDestinationId: string): Promise<SecurityAssuranceWorkbenchStateV1> {
    const session = this.session
    const current = this.state
    if (session === undefined || current.kind !== 'BUNDLE_READY') return current
    if (!current.deliveryDestinationIds.includes(deliveryDestinationId)) {
      return this.fail(session, {
        source: 'CLIENT',
        code: 'EXPORT_DESTINATION_NOT_REGISTERED',
        message: 'The Export destination is not one of the frozen Repository bindings.',
        retryable: false,
      })
    }
    this.publish(Object.freeze({
      ...current,
      export: Object.freeze({ kind: 'PREVIEW_LOADING' as const, deliveryDestinationId }),
    }))
    let result: RemoteResult<SecurityResult<import('../contracts.ts').ExportViewV1>>
    try {
      result = await this.ownerCtx.remote.securityAssuranceWorkbench.getExport(
        session.contextId,
        {
          schemaVersion: 1,
          kind: 'PREVIEW',
          assessmentId: current.assessmentId,
          exportProfileId: INTERNAL_JSON_EXPORT_PROFILE_ID,
          deliveryDestinationId,
        },
        session.abort.signal,
      )
    } catch (error) {
      return this.failClient(session, error)
    }
    if (
      !this.isActive(session)
      || this.state.kind !== 'BUNDLE_READY'
      || this.state.export.kind !== 'PREVIEW_LOADING'
      || this.state.export.deliveryDestinationId !== deliveryDestinationId
    ) return this.state
    const view = this.readRemoteResult(session, result)
    if (view === undefined) return this.state
    if (
      view.kind !== 'PREVIEW'
      || view.assessmentId !== current.assessmentId
      || view.assessmentRevision !== current.manifest.assessmentRevision
      || view.sealId !== current.manifest.seal.sealId
      || view.profile.exportProfileId !== INTERNAL_JSON_EXPORT_PROFILE_ID
      || view.destination.deliveryDestinationId !== deliveryDestinationId
    ) {
      return this.fail(session, {
        source: 'CLIENT',
        code: 'EXPORT_PREVIEW_PROTOCOL_VIOLATION',
        message: 'The Export Preview does not match the retained Bundle and registered Destination.',
        retryable: false,
      })
    }
    const ready = Object.freeze({
      ...current,
      export: Object.freeze({ kind: 'PREVIEW_READY' as const, preview: view }),
    })
    this.publish(ready)
    return ready
  }

  /** Submit one exact Service preview, then observe its owner-bound durable Delivery status. */
  async requestExport(): Promise<SecurityAssuranceWorkbenchStateV1> {
    const session = this.session
    const current = this.state
    if (
      session === undefined
      || current.kind !== 'BUNDLE_READY'
      || current.export.kind !== 'PREVIEW_READY'
    ) return current
    const preview = current.export.preview
    let idempotencyKey: string
    try {
      idempotencyKey = nextExportIdempotencyKey()
    } catch (error) {
      return this.failClient(session, error)
    }
    this.publish(Object.freeze({
      ...current,
      export: Object.freeze({ kind: 'REQUESTING' as const, preview }),
    }))
    let receiptResult: RemoteResult<SecurityResult<ExportRequestReceiptV1>>
    try {
      receiptResult = await this.ownerCtx.remote.securityAssuranceWorkbench.requestExport(
        session.contextId,
        {
          schemaVersion: 1,
          idempotencyKey,
          assessmentId: current.assessmentId,
          expectedAssessmentRevision: current.manifest.assessmentRevision,
          exportProfileId: preview.profile.exportProfileId,
          deliveryDestinationId: preview.destination.deliveryDestinationId,
        },
        session.abort.signal,
      )
    } catch (error) {
      return this.failClient(session, error)
    }
    if (
      !this.isActive(session)
      || this.state.kind !== 'BUNDLE_READY'
      || this.state.export.kind !== 'REQUESTING'
      || this.state.export.preview !== preview
    ) return this.state
    const receipt = this.readRemoteResult(session, receiptResult)
    if (receipt === undefined) return this.state
    if (
      receipt.operation !== 'request_export'
      || receipt.assessmentId !== current.assessmentId
      || receipt.assessmentRevision !== current.manifest.assessmentRevision
      || receipt.idempotencyKey !== idempotencyKey
      || receipt.acceptedState !== 'PENDING'
    ) {
      return this.fail(session, {
        source: 'CLIENT',
        code: 'EXPORT_RECEIPT_PROTOCOL_VIOLATION',
        message: 'The Export Receipt does not match the submitted Preview.',
        retryable: false,
      })
    }

    let statusResult: RemoteResult<SecurityResult<import('../contracts.ts').ExportViewV1>>
    try {
      statusResult = await this.ownerCtx.remote.securityAssuranceWorkbench.getExport(
        session.contextId,
        { schemaVersion: 1, kind: 'STATUS', exportId: receipt.exportId },
        session.abort.signal,
      )
    } catch (error) {
      return this.failClient(session, error)
    }
    if (
      !this.isActive(session)
      || this.state.kind !== 'BUNDLE_READY'
      || this.state.export.kind !== 'REQUESTING'
      || this.state.export.preview !== preview
    ) return this.state
    const status = this.readRemoteResult(session, statusResult)
    if (status === undefined) return this.state
    if (
      status.kind !== 'STATUS'
      || status.exportId !== receipt.exportId
      || status.assessmentId !== current.assessmentId
      || status.assessmentRevision !== current.manifest.assessmentRevision
      || status.profile.exportProfileId !== preview.profile.exportProfileId
      || status.destination.deliveryDestinationId !== preview.destination.deliveryDestinationId
    ) {
      return this.fail(session, {
        source: 'CLIENT',
        code: 'EXPORT_STATUS_PROTOCOL_VIOLATION',
        message: 'The Export status does not match the accepted Receipt and Preview.',
        retryable: false,
      })
    }
    const ready = Object.freeze({
      ...current,
      export: Object.freeze({
        kind: 'STATUS_READY' as const,
        preview,
        receipt,
        status,
        download: EXPORT_DOWNLOAD_IDLE,
      }),
    })
    this.publish(ready)
    return ready
  }

  /** Re-read durable Delivery truth; this observes Service retry state and never performs a retry itself. */
  async refreshExportStatus(): Promise<SecurityAssuranceWorkbenchStateV1> {
    const session = this.session
    const current = this.state
    if (
      session === undefined
      || current.kind !== 'BUNDLE_READY'
      || current.export.kind !== 'STATUS_READY'
    ) return current
    const retained = current.export
    let result: RemoteResult<SecurityResult<import('../contracts.ts').ExportViewV1>>
    try {
      result = await this.ownerCtx.remote.securityAssuranceWorkbench.getExport(
        session.contextId,
        { schemaVersion: 1, kind: 'STATUS', exportId: retained.receipt.exportId },
        session.abort.signal,
      )
    } catch (error) {
      return this.failClient(session, error)
    }
    if (
      !this.isActive(session)
      || this.state.kind !== 'BUNDLE_READY'
      || this.state.export !== retained
    ) return this.state
    const status = this.readRemoteResult(session, result)
    if (status === undefined) return this.state
    const allowedTransitions: Readonly<Record<
      ExportDeliveryStatusV1,
      readonly ExportDeliveryStatusV1[]
    >> = {
      PENDING: ['PENDING', 'DELIVERED', 'FAILED', 'EXPIRED'],
      DELIVERED: ['DELIVERED', 'EXPIRED'],
      FAILED: ['FAILED'],
      EXPIRED: ['EXPIRED'],
    }
    if (
      status.kind !== 'STATUS'
      || status.exportId !== retained.status.exportId
      || status.assessmentId !== current.assessmentId
      || status.assessmentRevision !== current.manifest.assessmentRevision
      || status.profile.exportProfileId !== retained.preview.profile.exportProfileId
      || status.destination.deliveryDestinationId !== retained.preview.destination.deliveryDestinationId
      || status.createdAt !== retained.status.createdAt
      || status.delivery.attemptCount < retained.status.delivery.attemptCount
      || !allowedTransitions[retained.status.status].includes(status.status)
    ) {
      return this.fail(session, {
        source: 'CLIENT',
        code: 'EXPORT_STATUS_PROTOCOL_VIOLATION',
        message: 'The refreshed Export status regressed or changed its accepted identity.',
        retryable: false,
      })
    }
    const ready = Object.freeze({
      ...current,
      export: Object.freeze({
        ...retained,
        status,
        download: EXPORT_DOWNLOAD_IDLE,
      }),
    })
    this.publish(ready)
    return ready
  }

  /** Reauthorize, atomically consume one Host-only capability, verify bytes, and invoke browser download. */
  async downloadExport(): Promise<SecurityAssuranceWorkbenchStateV1> {
    const session = this.session
    const current = this.state
    if (
      session === undefined
      || current.kind !== 'BUNDLE_READY'
      || current.export.kind !== 'STATUS_READY'
      || current.export.status.status !== 'DELIVERED'
      || current.export.status.artifact === null
      || current.export.status.accessAction.kind !== 'ONE_USE_DOWNLOAD'
      || current.export.download.kind === 'DOWNLOADING'
    ) return current
    const retainedExport = current.export
    const artifact = retainedExport.status.artifact
    if (artifact === null) return current
    this.publish(Object.freeze({
      ...current,
      export: Object.freeze({ ...retainedExport, download: Object.freeze({ kind: 'DOWNLOADING' as const }) }),
    }))
    let result: RemoteResult<SecurityResult<import('../contracts.ts').ExportViewV1>>
    try {
      result = await this.ownerCtx.remote.securityAssuranceWorkbench.getExport(
        session.contextId,
        {
          schemaVersion: 1,
          kind: 'DOWNLOAD',
          exportId: retainedExport.status.exportId,
          artifactId: artifact.artifactId,
          expectedDigest: artifact.digest,
        },
        session.abort.signal,
      )
    } catch (error) {
      return this.failClient(session, error)
    }
    if (
      !this.isActive(session)
      || this.state.kind !== 'BUNDLE_READY'
      || this.state.export.kind !== 'STATUS_READY'
      || this.state.export.status !== retainedExport.status
      || this.state.export.download.kind !== 'DOWNLOADING'
    ) return this.state
    const view = this.readRemoteResult(session, result)
    if (view === undefined) return this.state
    if (
      view.kind !== 'DOWNLOAD'
      || view.exportId !== retainedExport.status.exportId
      || view.assessmentId !== current.assessmentId
      || view.assessmentRevision !== current.manifest.assessmentRevision
      || view.artifactId !== artifact.artifactId
      || view.mediaType !== artifact.digest.mediaType
      || view.byteLength !== artifact.digest.byteLength
      || view.digest.value !== artifact.digest.value
      || view.digest.canonicalization !== 'raw-bytes'
      || view.content.encoding !== 'base64'
      || view.capability.kind !== 'CONSUMED_ONE_USE'
    ) {
      return this.fail(session, {
        source: 'CLIENT',
        code: 'EXPORT_DOWNLOAD_PROTOCOL_VIOLATION',
        message: 'The one-use Export download does not match the retained delivered artifact.',
        retryable: false,
      })
    }
    let bytes: Uint8Array
    try {
      bytes = decodeExportBase64(view.content.value)
      if (
        bytes.byteLength !== view.byteLength
        || await browserSha256Hex(bytes) !== view.digest.value
      ) throw new Error('Export download digest mismatch')
      triggerExportDownload(view, bytes)
    } catch (error) {
      return this.failClient(session, error)
    }
    const ready = Object.freeze({
      ...current,
      export: Object.freeze({
        ...retainedExport,
        download: Object.freeze({
          kind: 'COMPLETE' as const,
          fileName: view.fileName,
          byteLength: view.byteLength,
          digest: view.digest.value,
          consumedAt: view.capability.consumedAt,
        }),
      }),
    })
    this.publish(ready)
    return ready
  }

  /** Re-fetch the current Assessment after leaving its Bundle and Export readiness view. */
  async backToAssessmentDetail(): Promise<SecurityAssuranceWorkbenchStateV1> {
    const session = this.session
    const current = this.state
    if (session === undefined || current.kind !== 'BUNDLE_READY') return current
    return this.openAssessment({
      securityAssuranceWorkbenchContextId: session.contextId,
      assessmentId: current.assessmentId,
    })
  }

  /** Resolve the repository-specific Catalog before accepting any wizard selection. */
  async selectRepository(repositoryId: RepositorySnapshotV1['repositoryId']): Promise<SecurityAssuranceWorkbenchStateV1> {
    const session = this.session
    const current = this.state
    if (session === undefined || current.kind !== 'REPOSITORIES_READY') return current
    const repository = current.repositories.find(candidate => candidate.repositoryId === repositoryId)
    if (repository === undefined || repository.state !== 'ENABLED') {
      return this.fail(session, {
        source: 'CLIENT',
        code: 'REPOSITORY_NOT_STARTABLE',
        message: 'The Repository is not an enabled authority-projected choice.',
        retryable: false,
      })
    }
    this.publish(Object.freeze({ kind: 'CATALOG_LOADING', repository }))
    let result: RemoteResult<SecurityResult<SecurityCatalogSnapshotV1>>
    try {
      result = await this.ownerCtx.remote.securityAssuranceWorkbench.getCatalog(
        session.contextId,
        { schemaVersion: 1, repositoryId },
        session.abort.signal,
      )
    } catch (error) {
      return this.failClient(session, error)
    }
    if (!this.isActive(session) || this.state.kind !== 'CATALOG_LOADING') return this.state
    const catalog = this.readRemoteResult(session, result)
    if (catalog === undefined) return this.state
    if (
      catalog.repository?.repositoryId !== repositoryId
      || catalog.repository.repositoryRevision !== repository.repositoryRevision
      || catalog.startPreflight !== null
    ) {
      return this.fail(session, {
        source: 'CLIENT',
        code: 'CATALOG_PROTOCOL_VIOLATION',
        message: 'The Security Catalog is not bound to the selected Repository revision.',
        retryable: false,
      })
    }
    return this.publishWizard(repository, catalog, null)
  }

  /** Ask the Service to resolve an exact, immutable Start Preflight proposal. */
  async requestStartPreflight(
    selection: StartAssessmentSelectionV1,
  ): Promise<SecurityAssuranceWorkbenchStateV1> {
    const session = this.session
    const current = this.state
    if (
      session === undefined
      || current.kind !== 'WIZARD_READY'
      || current.startSubmission.kind !== 'IDLE'
      || selection.repositoryId !== current.repository.repositoryId
      || !current.catalog.assessmentModes.some(mode => (
        mode.assessmentMode === selection.assessmentMode && mode.support === 'SUPPORTED'
      ))
      || !current.catalog.assessmentProfiles.some(
        profile => profile.assessmentProfileId === selection.assessmentProfileId,
      )
      || selection.requestedStrongerControlIds.some(controlId => (
        !current.catalog.strongerControls.some(control => control.controlId === controlId)
      ))
    ) {
      return current
    }
    this.publish(Object.freeze({
      kind: 'PREFLIGHT_LOADING',
      repository: current.repository,
      catalog: current.catalog,
    }))
    let result: RemoteResult<SecurityResult<SecurityCatalogSnapshotV1>>
    try {
      result = await this.ownerCtx.remote.securityAssuranceWorkbench.getCatalog(
        session.contextId,
        {
          schemaVersion: 1,
          repositoryId: current.repository.repositoryId,
          proposedStart: selection,
        },
        session.abort.signal,
      )
    } catch (error) {
      return this.failClient(session, error)
    }
    if (!this.isActive(session) || this.state.kind !== 'PREFLIGHT_LOADING') return this.state
    const catalog = this.readRemoteResult(session, result)
    if (catalog === undefined) return this.state
    if (
      catalog.repository?.repositoryId !== current.repository.repositoryId
      || catalog.repository.repositoryRevision !== current.repository.repositoryRevision
      || catalog.startPreflight === null
      || JSON.stringify(catalog.startPreflight.selection) !== JSON.stringify(selection)
    ) {
      return this.fail(session, {
        source: 'CLIENT',
        code: 'PREFLIGHT_PROTOCOL_VIOLATION',
        message: 'The Start Preflight is not bound to the submitted wizard selection.',
        retryable: false,
      })
    }
    return this.publishWizard(current.repository, catalog, catalog.startPreflight)
  }

  /** Cancel the current proposal without mutating any Assessment. */
  cancelStartPreflight(): SecurityAssuranceWorkbenchStateV1 {
    const current = this.state
    if (current.kind !== 'WIZARD_READY' || current.startSubmission.kind !== 'IDLE') return current
    return this.publishWizard(current.repository, current.catalog, null)
  }

  /** Confirm the exact proposal digest, then open the committed Assessment Snapshot. */
  async confirmStartAssessment(): Promise<SecurityAssuranceWorkbenchStateV1> {
    const session = this.session
    const current = this.state
    if (
      session === undefined
      || current.kind !== 'WIZARD_READY'
      || current.startSubmission.kind !== 'IDLE'
      || current.startPreflight === null
      || !current.startPreflight.admissible
    ) return current
    let idempotencyKey: string
    try {
      idempotencyKey = nextStartAssessmentIdempotencyKey()
    } catch (error) {
      return this.failClient(session, error)
    }
    this.publishWizard(
      current.repository,
      current.catalog,
      current.startPreflight,
      Object.freeze({ kind: 'SUBMITTING' }),
    )
    let result: RemoteResult<SecurityResult<AssessmentReceiptV1>>
    try {
      result = await this.ownerCtx.remote.securityAssuranceWorkbench.startAssessment(
        session.contextId,
        {
          ...current.startPreflight.selection,
          idempotencyKey,
          startPreflightDigest: current.startPreflight.proposalDigest,
        },
        session.abort.signal,
      )
    } catch (error) {
      return this.failClient(session, error)
    }
    if (
      !this.isActive(session)
      || this.state.kind !== 'WIZARD_READY'
      || this.state.startSubmission.kind !== 'SUBMITTING'
    ) return this.state
    const receipt = this.readRemoteResult(session, result)
    if (receipt === undefined) return this.state
    if (
      receipt.operation !== 'start_assessment'
      || receipt.repositoryId !== current.repository.repositoryId
      || receipt.repositoryRevision !== current.repository.repositoryRevision
      || receipt.idempotencyKey !== idempotencyKey
      || receipt.assessmentRevision !== 1
      || receipt.state !== 'CREATED'
    ) {
      return this.fail(session, {
        source: 'CLIENT',
        code: 'START_RECEIPT_PROTOCOL_VIOLATION',
        message: 'The Assessment Receipt does not match the confirmed Start Preflight.',
        retryable: false,
      })
    }
    session.assessmentId = receipt.assessmentId
    return this.loadAssessment(session, receipt.assessmentId)
  }

  /** Return to the authority-projected Assessment selector using the same Host context. */
  async backToAssessmentSelection(): Promise<SecurityAssuranceWorkbenchStateV1> {
    const session = this.session
    if (session === undefined) return this.state
    return this.openAssessmentSelection({
      securityAssuranceWorkbenchContextId: session.contextId,
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
      riskDecisionSubmission: RISK_DECISION_IDLE,
    }))
  }

  /** Submit one exact Service-projected Risk Decision without accepting browser authority fields. */
  async recordRiskDecision(
    submission: WorkbenchRiskDecisionSubmissionV1,
  ): Promise<SecurityAssuranceWorkbenchStateV1> {
    const session = this.session
    const current = this.state
    if (
      session === undefined
      || current.kind !== 'READY'
      || current.findings.kind !== 'DETAIL_READY'
      || current.findings.riskDecisionSubmission.kind !== 'IDLE'
    ) return current

    const currentFindings = current.findings
    const detail = currentFindings.detail
    const action = current.snapshot.availableActions.find(candidate => (
      candidate.kind === 'RECORD_RISK_DECISION'
      && candidate.finding.recordId === detail.recordId
      && candidate.finding.recordRevision === detail.recordRevision
    ))
    const normalized = normalizeRiskDecisionSubmission(submission)
    if (
      action?.kind !== 'RECORD_RISK_DECISION'
      || !matchesRiskDecisionAction(current.snapshot, detail, action, normalized)
    ) {
      return this.fail(session, {
        source: 'CLIENT',
        code: 'RISK_DECISION_ACTION_MISMATCH',
        message: 'The Risk Decision does not match an option projected for this Finding revision.',
        retryable: false,
      })
    }

    let idempotencyKey: string
    try {
      idempotencyKey = nextRiskDecisionIdempotencyKey()
    } catch (error) {
      return this.failClient(session, error)
    }
    this.evidenceRequestGeneration += 1
    session.monitorGeneration += 1
    this.cancelEvidenceRequest(session)
    this.clearEvidenceExpiry(session)
    this.publishReady(current.assessmentId, current.snapshot, Object.freeze({
      ...currentFindings,
      evidence: EVIDENCE_NOT_LOADED,
      riskDecisionSubmission: Object.freeze({
        kind: 'SUBMITTING' as const,
        decision: normalized.decision,
      }),
    }))

    let result: RemoteResult<SecurityResult<RiskDecisionReceiptV1>>
    try {
      result = await this.ownerCtx.remote.securityAssuranceWorkbench.recordRiskDecision(
        session.contextId,
        {
          schemaVersion: 1,
          idempotencyKey,
          assessmentId: current.assessmentId,
          expectedAssessmentRevision: action.expectedAssessmentRevision,
          finding: action.finding,
          ...normalized,
        },
        session.abort.signal,
      )
    } catch (error) {
      if (!this.isActiveRiskDecisionRequest(
        session,
        current.snapshot.assessmentRevision,
        detail.recordId,
      )) return this.state
      return this.failClient(session, error)
    }
    if (!this.isActiveRiskDecisionRequest(
      session,
      current.snapshot.assessmentRevision,
      detail.recordId,
    )) return this.state
    const receipt = this.readRemoteResult(session, result)
    if (receipt === undefined) return this.state
    if (!matchesRiskDecisionReceipt(
      receipt,
      current.assessmentId,
      action,
      normalized,
      idempotencyKey,
    )) {
      return this.fail(session, {
        source: 'CLIENT',
        code: 'RISK_DECISION_PROTOCOL_VIOLATION',
        message: 'The Risk Decision receipt does not match the submitted Service action.',
        retryable: false,
      })
    }

    let refreshed: RemoteResult<SecurityResult<AssessmentSnapshotV1>>
    try {
      refreshed = await this.ownerCtx.remote.securityAssuranceWorkbench.getAssessment(
        session.contextId,
        { schemaVersion: 1, assessmentId: current.assessmentId },
        session.abort.signal,
      )
    } catch (error) {
      if (!this.isActiveRiskDecisionRequest(
        session,
        current.snapshot.assessmentRevision,
        detail.recordId,
      )) return this.state
      return this.failClient(session, error)
    }
    if (!this.isActiveRiskDecisionRequest(
      session,
      current.snapshot.assessmentRevision,
      detail.recordId,
    )) return this.state
    const snapshot = this.readRemoteResult(session, refreshed)
    if (snapshot === undefined) return this.state
    if (
      snapshot.assessmentId !== current.assessmentId
      || snapshot.assessmentRevision < receipt.assessmentRevision
    ) {
      return this.fail(session, {
        source: 'CLIENT',
        code: 'RISK_DECISION_PROTOCOL_VIOLATION',
        message: 'The refreshed Assessment does not include the committed Risk Decision revision.',
        retryable: false,
      })
    }
    const ready = this.publishReady(current.assessmentId, snapshot)
    if (!isTerminal(snapshot)) this.startMonitor(session, current.assessmentId, snapshot.assessmentRevision)
    return ready
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
      || current.findings.riskDecisionSubmission.kind !== 'IDLE'
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
    const evidenceAbort = this.beginEvidenceRequest(session)
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
        evidenceAbort.signal,
      )
    } catch (error) {
      if (!this.isActiveEvidenceRequest(
        session,
        current.snapshot.assessmentRevision,
        evidenceArtifactId,
        evidenceRequestGeneration,
      )) {
        this.finishEvidenceRequest(session, evidenceAbort)
        return this.state
      }
      this.finishEvidenceRequest(session, evidenceAbort)
      return this.failClient(session, error)
    }
    if (!this.isActiveEvidenceRequest(
      session,
      current.snapshot.assessmentRevision,
      evidenceArtifactId,
      evidenceRequestGeneration,
    )) {
      this.finishEvidenceRequest(session, evidenceAbort)
      return this.state
    }
    this.finishEvidenceRequest(session, evidenceAbort)
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
      evidence: Object.freeze({
        kind: 'METADATA_READY' as const,
        view,
        disclosureStatus: 'NOT_REQUESTED' as const,
      }),
    }))
  }

  /** Explicitly reauthorize bounded content from the retained metadata binding. */
  async discloseEvidence(): Promise<SecurityAssuranceWorkbenchStateV1> {
    const session = this.session
    const current = this.state
    if (
      session === undefined
      || current.kind !== 'READY'
      || current.findings.kind !== 'DETAIL_READY'
      || current.findings.evidence.kind !== 'METADATA_READY'
    ) return current
    const currentFindings = current.findings
    const currentEvidence = current.findings.evidence
    const metadata = currentEvidence.view
    const link = currentFindings.detail.evidenceLinks.find(candidate => (
      candidate.artifactId === metadata.evidence.artifactId
      && sameDigest(candidate.digest, metadata.evidence.digest)
    ))
    if (link === undefined) {
      return this.fail(session, {
        source: 'CLIENT',
        code: 'EVIDENCE_BINDING_LOST',
        message: 'The retained Evidence metadata is no longer linked to the Finding Detail.',
        retryable: false,
      })
    }
    this.clearEvidenceExpiry(session)
    const requestGeneration = ++this.evidenceRequestGeneration
    const evidenceAbort = this.beginEvidenceRequest(session)
    this.publishReady(current.assessmentId, current.snapshot, Object.freeze({
      ...currentFindings,
      evidence: Object.freeze({ kind: 'DISCLOSURE_LOADING' as const, metadata }),
    }))

    let result: RemoteResult<SecurityResult<WorkbenchEvidenceDisclosureViewV1>>
    try {
      result = await this.ownerCtx.remote.securityAssuranceWorkbench.discloseEvidence(
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
          purpose: 'VALIDATION_REVIEW',
          viewProfileId: 'security/evidence-view/bounded-json-v1',
        },
        evidenceAbort.signal,
      )
    } catch (error) {
      if (!this.isActiveDisclosureRequest(
        session,
        current.snapshot.assessmentRevision,
        metadata.evidence.artifactId,
        requestGeneration,
      )) {
        this.finishEvidenceRequest(session, evidenceAbort)
        return this.state
      }
      this.finishEvidenceRequest(session, evidenceAbort)
      return this.failClient(session, error)
    }
    if (!this.isActiveDisclosureRequest(
      session,
      current.snapshot.assessmentRevision,
      metadata.evidence.artifactId,
      requestGeneration,
    )) {
      this.finishEvidenceRequest(session, evidenceAbort)
      return this.state
    }
    this.finishEvidenceRequest(session, evidenceAbort)
    const view = this.readRemoteResult(session, result)
    if (view === undefined) return this.state
    if (!matchesEvidenceDisclosure(currentFindings.detail, link, metadata, view)) {
      return this.fail(session, {
        source: 'CLIENT',
        code: 'EVIDENCE_DISCLOSURE_PROTOCOL_VIOLATION',
        message: 'The bounded Evidence View does not match the selected metadata binding.',
        retryable: false,
      })
    }
    const ready = this.publishReady(current.assessmentId, current.snapshot, Object.freeze({
      ...currentFindings,
      evidence: Object.freeze({ kind: 'DISCLOSURE_READY' as const, metadata, view }),
    }))
    if (view.content.kind === 'BOUNDED_JSON') {
      this.scheduleEvidenceExpiry(session, requestGeneration)
    }
    return ready
  }

  /** Hide and immediately discard any in-memory bounded disclosure. */
  hideEvidenceDisclosure(): SecurityAssuranceWorkbenchStateV1 {
    const session = this.session
    const current = this.state
    if (
      session === undefined
      || current.kind !== 'READY'
      || current.findings.kind !== 'DETAIL_READY'
      || (
        current.findings.evidence.kind !== 'DISCLOSURE_LOADING'
        && current.findings.evidence.kind !== 'DISCLOSURE_READY'
      )
    ) return current
    const metadata = current.findings.evidence.metadata
    this.evidenceRequestGeneration += 1
    this.cancelEvidenceRequest(session)
    this.clearEvidenceExpiry(session)
    return this.publishReady(current.assessmentId, current.snapshot, Object.freeze({
      ...current.findings,
      evidence: Object.freeze({
        kind: 'METADATA_READY' as const,
        view: metadata,
        disclosureStatus: 'NOT_REQUESTED' as const,
      }),
    }))
  }

  /** Return from Evidence metadata and discard the protected View. */
  backToFindingDetail(): SecurityAssuranceWorkbenchStateV1 {
    const current = this.state
    if (current.kind !== 'READY' || current.findings.kind !== 'DETAIL_READY') return current
    this.evidenceRequestGeneration += 1
    if (this.session !== undefined) {
      this.cancelEvidenceRequest(this.session)
      this.clearEvidenceExpiry(this.session)
    }
    return this.publishReady(current.assessmentId, current.snapshot, Object.freeze({
      ...current.findings,
      evidence: EVIDENCE_NOT_LOADED,
    }))
  }

  /** Return from Finding Detail to the already authorized redacted list. */
  backToFindingList(): SecurityAssuranceWorkbenchStateV1 {
    const current = this.state
    if (
      current.kind !== 'READY'
      || current.findings.kind !== 'DETAIL_READY'
      || current.findings.riskDecisionSubmission.kind !== 'IDLE'
    ) return current
    this.evidenceRequestGeneration += 1
    if (this.session !== undefined) {
      this.cancelEvidenceRequest(this.session)
      this.clearEvidenceExpiry(this.session)
    }
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
      monitorGeneration: 0,
      evidenceExpiryTimer: undefined,
      evidenceAbort: undefined,
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
    if (!isTerminal(snapshot)) this.startMonitor(session, assessmentId, snapshot.assessmentRevision)
    return ready
  }

  /** Resume exactly the frozen BLOCKED Assessment revision projected by the Service. */
  async resumeAssessment(
    reason: WorkbenchAssessmentCommandReasonV1,
  ): Promise<SecurityAssuranceWorkbenchStateV1> {
    return this.submitAssessmentCommand('RESUME', reason)
  }

  /** Request cancellation of exactly the Assessment revision projected by the Service. */
  async cancelAssessment(
    reason: WorkbenchAssessmentCommandReasonV1,
  ): Promise<SecurityAssuranceWorkbenchStateV1> {
    return this.submitAssessmentCommand('CANCEL', reason)
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
    monitorGeneration: number,
  ): Promise<void> {
    let afterRevision = firstRevision
    while (this.isActive(session) && session.monitorGeneration === monitorGeneration) {
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
      if (!this.isActive(session) || session.monitorGeneration !== monitorGeneration) return
      const signal = this.readRemoteResult(session, waited)
      if (signal === undefined) return
      if (!signal.changed) continue

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
      if (!this.isActive(session) || session.monitorGeneration !== monitorGeneration) return
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

  private startMonitor(
    session: LiveAssessmentSession,
    assessmentId: AssessmentId,
    assessmentRevision: number,
  ): void {
    const monitorGeneration = ++session.monitorGeneration
    void this.monitor(session, assessmentId, assessmentRevision, monitorGeneration)
  }

  private async submitAssessmentCommand(
    command: 'RESUME' | 'CANCEL',
    reason: WorkbenchAssessmentCommandReasonV1,
  ): Promise<SecurityAssuranceWorkbenchStateV1> {
    const session = this.session
    const current = this.state
    if (
      session === undefined
      || current.kind !== 'READY'
      || current.assessmentCommand.kind !== 'IDLE'
    ) return current
    const actionKind = command === 'RESUME' ? 'RESUME_ASSESSMENT' : 'CANCEL_ASSESSMENT'
    const action = current.snapshot.availableActions.find(candidate => candidate.kind === actionKind)
    const normalizedReason = normalizeAssessmentCommandReason(reason)
    if (
      action === undefined
      || action.expectedAssessmentRevision !== current.snapshot.assessmentRevision
      || !isAssessmentCommandReason(normalizedReason)
    ) {
      return this.fail(session, {
        source: 'CLIENT',
        code: 'ASSESSMENT_COMMAND_ACTION_MISMATCH',
        message: 'The Assessment command does not match a current Service-projected action.',
        retryable: false,
      })
    }

    let idempotencyKey: string
    try {
      idempotencyKey = nextAssessmentCommandIdempotencyKey(command)
    } catch (error) {
      return this.failClient(session, error)
    }
    session.monitorGeneration += 1
    this.publishReady(
      current.assessmentId,
      current.snapshot,
      current.findings,
      Object.freeze({ kind: 'SUBMITTING', command }),
    )

    const request = {
      schemaVersion: 1 as const,
      assessmentId: current.assessmentId,
      expectedAssessmentRevision: action.expectedAssessmentRevision,
      idempotencyKey,
      reason: normalizedReason,
    }
    let receipt: AssessmentResumeReceiptV1 | AssessmentCancellationReceiptV1 | undefined
    try {
      if (command === 'RESUME') {
        const result = await this.ownerCtx.remote.securityAssuranceWorkbench.resumeAssessment(
          session.contextId,
          request,
          session.abort.signal,
        )
        receipt = this.readRemoteResult(session, result)
      } else {
        const result = await this.ownerCtx.remote.securityAssuranceWorkbench.cancelAssessment(
          session.contextId,
          request,
          session.abort.signal,
        )
        receipt = this.readRemoteResult(session, result)
      }
    } catch (error) {
      if (!this.isActiveAssessmentCommand(session, current.snapshot.assessmentRevision, command)) {
        return this.state
      }
      return this.failClient(session, error)
    }
    if (!this.isActiveAssessmentCommand(session, current.snapshot.assessmentRevision, command)) {
      return this.state
    }
    if (
      receipt === undefined
      || !matchesAssessmentCommandReceipt(
        receipt,
        command,
        current.snapshot,
        action.expectedAssessmentRevision,
        idempotencyKey,
      )
    ) {
      return this.fail(session, {
        source: 'CLIENT',
        code: 'ASSESSMENT_COMMAND_PROTOCOL_VIOLATION',
        message: 'The Assessment command receipt does not match the submitted Service action.',
        retryable: false,
      })
    }

    let refreshed: RemoteResult<SecurityResult<AssessmentSnapshotV1>>
    try {
      refreshed = await this.ownerCtx.remote.securityAssuranceWorkbench.getAssessment(
        session.contextId,
        { schemaVersion: 1, assessmentId: current.assessmentId },
        session.abort.signal,
      )
    } catch (error) {
      if (!this.isActiveAssessmentCommand(session, current.snapshot.assessmentRevision, command)) {
        return this.state
      }
      return this.failClient(session, error)
    }
    if (!this.isActiveAssessmentCommand(session, current.snapshot.assessmentRevision, command)) {
      return this.state
    }
    const snapshot = this.readRemoteResult(session, refreshed)
    if (snapshot === undefined) return this.state
    if (
      snapshot.assessmentId !== current.assessmentId
      || snapshot.assessmentRevision < receipt.assessmentRevision
    ) {
      return this.fail(session, {
        source: 'CLIENT',
        code: 'ASSESSMENT_COMMAND_PROTOCOL_VIOLATION',
        message: 'The refreshed Assessment does not include the committed command revision.',
        retryable: false,
      })
    }
    const ready = this.publishReady(current.assessmentId, snapshot)
    if (!isTerminal(snapshot)) this.startMonitor(session, current.assessmentId, snapshot.assessmentRevision)
    return ready
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
    assessmentCommand: WorkbenchAssessmentCommandStateV1 = ASSESSMENT_COMMAND_IDLE,
  ): SecurityAssuranceWorkbenchStateV1 {
    const ready = Object.freeze({
      kind: 'READY' as const,
      assessmentId,
      snapshot,
      findings,
      assessmentCommand,
    })
    this.publish(ready)
    return ready
  }

  private async loadRuntimeHealth(
    session: LiveAssessmentSession,
  ): Promise<SecurityAssuranceWorkbenchStateV1> {
    this.publish(Object.freeze({ kind: 'HEALTH_LOADING' }))
    let result: RemoteResult<SecurityResult<RuntimeHealthSnapshot>>
    try {
      result = await this.ownerCtx.remote.securityAssuranceWorkbench.getHealth(
        session.contextId,
        { schemaVersion: 1 },
        session.abort.signal,
      )
    } catch (error) {
      return this.failClient(session, error)
    }
    if (!this.isActive(session) || this.state.kind !== 'HEALTH_LOADING') return this.state
    const health = this.readRemoteResult(session, result)
    if (health === undefined) return this.state
    const ready = Object.freeze({ kind: 'HEALTH_READY' as const, health })
    this.publish(ready)
    return ready
  }

  private publishWizard(
    repository: RepositorySnapshotV1,
    catalog: SecurityCatalogSnapshotV1,
    startPreflight: StartPreflightV1 | null,
    startSubmission: WorkbenchStartSubmissionStateV1 = START_SUBMISSION_IDLE,
  ): SecurityAssuranceWorkbenchStateV1 {
    const ready = Object.freeze({
      kind: 'WIZARD_READY' as const,
      repository,
      catalog,
      startPreflight,
      startSubmission,
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
    this.cancelEvidenceRequest(session)
    this.clearEvidenceExpiry(session)
    session.abort.abort()
  }

  private eraseSession(): void {
    const active = this.session
    this.session = undefined
    if (active !== undefined) {
      this.cancelEvidenceRequest(active)
      this.clearEvidenceExpiry(active)
    }
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

  private isActiveDisclosureRequest(
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
      && this.state.findings.evidence.kind === 'DISCLOSURE_LOADING'
      && this.state.findings.evidence.metadata.evidence.artifactId === evidenceArtifactId
  }

  private isActiveRiskDecisionRequest(
    session: LiveAssessmentSession,
    assessmentRevision: number,
    recordId: string,
  ): boolean {
    return this.isActive(session)
      && this.state.kind === 'READY'
      && this.state.snapshot.assessmentRevision === assessmentRevision
      && this.state.findings.kind === 'DETAIL_READY'
      && this.state.findings.detail.recordId === recordId
      && this.state.findings.riskDecisionSubmission.kind === 'SUBMITTING'
  }

  private isActiveAssessmentCommand(
    session: LiveAssessmentSession,
    assessmentRevision: number,
    command: 'RESUME' | 'CANCEL',
  ): boolean {
    return this.isActive(session)
      && this.state.kind === 'READY'
      && this.state.snapshot.assessmentRevision === assessmentRevision
      && this.state.assessmentCommand.kind === 'SUBMITTING'
      && this.state.assessmentCommand.command === command
  }

  private scheduleEvidenceExpiry(
    session: LiveAssessmentSession,
    requestGeneration: number,
  ): void {
    this.clearEvidenceExpiry(session)
    const current = this.state
    if (
      !this.isActive(session)
      || this.evidenceRequestGeneration !== requestGeneration
      || current.kind !== 'READY'
      || current.findings.kind !== 'DETAIL_READY'
      || current.findings.evidence.kind !== 'DISCLOSURE_READY'
      || current.findings.evidence.view.content.kind !== 'BOUNDED_JSON'
    ) return
    const remaining = Date.parse(current.findings.evidence.view.content.expiresAt) - Date.now()
    if (remaining <= 0) {
      const metadata = current.findings.evidence.metadata
      this.publishReady(current.assessmentId, current.snapshot, Object.freeze({
        ...current.findings,
        evidence: Object.freeze({
          kind: 'METADATA_READY' as const,
          view: metadata,
          disclosureStatus: 'EXPIRED' as const,
        }),
      }))
      return
    }
    session.evidenceExpiryTimer = setTimeout(
      () => { this.scheduleEvidenceExpiry(session, requestGeneration) },
      Math.min(remaining, 2_147_483_647),
    )
  }

  private clearEvidenceExpiry(session: LiveAssessmentSession): void {
    if (session.evidenceExpiryTimer === undefined) return
    clearTimeout(session.evidenceExpiryTimer)
    session.evidenceExpiryTimer = undefined
  }

  private beginEvidenceRequest(session: LiveAssessmentSession): AbortController {
    this.cancelEvidenceRequest(session)
    const request = new AbortController()
    session.evidenceAbort = request
    return request
  }

  private finishEvidenceRequest(
    session: LiveAssessmentSession,
    request: AbortController,
  ): void {
    if (session.evidenceAbort === request) session.evidenceAbort = undefined
  }

  private cancelEvidenceRequest(session: LiveAssessmentSession): void {
    const request = session.evidenceAbort
    session.evidenceAbort = undefined
    request?.abort()
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

function matchesEvidenceDisclosure(
  detail: FindingDetailViewV1,
  link: FindingDetailViewV1['evidenceLinks'][number],
  metadata: WorkbenchEvidenceMetadataViewV1,
  view: WorkbenchEvidenceDisclosureViewV1,
): boolean {
  if (
    view.assessmentId !== detail.assessmentId
    || view.assessmentRevision !== detail.assessmentRevision
    || view.context.kind !== 'finding'
    || view.context.recordId !== detail.recordId
    || view.context.recordRevision !== detail.recordRevision
    || view.evidence.artifactId !== link.artifactId
    || view.evidence.schemaId !== link.schemaId
    || !sameDigest(view.evidence.digest, link.digest)
    || view.evidence.classification !== metadata.evidence.classification
    || view.link.purpose !== link.purpose
    || view.link.eligibilityDecision !== link.eligibilityDecision
    || view.link.eligibilityDecisionArtifactId !== link.eligibilityDecisionArtifactId
    || view.purpose !== 'VALIDATION_REVIEW'
    || view.viewProfileId !== 'security/evidence-view/bounded-json-v1'
    || view.protection.policyId !== metadata.protection.policyId
    || view.retention.status !== metadata.retention.status
    || view.egress.policyId !== metadata.egress.policyId
    || view.egress.status !== metadata.egress.status
  ) return false
  if (view.content.kind === 'REDACTED') return true
  const expiresAt = Date.parse(view.content.expiresAt)
  if (!Number.isFinite(expiresAt) || expiresAt <= Date.now()) return false
  try {
    const byteLength = new TextEncoder().encode(JSON.stringify(view.content.value)).byteLength
    return Number.isInteger(view.content.byteLength)
      && view.content.byteLength >= 0
      && view.content.byteLength <= 32 * 1024
      && view.content.byteLength === byteLength
  } catch {
    return false
  }
}

function sameDigest(
  left: DigestEnvelopeV1,
  right: DigestEnvelopeV1,
): boolean {
  return left.schemaVersion === right.schemaVersion
    && left.algorithm === right.algorithm
    && left.mediaType === right.mediaType
    && left.byteLength === right.byteLength
    && left.canonicalization === right.canonicalization
    && left.value === right.value
}

function matchesBundleManifest(
  snapshot: AssessmentSnapshotV1,
  manifest: BundleManifestV1,
): boolean {
  const seal = snapshot.seal
  return seal !== null
    && snapshot.state === 'SEALED'
    && snapshot.verdict !== null
    && manifest.assessmentId === snapshot.assessmentId
    && manifest.assessmentRevision === snapshot.assessmentRevision
    && manifest.verdict === snapshot.verdict
    && manifest.seal.sealId === seal.sealId
    && manifest.seal.assessmentRevision === seal.assessmentRevision
    && manifest.seal.verdict === seal.verdict
    && manifest.seal.sealedAt === seal.sealedAt
    && sameDigest(manifest.seal.digest, seal.digest)
}

function normalizeRiskDecisionSubmission(
  submission: WorkbenchRiskDecisionSubmissionV1,
): WorkbenchRiskDecisionSubmissionV1 {
  return Object.freeze({
    decision: submission.decision,
    rationale: submission.rationale.trim(),
    compensatingControls: Object.freeze(
      submission.compensatingControls.map(control => control.trim()),
    ),
    expiresAt: submission.expiresAt,
  })
}

function matchesRiskDecisionAction(
  snapshot: AssessmentSnapshotV1,
  detail: FindingDetailViewV1,
  action: Extract<AssessmentSnapshotV1['availableActions'][number], {
    readonly kind: 'RECORD_RISK_DECISION'
  }>,
  submission: WorkbenchRiskDecisionSubmissionV1,
): boolean {
  if (
    snapshot.state !== 'BLOCKED'
    || action.expectedAssessmentRevision !== snapshot.assessmentRevision
    || detail.assessmentId !== snapshot.assessmentId
    || detail.assessmentRevision !== snapshot.assessmentRevision
    || action.finding.recordId !== detail.recordId
    || action.finding.recordRevision !== detail.recordRevision
    || submission.rationale.length < 20
    || submission.rationale.length > 2_000
    || submission.compensatingControls.length > 16
    || submission.compensatingControls.some(control => control.length < 3 || control.length > 256)
  ) return false
  const option = action.options.find(candidate => candidate.decision === submission.decision)
  if (option === undefined) return false
  if (option.decision === 'DENY') {
    return detail.riskDecision.state === 'NOT_RECORDED'
      && submission.compensatingControls.length === 0
      && submission.expiresAt === null
  }
  if (
    submission.expiresAt === null
    || !Number.isFinite(Date.parse(submission.expiresAt))
    || submission.compensatingControls.length < option.minimumCompensatingControls
  ) return false
  if (!option.exactMatchRequired) return detail.riskDecision.state === 'NOT_RECORDED'
  return detail.riskDecision.state === 'PENDING_DUAL_AUTHORITY'
    && detail.riskDecision.authorizationMode === 'CRITICAL_DUAL_AUTHORITY'
    && (detail.riskDecision.attestations ?? []).length === 1
    && detail.riskDecision.rationale === submission.rationale
    && detail.riskDecision.expiresAt === submission.expiresAt
    && sameStrings(detail.riskDecision.compensatingControls, submission.compensatingControls)
}

function matchesRiskDecisionReceipt(
  receipt: RiskDecisionReceiptV1,
  assessmentId: AssessmentId,
  action: Extract<AssessmentSnapshotV1['availableActions'][number], {
    readonly kind: 'RECORD_RISK_DECISION'
  }>,
  submission: WorkbenchRiskDecisionSubmissionV1,
  idempotencyKey: string,
): boolean {
  const option = action.options.find(candidate => candidate.decision === submission.decision)
  if (option === undefined) return false
  const expectedResolution = option.decision === 'DENY'
    ? 'DENIED'
    : option.consequence === 'REQUIRES_SECOND_AUTHORITY'
      ? 'PENDING_DUAL_AUTHORITY'
      : 'ACCEPTED'
  return receipt.assessmentId === assessmentId
    && receipt.assessmentRevision > action.expectedAssessmentRevision
    && receipt.acceptedState === 'BLOCKED'
    && receipt.finding.recordId === action.finding.recordId
    && receipt.finding.recordRevision === action.finding.recordRevision
    && receipt.decision === submission.decision
    && receipt.resolution === expectedResolution
    && receipt.idempotencyKey === idempotencyKey
}

function sameStrings(left: readonly string[], right: readonly string[]): boolean {
  return left.length === right.length && left.every((value, index) => value === right[index])
}

function nextRiskDecisionIdempotencyKey(): string {
  if (typeof globalThis.crypto?.randomUUID !== 'function') {
    throw new Error('The browser cannot generate a Risk Decision idempotency identity.')
  }
  return `workbench-risk-decision:${globalThis.crypto.randomUUID()}`
}

function nextExportIdempotencyKey(): string {
  if (typeof globalThis.crypto?.randomUUID !== 'function') {
    throw new Error('The browser cannot generate an Export idempotency identity.')
  }
  return `workbench-export:${globalThis.crypto.randomUUID()}`
}

function decodeExportBase64(value: string): Uint8Array {
  const decoded = globalThis.atob(value)
  return Uint8Array.from(decoded, character => character.charCodeAt(0))
}

async function browserSha256Hex(bytes: Uint8Array): Promise<string> {
  if (typeof globalThis.crypto?.subtle?.digest !== 'function') {
    throw new Error('The browser cannot verify the Export download digest.')
  }
  const digest = await globalThis.crypto.subtle.digest('SHA-256', ownedArrayBuffer(bytes))
  return [...new Uint8Array(digest)].map(value => value.toString(16).padStart(2, '0')).join('')
}

function triggerExportDownload(download: ExportDownloadV1, bytes: Uint8Array): void {
  if (
    typeof document === 'undefined'
    || typeof globalThis.URL?.createObjectURL !== 'function'
    || typeof globalThis.URL?.revokeObjectURL !== 'function'
  ) throw new Error('The Host browser download facility is unavailable.')
  const blob = new Blob([ownedArrayBuffer(bytes)], { type: download.mediaType })
  const objectUrl = globalThis.URL.createObjectURL(blob)
  const anchor = document.createElement('a')
  anchor.href = objectUrl
  anchor.download = download.fileName
  anchor.rel = 'noopener'
  anchor.hidden = true
  document.body.appendChild(anchor)
  try {
    anchor.click()
  } finally {
    anchor.remove()
    globalThis.setTimeout(() => { globalThis.URL.revokeObjectURL(objectUrl) }, 0)
  }
}

function ownedArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(bytes.byteLength)
  copy.set(bytes)
  return copy.buffer
}

function normalizeAssessmentCommandReason(
  reason: WorkbenchAssessmentCommandReasonV1,
): WorkbenchAssessmentCommandReasonV1 {
  return Object.freeze({
    code: reason.code.trim(),
    summary: reason.summary.trim(),
  })
}

function isAssessmentCommandReason(reason: WorkbenchAssessmentCommandReasonV1): boolean {
  return /^[A-Z][A-Z0-9_]{0,63}$/.test(reason.code)
    && reason.summary.length >= 1
    && reason.summary.length <= 512
}

function nextAssessmentCommandIdempotencyKey(command: 'RESUME' | 'CANCEL'): string {
  if (typeof globalThis.crypto?.randomUUID !== 'function') {
    throw new Error('The browser cannot generate an Assessment command idempotency identity.')
  }
  return `workbench-${command.toLowerCase()}:${globalThis.crypto.randomUUID()}`
}

function nextStartAssessmentIdempotencyKey(): string {
  if (typeof globalThis.crypto?.randomUUID !== 'function') {
    throw new Error('The browser cannot generate an Assessment start idempotency identity.')
  }
  return `workbench-start:${globalThis.crypto.randomUUID()}`
}

function matchesAssessmentCommandReceipt(
  receipt: AssessmentResumeReceiptV1 | AssessmentCancellationReceiptV1,
  command: 'RESUME' | 'CANCEL',
  snapshot: AssessmentSnapshotV1,
  expectedAssessmentRevision: number,
  idempotencyKey: string,
): boolean {
  if (
    receipt.assessmentId !== snapshot.assessmentId
    || receipt.assessmentRevision <= expectedAssessmentRevision
    || receipt.idempotencyKey !== idempotencyKey
  ) return false
  if (command === 'RESUME') {
    return receipt.operation === 'resume_assessment'
      && receipt.state === 'CREATED'
      && snapshot.state === 'BLOCKED'
  }
  return receipt.operation === 'cancel_assessment'
    && receipt.acceptedState === snapshot.state
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
        backToAssessmentSelection: () => { void controller.backToAssessmentSelection() },
        backToAssessmentDetail: () => { void controller.backToAssessmentDetail() },
        backToFindingDetail: () => { controller.backToFindingDetail() },
        backToFindingList: () => { controller.backToFindingList() },
        cancelStartPreflight: () => { controller.cancelStartPreflight() },
        cancelAssessment: reason => { void controller.cancelAssessment(reason) },
        closeWorkbench: () => { presentation.hide() },
        confirmStartAssessment: () => { void controller.confirmStartAssessment() },
        discloseEvidence: () => { void controller.discloseEvidence() },
        downloadExport: () => { void controller.downloadExport() },
        hideEvidenceDisclosure: () => { controller.hideEvidenceDisclosure() },
        loadMoreAssessments: () => { void controller.loadMoreAssessments() },
        loadMoreFindings: () => { void controller.loadMoreFindings() },
        openFindings: () => { void controller.openFindings() },
        openBundle: () => { void controller.openBundle() },
        openRepositories: () => { void controller.openRepositories() },
        openRuntimeHealth: () => { void controller.openRuntimeHealth() },
        previewExport: deliveryDestinationId => { void controller.previewExport(deliveryDestinationId) },
        recordRiskDecision: submission => { void controller.recordRiskDecision(submission) },
        refreshRuntimeHealth: () => { void controller.refreshRuntimeHealth() },
        refreshExportStatus: () => { void controller.refreshExportStatus() },
        requestExport: () => { void controller.requestExport() },
        resumeAssessment: reason => { void controller.resumeAssessment(reason) },
        selectAssessment: assessmentId => { void controller.selectAssessment(assessmentId) },
        selectRepository: repositoryId => { void controller.selectRepository(repositoryId) },
        requestStartPreflight: selection => { void controller.requestStartPreflight(selection) },
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
