import { randomUUID } from 'node:crypto'
import { realpath, stat } from 'node:fs/promises'
import { join } from 'node:path'
import { Context, Service } from '@deepseek-ai/cordis'
import Schema from '@deepseek-ai/schemastery'
import { resolveDshHome } from '@deepseek-ai/dsh-home-paths'
import type { SubprocessRuntime } from '@deepseek-ai/dsh-subprocess'
import z from 'zod'
import {
  disableRepositoryRequestSchema,
  EVIDENCE_VIEW_BOUNDED_JSON_LIFETIME_MS,
  cancelAssessmentRequestSchema,
  getAssuranceSubmissionRequestSchema,
  getAssessmentRequestSchema,
  getBundleManifestRequestSchema,
  getEvidenceViewRequestSchema,
  getExportRequestSchema,
  getFindingRequestSchema,
  getCatalogRequestSchema,
  getRepositoryRequestSchema,
  getHealthRequestSchema,
  listFindingsRequestSchema,
  listAssessmentsRequestSchema,
  listRepositoriesRequestSchema,
  repositoryIdSchema,
  registerRepositoryRequestSchema,
  recordRiskDecisionRequestSchema,
  requestExportRequestSchema,
  resumeAssessmentRequestSchema,
  startAssessmentRequestSchema,
  updateRepositoryRequestSchema,
  REQUIRED_NODE_RANGE,
  CRITICAL_BREAK_GLASS_CONTROL_ID,
  RISK_DECISION_WINDOW_CONTROL_ID,
  runtimeHealthSnapshotSchema,
  securitySubmissionArtifactV1Schema,
  securitySubmissionJsonV1Schema,
  SECURITY_ASSURANCE_PRODUCT_NAME,
  SECURITY_ASSURANCE_PRODUCT_VERSION,
  TARGET_HARNESS_VERSION,
  waitForAssessmentRevisionRequestSchema,
} from './contracts.ts'
import type {
  AssessmentAvailableActionV1,
  AssessmentId,
  AssessmentReceiptV1,
  AssessmentResumeReceiptV1,
  AssessmentCancellationReceiptV1,
  AssessmentRevisionSignalV1,
  AssessmentSnapshotV1,
  AssessmentListPageV1,
  AssessmentSubjectSourceV1,
  AssessmentTargetSelectorV1,
  BundleManifestV1,
  CancelAssessmentRequest,
  DisableRepositoryRequest,
  GetAssuranceSubmissionRequest,
  GetAssessmentRequest,
  GetBundleManifestRequest,
  GetEvidenceViewRequest,
  GetExportRequest,
  GetFindingRequest,
  GetCatalogRequest,
  GetHealthRequest,
  GetRepositoryRequest,
  InvocationOptions,
  EvidenceViewV1,
  ExportRequestReceiptV1,
  ExportViewV1,
  FindingDetailViewV1,
  FindingListPageV1,
  ListFindingsRequest,
  ListAssessmentsRequest,
  ListRepositoriesRequest,
  PublicSecurityErrorCode,
  RegisterRepositoryRequest,
  RecordRiskDecisionRequest,
  RequestExportRequest,
  ResumeAssessmentRequest,
  RepositoryCommandReceiptV1,
  RepositoryListSnapshotV1,
  RepositorySnapshotV1,
  RepositoryBindingsV1,
  RiskDecisionReceiptV1,
  RuntimeHealthSnapshot,
  SecurityAssuranceSubmissionV1,
  SecurityCatalogSnapshotV1,
  SecurityInvocation,
  SecurityResult,
  StartAssessmentRequest,
  UpdateRepositoryRequest,
  WaitForAssessmentRevisionRequest,
} from './contracts.ts'
import type {
  AnalyzerDescriptorV1,
  AnalyzerFactoryV1,
  AnalyzerRegistrationDisposer,
} from './analyzer.ts'
import { REGISTER_ANALYZER_QUALIFICATION } from './internal/analyzer-qualification-registration.ts'
import {
  RESOLVE_TRUSTED_INVOCATION,
  SecurityAuthorityResolver,
} from './internal/authority.ts'
import {
  controlPlaneAssessmentIdentitySchema,
  LOOKUP_CONTROL_PLANE_ASSESSMENT,
  lookupControlPlaneAssessment,
} from './internal/control-plane-assessment.ts'
import {
  HARNESS_VERIFICATION_AUTHORITY,
  isHarnessVerificationOwner,
  RECEIVE_HARNESS_VERIFICATION,
  type HarnessVerificationCheck,
  type HarnessVerificationOwner,
  type HarnessVerificationReceiver,
  type HarnessVerificationResult,
} from './internal/harness-verification.ts'
import { reachControlPlaneCancellationCrashCheckpoint } from './internal/control-plane-cancellation-crash-checkpoint.ts'
import {
  EXECUTE_CONTROL_PLANE_PROVIDER_OPERATION,
  controlPlaneOperationIdempotencyKey,
  type ControlPlaneAssessmentOperation,
  type ControlPlaneAssessmentOperationOutcome,
  type ControlPlaneCancellationOperation,
  type ControlPlaneCancellationOperationOutcome,
  type ControlPlaneProviderOperation,
  type ControlPlaneProviderOperationOutcome,
} from './internal/control-plane-provider-operation.ts'
import {
  VERIFY_CONTROL_PLANE_REPOSITORY_BINDING,
  type ControlPlaneRepositoryBindingMatcher,
  verifyControlPlaneRepositoryBinding,
} from './internal/control-plane-repository-binding.ts'
import type { TrustedCallerChannel } from './internal/authority.ts'
import { AnalyzerRegistry } from './internal/analyzer-registry.ts'
import { canonicalJson } from './internal/canonical.ts'
import { deepFreeze } from './internal/freeze.ts'
import {
  EvidenceViewModule,
  EvidenceViewNotFoundError,
} from './internal/evidence-view.ts'
import {
  buildExportPreview,
  ExportDeliveryError,
  ExportDeliveryModule,
} from './internal/export-delivery.ts'
import {
  FindingQueryCursorError,
  FindingQueryModule,
  FindingQueryNotFoundError,
  FindingQueryRevisionError,
  type FindingQuerySourceV1,
} from './internal/finding-query.ts'
import { publicAssessmentSnapshot } from './internal/assessment-record.ts'
import {
  AssessmentListCursorError,
  AssessmentListQueryModule,
} from './internal/assessment-list-query.ts'
import { analyzeNodePackageInstallLifecycle } from './internal/builtin-node-package-lifecycle-analyzer.ts'
import {
  createNpmAuditAnalyzer,
  NPM_AUDIT_ANALYZER_ID,
  NPM_AUDIT_DESCRIPTOR,
  NPM_AUDIT_QUALIFICATION,
  NPM_AUDIT_REPORT_BASE_NAME,
} from './internal/npm-audit-analyzer.ts'
import {
  checkSealReadiness,
  evaluateDeterministicAssessment,
  prepareAssessmentContract,
} from './internal/deterministic-kernel.ts'
import {
  publishEvidenceSet,
  readPublishedEvidenceSet,
} from './internal/evidence-persistence.ts'
import {
  openSecurityPersistence,
  SecurityPersistenceError,
} from './internal/persistence.ts'
import type { SecurityPersistence } from './internal/persistence.ts'
import {
  RiskDecisionModule,
  RiskDecisionPolicyError,
} from './internal/risk-decision.ts'
import { buildSecurityCatalog } from './internal/security-catalog.ts'
import {
  assembleSealedArtifacts,
  publishSealedArtifacts,
  verifyPublishedSealedArtifacts,
} from './internal/sealed-artifacts.ts'
import {
  freezeSubject,
  reapSubjectStaging,
  readVerifiedExternalToolReportSlices,
  readVerifiedNodePackageManifestSlices,
  SubjectFreezeError,
} from './internal/subject-freeze.ts'

export * from './contracts.ts'
export * from './analyzer.ts'
export {
  analyzeNpmAuditReport,
  createNpmAuditAnalyzer,
  escapeJsonPointerSegment,
  NPM_AUDIT_ANALYZER_ID,
  NPM_AUDIT_ANALYZER_VERSION,
  NPM_AUDIT_DESCRIPTOR,
  NPM_AUDIT_EVIDENCE_SCHEMA_ID,
  NPM_AUDIT_NORMALIZATION_CONTRACT_ID,
  NPM_AUDIT_POLICY_ID,
  NPM_AUDIT_QUALIFICATION,
  NPM_AUDIT_REPORT_BASE_NAME,
  NPM_AUDIT_WEAKNESS_ID,
  npmAuditReportEvidenceV1Schema,
  npmAuditSeveritySchema,
} from './internal/npm-audit-analyzer.ts'

const EXPORT_DELIVERY_IDLE_SCAN_MS = 30_000
const EXPORT_DELIVERY_WORKER_ERROR_RETRY_MS = 1_000
const EXPORT_RETENTION_REAPER_RETRY_MS = 30_000

declare module '@deepseek-ai/cordis' {
  interface Context {
    securityAssurance: SecurityAssuranceService
  }
}

function nodeVersionIsSupported(version: string): boolean {
  const match = /^(\d+)\.(\d+)\.(\d+)/.exec(version)
  if (match === null) return false
  const major = Number(match[1])
  const minor = Number(match[2])
  return major >= 24 || (major === 22 && minor >= 19)
}

function failure<T>(
  code: PublicSecurityErrorCode,
  message: string,
  retryable = false,
): SecurityResult<T> {
  return deepFreeze({
    ok: false,
    error: {
      schemaVersion: 1,
      code,
      message,
      retryable,
      correlationId: `sec-${randomUUID()}`,
    },
  })
}

function interruption<T>(options: InvocationOptions): SecurityResult<T> | undefined {
  if (options.signal?.aborted) {
    return failure('CANCELED', 'The Security Assurance operation was canceled.')
  }
  if (options.deadlineEpochMs !== undefined) {
    if (!Number.isSafeInteger(options.deadlineEpochMs) || options.deadlineEpochMs < 0) {
      return failure('INVALID_REQUEST', 'The local invocation deadline is invalid.')
    }
    if (Date.now() >= options.deadlineEpochMs) {
      return failure('DEADLINE_EXCEEDED', 'The Security Assurance operation deadline was exceeded.', true)
    }
  }
  return undefined
}

type ServiceLifecycleState = 'ACTIVE' | 'QUIESCING' | 'STOPPED'

function buildRuntimeHealth(
  persistenceReady: boolean,
  lifecycleState: ServiceLifecycleState,
  actualNodeVersion: string,
  nodeSupported: boolean,
  harnessVerification: HarnessVerificationResult,
  harnessVerificationChecks: readonly HarnessVerificationCheck[],
): RuntimeHealthSnapshot {
  const harnessBlocked = harnessVerification === 'FAIL'
  const mutationsAdmitted = nodeSupported && persistenceReady && !harnessBlocked
  const state = lifecycleState === 'ACTIVE'
    ? mutationsAdmitted ? 'READY' : 'READ_ONLY_SAFE'
    : lifecycleState
  return runtimeHealthSnapshotSchema.parse({
    schemaVersion: 1,
    product: {
      name: SECURITY_ASSURANCE_PRODUCT_NAME,
      version: SECURITY_ASSURANCE_PRODUCT_VERSION,
    },
    compatibility: {
      targetHarnessVersion: TARGET_HARNESS_VERSION,
      requiredNodeRange: REQUIRED_NODE_RANGE,
      actualNodeVersion,
      harnessVerification,
    },
    state,
    admission: {
      queries: state !== 'STOPPED',
      mutations: state === 'READY',
      sealedExports: lifecycleState === 'ACTIVE' && persistenceReady,
    },
    checks: [
      {
        id: 'persistence.sqlite',
        status: persistenceReady ? 'PASS' : 'FAIL',
        required: true,
        message: persistenceReady
          ? 'The private Security Assurance store passed startup validation.'
          : 'The private Security Assurance store is unavailable; mutations are blocked.',
      },
      {
        id: 'runtime.node',
        status: nodeSupported ? 'PASS' : 'FAIL',
        required: true,
        message: nodeSupported
          ? `Node ${actualNodeVersion} satisfies ${REQUIRED_NODE_RANGE}.`
          : `Node ${actualNodeVersion} does not satisfy ${REQUIRED_NODE_RANGE}.`,
      },
      ...harnessVerificationChecks,
    ],
  })
}

function controlPlaneSecurityFailure(code: PublicSecurityErrorCode): ControlPlaneAssessmentOperationOutcome {
  return {
    kind: 'EXTERNAL_FAILURE',
    reason: code === 'CANCELED' ? 'canceled' : code === 'UNAVAILABLE' ? 'blocked' : 'failed',
    code: `security_${code.toLowerCase()}`,
  }
}

function controlPlaneSealedOutcome(
  assessment: AssessmentSnapshotV1,
  securitySubmission: SecurityAssuranceSubmissionV1,
): ControlPlaneAssessmentOperationOutcome {
  const claimedOutcome = assessment.verdict === 'SATISFIED'
    ? 'satisfied'
    : assessment.verdict === 'FAILED' ? 'failed' : 'indeterminate'
  const resolutions = assessment.coverage.resolutions.length === 0
    ? [{
        obligationId: 'security/assessment',
        state: assessment.coverage.status === 'COMPLETE' ? 'SATISFIED' as const : 'GAP' as const,
      }]
    : assessment.coverage.resolutions
  const coverageComplete = assessment.coverage.status === 'COMPLETE'
    && resolutions.every(resolution => resolution.state === 'SATISFIED')
  return {
    kind: 'SEALED_ASSESSMENT',
    assessmentId: assessment.assessmentId,
    claimedOutcome,
    coverage: {
      status: coverageComplete ? 'complete' : 'incomplete',
      dimensions: resolutions.map(resolution => ({
        dimensionId: resolution.obligationId,
        status: resolution.state === 'SATISFIED' ? 'covered' : 'not_covered',
      })),
    },
    securitySubmission,
  }
}

function assessmentSelectionIsConsistent(
  subject: AssessmentSubjectSourceV1,
  mode: StartAssessmentRequest['assessmentMode'],
  target: AssessmentTargetSelectorV1,
): boolean {
  if (mode === 'REPOSITORY') {
    return target.kind === 'repository'
      && subject.kind !== 'change'
      && subject.kind !== 'workspace_change'
  }
  if (mode === 'TARGETED') {
    return target.kind === 'targeted'
      && subject.kind !== 'change'
      && subject.kind !== 'workspace_change'
  }
  if (mode !== 'CHANGE' || target.kind !== 'change') return false
  if (subject.kind === 'change') {
    return 'headCommit' in target
      && subject.baseCommit === target.baseCommit
      && subject.headCommit === target.headCommit
  }
  return subject.kind === 'workspace_change'
    && 'workspaceFingerprint' in target
    && subject.baseCommit === target.baseCommit
    && subject.workspaceFingerprint === target.workspaceFingerprint
    && subject.producedChangeFingerprint === target.producedChangeFingerprint
}

function requestedStrongerControlsAreValid(controlIds: readonly string[]): boolean {
  return controlIds.every(controlId => (
    controlId === RISK_DECISION_WINDOW_CONTROL_ID
    || controlId === CRITICAL_BREAK_GLASS_CONTROL_ID
  ))
    && new Set(controlIds).size === controlIds.length
    && (
      !controlIds.includes(CRITICAL_BREAK_GLASS_CONTROL_ID)
      || controlIds.includes(RISK_DECISION_WINDOW_CONTROL_ID)
    )
}

export interface Config {
  /** Optional explicit Harness home; defaults through the shared DSH_HOME resolver. */
  readonly dshHome?: string | undefined
}

/** Harness/Cordis configuration contract for startup-time validation and UI tooling. */
export const Config = Schema.object({
  dshHome: Schema.string(),
})

const securityAssuranceConfigSchema: z.ZodType<Config> = z.strictObject({
  dshHome: z.string().min(1).max(4096).optional(),
})

class SecurityArtifactIntegrityError extends Error {
  override readonly name = 'SecurityArtifactIntegrityError'
}

/**
 * Sole public business Interface for Security Assurance.
 * Internal adapters use the hidden Resolver symbol; package consumers cannot
 * mint or deserialize Security Invocations.
 */
export class SecurityAssuranceService extends Service {
  static inject = ['subprocess']

  private readonly authorityResolver = new SecurityAuthorityResolver()
  private readonly analyzerRegistry = new AnalyzerRegistry()
  private readonly findingQueries = new FindingQueryModule()
  private readonly assessmentLists = new AssessmentListQueryModule()
  private readonly evidenceViews = new EvidenceViewModule()
  private readonly exportDelivery: ExportDeliveryModule
  private readonly riskDecisions = new RiskDecisionModule()
  private readonly actualNodeVersion = process.versions.node
  private readonly runtimeCompatible = nodeVersionIsSupported(this.actualNodeVersion)
  private readonly ready: Promise<SecurityPersistence | undefined>
  private readonly securityRoot: string
  private readonly subprocess: SubprocessRuntime
  private readonly runningAssessments = new Map<AssessmentId, {
    readonly controller: AbortController
    readonly task: Promise<void>
  }>()
  private readonly exportDeliveryWorkerController = new AbortController()
  private exportDeliveryWorkerTask: Promise<void> | undefined
  private exportDeliveryWakePending = false
  private exportDeliveryWake: (() => void) | undefined
  private lifecycleState: ServiceLifecycleState = 'ACTIVE'
  private disposed = false
  private harnessVerification: HarnessVerificationResult = 'PENDING_INVARIANT'
  private harnessVerificationChecks: readonly HarnessVerificationCheck[] = []
  #harnessVerificationOwner: HarnessVerificationOwner | undefined

  constructor(ctx: Context, config: Config = {}) {
    super(ctx, 'securityAssurance')
    this.subprocess = ctx.subprocess
    const parsedConfig = securityAssuranceConfigSchema.safeParse(config)
    if (!parsedConfig.success) throw new TypeError('Security Assurance configuration is invalid')
    this.securityRoot = join(resolveDshHome(parsedConfig.data.dshHome), 'security-assurance')
    this.exportDelivery = new ExportDeliveryModule(this.securityRoot)
    // Self-register the bundled npm audit normalization Analyzer and its
    // development Qualification before any Assessment admission closes
    // startup registration. It only composes for the npm-dependency-audit
    // Policy, so other Policies never see it in their Analyzer portfolio.
    this.analyzerRegistry.register(NPM_AUDIT_DESCRIPTOR, createNpmAuditAnalyzer)
    this.analyzerRegistry.registerQualification(NPM_AUDIT_QUALIFICATION)
    Object.defineProperty(this, RESOLVE_TRUSTED_INVOCATION, {
      configurable: false,
      enumerable: false,
      writable: false,
      value: (channel: TrustedCallerChannel) => this.authorityResolver.resolve(channel),
    })
    Object.defineProperty(this, REGISTER_ANALYZER_QUALIFICATION, {
      configurable: false,
      enumerable: false,
      writable: false,
      value: (record: unknown) => {
        if (this.disposed) throw new TypeError('Security Assurance is disposed')
        return this.analyzerRegistry.registerQualification(record)
      },
    })
    this.ready = this.initialize(parsedConfig.data)
    Object.defineProperty(this, LOOKUP_CONTROL_PLANE_ASSESSMENT, {
      configurable: false,
      enumerable: false,
      writable: false,
      value: async (invocation: SecurityInvocation, identity: unknown) => {
        const authority = this.authorityResolver.authority(invocation)
        if (
          authority?.kind !== 'control-plane'
          || !authority.permissions.has('assessment:read')
        ) throw new TypeError('control-plane Assessment lookup is unauthorized')
        const parsed = controlPlaneAssessmentIdentitySchema.safeParse(identity)
        if (!parsed.success) throw new TypeError('control-plane Assessment identity is invalid')
        const persistence = await this.ready
        if (persistence === undefined || this.disposed) {
          throw new SecurityPersistenceError('corrupt_database', 'Assessment store is unavailable')
        }
        return persistence.findAssessmentStartIdentity({
          principalId: authority.principalId,
          authorityKind: authority.kind,
          idempotencyKey: parsed.data.idempotencyKey,
          repositoryId: parsed.data.repositoryId,
        })
      },
    })
    Object.defineProperty(this, VERIFY_CONTROL_PLANE_REPOSITORY_BINDING, {
      configurable: false,
      enumerable: false,
      writable: false,
      value: async (
        invocation: SecurityInvocation,
        repositoryId: unknown,
        matcher: ControlPlaneRepositoryBindingMatcher,
      ) => {
        const authority = this.authorityResolver.authority(invocation)
        if (
          authority?.kind !== 'control-plane'
          || !authority.permissions.has('repository:read')
        ) throw new TypeError('control-plane Repository binding verification is unauthorized')
        const parsedRepositoryId = repositoryIdSchema.safeParse(repositoryId)
        if (!parsedRepositoryId.success || typeof matcher?.matchesCanonicalRepository !== 'function') {
          throw new TypeError('control-plane Repository binding verification is invalid')
        }
        const persistence = await this.ready
        if (persistence === undefined || this.disposed) {
          throw new SecurityPersistenceError('corrupt_database', 'Repository store is unavailable')
        }
        const repository = persistence.resolveRepository(parsedRepositoryId.data)
        if (repository === undefined) return false
        try {
          return matcher.matchesCanonicalRepository(repository.canonicalRoot) === true
        } catch {
          return false
        }
      },
    })
    Object.defineProperty(this, EXECUTE_CONTROL_PLANE_PROVIDER_OPERATION, {
      configurable: false,
      enumerable: false,
      writable: false,
      value: (
        invocation: SecurityInvocation,
        operation: ControlPlaneProviderOperation,
        options: InvocationOptions,
      ) => this.executeControlPlaneProviderOperation(invocation, operation, options),
    })

    Object.defineProperty(this, RECEIVE_HARNESS_VERIFICATION, {
      configurable: false,
      enumerable: false,
      writable: false,
      value: ((authority, owner, contribution) => {
        if (authority !== HARNESS_VERIFICATION_AUTHORITY || !isHarnessVerificationOwner(owner)) return false
        if (contribution === undefined) {
          if (this.#harnessVerificationOwner !== owner) return false
          this.#harnessVerificationOwner = undefined
          this.harnessVerification = 'PENDING_INVARIANT'
          this.harnessVerificationChecks = []
          return true
        }
        this.#harnessVerificationOwner = owner
        this.harnessVerification = contribution.result
        this.harnessVerificationChecks = deepFreeze(
          contribution.checks.map(check => ({ ...check })),
        )
        return true
      }) satisfies HarnessVerificationReceiver,
    })

    void this.ready.catch(() => {})
    void this.ready.then(persistence => {
      if (!this.admitsMutations(persistence)) return
      for (const assessmentId of persistence.listCreatedAssessmentIds()) {
        this.launchAssessment(persistence, assessmentId)
      }
      this.startExportDeliveryWorker()
    }).catch(() => {})
    ctx.effect(async () => {
      const persistence = await this.ready
      return async () => {
        this.lifecycleState = 'QUIESCING'
        try {
          for (const running of this.runningAssessments.values()) running.controller.abort()
          this.exportDeliveryWorkerController.abort()
          this.wakeExportDeliveryWorker()
          await Promise.allSettled([
            ...[...this.runningAssessments.values()].map(running => running.task),
            ...(this.exportDeliveryWorkerTask === undefined ? [] : [this.exportDeliveryWorkerTask]),
          ])
          persistence?.close()
        } finally {
          this.disposed = true
          this.lifecycleState = 'STOPPED'
        }
      }
    }, 'security assurance teardown')
  }

  /** Join private-store validation without exposing the Store itself. */
  async whenReady(): Promise<void> {
    if (await this.ready === undefined) {
      throw new Error('Security Assurance entered read-only-safe mode during startup')
    }
  }

  /** Register one local Host-approved Analyzer contribution during startup composition. */
  registerAnalyzer(
    descriptor: AnalyzerDescriptorV1,
    factory: AnalyzerFactoryV1,
  ): AnalyzerRegistrationDisposer {
    if (this.disposed) throw new TypeError('Security Assurance is disposed')
    return this.analyzerRegistry.register(descriptor, factory)
  }

  /** Return a bounded authorized Runtime Health Snapshot. */
  async getHealth(
    invocation: SecurityInvocation,
    request: GetHealthRequest,
    options: InvocationOptions = {},
  ): Promise<SecurityResult<RuntimeHealthSnapshot>> {
    try {
      if (!this.authorityResolver.authorizes(invocation, 'health:read')) {
        return failure('UNAUTHORIZED', 'The caller is not authorized to read Security Assurance health.')
      }
      const interrupted = interruption<RuntimeHealthSnapshot>(options)
      if (interrupted !== undefined) return interrupted
      if (!getHealthRequestSchema.safeParse(request).success) {
        return failure('INVALID_REQUEST', 'The request does not match getHealth schema version 1.')
      }
      const persistence = await this.ready
      const persistenceReady = persistence !== undefined && this.lifecycleState !== 'STOPPED'
      return deepFreeze({
        ok: true,
        value: buildRuntimeHealth(
          persistenceReady,
          this.lifecycleState,
          this.actualNodeVersion,
          this.runtimeCompatible,
          this.harnessVerification,
          this.harnessVerificationChecks,
        ),
      })
    } catch {
      return failure('INTERNAL', 'Security Assurance could not complete the operation.', true)
    }
  }

  /** Return effective capability and an optional digest-bound Start Preflight. */
  async getCatalog(
    invocation: SecurityInvocation,
    request: GetCatalogRequest,
    options: InvocationOptions = {},
  ): Promise<SecurityResult<SecurityCatalogSnapshotV1>> {
    try {
      const authority = this.authorityResolver.authority(invocation)
      if (authority === undefined || !authority.permissions.has('repository:read')) {
        return failure('UNAUTHORIZED', 'The caller is not authorized to read the Security Catalog.')
      }
      const interrupted = interruption<SecurityCatalogSnapshotV1>(options)
      if (interrupted !== undefined) return interrupted
      const parsed = getCatalogRequestSchema.safeParse(request)
      if (!parsed.success) {
        return failure('INVALID_REQUEST', 'The request does not match getCatalog schema version 1.')
      }
      if (
        parsed.data.proposedStart !== undefined
        && !authority.permissions.has('assessment:start')
      ) {
        return failure('UNAUTHORIZED', 'The caller is not authorized to preflight Assessment start.')
      }
      if (
        parsed.data.proposedStart !== undefined
        && (
          !assessmentSelectionIsConsistent(
            parsed.data.proposedStart.subject,
            parsed.data.proposedStart.assessmentMode,
            parsed.data.proposedStart.target,
          )
          || !requestedStrongerControlsAreValid(
            parsed.data.proposedStart.requestedStrongerControlIds,
          )
        )
      ) {
        return failure('INVALID_REQUEST', 'The proposed Assessment selection is inconsistent.')
      }
      const repositoryId = parsed.data.proposedStart?.repositoryId ?? parsed.data.repositoryId
      const persistence = await this.ready
      if (this.disposed || (persistence === undefined && repositoryId !== undefined)) {
        return failure('UNAVAILABLE', 'The Security Catalog is unavailable while the private store is offline.', true)
      }
      const repository = repositoryId === undefined || persistence === undefined
        ? undefined
        : persistence.resolveRepository(repositoryId)
      if (repositoryId !== undefined && repository === undefined) {
        return failure('NOT_FOUND', 'The Repository does not exist.')
      }
      const evaluatedAt = new Date().toISOString()
      const value = buildSecurityCatalog({
        repository: repository?.snapshot ?? null,
        proposedStart: parsed.data.proposedStart,
        portfolioForMode: mode => repository === undefined
          ? []
          : this.analyzerRegistry.previewSelection(
              repository.snapshot.bindings.policyId,
              mode,
              repository.snapshot.bindings.platform,
              evaluatedAt,
            ),
      })
      return deepFreeze({ ok: true, value })
    } catch (error) {
      if (error instanceof SecurityPersistenceError) {
        return failure('UNAVAILABLE', 'The private Security Assurance store is unavailable.', true)
      }
      return failure('INTERNAL', 'Security Assurance could not complete the operation.', true)
    }
  }

  /** Explicitly register one Host-resolved canonical Repository root. */
  async registerRepository(
    invocation: SecurityInvocation,
    request: RegisterRepositoryRequest,
    options: InvocationOptions = {},
  ): Promise<SecurityResult<RepositoryCommandReceiptV1>> {
    try {
      const authority = this.authorityResolver.authority(invocation)
      if (authority === undefined || !authority.permissions.has('repository:admin')) {
        return failure('UNAUTHORIZED', 'The caller is not authorized to administer Repositories.')
      }
      const interrupted = interruption<RepositoryCommandReceiptV1>(options)
      if (interrupted !== undefined) return interrupted
      const parsed = registerRepositoryRequestSchema.safeParse(request)
      if (!parsed.success) {
        return failure('INVALID_REQUEST', 'The request does not match registerRepository schema version 1.')
      }
      const persistence = await this.ready
      if (!this.admitsMutations(persistence)) {
        return failure('UNAVAILABLE', 'Repository mutations are unavailable in read-only-safe mode.', true)
      }
      const canonicalRoot = await realpath(parsed.data.root)
      if (!(await stat(canonicalRoot)).isDirectory()) {
        return failure('INVALID_REQUEST', 'The Repository root must resolve to a directory.')
      }
      const interruptedAfterResolution = interruption<RepositoryCommandReceiptV1>(options)
      if (interruptedAfterResolution !== undefined) return interruptedAfterResolution
      const receipt = persistence.registerRepository({
        principalId: authority.principalId,
        authorityKind: authority.kind,
        idempotencyKey: parsed.data.idempotencyKey,
        canonicalRequest: { ...parsed.data, root: canonicalRoot },
        canonicalRoot,
        displayName: parsed.data.displayName,
        bindings: parsed.data.bindings,
      })
      return deepFreeze({ ok: true, value: receipt })
    } catch (error) {
      if (error instanceof SecurityPersistenceError) {
        if (error.code === 'idempotency_conflict') {
          return failure('IDEMPOTENCY_CONFLICT', 'The idempotency key is bound to a different request.')
        }
        if (error.code === 'repository_conflict') {
          return failure('CONFLICT', 'The canonical Repository is already registered.')
        }
        return failure('UNAVAILABLE', 'The private Security Assurance store is unavailable.', true)
      }
      if ((error as NodeJS.ErrnoException).code !== undefined) {
        return failure('INVALID_REQUEST', 'The Repository root could not be resolved.')
      }
      return failure('INTERNAL', 'Security Assurance could not complete the operation.', true)
    }
  }

  /** Append a new immutable Registry revision after exact compare-and-set. */
  async updateRepository(
    invocation: SecurityInvocation,
    request: UpdateRepositoryRequest,
    options: InvocationOptions = {},
  ): Promise<SecurityResult<RepositoryCommandReceiptV1>> {
    try {
      const authority = this.authorityResolver.authority(invocation)
      if (authority === undefined || !authority.permissions.has('repository:admin')) {
        return failure('UNAUTHORIZED', 'The caller is not authorized to administer Repositories.')
      }
      const interrupted = interruption<RepositoryCommandReceiptV1>(options)
      if (interrupted !== undefined) return interrupted
      const parsed = updateRepositoryRequestSchema.safeParse(request)
      if (!parsed.success) {
        return failure('INVALID_REQUEST', 'The request does not match updateRepository schema version 1.')
      }
      const persistence = await this.ready
      if (!this.admitsMutations(persistence)) {
        return failure('UNAVAILABLE', 'Repository mutations are unavailable in read-only-safe mode.', true)
      }
      const receipt = persistence.updateRepository({
        principalId: authority.principalId,
        authorityKind: authority.kind,
        idempotencyKey: parsed.data.idempotencyKey,
        canonicalRequest: parsed.data,
        repositoryId: parsed.data.repositoryId,
        expectedRepositoryRevision: parsed.data.expectedRepositoryRevision,
        ...parsed.data.displayName === undefined ? {} : { displayName: parsed.data.displayName },
        ...parsed.data.bindings === undefined ? {} : { bindings: parsed.data.bindings },
      })
      return deepFreeze({ ok: true, value: receipt })
    } catch (error) {
      return this.repositoryMutationFailure(error)
    }
  }

  /** Disable future Assessment starts while preserving all Registry history. */
  async disableRepository(
    invocation: SecurityInvocation,
    request: DisableRepositoryRequest,
    options: InvocationOptions = {},
  ): Promise<SecurityResult<RepositoryCommandReceiptV1>> {
    try {
      const authority = this.authorityResolver.authority(invocation)
      if (authority === undefined || !authority.permissions.has('repository:admin')) {
        return failure('UNAUTHORIZED', 'The caller is not authorized to administer Repositories.')
      }
      const interrupted = interruption<RepositoryCommandReceiptV1>(options)
      if (interrupted !== undefined) return interrupted
      const parsed = disableRepositoryRequestSchema.safeParse(request)
      if (!parsed.success) {
        return failure('INVALID_REQUEST', 'The request does not match disableRepository schema version 1.')
      }
      const persistence = await this.ready
      if (!this.admitsMutations(persistence)) {
        return failure('UNAVAILABLE', 'Repository mutations are unavailable in read-only-safe mode.', true)
      }
      const receipt = persistence.disableRepository({
        principalId: authority.principalId,
        authorityKind: authority.kind,
        idempotencyKey: parsed.data.idempotencyKey,
        canonicalRequest: parsed.data,
        repositoryId: parsed.data.repositoryId,
        expectedRepositoryRevision: parsed.data.expectedRepositoryRevision,
      })
      return deepFreeze({ ok: true, value: receipt })
    } catch (error) {
      return this.repositoryMutationFailure(error)
    }
  }

  /** Read one current, immutable and path-free Repository Snapshot. */
  async getRepository(
    invocation: SecurityInvocation,
    request: GetRepositoryRequest,
    options: InvocationOptions = {},
  ): Promise<SecurityResult<RepositorySnapshotV1>> {
    try {
      if (!this.authorityResolver.authorizes(invocation, 'repository:read')) {
        return failure('UNAUTHORIZED', 'The caller is not authorized to read Repositories.')
      }
      const interrupted = interruption<RepositorySnapshotV1>(options)
      if (interrupted !== undefined) return interrupted
      const parsed = getRepositoryRequestSchema.safeParse(request)
      if (!parsed.success) {
        return failure('INVALID_REQUEST', 'The request does not match getRepository schema version 1.')
      }
      const persistence = await this.ready
      if (persistence === undefined || this.disposed) {
        return failure('UNAVAILABLE', 'Repository queries are unavailable while the private store is offline.', true)
      }
      const snapshot = persistence.getRepository(parsed.data.repositoryId)
      if (snapshot === undefined) return failure('NOT_FOUND', 'The Repository does not exist.')
      return deepFreeze({ ok: true, value: snapshot })
    } catch (error) {
      if (error instanceof SecurityPersistenceError) {
        return failure('UNAVAILABLE', 'The private Security Assurance store is unavailable.', true)
      }
      return failure('INTERNAL', 'Security Assurance could not complete the operation.', true)
    }
  }

  /** Return a bounded current Registry projection without Host roots. */
  async listRepositories(
    invocation: SecurityInvocation,
    request: ListRepositoriesRequest,
    options: InvocationOptions = {},
  ): Promise<SecurityResult<RepositoryListSnapshotV1>> {
    try {
      if (!this.authorityResolver.authorizes(invocation, 'repository:read')) {
        return failure('UNAUTHORIZED', 'The caller is not authorized to read Repositories.')
      }
      const interrupted = interruption<RepositoryListSnapshotV1>(options)
      if (interrupted !== undefined) return interrupted
      const parsed = listRepositoriesRequestSchema.safeParse(request)
      if (!parsed.success) {
        return failure('INVALID_REQUEST', 'The request does not match listRepositories schema version 1.')
      }
      const persistence = await this.ready
      if (persistence === undefined || this.disposed) {
        return failure('UNAVAILABLE', 'Repository queries are unavailable while the private store is offline.', true)
      }
      const value = persistence.listRepositories(parsed.data.limit, parsed.data.state)
      return deepFreeze({ ok: true, value })
    } catch (error) {
      if (error instanceof SecurityPersistenceError) {
        return failure('UNAVAILABLE', 'The private Security Assurance store is unavailable.', true)
      }
      return failure('INTERNAL', 'Security Assurance could not complete the operation.', true)
    }
  }

  /** Freeze one exact Subject, then atomically publish its durable Assessment Receipt. */
  async startAssessment(
    invocation: SecurityInvocation,
    request: StartAssessmentRequest,
    options: InvocationOptions = {},
  ): Promise<SecurityResult<AssessmentReceiptV1>> {
    try {
      const authority = this.authorityResolver.authority(invocation)
      if (authority === undefined || !authority.permissions.has('assessment:start')) {
        return failure('UNAUTHORIZED', 'The caller is not authorized to start Assessments.')
      }
      const interrupted = interruption<AssessmentReceiptV1>(options)
      if (interrupted !== undefined) return interrupted
      const parsed = startAssessmentRequestSchema.safeParse(request)
      if (!parsed.success || !assessmentSelectionIsConsistent(
        parsed.data.subject,
        parsed.data.assessmentMode,
        parsed.data.target,
      )) {
        return failure('INVALID_REQUEST', 'The request does not match startAssessment schema version 1.')
      }
      if (!requestedStrongerControlsAreValid(parsed.data.requestedStrongerControlIds)) {
        return failure('INVALID_REQUEST', 'The request contains an unknown or duplicate stronger control.')
      }
      const persistence = await this.ready
      if (!this.admitsMutations(persistence)) {
        return failure('UNAVAILABLE', 'Assessment start is unavailable in read-only-safe mode.', true)
      }
      // An accepted start is a replay of its frozen contract, not a new start subject to current Registry admission.
      const replay = persistence.findAssessmentStartReplay({
        principalId: authority.principalId,
        authorityKind: authority.kind,
        idempotencyKey: parsed.data.idempotencyKey,
        repositoryId: parsed.data.repositoryId,
        canonicalRequest: parsed.data,
      })
      if (replay !== undefined) {
        this.launchAssessment(persistence, replay.assessmentId)
        return deepFreeze({ ok: true, value: replay })
      }
      const repository = persistence.resolveRepository(parsed.data.repositoryId)
      if (repository === undefined) return failure('NOT_FOUND', 'The Repository does not exist.')
      if (repository.snapshot.state !== 'ENABLED') {
        return failure('CONFLICT', 'The Repository is disabled and cannot start new Assessments.')
      }
      if (parsed.data.assessmentProfileId !== repository.snapshot.bindings.assessmentProfileId) {
        return failure('INVALID_REQUEST', 'The requested Assessment Profile is not bound to this Repository.')
      }

      const qualificationEvaluationInstant = new Date().toISOString()
      if (parsed.data.startPreflightDigest !== undefined) {
        const catalog = buildSecurityCatalog({
          repository: repository.snapshot,
          proposedStart: {
            schemaVersion: parsed.data.schemaVersion,
            repositoryId: parsed.data.repositoryId,
            subject: parsed.data.subject,
            assessmentMode: parsed.data.assessmentMode,
            assessmentProfileId: parsed.data.assessmentProfileId,
            target: parsed.data.target,
            requestedStrongerControlIds: parsed.data.requestedStrongerControlIds,
          },
          portfolioForMode: mode => this.analyzerRegistry.previewSelection(
            repository.snapshot.bindings.policyId,
            mode,
            repository.snapshot.bindings.platform,
            qualificationEvaluationInstant,
          ),
        })
        if (
          catalog.startPreflight === null
          || !catalog.startPreflight.admissible
          || canonicalJson(catalog.startPreflight.proposalDigest)
            !== canonicalJson(parsed.data.startPreflightDigest)
        ) {
          return failure(
            'CONFLICT',
            'The Start Preflight no longer matches the effective Assessment contract; request a new proposal.',
            true,
          )
        }
      }
      const analyzerPortfolio = this.analyzerRegistry.freezeSelection(
        repository.snapshot.bindings.policyId,
        parsed.data.assessmentMode,
        repository.snapshot.bindings.platform,
        qualificationEvaluationInstant,
      )

      const frozen = await freezeSubject({
        subprocess: this.subprocess,
        repositoryRoot: repository.canonicalRoot,
        securityRoot: this.securityRoot,
        source: parsed.data.subject,
        target: parsed.data.target,
        signal: options.signal,
      })
      const interruptedAfterFreeze = interruption<AssessmentReceiptV1>(options)
      if (interruptedAfterFreeze !== undefined) return interruptedAfterFreeze
      const preparedContract = prepareAssessmentContract({
        policyId: repository.snapshot.bindings.policyId,
        assessmentMode: parsed.data.assessmentMode,
        assessmentProfileId: parsed.data.assessmentProfileId,
        target: parsed.data.target,
        targetDigest: frozen.targetDigest,
        requestedStrongerControlIds: parsed.data.requestedStrongerControlIds,
        analyzerPortfolio,
      })
      const receipt = persistence.createAssessment({
        principalId: authority.principalId,
        authorityKind: authority.kind,
        idempotencyKey: parsed.data.idempotencyKey,
        repositoryId: parsed.data.repositoryId,
        expectedRepositoryRevision: repository.snapshot.repositoryRevision,
        canonicalRequest: parsed.data,
        subject: parsed.data.subject,
        subjectDigest: frozen.manifestDigest,
        subjectStats: {
          files: frozen.files,
          bytes: frozen.bytes,
          symbolicLinks: frozen.symbolicLinks,
          submodules: frozen.submodules,
        },
        preparedContract,
      })
      this.launchAssessment(persistence, receipt.assessmentId)
      return deepFreeze({ ok: true, value: receipt })
    } catch (error) {
      if (error instanceof SubjectFreezeError) {
        if (error.code === 'canceled') {
          return interruption<AssessmentReceiptV1>(options)
            ?? failure('CANCELED', 'The Security Assurance operation was canceled.')
        }
        if (error.code === 'unstable_subject') {
          return failure('CONFLICT', 'The Subject changed while it was being frozen.', true)
        }
        if (error.code === 'integrity_failure') {
          return failure('UNAVAILABLE', 'The private Subject store failed integrity validation.', true)
        }
        return failure('INVALID_REQUEST', 'The requested Subject could not be frozen safely.')
      }
      return this.repositoryMutationFailure(error)
    }
  }

  /** Explicitly admit a replacement execution for one exact BLOCKED Assessment revision. */
  async resumeAssessment(
    invocation: SecurityInvocation,
    request: ResumeAssessmentRequest,
    options: InvocationOptions = {},
  ): Promise<SecurityResult<AssessmentResumeReceiptV1>> {
    try {
      const authority = this.authorityResolver.authority(invocation)
      if (authority === undefined || !authority.permissions.has('assessment:resume')) {
        return failure('UNAUTHORIZED', 'The caller is not authorized to resume Assessments.')
      }
      const interrupted = interruption<AssessmentResumeReceiptV1>(options)
      if (interrupted !== undefined) return interrupted
      const parsed = resumeAssessmentRequestSchema.safeParse(request)
      if (!parsed.success) {
        return failure('INVALID_REQUEST', 'The request does not match resumeAssessment schema version 1.')
      }
      const persistence = await this.ready
      if (!this.admitsMutations(persistence)) {
        return failure('UNAVAILABLE', 'Assessment resume is unavailable in read-only-safe mode.', true)
      }
      const receipt = persistence.resumeAssessment({
        principalId: authority.principalId,
        authorityKind: authority.kind,
        idempotencyKey: parsed.data.idempotencyKey,
        assessmentId: parsed.data.assessmentId,
        expectedAssessmentRevision: parsed.data.expectedAssessmentRevision,
        reason: parsed.data.reason,
        canonicalRequest: parsed.data,
      })
      this.launchAssessment(persistence, receipt.assessmentId)
      return deepFreeze({ ok: true, value: receipt })
    } catch (error) {
      if (error instanceof SecurityPersistenceError) {
        if (error.code === 'idempotency_conflict') {
          return failure('IDEMPOTENCY_CONFLICT', 'The idempotency key is bound to a different request.')
        }
        if (error.code === 'assessment_not_found') {
          return failure('NOT_FOUND', 'The Assessment does not exist.')
        }
        if (error.code === 'revision_conflict') {
          return failure('CONFLICT', 'The Assessment cannot resume from the requested revision or state.')
        }
        return failure('UNAVAILABLE', 'The private Security Assurance store is unavailable.', true)
      }
      return failure('INTERNAL', 'Security Assurance could not complete the operation.', true)
    }
  }

  /** Persist intent, quiesce the local evaluator, then durably finalize CANCELED. */
  async cancelAssessment(
    invocation: SecurityInvocation,
    request: CancelAssessmentRequest,
    options: InvocationOptions = {},
  ): Promise<SecurityResult<AssessmentCancellationReceiptV1>> {
    try {
      const authority = this.authorityResolver.authority(invocation)
      if (authority === undefined || !authority.permissions.has('assessment:cancel')) {
        return failure('UNAUTHORIZED', 'The caller is not authorized to cancel Assessments.')
      }
      const interrupted = interruption<AssessmentCancellationReceiptV1>(options)
      if (interrupted !== undefined) return interrupted
      const parsed = cancelAssessmentRequestSchema.safeParse(request)
      if (!parsed.success) {
        return failure('INVALID_REQUEST', 'The request does not match cancelAssessment schema version 1.')
      }
      const persistence = await this.ready
      if (!this.admitsMutations(persistence)) {
        return failure('UNAVAILABLE', 'Assessment cancellation is unavailable in read-only-safe mode.', true)
      }
      const receipt = persistence.requestAssessmentCancellation({
        principalId: authority.principalId,
        authorityKind: authority.kind,
        idempotencyKey: parsed.data.idempotencyKey,
        assessmentId: parsed.data.assessmentId,
        expectedAssessmentRevision: parsed.data.expectedAssessmentRevision,
        reason: parsed.data.reason,
        canonicalRequest: parsed.data,
      })
      const running = this.runningAssessments.get(receipt.assessmentId)
      if (running !== undefined) {
        running.controller.abort(new Error('Assessment cancellation requested'))
        await running.task.catch(() => {})
      }
      persistence.completeAssessmentCancellation(receipt.assessmentId, receipt.assessmentRevision)
      return deepFreeze({ ok: true, value: receipt })
    } catch (error) {
      if (error instanceof SecurityPersistenceError) {
        if (error.code === 'idempotency_conflict') {
          return failure('IDEMPOTENCY_CONFLICT', 'The idempotency key is bound to a different request.')
        }
        if (error.code === 'assessment_not_found') {
          return failure('NOT_FOUND', 'The Assessment does not exist.')
        }
        if (error.code === 'revision_conflict') {
          return failure('CONFLICT', 'The Assessment cannot be canceled from the requested revision or state.')
        }
        return failure('UNAVAILABLE', 'The private Security Assurance store is unavailable.', true)
      }
      return failure('INTERNAL', 'Security Assurance could not complete the operation.', true)
    }
  }

  /** List redacted Assessment identities through an authority-bound stable keyset cursor. */
  async listAssessments(
    invocation: SecurityInvocation,
    request: ListAssessmentsRequest,
    options: InvocationOptions = {},
  ): Promise<SecurityResult<AssessmentListPageV1>> {
    try {
      const authority = this.authorityResolver.authority(invocation)
      if (authority === undefined || !authority.permissions.has('assessment:read')) {
        return failure('UNAUTHORIZED', 'The caller is not authorized to list Assessments.')
      }
      const interrupted = interruption<AssessmentListPageV1>(options)
      if (interrupted !== undefined) return interrupted
      const parsed = listAssessmentsRequestSchema.safeParse(request)
      if (!parsed.success) {
        return failure('INVALID_REQUEST', 'The request does not match listAssessments schema version 1.')
      }
      const persistence = await this.ready
      if (persistence === undefined || this.disposed) {
        return failure('UNAVAILABLE', 'Assessment queries are unavailable while the private store is offline.', true)
      }
      return deepFreeze({
        ok: true,
        value: this.assessmentLists.list(persistence, parsed.data, {
          kind: authority.kind,
          principalId: authority.principalId,
        }),
      })
    } catch (error) {
      if (error instanceof AssessmentListCursorError) {
        return failure('INVALID_REQUEST', 'The Assessment list cursor is invalid for this request.')
      }
      return this.assessmentReadFailure(error)
    }
  }

  /** Read one immutable, path-free Assessment projection. */
  async getAssessment(
    invocation: SecurityInvocation,
    request: GetAssessmentRequest,
    options: InvocationOptions = {},
  ): Promise<SecurityResult<AssessmentSnapshotV1>> {
    try {
      const authority = this.authorityResolver.authority(invocation)
      if (authority === undefined || !authority.permissions.has('assessment:read')) {
        return failure('UNAUTHORIZED', 'The caller is not authorized to read Assessments.')
      }
      const interrupted = interruption<AssessmentSnapshotV1>(options)
      if (interrupted !== undefined) return interrupted
      const parsed = getAssessmentRequestSchema.safeParse(request)
      if (!parsed.success) {
        return failure('INVALID_REQUEST', 'The request does not match getAssessment schema version 1.')
      }
      const persistence = await this.ready
      if (persistence === undefined || this.disposed) {
        return failure('UNAVAILABLE', 'Assessment queries are unavailable while the private store is offline.', true)
      }
      const record = persistence.getAssessmentRecord(parsed.data.assessmentId)
      if (record === undefined) return failure('NOT_FOUND', 'The Assessment does not exist.')
      const availableActions: AssessmentAvailableActionV1[] = []
      if (
        authority.permissions.has('assessment:cancel')
        && record.state !== 'SEALED'
        && record.state !== 'CANCELED'
        && record.pendingCancellation === null
      ) {
        availableActions.push({
          kind: 'CANCEL_ASSESSMENT',
          expectedAssessmentRevision: record.assessmentRevision,
        })
      }
      if (
        authority.permissions.has('assessment:resume')
        && record.state === 'BLOCKED'
        && record.riskDecisionWindow === null
        && record.pendingCancellation === null
      ) {
        availableActions.push({
          kind: 'RESUME_ASSESSMENT',
          expectedAssessmentRevision: record.assessmentRevision,
        })
      }
      if (
        authority.permissions.has('risk:decide')
        && record.riskDecisionWindow?.state === 'OPEN'
      ) {
        const source = await this.findingQuerySource(record.assessmentId)
        if (source === undefined) throw new TypeError('Risk Decision Window has no Finding projection source')
        for (const recordId of record.riskDecisionWindow.findingRecordIds) {
          const finding = this.findingQueries.get(source, {
            schemaVersion: 1,
            assessmentId: record.assessmentId,
            assessmentRevision: record.assessmentRevision,
            recordId,
            recordRevision: 1,
          })
          const action = this.riskDecisions.projectAvailableAction(
            record,
            finding,
            authority,
            new Date().toISOString(),
          )
          if (action !== undefined) availableActions.push(action)
        }
      }
      return deepFreeze({ ok: true, value: publicAssessmentSnapshot(record, availableActions) })
    } catch (error) {
      return this.assessmentReadFailure(error)
    }
  }

  /** List bounded redacted Finding Summaries from a verified Seal or Risk Decision Window. */
  async listFindings(
    invocation: SecurityInvocation,
    request: ListFindingsRequest,
    options: InvocationOptions = {},
  ): Promise<SecurityResult<FindingListPageV1>> {
    try {
      const authority = this.authorityResolver.authority(invocation)
      if (authority === undefined || !authority.permissions.has('assessment:read')) {
        return failure('UNAUTHORIZED', 'The caller is not authorized to read Findings.')
      }
      const interrupted = interruption<FindingListPageV1>(options)
      if (interrupted !== undefined) return interrupted
      const parsed = listFindingsRequestSchema.safeParse(request)
      if (!parsed.success) {
        return failure('INVALID_REQUEST', 'The request does not match listFindings schema version 1.')
      }
      const source = await this.findingQuerySource(parsed.data.assessmentId)
      if (source === undefined) {
        const persistence = await this.ready
        if (persistence?.getAssessmentRecord(parsed.data.assessmentId) === undefined) {
          return failure('NOT_FOUND', 'The Assessment does not exist.')
        }
        return failure('CONFLICT', 'The Assessment has not produced queryable Finding records.')
      }
      return deepFreeze({
        ok: true,
        value: this.findingQueries.list(source, parsed.data, {
          kind: authority.kind,
          principalId: authority.principalId,
        }),
      })
    } catch (error) {
      if (error instanceof FindingQueryCursorError) {
        return failure('INVALID_REQUEST', 'The Finding query cursor is invalid for this request.')
      }
      return this.assessmentReadFailure(error, true)
    }
  }

  /** Read one exact immutable Finding revision without disclosing Evidence content. */
  async getFinding(
    invocation: SecurityInvocation,
    request: GetFindingRequest,
    options: InvocationOptions = {},
  ): Promise<SecurityResult<FindingDetailViewV1>> {
    try {
      if (!this.authorityResolver.authorizes(invocation, 'assessment:read')) {
        return failure('UNAUTHORIZED', 'The caller is not authorized to read Findings.')
      }
      const interrupted = interruption<FindingDetailViewV1>(options)
      if (interrupted !== undefined) return interrupted
      const parsed = getFindingRequestSchema.safeParse(request)
      if (!parsed.success) {
        return failure('INVALID_REQUEST', 'The request does not match getFinding schema version 1.')
      }
      const source = await this.findingQuerySource(parsed.data.assessmentId)
      if (source === undefined) {
        const persistence = await this.ready
        if (persistence?.getAssessmentRecord(parsed.data.assessmentId) === undefined) {
          return failure('NOT_FOUND', 'The Assessment does not exist.')
        }
        return failure('CONFLICT', 'The Assessment has not produced queryable Finding records.')
      }
      return deepFreeze({
        ok: true,
        value: this.findingQueries.get(source, parsed.data),
      })
    } catch (error) {
      if (error instanceof FindingQueryNotFoundError) {
        return failure('NOT_FOUND', 'The Finding record does not exist.')
      }
      if (error instanceof FindingQueryRevisionError) {
        return failure('CONFLICT', 'The requested Finding revision does not match the sealed record.')
      }
      return this.assessmentReadFailure(error, true)
    }
  }

  /** Resolve one purpose/profile-bound View without exposing Evidence storage authority. */
  async getEvidenceView(
    invocation: SecurityInvocation,
    request: GetEvidenceViewRequest,
    options: InvocationOptions = {},
  ): Promise<SecurityResult<EvidenceViewV1>> {
    try {
      const authority = this.authorityResolver.authority(invocation)
      if (authority === undefined || !authority.permissions.has('assessment:read')) {
        return failure('UNAUTHORIZED', 'The caller is not authorized to read Evidence metadata.')
      }
      const interrupted = interruption<EvidenceViewV1>(options)
      if (interrupted !== undefined) return interrupted
      const parsed = getEvidenceViewRequestSchema.safeParse(request)
      if (!parsed.success) {
        return failure('INVALID_REQUEST', 'The request does not match getEvidenceView schema version 1.')
      }
      const sealed = await this.verifiedSealedRecord(parsed.data.assessmentId)
      if (sealed === undefined) {
        const persistence = await this.ready
        if (persistence?.getAssessmentRecord(parsed.data.assessmentId) === undefined) {
          return failure('NOT_FOUND', 'The Assessment does not exist.')
        }
        return failure('CONFLICT', 'The Assessment has not produced sealed Evidence records.')
      }
      const finding = this.findingQueries.get(sealed.submission, {
        schemaVersion: 1,
        assessmentId: parsed.data.assessmentId,
        assessmentRevision: parsed.data.assessmentRevision,
        recordId: parsed.data.context.recordId,
        recordRevision: parsed.data.context.recordRevision,
      })
      return deepFreeze({
        ok: true,
        value: this.evidenceViews.get(
          sealed.submission,
          sealed.bundleManifest,
          finding,
          parsed.data,
          {
            evidenceProtectionId: sealed.bindings.evidenceProtectionId,
            dataEgressPolicyId: sealed.bindings.dataEgressPolicyId,
          },
          {
            canDiscloseValidationReview: authority.permissions.has(
              'evidence:disclose:validation-review',
            ),
          },
          new Date(Date.now() + EVIDENCE_VIEW_BOUNDED_JSON_LIFETIME_MS).toISOString(),
        ),
      })
    } catch (error) {
      if (error instanceof FindingQueryNotFoundError) {
        return failure('NOT_FOUND', 'The consuming Finding record does not exist.')
      }
      if (error instanceof EvidenceViewNotFoundError) {
        return failure('NOT_FOUND', 'The Evidence is not linked to the consuming Finding revision.')
      }
      if (error instanceof FindingQueryRevisionError) {
        return failure('CONFLICT', 'The requested Finding revision does not match the sealed record.')
      }
      return this.assessmentReadFailure(error, true)
    }
  }

  /** Record one immutable authority-derived decision inside an explicit pre-Seal window. */
  async recordRiskDecision(
    invocation: SecurityInvocation,
    request: RecordRiskDecisionRequest,
    options: InvocationOptions = {},
  ): Promise<SecurityResult<RiskDecisionReceiptV1>> {
    try {
      const authority = this.authorityResolver.authority(invocation)
      if (
        authority === undefined
        || !authority.permissions.has('risk:decide')
        || (authority.kind !== 'host-operator' && authority.kind !== 'control-plane')
      ) {
        return failure('UNAUTHORIZED', 'The caller has no Risk Decision Authority.')
      }
      const interrupted = interruption<RiskDecisionReceiptV1>(options)
      if (interrupted !== undefined) return interrupted
      const parsed = recordRiskDecisionRequestSchema.safeParse(request)
      if (!parsed.success) {
        return failure('INVALID_REQUEST', 'The request does not match recordRiskDecision schema version 1.')
      }
      const persistence = await this.ready
      if (!this.admitsMutations(persistence)) {
        return failure('UNAVAILABLE', 'Risk Decision mutations are unavailable in read-only-safe mode.', true)
      }
      const persistenceInput = {
        principalId: authority.principalId,
        authorityKind: authority.kind,
        request: parsed.data,
        canonicalRequest: parsed.data,
      } as const
      const replay = persistence.replayRiskDecision(persistenceInput)
      if (replay !== undefined) {
        try {
          await this.finalizeResolvedRiskDecision(persistence, replay.assessmentId)
        } catch {
          // The immutable receipt remains replayable while a failed Seal stays BLOCKED for recovery.
        }
        return deepFreeze({ ok: true, value: replay })
      }
      const assessment = persistence.getAssessmentRecord(parsed.data.assessmentId)
      const source = await this.findingQuerySource(parsed.data.assessmentId)
      if (source === undefined) {
        if (assessment === undefined) {
          return failure('NOT_FOUND', 'The Assessment does not exist.')
        }
        return failure('CONFLICT', 'The Assessment has no active or recorded Risk Decision context.')
      }
      const finding = this.findingQueries.get(source, {
        schemaVersion: 1,
        assessmentId: parsed.data.assessmentId,
        assessmentRevision: parsed.data.expectedAssessmentRevision,
        recordId: parsed.data.finding.recordId,
        recordRevision: parsed.data.finding.recordRevision,
      })
      const criticalBreakGlassAuthorized = authority.kind === 'host-operator'
        && authority.permissions.has('risk:break-glass')
      if (
        parsed.data.decision === 'ACCEPT'
        && finding.technicalSeverity?.value === 'CRITICAL'
        && !criticalBreakGlassAuthorized
      ) {
        return failure('UNAUTHORIZED', 'Critical Risk Acceptance requires qualified break-glass authority.')
      }
      const authorizationMode = finding.riskDecision.state === 'NOT_RECORDED'
        ? this.riskDecisions.admit(finding, parsed.data, new Date().toISOString(), {
            criticalBreakGlassEnabled: assessment?.contract.requestedStrongerControlIds.includes(
              CRITICAL_BREAK_GLASS_CONTROL_ID,
            ) ?? false,
            criticalBreakGlassAuthorized,
          })
        : finding.riskDecision.authorizationMode ?? 'SINGLE_AUTHORITY'
      const receipt = persistence.recordRiskDecision({ ...persistenceInput, authorizationMode })
      try {
        await this.finalizeResolvedRiskDecision(persistence, receipt.assessmentId)
      } catch {
        // The decision commit is authoritative; a failed Seal remains visibly BLOCKED for recovery.
      }
      return deepFreeze({ ok: true, value: receipt })
    } catch (error) {
      if (error instanceof FindingQueryNotFoundError) {
        return failure('NOT_FOUND', 'The Finding record does not exist.')
      }
      if (error instanceof FindingQueryRevisionError || error instanceof RiskDecisionPolicyError) {
        return failure('CONFLICT', 'The Risk Decision is not admissible for this Finding or revision.')
      }
      if (error instanceof SecurityPersistenceError) {
        if (error.code === 'idempotency_conflict') {
          return failure('IDEMPOTENCY_CONFLICT', 'The idempotency key is bound to a different request.')
        }
        if (error.code === 'assessment_not_found') {
          return failure('NOT_FOUND', 'The Assessment does not exist.')
        }
        if (error.code === 'revision_conflict') {
          return failure('CONFLICT', 'The Risk Decision conflicts with the current Assessment revision or window.')
        }
        return failure('UNAVAILABLE', 'The private Security Assurance store is unavailable.', true)
      }
      return failure('INTERNAL', 'Security Assurance could not record the Risk Decision.', true)
    }
  }

  /** Bounded long-poll for a durable Assessment revision without holding a Store transaction. */
  async waitForAssessmentRevision(
    invocation: SecurityInvocation,
    request: WaitForAssessmentRevisionRequest,
    options: InvocationOptions = {},
  ): Promise<SecurityResult<AssessmentRevisionSignalV1>> {
    try {
      if (!this.authorityResolver.authorizes(invocation, 'assessment:read')) {
        return failure('UNAUTHORIZED', 'The caller is not authorized to read Assessments.')
      }
      const parsed = waitForAssessmentRevisionRequestSchema.safeParse(request)
      if (!parsed.success) {
        return failure('INVALID_REQUEST', 'The request does not match waitForAssessmentRevision schema version 1.')
      }
      const persistence = await this.ready
      if (persistence === undefined || this.disposed) {
        return failure('UNAVAILABLE', 'Assessment queries are unavailable while the private store is offline.', true)
      }
      const timeoutAt = Date.now() + parsed.data.timeoutMs
      while (true) {
        const interrupted = interruption<AssessmentRevisionSignalV1>(options)
        if (interrupted !== undefined) return interrupted
        const record = persistence.getAssessmentRecord(parsed.data.assessmentId)
        if (record === undefined) return failure('NOT_FOUND', 'The Assessment does not exist.')
        if (record.assessmentRevision > parsed.data.afterRevision) {
          return deepFreeze({
            ok: true,
            value: {
              schemaVersion: 1,
              assessmentId: record.assessmentId,
              kind: 'CHANGED',
              changed: true,
              assessmentRevision: record.assessmentRevision,
              state: record.state,
              terminal: record.state === 'SEALED' || record.state === 'CANCELED',
              snapshotRefreshRequired: true,
            },
          })
        }
        const remaining = timeoutAt - Date.now()
        if (remaining <= 0) {
          return deepFreeze({
            ok: true,
            value: {
              schemaVersion: 1,
              assessmentId: record.assessmentId,
              kind: 'TIMED_OUT',
              changed: false,
              assessmentRevision: record.assessmentRevision,
              state: record.state,
              terminal: record.state === 'SEALED' || record.state === 'CANCELED',
              snapshotRefreshRequired: false,
            },
          })
        }
        await new Promise(resolve => setTimeout(resolve, Math.min(25, remaining)))
      }
    } catch (error) {
      return this.assessmentReadFailure(error)
    }
  }

  /** Serve the machine-authoritative Bundle Manifest only after publication verification. */
  async getBundleManifest(
    invocation: SecurityInvocation,
    request: GetBundleManifestRequest,
    options: InvocationOptions = {},
  ): Promise<SecurityResult<BundleManifestV1>> {
    try {
      if (!this.authorityResolver.authorizes(invocation, 'assessment:read')) {
        return failure('UNAUTHORIZED', 'The caller is not authorized to read Assessment Bundles.')
      }
      const interrupted = interruption<BundleManifestV1>(options)
      if (interrupted !== undefined) return interrupted
      const parsed = getBundleManifestRequestSchema.safeParse(request)
      if (!parsed.success) {
        return failure('INVALID_REQUEST', 'The request does not match getBundleManifest schema version 1.')
      }
      const sealed = await this.verifiedSealedRecord(parsed.data.assessmentId)
      if (sealed === undefined) {
        const persistence = await this.ready
        if (persistence?.getAssessmentRecord(parsed.data.assessmentId) === undefined) {
          return failure('NOT_FOUND', 'The Assessment does not exist.')
        }
        return failure('CONFLICT', 'The Assessment has not produced a sealed Bundle.')
      }
      return deepFreeze({ ok: true, value: sealed.bundleManifest })
    } catch (error) {
      return this.assessmentReadFailure(error, true)
    }
  }

  /** Serve a self-contained immutable Submission by value; private paths never cross this seam. */
  async getAssuranceSubmission(
    invocation: SecurityInvocation,
    request: GetAssuranceSubmissionRequest,
    options: InvocationOptions = {},
  ): Promise<SecurityResult<SecurityAssuranceSubmissionV1>> {
    try {
      if (!this.authorityResolver.authorizes(invocation, 'assurance-submission:read')) {
        return failure('UNAUTHORIZED', 'The caller is not authorized to read Assurance Submissions.')
      }
      const interrupted = interruption<SecurityAssuranceSubmissionV1>(options)
      if (interrupted !== undefined) return interrupted
      const parsed = getAssuranceSubmissionRequestSchema.safeParse(request)
      if (!parsed.success) {
        return failure('INVALID_REQUEST', 'The request does not match getAssuranceSubmission schema version 1.')
      }
      const sealed = await this.verifiedSealedRecord(parsed.data.assessmentId)
      if (sealed === undefined) {
        const persistence = await this.ready
        if (persistence?.getAssessmentRecord(parsed.data.assessmentId) === undefined) {
          return failure('NOT_FOUND', 'The Assessment does not exist.')
        }
        return failure('CONFLICT', 'The Assessment has not produced a sealed Submission.')
      }
      return deepFreeze({ ok: true, value: sealed.submission })
    } catch (error) {
      return this.assessmentReadFailure(error, true)
    }
  }

  /** Accept one idempotent SEALED Export and deliver it without exposing a private path. */
  async requestExport(
    invocation: SecurityInvocation,
    request: RequestExportRequest,
    options: InvocationOptions = {},
  ): Promise<SecurityResult<ExportRequestReceiptV1>> {
    try {
      const authority = this.authorityResolver.authority(invocation)
      if (authority === undefined || !authority.permissions.has('export:request')) {
        return failure('UNAUTHORIZED', 'The caller is not authorized to request Exports.')
      }
      const interrupted = interruption<ExportRequestReceiptV1>(options)
      if (interrupted !== undefined) return interrupted
      const parsed = requestExportRequestSchema.safeParse(request)
      if (!parsed.success) {
        return failure('INVALID_REQUEST', 'The request does not match requestExport schema version 1.')
      }
      const persistence = await this.ready
      if (!this.admitsMutations(persistence)) {
        return failure('UNAVAILABLE', 'Export Requests are unavailable in read-only-safe mode.', true)
      }
      const sealed = await this.verifiedSealedRecord(parsed.data.assessmentId)
      if (sealed === undefined) {
        if (persistence?.getAssessmentRecord(parsed.data.assessmentId) === undefined) {
          return failure('NOT_FOUND', 'The Assessment does not exist.')
        }
        return failure('CONFLICT', 'Only a SEALED Assessment may produce an official Export.')
      }
      if (sealed.bundleManifest.assessmentRevision !== parsed.data.expectedAssessmentRevision) {
        return failure('CONFLICT', 'The Export Request does not match the sealed Assessment revision.')
      }
      if (!sealed.bindings.deliveryDestinationIds.includes(parsed.data.deliveryDestinationId)) {
        return failure('CONFLICT', 'The Delivery Destination is not frozen into this Assessment contract.')
      }
      const preview = buildExportPreview({
        assessmentId: parsed.data.assessmentId,
        assessmentRevision: sealed.bundleManifest.assessmentRevision,
        sealId: sealed.bundleManifest.seal.sealId,
        deliveryDestinationId: parsed.data.deliveryDestinationId,
      })
      if (preview === undefined) {
        return failure('CONFLICT', 'The registered Delivery Destination has no active v1 delivery adapter.')
      }
      const begin = await this.exportDelivery.begin({
        principalId: authority.principalId,
        authorityKind: authority.kind,
      }, parsed.data, preview)
      this.wakeExportDeliveryWorker()
      await this.exportDelivery.deliver(begin, sealed.submission)
      return deepFreeze({ ok: true, value: begin.record.receipt })
    } catch (error) {
      return this.exportFailure(error)
    }
  }

  /** Preview one authorized Export selection or read one owner-bound durable Delivery status. */
  async getExport(
    invocation: SecurityInvocation,
    request: GetExportRequest,
    options: InvocationOptions = {},
  ): Promise<SecurityResult<ExportViewV1>> {
    try {
      const authority = this.authorityResolver.authority(invocation)
      if (authority === undefined || !authority.permissions.has('export:read')) {
        return failure('UNAUTHORIZED', 'The caller is not authorized to read Exports.')
      }
      const interrupted = interruption<ExportViewV1>(options)
      if (interrupted !== undefined) return interrupted
      const parsed = getExportRequestSchema.safeParse(request)
      if (!parsed.success) {
        return failure('INVALID_REQUEST', 'The request does not match getExport schema version 1.')
      }
      if (parsed.data.kind === 'DOWNLOAD') {
        if (!authority.permissions.has('export:download')) {
          return failure('UNAUTHORIZED', 'The caller is not authorized to download Exports.')
        }
        const downloadAuthority = {
          principalId: authority.principalId,
          authorityKind: authority.kind,
        }
        const capability = await this.exportDelivery.authorizeDownload(downloadAuthority, parsed.data)
        const download = await this.exportDelivery.consumeDownload(downloadAuthority, capability)
        return deepFreeze({ ok: true, value: download })
      }
      if (parsed.data.kind === 'STATUS') {
        const view = await this.exportDelivery.get(parsed.data.exportId, {
          principalId: authority.principalId,
          authorityKind: authority.kind,
        })
        if (view === undefined) return failure('NOT_FOUND', 'The Export does not exist.')
        return deepFreeze({
          ok: true,
          value: this.exportDelivery.projectAuthorizedAccess(
            view,
            authority.permissions.has('export:download'),
          ),
        })
      }
      const sealed = await this.verifiedSealedRecord(parsed.data.assessmentId)
      if (sealed === undefined) {
        const persistence = await this.ready
        if (persistence?.getAssessmentRecord(parsed.data.assessmentId) === undefined) {
          return failure('NOT_FOUND', 'The Assessment does not exist.')
        }
        return failure('CONFLICT', 'Only a SEALED Assessment may be previewed for official Export.')
      }
      if (!sealed.bindings.deliveryDestinationIds.includes(parsed.data.deliveryDestinationId)) {
        return failure('CONFLICT', 'The Delivery Destination is not frozen into this Assessment contract.')
      }
      const preview = buildExportPreview({
        assessmentId: parsed.data.assessmentId,
        assessmentRevision: sealed.bundleManifest.assessmentRevision,
        sealId: sealed.bundleManifest.seal.sealId,
        deliveryDestinationId: parsed.data.deliveryDestinationId,
      })
      if (preview === undefined) {
        return failure('CONFLICT', 'The registered Delivery Destination has no active v1 delivery adapter.')
      }
      return deepFreeze({ ok: true, value: preview })
    } catch (error) {
      return this.exportFailure(error)
    }
  }

  private executeControlPlaneProviderOperation(
    invocation: SecurityInvocation,
    operation: ControlPlaneProviderOperation,
    options: InvocationOptions,
  ): Promise<ControlPlaneProviderOperationOutcome> {
    return operation.kind === 'CANCEL'
      ? this.cancelControlPlaneAssessment(invocation, operation, options)
      : this.runControlPlaneAssessment(invocation, operation, options)
  }

  private async runControlPlaneAssessment(
    invocation: SecurityInvocation,
    operation: ControlPlaneAssessmentOperation,
    options: InvocationOptions,
  ): Promise<ControlPlaneAssessmentOperationOutcome> {
    const repository = await this.getRepository(
      invocation,
      { schemaVersion: 1, repositoryId: operation.repositoryId },
      options,
    )
    if (!repository.ok) return controlPlaneSecurityFailure(repository.error.code)
    if (repository.value.state !== 'ENABLED') {
      return { kind: 'EXTERNAL_FAILURE', reason: 'blocked', code: 'repository_disabled' }
    }
    let repositoryBindingMatches: boolean
    try {
      repositoryBindingMatches = await verifyControlPlaneRepositoryBinding(
        this,
        invocation,
        operation.repositoryId,
        operation.context,
      )
    } catch {
      return { kind: 'EXTERNAL_FAILURE', reason: 'blocked', code: 'repository_binding_unavailable' }
    }
    if (!repositoryBindingMatches) {
      return { kind: 'EXTERNAL_FAILURE', reason: 'failed', code: 'repository_binding_mismatch' }
    }

    const started = await this.startAssessment(invocation, {
      schemaVersion: 1,
      contractVersion: 1,
      idempotencyKey: controlPlaneOperationIdempotencyKey(
        'start',
        operation.context,
        operation.repositoryId,
      ),
      repositoryId: operation.repositoryId,
      subject: {
        kind: 'workspace_change',
        branch: operation.context.subject.branch,
        baseCommit: operation.context.subject.head,
        workspaceFingerprint: operation.context.subject.workspaceFingerprint,
        producedChangeFingerprint: operation.context.subject.producedChangeFingerprint,
      },
      assessmentMode: 'CHANGE',
      assessmentProfileId: repository.value.bindings.assessmentProfileId,
      target: {
        kind: 'change',
        baseCommit: operation.context.subject.head,
        workspaceFingerprint: operation.context.subject.workspaceFingerprint,
        producedChangeFingerprint: operation.context.subject.producedChangeFingerprint,
        impactCone: 'POLICY_DEFAULT',
      },
      requestedStrongerControlIds: [],
    }, options)
    if (!started.ok) return controlPlaneSecurityFailure(started.error.code)
    await reachControlPlaneCancellationCrashCheckpoint(
      this,
      'after_assessment_started',
      started.value.assessmentId,
    )

    let revision: number = started.value.assessmentRevision
    while (true) {
      const assessment = await this.getAssessment(invocation, {
        schemaVersion: 1,
        assessmentId: started.value.assessmentId,
      }, options)
      if (!assessment.ok) return controlPlaneSecurityFailure(assessment.error.code)
      revision = assessment.value.assessmentRevision
      if (assessment.value.state === 'SEALED') {
        const submission = await this.getAssuranceSubmission(invocation, {
          schemaVersion: 1,
          assessmentId: started.value.assessmentId,
        }, options)
        if (!submission.ok) return controlPlaneSecurityFailure(submission.error.code)
        return controlPlaneSealedOutcome(assessment.value, submission.value)
      }
      if (assessment.value.state === 'BLOCKED') {
        if (operation.kind !== 'RECOVER') {
          return { kind: 'EXTERNAL_FAILURE', reason: 'blocked', code: 'assessment_blocked' }
        }
        const resumed = await this.resumeAssessment(invocation, {
          schemaVersion: 1,
          contractVersion: 1,
          assessmentId: assessment.value.assessmentId,
          expectedAssessmentRevision: assessment.value.assessmentRevision,
          idempotencyKey: controlPlaneOperationIdempotencyKey('resume', operation.context),
          reason: {
            code: 'CONTROL_PLANE_PROVIDER_RECOVERY',
            summary: 'Reconcile the durable Control Plane Provider invocation after host restart.',
          },
        }, options)
        if (!resumed.ok) return controlPlaneSecurityFailure(resumed.error.code)
        revision = resumed.value.assessmentRevision
        continue
      }
      if (assessment.value.state === 'CANCELED') {
        return { kind: 'EXTERNAL_FAILURE', reason: 'canceled', code: 'assessment_canceled' }
      }

      const changed = await this.waitForAssessmentRevision(invocation, {
        schemaVersion: 1,
        assessmentId: started.value.assessmentId,
        afterRevision: revision,
        timeoutMs: 5_000,
      }, options)
      if (!changed.ok) return controlPlaneSecurityFailure(changed.error.code)
      revision = changed.value.assessmentRevision
    }
  }

  private async cancelControlPlaneAssessment(
    invocation: SecurityInvocation,
    operation: ControlPlaneCancellationOperation,
    options: InvocationOptions,
  ): Promise<ControlPlaneCancellationOperationOutcome> {
    const started = await lookupControlPlaneAssessment(this, invocation, {
      idempotencyKey: controlPlaneOperationIdempotencyKey(
        'start',
        operation.context,
        operation.repositoryId,
      ),
      repositoryId: operation.repositoryId,
    })
    if (started === undefined) return { kind: 'EXTERNAL_ASSESSMENT_NOT_STARTED' }

    for (let reconciliation = 0; reconciliation < 4; reconciliation += 1) {
      const assessment = await this.getAssessment(invocation, {
        schemaVersion: 1,
        assessmentId: started.assessmentId,
      }, options)
      if (!assessment.ok) throw new Error(`Security Assessment lookup failed (${assessment.error.code})`)
      if (assessment.value.state === 'SEALED') {
        return {
          kind: 'EXTERNAL_ASSESSMENT_TERMINAL',
          externalAssessmentId: assessment.value.assessmentId,
          terminalState: 'sealed',
        }
      }
      if (assessment.value.state === 'CANCELED') {
        return {
          kind: 'EXTERNAL_ASSESSMENT_TERMINAL',
          externalAssessmentId: assessment.value.assessmentId,
          terminalState: 'canceled',
        }
      }
      const canceled = await this.cancelAssessment(invocation, {
        schemaVersion: 1,
        contractVersion: 1,
        assessmentId: assessment.value.assessmentId,
        expectedAssessmentRevision: assessment.value.assessmentRevision,
        idempotencyKey: controlPlaneOperationIdempotencyKey('cancel', operation.context),
        reason: {
          code: 'CONTROL_PLANE_MISSION_CANCELED',
          summary: 'Cancel the external Assessment because its owning Mission was explicitly canceled.',
        },
      }, options)
      if (!canceled.ok) {
        if (canceled.error.code === 'CONFLICT') continue
        throw new Error(`Security Assessment cancellation failed (${canceled.error.code})`)
      }
      const terminal = await this.getAssessment(invocation, {
        schemaVersion: 1,
        assessmentId: assessment.value.assessmentId,
      }, options)
      if (!terminal.ok || terminal.value.state !== 'CANCELED') {
        throw new Error('Security Assessment cancellation did not reach CANCELED')
      }
      await reachControlPlaneCancellationCrashCheckpoint(
        this,
        'after_assessment_canceled_before_provider_outcome',
        terminal.value.assessmentId,
      )
      return {
        kind: 'EXTERNAL_ASSESSMENT_CANCELED',
        externalAssessmentId: terminal.value.assessmentId,
      }
    }
    throw new Error('Security Assessment changed repeatedly during cancellation')
  }

  private admitsMutations(
    persistence: SecurityPersistence | undefined,
  ): persistence is SecurityPersistence {
    return persistence !== undefined
      && this.lifecycleState === 'ACTIVE'
      && this.runtimeCompatible
      && this.harnessVerification !== 'FAIL'
  }

  private startExportDeliveryWorker(): void {
    if (this.disposed || this.exportDeliveryWorkerTask !== undefined) return
    this.exportDeliveryWorkerTask = this.runExportDeliveryWorker(this.exportDeliveryWorkerController.signal)
  }

  private async runExportDeliveryWorker(signal: AbortSignal): Promise<void> {
    while (!signal.aborted) {
      let waitMs = EXPORT_DELIVERY_IDLE_SCAN_MS
      try {
        const recoverable = await this.exportDelivery.listRecoverable()
        const expirable = await this.exportDelivery.listExpirable()
        const observedAt = Date.now()
        let attempted = false
        let purgePending = false
        for (const delivery of recoverable) {
          if (signal.aborted) return
          const retryAt = delivery.nextRetryAt === null ? observedAt : Date.parse(delivery.nextRetryAt)
          if (retryAt > observedAt) {
            waitMs = Math.min(waitMs, retryAt - observedAt)
            continue
          }
          attempted = true
          let submission: SecurityAssuranceSubmissionV1 | undefined
          try {
            submission = (await this.verifiedSealedRecord(delivery.assessmentId))?.submission
          } catch {
            // A missing or unverifiable source is recorded through the same bounded attempt policy.
          }
          if (signal.aborted) return
          if (submission === undefined) {
            await this.exportDelivery.recordSourceUnavailable(delivery.exportId)
          } else {
            await this.exportDelivery.deliverPending(delivery.exportId, submission)
          }
        }
        for (const expiry of expirable) {
          if (signal.aborted) return
          const expiresAt = expiry.purgePending ? observedAt : Date.parse(expiry.expiresAt)
          if (expiresAt > observedAt) {
            waitMs = Math.min(waitMs, expiresAt - observedAt)
            continue
          }
          attempted = true
          const status = await this.exportDelivery.reconcileExpiry(expiry.exportId)
          if (status.status === 'EXPIRED' && status.retention.status === 'PURGE_PENDING') {
            purgePending = true
          }
        }
        if (attempted && !purgePending) continue
        if (purgePending) waitMs = Math.min(waitMs, EXPORT_RETENTION_REAPER_RETRY_MS)
      } catch {
        waitMs = EXPORT_DELIVERY_WORKER_ERROR_RETRY_MS
      }
      await this.waitForExportDeliveryWake(waitMs, signal)
    }
  }

  private wakeExportDeliveryWorker(): void {
    this.exportDeliveryWakePending = true
    this.exportDeliveryWake?.()
  }

  private waitForExportDeliveryWake(delayMs: number, signal: AbortSignal): Promise<void> {
    if (signal.aborted) return Promise.resolve()
    if (this.exportDeliveryWakePending) {
      this.exportDeliveryWakePending = false
      return Promise.resolve()
    }
    return new Promise(resolve => {
      let settled = false
      let timer: ReturnType<typeof setTimeout> | undefined
      const finish = (): void => {
        if (settled) return
        settled = true
        if (timer !== undefined) clearTimeout(timer)
        signal.removeEventListener('abort', finish)
        if (this.exportDeliveryWake === finish) this.exportDeliveryWake = undefined
        this.exportDeliveryWakePending = false
        resolve()
      }
      this.exportDeliveryWake = finish
      signal.addEventListener('abort', finish, { once: true })
      timer = setTimeout(finish, Math.max(0, delayMs))
    })
  }

  private launchAssessment(persistence: SecurityPersistence, assessmentId: AssessmentId): void {
    if (this.disposed || this.runningAssessments.has(assessmentId)) return
    const controller = new AbortController()
    const task = this.runAssessment(persistence, assessmentId, controller.signal)
    const running = { controller, task }
    this.runningAssessments.set(assessmentId, running)
    void task.finally(() => {
      if (this.runningAssessments.get(assessmentId) === running) {
        this.runningAssessments.delete(assessmentId)
      }
    })
  }

  private async runAssessment(
    persistence: SecurityPersistence,
    assessmentId: AssessmentId,
    signal: AbortSignal,
  ): Promise<void> {
    let runningRevision: number | undefined
    try {
      const running = persistence.beginAssessment(assessmentId)
      if (running === undefined) return
      runningRevision = running.assessmentRevision
      if (signal.aborted) throw new Error('assessment execution canceled')
      const sealedAt = new Date().toISOString()
      const needsSourceSlices = running.contract.policy.policyId === 'security/node-package-lifecycle'
        || running.contract.analyzerPortfolio.length > 0
      const sourceSlices = needsSourceSlices
        ? await readVerifiedNodePackageManifestSlices(
            this.securityRoot,
            running.subject.digest,
            signal,
          )
        : []
      const needsNpmAuditSlices = running.contract.analyzerPortfolio.some(entry => (
        entry.descriptor.analyzerId === NPM_AUDIT_ANALYZER_ID
      ))
      const npmAuditSlices = needsNpmAuditSlices
        ? await readVerifiedExternalToolReportSlices(
            this.securityRoot,
            running.subject.digest,
            [NPM_AUDIT_REPORT_BASE_NAME],
            signal,
          )
        : []
      const analyzerSlices = npmAuditSlices.length > 0
        ? [...sourceSlices, ...npmAuditSlices]
        : sourceSlices
      const analysis = running.contract.policy.policyId === 'security/node-package-lifecycle'
        ? {
            expectedSubjectDigest: running.subject.digest,
            contribution: analyzeNodePackageInstallLifecycle({
              subjectDigest: running.subject.digest,
              slices: sourceSlices,
            }),
          }
        : undefined
      const externalAnalyses = await Promise.all(running.contract.analyzerPortfolio.map(
        async portfolioEntry => ({
          portfolioEntry,
          subjectSlices: analyzerSlices,
          contribution: await this.analyzerRegistry.execute(portfolioEntry.descriptor, {
            schemaVersion: 1,
            assessmentId,
            attemptId: `${assessmentId}:${portfolioEntry.descriptor.analyzerId}:${runningRevision}`,
            assessmentMode: running.contract.assessmentMode,
            subject: {
              digest: running.subject.digest,
              textSlices: analyzerSlices.map(slice => ({
                path: slice.path,
                mediaType: 'application/json',
                digest: slice.digest,
                text: slice.text,
              })),
            },
            policy: {
              policyId: running.contract.policy.policyId,
              digest: running.contract.policy.digest,
            },
            coverageObligationIds: portfolioEntry.descriptor.coverageObligationIds,
          }, { signal }),
        }),
      ))
      const outcome = evaluateDeterministicAssessment(
        running.contract,
        sealedAt,
        analysis,
        externalAnalyses,
      )
      const publishedEvidence = await publishEvidenceSet(
        this.securityRoot,
        assessmentId,
        running.subject.digest,
        outcome.evidence,
      )
      if (
        running.contract.requestedStrongerControlIds.includes(RISK_DECISION_WINDOW_CONTROL_ID)
        && outcome.findings.length > 0
      ) {
        const findingRecordIds = outcome.findings.map(finding => {
          if (typeof finding !== 'object' || finding === null || Array.isArray(finding)) {
            throw new TypeError('Risk Decision Window Finding is not an object')
          }
          const findingId = (finding as Readonly<Record<string, unknown>>).findingId
          if (typeof findingId !== 'string' || !/^finding-[0-9a-f]{64}$/.test(findingId)) {
            throw new TypeError('Risk Decision Window Finding identity is invalid')
          }
          return findingId
        })
        persistence.openRiskDecisionWindow({
          assessmentId,
          expectedAssessmentRevision: runningRevision,
          evaluationInstant: sealedAt,
          findingRecordIds,
          outcome,
          evidenceReceipts: publishedEvidence,
        })
        return
      }
      const readiness = checkSealReadiness(running.contract, outcome, publishedEvidence)
      if (!readiness.ready) throw new Error(`seal readiness failed: ${readiness.violations.join(',')}`)
      const artifacts = assembleSealedArtifacts(running, outcome, {
        sealId: `seal-${randomUUID()}`,
        sealedAt,
      })
      await publishSealedArtifacts(this.securityRoot, assessmentId, artifacts)
      if (signal.aborted) throw new Error('assessment execution canceled')
      persistence.sealAssessment({
        assessmentId,
        expectedAssessmentRevision: runningRevision,
        coverage: outcome.coverage,
        findings: outcome.findings,
        evaluationTrace: outcome.evaluationTrace,
        verdict: outcome.verdict,
        seal: artifacts.seal,
        bundleManifest: artifacts.bundleManifest,
        submission: artifacts.submission,
        publicationDigest: artifacts.publicationDigest,
      })
    } catch {
      if (runningRevision !== undefined) {
        try {
          persistence.blockAssessment(assessmentId, runningRevision, 'ASSESSMENT_EXECUTION_FAILED')
        } catch {
          // Teardown or a concurrent terminal transition already made this failure durable.
        }
      }
    }
  }

  private async verifiedSealedRecord(assessmentId: AssessmentId): Promise<{
    readonly bundleManifest: BundleManifestV1
    readonly submission: SecurityAssuranceSubmissionV1
    readonly bindings: RepositoryBindingsV1
  } | undefined> {
    const persistence = await this.ready
    if (persistence === undefined || this.disposed) {
      throw new SecurityPersistenceError('corrupt_database', 'Assessment store is unavailable')
    }
    const record = persistence.getAssessmentRecord(assessmentId)
    if (
      record === undefined
      || record.state !== 'SEALED'
      || record.seal === null
      || record.bundleManifest === null
      || record.submission === null
      || record.publicationDigest === null
    ) return undefined
    try {
      await verifyPublishedSealedArtifacts(this.securityRoot, assessmentId, {
        seal: record.seal,
        bundleManifest: record.bundleManifest,
        submission: record.submission,
        publicationDigest: record.publicationDigest,
      })
    } catch (error) {
      throw new SecurityArtifactIntegrityError('Sealed Assessment artifact verification failed', {
        cause: error,
      })
    }
    return {
      bundleManifest: record.bundleManifest,
      submission: record.submission,
      bindings: record.repository.bindings,
    }
  }

  private async findingQuerySource(assessmentId: AssessmentId): Promise<FindingQuerySourceV1 | undefined> {
    const sealed = await this.verifiedSealedRecord(assessmentId)
    if (sealed !== undefined) return sealed.submission
    const persistence = await this.ready
    if (persistence === undefined || this.disposed) {
      throw new SecurityPersistenceError('corrupt_database', 'Assessment store is unavailable')
    }
    const record = persistence.getAssessmentRecord(assessmentId)
    if (
      record === undefined
      || record.state !== 'BLOCKED'
      || record.failureCode !== 'RISK_DECISION_WINDOW'
    ) return undefined
    const window = record.riskDecisionWindow
    if (window === null) return undefined
    let values: Awaited<ReturnType<typeof readPublishedEvidenceSet>>
    try {
      values = await readPublishedEvidenceSet(
        this.securityRoot,
        assessmentId,
        record.subject.digest,
        window.evidenceReceipts,
      )
    } catch (error) {
      throw new SecurityArtifactIntegrityError('Risk Decision Window Evidence verification failed', {
        cause: error,
      })
    }
    if (values.length !== window.evidenceReceipts.length) {
      throw new SecurityArtifactIntegrityError('Risk Decision Window Evidence receipt count changed')
    }
    const evidence = values.map((value, index) => {
      const receipt = window.evidenceReceipts[index]
      if (receipt === undefined || receipt.artifactId !== value.artifactId || receipt.schemaId !== value.schemaId) {
        throw new SecurityArtifactIntegrityError('Risk Decision Window Evidence order or identity changed')
      }
      return securitySubmissionArtifactV1Schema.parse({
        artifactId: value.artifactId,
        schemaId: value.schemaId,
        schemaVersion: 1,
        digest: receipt.digest,
        value: value.value,
      })
    })
    return {
      payload: {
        assessment: {
          assessmentId: record.assessmentId,
          assessmentRevision: record.assessmentRevision,
        },
        binding: { repositoryId: record.repository.repositoryId },
        coverage: { value: securitySubmissionJsonV1Schema.parse(record.coverage) },
        findings: {
          value: securitySubmissionJsonV1Schema.parse({
            schemaVersion: 1,
            findings: record.findings,
          }),
        },
        riskDecisions: {
          value: securitySubmissionJsonV1Schema.parse({
            schemaVersion: 1,
            decisions: record.riskDecisions,
          }),
        },
        evidence,
      },
    }
  }

  private async finalizeResolvedRiskDecision(
    persistence: SecurityPersistence,
    assessmentId: AssessmentId,
  ): Promise<void> {
    const record = persistence.getAssessmentRecord(assessmentId)
    const window = record?.riskDecisionWindow
    if (
      record === undefined
      || record.state !== 'BLOCKED'
      || window === undefined
      || window === null
      || window.state !== 'RESOLVED'
    ) return
    const evidence = await readPublishedEvidenceSet(
      this.securityRoot,
      assessmentId,
      record.subject.digest,
      window.evidenceReceipts,
    )
    const finalizedAt = new Date().toISOString()
    const outcome = this.riskDecisions.finalizedOutcome(record, evidence, finalizedAt)
    const readiness = checkSealReadiness(record.contract, outcome, window.evidenceReceipts)
    if (!readiness.ready) throw new Error(`seal readiness failed: ${readiness.violations.join(',')}`)
    const artifacts = assembleSealedArtifacts(record, outcome, {
      sealId: `seal-${randomUUID()}`,
      sealedAt: finalizedAt,
    })
    await publishSealedArtifacts(this.securityRoot, assessmentId, artifacts)
    persistence.sealAssessment({
      assessmentId,
      expectedAssessmentRevision: record.assessmentRevision,
      coverage: outcome.coverage,
      findings: outcome.findings,
      evaluationTrace: outcome.evaluationTrace,
      verdict: outcome.verdict,
      seal: artifacts.seal,
      bundleManifest: artifacts.bundleManifest,
      submission: artifacts.submission,
      publicationDigest: artifacts.publicationDigest,
    })
  }

  private async initialize(config: Config): Promise<SecurityPersistence | undefined> {
    try {
      const dshHome = resolveDshHome(config.dshHome)
      await reapSubjectStaging(join(dshHome, 'security-assurance'))
      const persistence = await openSecurityPersistence({
        databasePath: join(dshHome, 'security-assurance', 'security-assurance.sqlite'),
      })
      try {
        persistence.recoverInterruptedAssessments()
        return persistence
      } catch (error) {
        persistence.close()
        throw error
      }
    } catch {
      return undefined
    }
  }

  private repositoryMutationFailure<T>(error: unknown): SecurityResult<T> {
    if (error instanceof SecurityPersistenceError) {
      if (error.code === 'idempotency_conflict') {
        return failure('IDEMPOTENCY_CONFLICT', 'The idempotency key is bound to a different request.')
      }
      if (error.code === 'repository_not_found') {
        return failure('NOT_FOUND', 'The Repository does not exist.')
      }
      if (error.code === 'revision_conflict' || error.code === 'repository_conflict') {
        return failure('CONFLICT', 'The Repository command conflicts with its current revision or state.')
      }
      return failure('UNAVAILABLE', 'The private Security Assurance store is unavailable.', true)
    }
    return failure('INTERNAL', 'Security Assurance could not complete the operation.', true)
  }

  private assessmentReadFailure<T>(error: unknown, artifactRead = false): SecurityResult<T> {
    if (error instanceof SecurityPersistenceError) {
      return failure('UNAVAILABLE', 'The private Security Assurance store is unavailable.', true)
    }
    if (artifactRead && error instanceof SecurityArtifactIntegrityError) {
      return failure('UNAVAILABLE', 'The sealed Assessment artifact failed integrity verification.', true)
    }
    return failure('INTERNAL', 'Security Assurance could not complete the operation.', true)
  }

  private exportFailure<T>(error: unknown): SecurityResult<T> {
    if (error instanceof ExportDeliveryError) {
      if (error.code === 'IDEMPOTENCY_CONFLICT') {
        return failure('CONFLICT', 'The Export idempotency key conflicts with a different request.')
      }
      if (error.code === 'NOT_FOUND') return failure('NOT_FOUND', 'The Export does not exist.')
      if (
        error.code === 'CONFLICT'
        || error.code === 'CAPABILITY_CONSUMED'
        || error.code === 'CAPABILITY_EXPIRED'
      ) {
        return failure('CONFLICT', 'The one-use Export download is no longer available.')
      }
      return failure('UNAVAILABLE', 'Export delivery state is unavailable.', true)
    }
    if (error instanceof SecurityPersistenceError) {
      return failure('UNAVAILABLE', 'The private Security Assurance store is unavailable.', true)
    }
    return failure('INTERNAL', 'Security Assurance could not complete the operation.', true)
  }
}

export default SecurityAssuranceService
