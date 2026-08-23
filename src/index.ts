import { randomUUID } from 'node:crypto'
import { realpath, stat } from 'node:fs/promises'
import { join } from 'node:path'
import { Context, Service } from '@deepseek-ai/cordis'
import { resolveDshHome } from '@deepseek-ai/dsh-home-paths'
import {
  disableRepositoryRequestSchema,
  getRepositoryRequestSchema,
  getHealthRequestSchema,
  listRepositoriesRequestSchema,
  registerRepositoryRequestSchema,
  startAssessmentRequestSchema,
  updateRepositoryRequestSchema,
  REQUIRED_NODE_RANGE,
  runtimeHealthSnapshotSchema,
  SECURITY_ASSURANCE_PRODUCT_NAME,
  SECURITY_ASSURANCE_PRODUCT_VERSION,
  TARGET_HARNESS_VERSION,
} from './contracts.ts'
import type {
  AssessmentReceiptV1,
  AssessmentSubjectSourceV1,
  AssessmentTargetSelectorV1,
  DisableRepositoryRequest,
  GetHealthRequest,
  GetRepositoryRequest,
  InvocationOptions,
  ListRepositoriesRequest,
  PublicSecurityErrorCode,
  RegisterRepositoryRequest,
  RepositoryCommandReceiptV1,
  RepositoryListSnapshotV1,
  RepositorySnapshotV1,
  RuntimeHealthSnapshot,
  SecurityInvocation,
  SecurityResult,
  StartAssessmentRequest,
  UpdateRepositoryRequest,
} from './contracts.ts'
import {
  RESOLVE_TRUSTED_INVOCATION,
  SecurityAuthorityResolver,
} from './internal/authority.ts'
import type { TrustedCallerChannel } from './internal/authority.ts'
import { deepFreeze } from './internal/freeze.ts'
import {
  openSecurityPersistence,
  SecurityPersistenceError,
} from './internal/persistence.ts'
import type { SecurityPersistence } from './internal/persistence.ts'
import { freezeSubject, SubjectFreezeError } from './internal/subject-freeze.ts'

export * from './contracts.ts'

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

function buildRuntimeHealth(persistenceReady: boolean): RuntimeHealthSnapshot {
  const actualNodeVersion = process.versions.node
  const nodeSupported = nodeVersionIsSupported(actualNodeVersion)
  const mutationsAdmitted = nodeSupported && persistenceReady
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
      harnessVerification: 'PENDING_INVARIANT',
    },
    state: mutationsAdmitted ? 'READY' : 'READ_ONLY_SAFE',
    admission: {
      queries: true,
      mutations: mutationsAdmitted,
      sealedExports: mutationsAdmitted,
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
      {
        id: 'compatibility.harness',
        status: 'NOT_EVALUATED',
        required: false,
        message: 'The dormant invariant entry will verify the exact Harness composition.',
      },
    ],
  })
}

function assessmentSelectionIsConsistent(
  subject: AssessmentSubjectSourceV1,
  mode: StartAssessmentRequest['assessmentMode'],
  target: AssessmentTargetSelectorV1,
): boolean {
  if (mode === 'REPOSITORY') return target.kind === 'repository' && subject.kind !== 'change'
  if (mode === 'TARGETED') return target.kind === 'targeted' && subject.kind !== 'change'
  return mode === 'CHANGE'
    && subject.kind === 'change'
    && target.kind === 'change'
    && subject.baseCommit === target.baseCommit
    && subject.headCommit === target.headCommit
}

export interface Config {
  /** Optional explicit Harness home; defaults through the shared DSH_HOME resolver. */
  readonly dshHome?: string
}

/**
 * Sole public business Interface for Security Assurance.
 * Internal adapters use the hidden Resolver symbol; package consumers cannot
 * mint or deserialize Security Invocations.
 */
export class SecurityAssuranceService extends Service {
  private readonly authorityResolver = new SecurityAuthorityResolver()
  private readonly ready: Promise<SecurityPersistence | undefined>
  private readonly securityRoot: string
  private disposed = false

  constructor(ctx: Context, config: Config = {}) {
    super(ctx, 'securityAssurance')
    this.securityRoot = join(resolveDshHome(config.dshHome), 'security-assurance')
    Object.defineProperty(this, RESOLVE_TRUSTED_INVOCATION, {
      configurable: false,
      enumerable: false,
      writable: false,
      value: (channel: TrustedCallerChannel) => this.authorityResolver.resolve(channel),
    })
    this.ready = this.initialize(config)
    void this.ready.catch(() => {})
    ctx.effect(async () => {
      const persistence = await this.ready
      return () => {
        this.disposed = true
        persistence?.close()
      }
    }, 'security assurance teardown')
  }

  /** Join private-store validation without exposing the Store itself. */
  async whenReady(): Promise<void> {
    if (await this.ready === undefined) {
      throw new Error('Security Assurance entered read-only-safe mode during startup')
    }
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
      return deepFreeze({ ok: true, value: buildRuntimeHealth(persistence !== undefined && !this.disposed) })
    } catch {
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
      if (persistence === undefined || this.disposed) {
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
      if (persistence === undefined || this.disposed) {
        return failure('UNAVAILABLE', 'Repository mutations are unavailable in read-only-safe mode.', true)
      }
      const receipt = persistence.updateRepository({
        principalId: authority.principalId,
        authorityKind: authority.kind,
        idempotencyKey: parsed.data.idempotencyKey,
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
      if (persistence === undefined || this.disposed) {
        return failure('UNAVAILABLE', 'Repository mutations are unavailable in read-only-safe mode.', true)
      }
      const receipt = persistence.disableRepository({
        principalId: authority.principalId,
        authorityKind: authority.kind,
        idempotencyKey: parsed.data.idempotencyKey,
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
      if (parsed.data.requestedStrongerControlIds.length > 0) {
        return failure('INVALID_REQUEST', 'No requested stronger controls are registered in this development slice.')
      }
      const persistence = await this.ready
      if (persistence === undefined || this.disposed) {
        return failure('UNAVAILABLE', 'Assessment start is unavailable in read-only-safe mode.', true)
      }
      const repository = persistence.resolveRepository(parsed.data.repositoryId)
      if (repository === undefined) return failure('NOT_FOUND', 'The Repository does not exist.')
      if (repository.snapshot.state !== 'ENABLED') {
        return failure('CONFLICT', 'The Repository is disabled and cannot start new Assessments.')
      }
      if (parsed.data.assessmentProfileId !== repository.snapshot.bindings.assessmentProfileId) {
        return failure('INVALID_REQUEST', 'The requested Assessment Profile is not bound to this Repository.')
      }
      const replay = persistence.findAssessmentStartReplay({
        principalId: authority.principalId,
        authorityKind: authority.kind,
        idempotencyKey: parsed.data.idempotencyKey,
        repositoryId: parsed.data.repositoryId,
        canonicalRequest: parsed.data,
      })
      if (replay !== undefined) return deepFreeze({ ok: true, value: replay })

      const frozen = await freezeSubject({
        repositoryRoot: repository.canonicalRoot,
        securityRoot: this.securityRoot,
        source: parsed.data.subject,
        signal: options.signal,
      })
      const interruptedAfterFreeze = interruption<AssessmentReceiptV1>(options)
      if (interruptedAfterFreeze !== undefined) return interruptedAfterFreeze
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
        assessmentMode: parsed.data.assessmentMode,
        assessmentProfileId: parsed.data.assessmentProfileId,
        target: parsed.data.target,
        requestedStrongerControlIds: parsed.data.requestedStrongerControlIds,
      })
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

  private async initialize(config: Config): Promise<SecurityPersistence | undefined> {
    try {
      const dshHome = resolveDshHome(config.dshHome)
      return await openSecurityPersistence({
        databasePath: join(dshHome, 'security-assurance', 'security-assurance.sqlite'),
      })
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
}

export default SecurityAssuranceService
