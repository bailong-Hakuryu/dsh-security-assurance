import { z } from 'zod'

/** Public product identity of this development slice. */
export const SECURITY_ASSURANCE_PRODUCT_NAME = 'dsh-security-assurance' as const
export const SECURITY_ASSURANCE_PRODUCT_VERSION = '0.0.0-development' as const
export const TARGET_HARNESS_VERSION = '0.1.1-rc.2' as const
export const REQUIRED_NODE_RANGE = '^22.19.0 || >=24.0.0' as const

declare const securityInvocationBrand: unique symbol

/**
 * Non-serializable authority capability issued from a trusted caller channel.
 * The runtime verifies object identity; a TypeScript cast cannot forge it.
 */
export interface SecurityInvocation {
  readonly [securityInvocationBrand]: never
}

/** Process-local controls that are intentionally separate from request DTOs. */
export interface InvocationOptions {
  readonly signal?: AbortSignal
  readonly deadlineEpochMs?: number
}

/** Stable error codes implemented by the first public contract slice. */
export const publicSecurityErrorCodeSchema = z.enum([
  'UNAUTHORIZED',
  'INVALID_REQUEST',
  'NOT_FOUND',
  'CONFLICT',
  'IDEMPOTENCY_CONFLICT',
  'UNAVAILABLE',
  'CANCELED',
  'DEADLINE_EXCEEDED',
  'INTERNAL',
])

export type PublicSecurityErrorCode = z.infer<typeof publicSecurityErrorCodeSchema>

/** Redacted failure returned by every asynchronous Service operation. */
export interface PublicSecurityError {
  readonly schemaVersion: 1
  readonly code: PublicSecurityErrorCode
  readonly message: string
  readonly retryable: boolean
  readonly correlationId: string
}

export const publicSecurityErrorSchema: z.ZodType<PublicSecurityError> = z.strictObject({
  schemaVersion: z.literal(1),
  code: publicSecurityErrorCodeSchema,
  message: z.string().min(1).max(512),
  retryable: z.boolean(),
  correlationId: z.string().regex(/^sec-[0-9a-f-]{36}$/),
})

/** One transport-neutral public outcome envelope. */
export type SecurityResult<T> =
  | { readonly ok: true; readonly value: T }
  | { readonly ok: false; readonly error: PublicSecurityError }

/** Versioned, bounded request for Runtime Health. */
export interface GetHealthRequest {
  readonly schemaVersion: 1
}

export const getHealthRequestSchema: z.ZodType<GetHealthRequest> = z.strictObject({
  schemaVersion: z.literal(1),
})

export const runtimeHealthStateSchema = z.enum([
  'READY',
  'READ_ONLY_SAFE',
  'QUIESCING',
  'STOPPED',
])

export type RuntimeHealthState = z.infer<typeof runtimeHealthStateSchema>

export const runtimeHealthCheckStatusSchema = z.enum([
  'PASS',
  'FAIL',
  'NOT_EVALUATED',
])

export type RuntimeHealthCheckStatus = z.infer<typeof runtimeHealthCheckStatusSchema>

/** One bounded, redacted runtime admission check. */
export interface RuntimeHealthCheck {
  readonly id: string
  readonly status: RuntimeHealthCheckStatus
  readonly required: boolean
  readonly message: string
}

export const runtimeHealthCheckSchema: z.ZodType<RuntimeHealthCheck> = z.strictObject({
  id: z.string().regex(/^[a-z][a-z0-9]*(?:[.-][a-z0-9]+)*$/).max(96),
  status: runtimeHealthCheckStatusSchema,
  required: z.boolean(),
  message: z.string().min(1).max(512),
})

/** Immutable, JSON-safe Runtime Health Snapshot schema version 1. */
export interface RuntimeHealthSnapshot {
  readonly schemaVersion: 1
  readonly product: {
    readonly name: typeof SECURITY_ASSURANCE_PRODUCT_NAME
    readonly version: typeof SECURITY_ASSURANCE_PRODUCT_VERSION
  }
  readonly compatibility: {
    readonly targetHarnessVersion: typeof TARGET_HARNESS_VERSION
    readonly requiredNodeRange: typeof REQUIRED_NODE_RANGE
    readonly actualNodeVersion: string
    readonly harnessVerification: 'PENDING_INVARIANT'
  }
  readonly state: RuntimeHealthState
  readonly admission: {
    readonly queries: boolean
    readonly mutations: boolean
    readonly sealedExports: boolean
  }
  readonly checks: readonly RuntimeHealthCheck[]
}

export const runtimeHealthSnapshotSchema: z.ZodType<RuntimeHealthSnapshot> = z.strictObject({
  schemaVersion: z.literal(1),
  product: z.strictObject({
    name: z.literal(SECURITY_ASSURANCE_PRODUCT_NAME),
    version: z.literal(SECURITY_ASSURANCE_PRODUCT_VERSION),
  }),
  compatibility: z.strictObject({
    targetHarnessVersion: z.literal(TARGET_HARNESS_VERSION),
    requiredNodeRange: z.literal(REQUIRED_NODE_RANGE),
    actualNodeVersion: z.string().regex(/^\d+\.\d+\.\d+(?:[-+].+)?$/).max(64),
    harnessVerification: z.literal('PENDING_INVARIANT'),
  }),
  state: runtimeHealthStateSchema,
  admission: z.strictObject({
    queries: z.boolean(),
    mutations: z.boolean(),
    sealedExports: z.boolean(),
  }),
  checks: z.array(runtimeHealthCheckSchema).max(64),
})

/** Runtime schema for the first operation's complete Result. */
export const runtimeHealthResultSchema: z.ZodType<SecurityResult<RuntimeHealthSnapshot>> = z.discriminatedUnion('ok', [
  z.strictObject({
    ok: z.literal(true),
    value: runtimeHealthSnapshotSchema,
  }),
  z.strictObject({
    ok: z.literal(false),
    error: publicSecurityErrorSchema,
  }),
])

export const repositoryIdSchema = z.string().regex(/^repo-[0-9a-f-]{36}$/)
export type RepositoryId = z.infer<typeof repositoryIdSchema>

export const repositoryStateSchema = z.enum(['ENABLED', 'DISABLED'])
export type RepositoryState = z.infer<typeof repositoryStateSchema>

export const repositoryPlatformSchema = z.enum(['win32', 'linux', 'darwin'])
export type RepositoryPlatform = z.infer<typeof repositoryPlatformSchema>

const boundedBindingId = z.string().regex(/^[a-z0-9][a-z0-9._/-]{0,127}$/i)

export interface RepositoryBindingsV1 {
  readonly policyId: string
  readonly assessmentProfileId: string
  readonly evidenceProtectionId: string
  readonly dataEgressPolicyId: string
  readonly platform: RepositoryPlatform
  readonly deliveryDestinationIds: readonly string[]
}

export const repositoryBindingsV1Schema: z.ZodType<RepositoryBindingsV1> = z.strictObject({
  policyId: boundedBindingId,
  assessmentProfileId: boundedBindingId,
  evidenceProtectionId: boundedBindingId,
  dataEgressPolicyId: boundedBindingId,
  platform: repositoryPlatformSchema,
  deliveryDestinationIds: z.array(boundedBindingId).max(32),
})

export interface RegisterRepositoryRequest {
  readonly schemaVersion: 1
  readonly idempotencyKey: string
  readonly root: string
  readonly displayName: string
  readonly bindings: RepositoryBindingsV1
}

export const registerRepositoryRequestSchema: z.ZodType<RegisterRepositoryRequest> = z.strictObject({
  schemaVersion: z.literal(1),
  idempotencyKey: z.string().min(1).max(128).regex(/^[a-zA-Z0-9._:-]+$/),
  root: z.string().min(1).max(4096),
  displayName: z.string().trim().min(1).max(128),
  bindings: repositoryBindingsV1Schema,
})

export interface GetRepositoryRequest {
  readonly schemaVersion: 1
  readonly repositoryId: RepositoryId
}

export const getRepositoryRequestSchema: z.ZodType<GetRepositoryRequest> = z.strictObject({
  schemaVersion: z.literal(1),
  repositoryId: repositoryIdSchema,
})

export interface UpdateRepositoryRequest {
  readonly schemaVersion: 1
  readonly idempotencyKey: string
  readonly repositoryId: RepositoryId
  readonly expectedRepositoryRevision: number
  readonly displayName?: string | undefined
  readonly bindings?: RepositoryBindingsV1 | undefined
}

export const updateRepositoryRequestSchema: z.ZodType<UpdateRepositoryRequest> = z.strictObject({
  schemaVersion: z.literal(1),
  idempotencyKey: z.string().min(1).max(128).regex(/^[a-zA-Z0-9._:-]+$/),
  repositoryId: repositoryIdSchema,
  expectedRepositoryRevision: z.number().int().positive(),
  displayName: z.string().trim().min(1).max(128).optional(),
  bindings: repositoryBindingsV1Schema.optional(),
}).refine(
  request => request.displayName !== undefined || request.bindings !== undefined,
  { message: 'an update must change displayName or bindings' },
)

export interface DisableRepositoryRequest {
  readonly schemaVersion: 1
  readonly idempotencyKey: string
  readonly repositoryId: RepositoryId
  readonly expectedRepositoryRevision: number
}

export const disableRepositoryRequestSchema: z.ZodType<DisableRepositoryRequest> = z.strictObject({
  schemaVersion: z.literal(1),
  idempotencyKey: z.string().min(1).max(128).regex(/^[a-zA-Z0-9._:-]+$/),
  repositoryId: repositoryIdSchema,
  expectedRepositoryRevision: z.number().int().positive(),
})

export interface ListRepositoriesRequest {
  readonly schemaVersion: 1
  readonly limit: number
  readonly state?: RepositoryState | undefined
}

export const listRepositoriesRequestSchema: z.ZodType<ListRepositoriesRequest> = z.strictObject({
  schemaVersion: z.literal(1),
  limit: z.number().int().min(1).max(100),
  state: repositoryStateSchema.optional(),
})

export interface RepositoryCommandReceiptV1 {
  readonly schemaVersion: 1
  readonly operation: 'register_repository' | 'update_repository' | 'disable_repository'
  readonly repositoryId: RepositoryId
  readonly repositoryRevision: number
  readonly idempotencyKey: string
  readonly acceptedState: RepositoryState
  readonly acceptedAt: string
  readonly correlationId: string
}

export const repositoryCommandReceiptV1Schema: z.ZodType<RepositoryCommandReceiptV1> = z.strictObject({
  schemaVersion: z.literal(1),
  operation: z.enum(['register_repository', 'update_repository', 'disable_repository']),
  repositoryId: repositoryIdSchema,
  repositoryRevision: z.number().int().positive(),
  idempotencyKey: z.string().min(1).max(128),
  acceptedState: repositoryStateSchema,
  acceptedAt: z.iso.datetime({ offset: true }),
  correlationId: z.string().regex(/^sec-[0-9a-f-]{36}$/),
})

export interface RepositorySnapshotV1 {
  readonly schemaVersion: 1
  readonly repositoryId: RepositoryId
  readonly repositoryRevision: number
  readonly state: RepositoryState
  readonly displayName: string
  readonly rootIdentityDigest: string
  readonly bindings: RepositoryBindingsV1
  readonly createdAt: string
  readonly updatedAt: string
}

export const repositorySnapshotV1Schema: z.ZodType<RepositorySnapshotV1> = z.strictObject({
  schemaVersion: z.literal(1),
  repositoryId: repositoryIdSchema,
  repositoryRevision: z.number().int().positive(),
  state: repositoryStateSchema,
  displayName: z.string().min(1).max(128),
  rootIdentityDigest: z.string().regex(/^sha256:[0-9a-f]{64}$/),
  bindings: repositoryBindingsV1Schema,
  createdAt: z.iso.datetime({ offset: true }),
  updatedAt: z.iso.datetime({ offset: true }),
})

export const repositoryCommandResultSchema: z.ZodType<SecurityResult<RepositoryCommandReceiptV1>> =
  z.discriminatedUnion('ok', [
    z.strictObject({ ok: z.literal(true), value: repositoryCommandReceiptV1Schema }),
    z.strictObject({ ok: z.literal(false), error: publicSecurityErrorSchema }),
  ])

export const repositorySnapshotResultSchema: z.ZodType<SecurityResult<RepositorySnapshotV1>> =
  z.discriminatedUnion('ok', [
    z.strictObject({ ok: z.literal(true), value: repositorySnapshotV1Schema }),
    z.strictObject({ ok: z.literal(false), error: publicSecurityErrorSchema }),
  ])

export interface RepositoryListSnapshotV1 {
  readonly schemaVersion: 1
  readonly repositories: readonly RepositorySnapshotV1[]
  readonly truncated: boolean
}

export const repositoryListSnapshotV1Schema: z.ZodType<RepositoryListSnapshotV1> = z.strictObject({
  schemaVersion: z.literal(1),
  repositories: z.array(repositorySnapshotV1Schema).max(100),
  truncated: z.boolean(),
})

export const repositoryListResultSchema: z.ZodType<SecurityResult<RepositoryListSnapshotV1>> =
  z.discriminatedUnion('ok', [
    z.strictObject({ ok: z.literal(true), value: repositoryListSnapshotV1Schema }),
    z.strictObject({ ok: z.literal(false), error: publicSecurityErrorSchema }),
  ])

export interface DigestEnvelopeV1 {
  readonly schemaVersion: 1
  readonly algorithm: 'sha256'
  readonly mediaType: string
  readonly byteLength: number
  readonly canonicalization: 'raw-bytes' | 'dsh-canonical-json-v1'
  readonly value: string
}

export const digestEnvelopeV1Schema: z.ZodType<DigestEnvelopeV1> = z.strictObject({
  schemaVersion: z.literal(1),
  algorithm: z.literal('sha256'),
  mediaType: z.string().regex(/^application\/[a-z0-9.+-]+$|^text\/[a-z0-9.+-]+$/).max(128),
  byteLength: z.number().int().nonnegative(),
  canonicalization: z.enum(['raw-bytes', 'dsh-canonical-json-v1']),
  value: z.string().regex(/^[0-9a-f]{64}$/),
})

const exactGitCommitSchema = z.string().regex(/^[0-9a-f]{40}$/)

export const assessmentSubjectSourceV1Schema = z.discriminatedUnion('kind', [
  z.strictObject({
    kind: z.literal('git_revision'),
    commit: exactGitCommitSchema,
  }),
  z.strictObject({
    kind: z.literal('change'),
    baseCommit: exactGitCommitSchema,
    headCommit: exactGitCommitSchema,
  }),
  z.strictObject({
    kind: z.literal('workspace_snapshot'),
  }),
])

export type AssessmentSubjectSourceV1 = z.infer<typeof assessmentSubjectSourceV1Schema>

export const assessmentModeSchema = z.enum(['REPOSITORY', 'CHANGE', 'TARGETED'])
export type AssessmentMode = z.infer<typeof assessmentModeSchema>

export const assessmentProfileIdSchema = boundedBindingId
export type AssessmentProfileId = z.infer<typeof assessmentProfileIdSchema>

const subjectRelativePathSchema = z.string().min(1).max(1024).refine(path => (
  !path.startsWith('/')
  && !path.startsWith('\\')
  && !/^[a-z]:/iu.test(path)
  && !path.includes('\\')
  && path.split('/').every(segment => segment.length > 0 && segment !== '.' && segment !== '..')
), 'target paths must be canonical Subject-relative paths')

export const assessmentTargetSelectorV1Schema = z.discriminatedUnion('kind', [
  z.strictObject({ kind: z.literal('repository') }),
  z.strictObject({
    kind: z.literal('change'),
    baseCommit: exactGitCommitSchema,
    headCommit: exactGitCommitSchema,
    impactCone: z.literal('POLICY_DEFAULT'),
  }),
  z.strictObject({
    kind: z.literal('targeted'),
    relativePaths: z.array(subjectRelativePathSchema).min(1).max(128),
  }),
])

export type AssessmentTargetSelectorV1 = z.infer<typeof assessmentTargetSelectorV1Schema>

export interface StartAssessmentRequest {
  readonly schemaVersion: 1
  readonly idempotencyKey: string
  readonly repositoryId: RepositoryId
  readonly subject: AssessmentSubjectSourceV1
  readonly assessmentMode: AssessmentMode
  readonly assessmentProfileId: AssessmentProfileId
  readonly target: AssessmentTargetSelectorV1
  readonly requestedStrongerControlIds: readonly string[]
}

export const startAssessmentRequestSchema: z.ZodType<StartAssessmentRequest> = z.strictObject({
  schemaVersion: z.literal(1),
  idempotencyKey: z.string().min(1).max(128).regex(/^[a-zA-Z0-9._:-]+$/),
  repositoryId: repositoryIdSchema,
  subject: assessmentSubjectSourceV1Schema,
  assessmentMode: assessmentModeSchema,
  assessmentProfileId: assessmentProfileIdSchema,
  target: assessmentTargetSelectorV1Schema,
  requestedStrongerControlIds: z.array(boundedBindingId).max(16),
})

export const assessmentIdSchema = z.string().regex(/^asm-[0-9a-f-]{36}$/)
export type AssessmentId = z.infer<typeof assessmentIdSchema>

export const assessmentStateSchema = z.enum(['CREATED', 'RUNNING', 'BLOCKED', 'SEALED', 'CANCELED'])
export type AssessmentState = z.infer<typeof assessmentStateSchema>

export interface AssessmentSubjectReceiptV1 {
  readonly kind: AssessmentSubjectSourceV1['kind']
  readonly digest: DigestEnvelopeV1
}

export const assessmentSubjectReceiptV1Schema: z.ZodType<AssessmentSubjectReceiptV1> = z.strictObject({
  kind: z.enum(['git_revision', 'change', 'workspace_snapshot']),
  digest: digestEnvelopeV1Schema,
})

export interface AssessmentReceiptV1 {
  readonly schemaVersion: 1
  readonly operation: 'start_assessment'
  readonly assessmentId: AssessmentId
  readonly assessmentRevision: 1
  readonly state: 'CREATED'
  readonly repositoryId: RepositoryId
  readonly repositoryRevision: number
  readonly subject: AssessmentSubjectReceiptV1
  readonly idempotencyKey: string
  readonly acceptedAt: string
  readonly correlationId: string
}

export const assessmentReceiptV1Schema: z.ZodType<AssessmentReceiptV1> = z.strictObject({
  schemaVersion: z.literal(1),
  operation: z.literal('start_assessment'),
  assessmentId: assessmentIdSchema,
  assessmentRevision: z.literal(1),
  state: z.literal('CREATED'),
  repositoryId: repositoryIdSchema,
  repositoryRevision: z.number().int().positive(),
  subject: assessmentSubjectReceiptV1Schema,
  idempotencyKey: z.string().min(1).max(128),
  acceptedAt: z.iso.datetime({ offset: true }),
  correlationId: z.string().regex(/^sec-[0-9a-f-]{36}$/),
})

export const assessmentReceiptResultSchema: z.ZodType<SecurityResult<AssessmentReceiptV1>> =
  z.discriminatedUnion('ok', [
    z.strictObject({ ok: z.literal(true), value: assessmentReceiptV1Schema }),
    z.strictObject({ ok: z.literal(false), error: publicSecurityErrorSchema }),
  ])

export const securityVerdictSchema = z.enum(['SATISFIED', 'FAILED', 'INDETERMINATE'])
export type SecurityVerdict = z.infer<typeof securityVerdictSchema>

export interface GetAssessmentRequest {
  readonly schemaVersion: 1
  readonly assessmentId: AssessmentId
}

export const getAssessmentRequestSchema: z.ZodType<GetAssessmentRequest> = z.strictObject({
  schemaVersion: z.literal(1),
  assessmentId: assessmentIdSchema,
})

export interface WaitForAssessmentRevisionRequest {
  readonly schemaVersion: 1
  readonly assessmentId: AssessmentId
  readonly afterRevision: number
  readonly timeoutMs: number
}

export const waitForAssessmentRevisionRequestSchema: z.ZodType<WaitForAssessmentRevisionRequest> = z.strictObject({
  schemaVersion: z.literal(1),
  assessmentId: assessmentIdSchema,
  afterRevision: z.number().int().positive(),
  timeoutMs: z.number().int().min(1).max(30_000),
})

export interface AssessmentCoverageResolutionV1 {
  readonly obligationId: string
  readonly state: 'SATISFIED' | 'GAP'
  readonly reason: 'ELIGIBLE_EVIDENCE' | 'NO_ELIGIBLE_ANALYZER'
}

export const assessmentCoverageResolutionV1Schema: z.ZodType<AssessmentCoverageResolutionV1> = z.strictObject({
  obligationId: boundedBindingId,
  state: z.enum(['SATISFIED', 'GAP']),
  reason: z.enum(['ELIGIBLE_EVIDENCE', 'NO_ELIGIBLE_ANALYZER']),
})

export interface AssessmentCoverageSnapshotV1 {
  readonly status: 'PENDING' | 'COMPLETE' | 'GAP'
  readonly mandatoryObligations: number
  readonly satisfiedObligations: number
  readonly gapObligations: number
  readonly resolutions: readonly AssessmentCoverageResolutionV1[]
  readonly digest: DigestEnvelopeV1
}

export const assessmentCoverageSnapshotV1Schema: z.ZodType<AssessmentCoverageSnapshotV1> = z.strictObject({
  status: z.enum(['PENDING', 'COMPLETE', 'GAP']),
  mandatoryObligations: z.number().int().nonnegative(),
  satisfiedObligations: z.number().int().nonnegative(),
  gapObligations: z.number().int().nonnegative(),
  resolutions: z.array(assessmentCoverageResolutionV1Schema).max(256),
  digest: digestEnvelopeV1Schema,
})

export interface AssessmentSealV1 {
  readonly schemaVersion: 1
  readonly sealId: string
  readonly assessmentRevision: number
  readonly verdict: SecurityVerdict
  readonly digest: DigestEnvelopeV1
  readonly sealedAt: string
}

export const assessmentSealV1Schema: z.ZodType<AssessmentSealV1> = z.strictObject({
  schemaVersion: z.literal(1),
  sealId: z.string().regex(/^seal-[0-9a-f-]{36}$/),
  assessmentRevision: z.number().int().positive(),
  verdict: securityVerdictSchema,
  digest: digestEnvelopeV1Schema,
  sealedAt: z.iso.datetime({ offset: true }),
})

export interface AssessmentSnapshotV1 {
  readonly schemaVersion: 1
  readonly assessmentId: AssessmentId
  readonly assessmentRevision: number
  readonly state: AssessmentState
  readonly repository: {
    readonly repositoryId: RepositoryId
    readonly repositoryRevision: number
  }
  readonly subject: AssessmentSubjectReceiptV1
  readonly policy: {
    readonly policyId: string
    readonly digest: DigestEnvelopeV1
  }
  readonly coverage: AssessmentCoverageSnapshotV1
  readonly verdict: SecurityVerdict | null
  readonly seal: AssessmentSealV1 | null
  readonly createdAt: string
  readonly updatedAt: string
}

export const assessmentSnapshotV1Schema: z.ZodType<AssessmentSnapshotV1> = z.strictObject({
  schemaVersion: z.literal(1),
  assessmentId: assessmentIdSchema,
  assessmentRevision: z.number().int().positive(),
  state: assessmentStateSchema,
  repository: z.strictObject({
    repositoryId: repositoryIdSchema,
    repositoryRevision: z.number().int().positive(),
  }),
  subject: assessmentSubjectReceiptV1Schema,
  policy: z.strictObject({
    policyId: boundedBindingId,
    digest: digestEnvelopeV1Schema,
  }),
  coverage: assessmentCoverageSnapshotV1Schema,
  verdict: securityVerdictSchema.nullable(),
  seal: assessmentSealV1Schema.nullable(),
  createdAt: z.iso.datetime({ offset: true }),
  updatedAt: z.iso.datetime({ offset: true }),
})

export interface AssessmentRevisionSignalV1 {
  readonly schemaVersion: 1
  readonly assessmentId: AssessmentId
  readonly kind: 'CHANGED' | 'TIMED_OUT'
  readonly assessmentRevision: number
}

export const assessmentRevisionSignalV1Schema: z.ZodType<AssessmentRevisionSignalV1> = z.strictObject({
  schemaVersion: z.literal(1),
  assessmentId: assessmentIdSchema,
  kind: z.enum(['CHANGED', 'TIMED_OUT']),
  assessmentRevision: z.number().int().positive(),
})

export interface GetBundleManifestRequest {
  readonly schemaVersion: 1
  readonly assessmentId: AssessmentId
}

export const getBundleManifestRequestSchema: z.ZodType<GetBundleManifestRequest> = z.strictObject({
  schemaVersion: z.literal(1),
  assessmentId: assessmentIdSchema,
})

export interface GetAssuranceSubmissionRequest {
  readonly schemaVersion: 1
  readonly assessmentId: AssessmentId
}

export const getAssuranceSubmissionRequestSchema: z.ZodType<GetAssuranceSubmissionRequest> = z.strictObject({
  schemaVersion: z.literal(1),
  assessmentId: assessmentIdSchema,
})

export interface BundleRecordDescriptorV1 {
  readonly recordId: string
  readonly schemaId: string
  readonly schemaVersion: 1
  readonly classification: 'INTERNAL' | 'CONTROL_PLANE'
  readonly digest: DigestEnvelopeV1
}

const schemaIdSchema = z.string().regex(/^[a-z0-9][a-z0-9._-]*(?:\/[a-z0-9][a-z0-9._-]*){1,7}$/)

export const bundleRecordDescriptorV1Schema: z.ZodType<BundleRecordDescriptorV1> = z.strictObject({
  recordId: boundedBindingId,
  schemaId: schemaIdSchema,
  schemaVersion: z.literal(1),
  classification: z.enum(['INTERNAL', 'CONTROL_PLANE']),
  digest: digestEnvelopeV1Schema,
})

export interface BundleOmissionV1 {
  readonly schemaId: string
  readonly reason: 'NO_ELIGIBLE_ANALYZER'
}

export const bundleOmissionV1Schema: z.ZodType<BundleOmissionV1> = z.strictObject({
  schemaId: schemaIdSchema,
  reason: z.literal('NO_ELIGIBLE_ANALYZER'),
})

export interface BundleManifestV1 {
  readonly schemaVersion: 1
  readonly assessmentId: AssessmentId
  readonly assessmentRevision: number
  readonly verdict: SecurityVerdict
  readonly seal: AssessmentSealV1
  readonly records: readonly BundleRecordDescriptorV1[]
  readonly omissions: readonly BundleOmissionV1[]
  readonly digest: DigestEnvelopeV1
}

export const bundleManifestV1Schema: z.ZodType<BundleManifestV1> = z.strictObject({
  schemaVersion: z.literal(1),
  assessmentId: assessmentIdSchema,
  assessmentRevision: z.number().int().positive(),
  verdict: securityVerdictSchema,
  seal: assessmentSealV1Schema,
  records: z.array(bundleRecordDescriptorV1Schema).min(1).max(128),
  omissions: z.array(bundleOmissionV1Schema).max(128),
  digest: digestEnvelopeV1Schema,
})

export const securitySubmissionJsonV1Schema = z.json()
export type SecuritySubmissionJsonV1 = z.infer<typeof securitySubmissionJsonV1Schema>

export interface SecuritySubmissionArtifactV1 {
  readonly artifactId: string
  readonly schemaId: string
  readonly schemaVersion: 1
  readonly digest: DigestEnvelopeV1
  readonly value: SecuritySubmissionJsonV1
}

export const securitySubmissionArtifactV1Schema: z.ZodType<SecuritySubmissionArtifactV1> = z.strictObject({
  artifactId: boundedBindingId,
  schemaId: schemaIdSchema,
  schemaVersion: z.literal(1),
  digest: digestEnvelopeV1Schema,
  value: securitySubmissionJsonV1Schema,
})

export interface SecurityAssuranceSubmissionV1 {
  readonly schemaVersion: 1
  readonly payload: {
    readonly assessment: {
      readonly assessmentId: AssessmentId
      readonly assessmentRevision: number
      readonly state: 'SEALED'
      readonly verdict: SecurityVerdict
    }
    readonly binding: {
      readonly repositoryId: RepositoryId
      readonly repositoryRevision: number
      readonly subjectDigest: DigestEnvelopeV1
      readonly policyId: string
      readonly policyDigest: DigestEnvelopeV1
    }
    readonly providerComposition: SecuritySubmissionArtifactV1
    readonly providerPolicy: SecuritySubmissionArtifactV1
    readonly coverage: SecuritySubmissionArtifactV1
    readonly findings: SecuritySubmissionArtifactV1
    readonly sourceSeal: SecuritySubmissionArtifactV1
    readonly provenance: SecuritySubmissionArtifactV1
    readonly evidence: readonly SecuritySubmissionArtifactV1[]
  }
  readonly digest: DigestEnvelopeV1
}

export const securityAssuranceSubmissionV1Schema: z.ZodType<SecurityAssuranceSubmissionV1> = z.strictObject({
  schemaVersion: z.literal(1),
  payload: z.strictObject({
    assessment: z.strictObject({
      assessmentId: assessmentIdSchema,
      assessmentRevision: z.number().int().positive(),
      state: z.literal('SEALED'),
      verdict: securityVerdictSchema,
    }),
    binding: z.strictObject({
      repositoryId: repositoryIdSchema,
      repositoryRevision: z.number().int().positive(),
      subjectDigest: digestEnvelopeV1Schema,
      policyId: boundedBindingId,
      policyDigest: digestEnvelopeV1Schema,
    }),
    providerComposition: securitySubmissionArtifactV1Schema,
    providerPolicy: securitySubmissionArtifactV1Schema,
    coverage: securitySubmissionArtifactV1Schema,
    findings: securitySubmissionArtifactV1Schema,
    sourceSeal: securitySubmissionArtifactV1Schema,
    provenance: securitySubmissionArtifactV1Schema,
    evidence: z.array(securitySubmissionArtifactV1Schema).min(1).max(128),
  }),
  digest: digestEnvelopeV1Schema,
})

export const assessmentSnapshotResultSchema: z.ZodType<SecurityResult<AssessmentSnapshotV1>> =
  z.discriminatedUnion('ok', [
    z.strictObject({ ok: z.literal(true), value: assessmentSnapshotV1Schema }),
    z.strictObject({ ok: z.literal(false), error: publicSecurityErrorSchema }),
  ])

export const assessmentRevisionSignalResultSchema: z.ZodType<SecurityResult<AssessmentRevisionSignalV1>> =
  z.discriminatedUnion('ok', [
    z.strictObject({ ok: z.literal(true), value: assessmentRevisionSignalV1Schema }),
    z.strictObject({ ok: z.literal(false), error: publicSecurityErrorSchema }),
  ])

export const bundleManifestResultSchema: z.ZodType<SecurityResult<BundleManifestV1>> =
  z.discriminatedUnion('ok', [
    z.strictObject({ ok: z.literal(true), value: bundleManifestV1Schema }),
    z.strictObject({ ok: z.literal(false), error: publicSecurityErrorSchema }),
  ])

export const securityAssuranceSubmissionResultSchema: z.ZodType<SecurityResult<SecurityAssuranceSubmissionV1>> =
  z.discriminatedUnion('ok', [
    z.strictObject({ ok: z.literal(true), value: securityAssuranceSubmissionV1Schema }),
    z.strictObject({ ok: z.literal(false), error: publicSecurityErrorSchema }),
  ])
