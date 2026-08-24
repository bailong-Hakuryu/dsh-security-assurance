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

export const RISK_DECISION_WINDOW_CONTROL_ID = 'security/risk-decision-window-v1' as const
export const CRITICAL_BREAK_GLASS_CONTROL_ID = 'security/critical-break-glass-v1' as const

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

export interface AssessmentOperatorReasonV1 {
  readonly code: string
  readonly summary: string
}

export const assessmentOperatorReasonV1Schema: z.ZodType<AssessmentOperatorReasonV1> = z.strictObject({
  code: z.string().regex(/^[A-Z][A-Z0-9_]{0,63}$/),
  summary: z.string().trim().min(1).max(512),
})

export interface ResumeAssessmentRequest {
  readonly schemaVersion: 1
  readonly assessmentId: AssessmentId
  readonly expectedAssessmentRevision: number
  readonly idempotencyKey: string
  readonly reason: AssessmentOperatorReasonV1
}

export const resumeAssessmentRequestSchema: z.ZodType<ResumeAssessmentRequest> = z.strictObject({
  schemaVersion: z.literal(1),
  assessmentId: assessmentIdSchema,
  expectedAssessmentRevision: z.number().int().positive(),
  idempotencyKey: z.string().min(1).max(128).regex(/^[a-zA-Z0-9._:-]+$/),
  reason: assessmentOperatorReasonV1Schema,
})

export interface AssessmentResumeReceiptV1 {
  readonly schemaVersion: 1
  readonly operation: 'resume_assessment'
  readonly assessmentId: AssessmentId
  readonly assessmentRevision: number
  readonly state: 'CREATED'
  readonly idempotencyKey: string
  readonly acceptedAt: string
  readonly correlationId: string
}

export const assessmentResumeReceiptV1Schema: z.ZodType<AssessmentResumeReceiptV1> = z.strictObject({
  schemaVersion: z.literal(1),
  operation: z.literal('resume_assessment'),
  assessmentId: assessmentIdSchema,
  assessmentRevision: z.number().int().positive(),
  state: z.literal('CREATED'),
  idempotencyKey: z.string().min(1).max(128),
  acceptedAt: z.iso.datetime({ offset: true }),
  correlationId: z.string().regex(/^sec-[0-9a-f-]{36}$/),
})

export const assessmentResumeResultSchema: z.ZodType<SecurityResult<AssessmentResumeReceiptV1>> =
  z.discriminatedUnion('ok', [
    z.strictObject({ ok: z.literal(true), value: assessmentResumeReceiptV1Schema }),
    z.strictObject({ ok: z.literal(false), error: publicSecurityErrorSchema }),
  ])

export interface CancelAssessmentRequest {
  readonly schemaVersion: 1
  readonly assessmentId: AssessmentId
  readonly expectedAssessmentRevision: number
  readonly idempotencyKey: string
  readonly reason: AssessmentOperatorReasonV1
}

export const cancelAssessmentRequestSchema: z.ZodType<CancelAssessmentRequest> = z.strictObject({
  schemaVersion: z.literal(1),
  assessmentId: assessmentIdSchema,
  expectedAssessmentRevision: z.number().int().positive(),
  idempotencyKey: z.string().min(1).max(128).regex(/^[a-zA-Z0-9._:-]+$/),
  reason: assessmentOperatorReasonV1Schema,
})

export interface AssessmentCancellationReceiptV1 {
  readonly schemaVersion: 1
  readonly operation: 'cancel_assessment'
  readonly assessmentId: AssessmentId
  /** Revision that durably records the cancellation request, not the terminal transition. */
  readonly assessmentRevision: number
  readonly acceptedState: 'CREATED' | 'RUNNING' | 'BLOCKED'
  readonly idempotencyKey: string
  readonly acceptedAt: string
  readonly correlationId: string
}

export const assessmentCancellationReceiptV1Schema: z.ZodType<AssessmentCancellationReceiptV1> = z.strictObject({
  schemaVersion: z.literal(1),
  operation: z.literal('cancel_assessment'),
  assessmentId: assessmentIdSchema,
  assessmentRevision: z.number().int().positive(),
  acceptedState: z.enum(['CREATED', 'RUNNING', 'BLOCKED']),
  idempotencyKey: z.string().min(1).max(128),
  acceptedAt: z.iso.datetime({ offset: true }),
  correlationId: z.string().regex(/^sec-[0-9a-f-]{36}$/),
})

export const assessmentCancellationResultSchema: z.ZodType<SecurityResult<AssessmentCancellationReceiptV1>> =
  z.discriminatedUnion('ok', [
    z.strictObject({ ok: z.literal(true), value: assessmentCancellationReceiptV1Schema }),
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

export const findingValidationStateSchema = z.enum(['VALIDATED', 'REJECTED', 'UNRESOLVED'])
export type FindingValidationState = z.infer<typeof findingValidationStateSchema>

export const findingRecordKindSchema = z.enum([
  'FINDING',
  'REJECTED_CANDIDATE',
  'UNRESOLVED_CANDIDATE',
])
export type FindingRecordKind = z.infer<typeof findingRecordKindSchema>

export const technicalSeveritySchema = z.enum([
  'CRITICAL',
  'HIGH',
  'MEDIUM',
  'LOW',
  'INFORMATIONAL',
])
export type TechnicalSeverity = z.infer<typeof technicalSeveritySchema>

export const evidenceConfidenceSchema = z.enum(['HIGH', 'MEDIUM', 'LOW'])
export type EvidenceConfidence = z.infer<typeof evidenceConfidenceSchema>

export const policySignificanceSchema = z.enum(['BLOCKING', 'NON_BLOCKING', 'ADVISORY'])
export type PolicySignificance = z.infer<typeof policySignificanceSchema>

export interface FindingWeaknessClassificationV1 {
  readonly primary: string
  readonly secondary: readonly string[]
}

export const findingWeaknessClassificationV1Schema: z.ZodType<FindingWeaknessClassificationV1> =
  z.strictObject({
    primary: boundedBindingId,
    secondary: z.array(boundedBindingId).max(16),
  })

export interface ListFindingsRequest {
  readonly schemaVersion: 1
  readonly assessmentId: AssessmentId
  readonly limit: number
  readonly cursor?: string | undefined
  readonly validationStates?: readonly FindingValidationState[] | undefined
}

export const listFindingsRequestSchema: z.ZodType<ListFindingsRequest> = z.strictObject({
  schemaVersion: z.literal(1),
  assessmentId: assessmentIdSchema,
  limit: z.number().int().min(1).max(100),
  cursor: z.string().min(1).max(2048).regex(/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/).optional(),
  validationStates: z.array(findingValidationStateSchema)
    .min(1)
    .max(3)
    .refine(states => new Set(states).size === states.length, {
      message: 'validationStates must be unique',
    })
    .optional(),
})

export interface FindingSummaryV1 {
  readonly schemaVersion: 1
  readonly assessmentId: AssessmentId
  readonly assessmentRevision: number
  readonly recordKind: FindingRecordKind
  readonly recordId: string
  readonly candidateId: string
  readonly recordRevision: number
  readonly validationState: FindingValidationState
  readonly validationContractId: string | null
  readonly weaknessClassification: FindingWeaknessClassificationV1
  readonly technicalSeverity: TechnicalSeverity | null
  readonly evidenceConfidence: EvidenceConfidence | null
  readonly policySignificance: PolicySignificance | null
  readonly hasProtectedDetail: boolean
}

const candidateIdSchema = z.string().regex(/^candidate-[0-9a-f]{64}$/)
const findingRecordIdSchema = z.string().regex(/^(?:finding-[0-9a-f]{64}|candidate-[0-9a-f]{64})$/)

export const findingSummaryV1Schema: z.ZodType<FindingSummaryV1> = z.strictObject({
  schemaVersion: z.literal(1),
  assessmentId: assessmentIdSchema,
  assessmentRevision: z.number().int().positive(),
  recordKind: findingRecordKindSchema,
  recordId: findingRecordIdSchema,
  candidateId: candidateIdSchema,
  recordRevision: z.number().int().positive(),
  validationState: findingValidationStateSchema,
  validationContractId: boundedBindingId.nullable(),
  weaknessClassification: findingWeaknessClassificationV1Schema,
  technicalSeverity: technicalSeveritySchema.nullable(),
  evidenceConfidence: evidenceConfidenceSchema.nullable(),
  policySignificance: policySignificanceSchema.nullable(),
  hasProtectedDetail: z.boolean(),
})

export interface FindingListPageV1 {
  readonly schemaVersion: 1
  readonly assessmentId: AssessmentId
  readonly assessmentRevision: number
  readonly findings: readonly FindingSummaryV1[]
  readonly nextCursor: string | null
}

export const findingListPageV1Schema: z.ZodType<FindingListPageV1> = z.strictObject({
  schemaVersion: z.literal(1),
  assessmentId: assessmentIdSchema,
  assessmentRevision: z.number().int().positive(),
  findings: z.array(findingSummaryV1Schema).max(100),
  nextCursor: z.string().min(1).max(2048).nullable(),
})

export interface GetFindingRequest {
  readonly schemaVersion: 1
  readonly assessmentId: AssessmentId
  readonly assessmentRevision: number
  readonly recordId: string
  readonly recordRevision: number
}

export const getFindingRequestSchema: z.ZodType<GetFindingRequest> = z.strictObject({
  schemaVersion: z.literal(1),
  assessmentId: assessmentIdSchema,
  assessmentRevision: z.number().int().positive(),
  recordId: findingRecordIdSchema,
  recordRevision: z.number().int().positive(),
})

export const EVIDENCE_VIEW_METADATA_ONLY_PROFILE_ID =
  'security/evidence-view/metadata-only-v1' as const
export const EVIDENCE_VIEW_BOUNDED_JSON_PROFILE_ID =
  'security/evidence-view/bounded-json-v1' as const
export const EVIDENCE_VIEW_BOUNDED_JSON_LIFETIME_MS = 5 * 60_000

export type EvidenceViewPurposeV1 = 'FINDING_TRIAGE' | 'VALIDATION_REVIEW'
export type EvidenceViewProfileIdV1 =
  | typeof EVIDENCE_VIEW_METADATA_ONLY_PROFILE_ID
  | typeof EVIDENCE_VIEW_BOUNDED_JSON_PROFILE_ID

export interface GetEvidenceViewRequest {
  readonly schemaVersion: 1
  readonly assessmentId: AssessmentId
  readonly assessmentRevision: number
  readonly context: {
    readonly kind: 'finding'
    readonly recordId: string
    readonly recordRevision: number
  }
  readonly evidenceArtifactId: string
  readonly evidenceDigest: DigestEnvelopeV1
  readonly purpose: EvidenceViewPurposeV1
  readonly viewProfileId: EvidenceViewProfileIdV1
}

export const getEvidenceViewRequestSchema: z.ZodType<GetEvidenceViewRequest> = z.strictObject({
  schemaVersion: z.literal(1),
  assessmentId: assessmentIdSchema,
  assessmentRevision: z.number().int().positive(),
  context: z.strictObject({
    kind: z.literal('finding'),
    recordId: findingRecordIdSchema,
    recordRevision: z.number().int().positive(),
  }),
  evidenceArtifactId: boundedBindingId,
  evidenceDigest: digestEnvelopeV1Schema,
  purpose: z.enum(['FINDING_TRIAGE', 'VALIDATION_REVIEW']),
  viewProfileId: z.enum([
    EVIDENCE_VIEW_METADATA_ONLY_PROFILE_ID,
    EVIDENCE_VIEW_BOUNDED_JSON_PROFILE_ID,
  ]),
})

export type RiskDecisionKindV1 = 'DENY' | 'ACCEPT'
export type RiskDecisionResolutionV1 = 'DENIED' | 'ACCEPTED' | 'PENDING_DUAL_AUTHORITY'
export type RiskDecisionAuthorizationModeV1 = 'SINGLE_AUTHORITY' | 'CRITICAL_DUAL_AUTHORITY'

export interface RiskDecisionAttestationV1 {
  readonly sequence: number
  readonly decisionMaker: {
    readonly kind: 'host-operator'
    readonly principalId: string
  }
  readonly authorizationEvidence: {
    readonly permission: 'risk:break-glass'
    readonly invocationClass: 'independently-authenticated'
  }
  readonly attestedAt: string
}

export const riskDecisionAttestationV1Schema: z.ZodType<RiskDecisionAttestationV1> = z.strictObject({
  sequence: z.number().int().min(1).max(2),
  decisionMaker: z.strictObject({
    kind: z.literal('host-operator'),
    principalId: z.string().regex(/^[a-z0-9][a-z0-9._:-]{0,127}$/i),
  }),
  authorizationEvidence: z.strictObject({
    permission: z.literal('risk:break-glass'),
    invocationClass: z.literal('independently-authenticated'),
  }),
  attestedAt: z.iso.datetime({ offset: true }),
})

export interface RecordRiskDecisionRequest {
  readonly schemaVersion: 1
  readonly idempotencyKey: string
  readonly assessmentId: AssessmentId
  readonly expectedAssessmentRevision: number
  readonly finding: {
    readonly recordId: string
    readonly recordRevision: number
  }
  readonly decision: RiskDecisionKindV1
  readonly rationale: string
  readonly compensatingControls: readonly string[]
  readonly expiresAt: string | null
}

export const recordRiskDecisionRequestSchema: z.ZodType<RecordRiskDecisionRequest> = z.strictObject({
  schemaVersion: z.literal(1),
  idempotencyKey: z.string().min(1).max(128).regex(/^[a-zA-Z0-9._:-]+$/),
  assessmentId: assessmentIdSchema,
  expectedAssessmentRevision: z.number().int().positive(),
  finding: z.strictObject({
    recordId: z.string().regex(/^finding-[0-9a-f]{64}$/),
    recordRevision: z.number().int().positive(),
  }),
  decision: z.enum(['DENY', 'ACCEPT']),
  rationale: z.string().trim().min(20).max(2_000),
  compensatingControls: z.array(z.string().trim().min(3).max(256)).max(16),
  expiresAt: z.iso.datetime({ offset: true }).nullable(),
}).superRefine((request, context) => {
  if (request.decision === 'DENY' && (request.expiresAt !== null || request.compensatingControls.length > 0)) {
    context.addIssue({
      code: 'custom',
      message: 'DENY decisions cannot declare expiry or compensating controls',
    })
  }
  if (request.decision === 'ACCEPT' && (request.expiresAt === null || request.compensatingControls.length === 0)) {
    context.addIssue({
      code: 'custom',
      message: 'ACCEPT decisions require expiry and compensating controls',
    })
  }
})

export interface RiskDecisionRecordV1 {
  readonly schemaVersion: 1
  readonly decisionId: string
  readonly assessmentId: AssessmentId
  readonly finding: {
    readonly recordId: string
    readonly recordRevision: number
  }
  readonly decision: RiskDecisionKindV1
  readonly resolution: RiskDecisionResolutionV1
  readonly authorizationMode?: RiskDecisionAuthorizationModeV1 | undefined
  readonly rationale: string
  readonly compensatingControls: readonly string[]
  readonly expiresAt: string | null
  readonly decisionMaker: {
    readonly kind: 'host-operator' | 'control-plane'
    readonly principalId: string
  }
  readonly scope?: {
    readonly subjectDigest: DigestEnvelopeV1
    readonly policyDigest: DigestEnvelopeV1
  } | undefined
  readonly attestations?: readonly RiskDecisionAttestationV1[] | undefined
  readonly recordedAt: string
}

export const riskDecisionRecordV1Schema: z.ZodType<RiskDecisionRecordV1> = z.strictObject({
  schemaVersion: z.literal(1),
  decisionId: z.string().regex(/^risk-decision-[0-9a-f-]{36}$/),
  assessmentId: assessmentIdSchema,
  finding: z.strictObject({
    recordId: z.string().regex(/^finding-[0-9a-f]{64}$/),
    recordRevision: z.number().int().positive(),
  }),
  decision: z.enum(['DENY', 'ACCEPT']),
  resolution: z.enum(['DENIED', 'ACCEPTED', 'PENDING_DUAL_AUTHORITY']),
  authorizationMode: z.enum(['SINGLE_AUTHORITY', 'CRITICAL_DUAL_AUTHORITY']).optional(),
  rationale: z.string().trim().min(20).max(2_000),
  compensatingControls: z.array(z.string().trim().min(3).max(256)).max(16),
  expiresAt: z.iso.datetime({ offset: true }).nullable(),
  decisionMaker: z.strictObject({
    kind: z.enum(['host-operator', 'control-plane']),
    principalId: z.string().regex(/^[a-z0-9][a-z0-9._:-]{0,127}$/i),
  }),
  scope: z.strictObject({
    subjectDigest: digestEnvelopeV1Schema,
    policyDigest: digestEnvelopeV1Schema,
  }).optional(),
  attestations: z.array(riskDecisionAttestationV1Schema).max(2).optional(),
  recordedAt: z.iso.datetime({ offset: true }),
}).superRefine((record, context) => {
  const authorizationMode = record.authorizationMode ?? 'SINGLE_AUTHORITY'
  const attestations = record.attestations ?? []
  if (record.decision === 'DENY' && (
    record.resolution !== 'DENIED'
    || authorizationMode !== 'SINGLE_AUTHORITY'
    || record.expiresAt !== null
    || record.compensatingControls.length > 0
    || attestations.length > 0
  )) context.addIssue({ code: 'custom', message: 'DENY Risk Decision fields disagree' })
  if (record.decision === 'ACCEPT' && (
    record.expiresAt === null
    || record.compensatingControls.length === 0
    || (authorizationMode === 'SINGLE_AUTHORITY' && record.resolution !== 'ACCEPTED')
    || (authorizationMode === 'CRITICAL_DUAL_AUTHORITY' && record.resolution === 'DENIED')
  )) context.addIssue({ code: 'custom', message: 'ACCEPT Risk Decision fields disagree' })
  if (authorizationMode === 'SINGLE_AUTHORITY' && (
    record.resolution === 'PENDING_DUAL_AUTHORITY'
    || attestations.length > 0
  )) context.addIssue({ code: 'custom', message: 'Single-authority Risk Decision fields disagree' })
  if (authorizationMode === 'CRITICAL_DUAL_AUTHORITY') {
    const expectedCount = record.resolution === 'PENDING_DUAL_AUTHORITY' ? 1 : 2
    const principals = new Set(attestations.map(attestation => attestation.decisionMaker.principalId))
    if (
      record.decision !== 'ACCEPT'
      || record.scope === undefined
      || record.decisionMaker.kind !== 'host-operator'
      || attestations.length !== expectedCount
      || principals.size !== attestations.length
      || attestations.some((attestation, index) => attestation.sequence !== index + 1)
      || attestations[0]?.decisionMaker.principalId !== record.decisionMaker.principalId
    ) context.addIssue({ code: 'custom', message: 'Critical Dual Authority fields disagree' })
  }
})

export interface RiskDecisionReceiptV1 {
  readonly schemaVersion: 1
  readonly operation: 'record_risk_decision'
  readonly assessmentId: AssessmentId
  readonly assessmentRevision: number
  readonly acceptedState: 'BLOCKED'
  readonly decisionId: string
  readonly finding: {
    readonly recordId: string
    readonly recordRevision: number
  }
  readonly decision: RiskDecisionKindV1
  readonly resolution: RiskDecisionResolutionV1
  readonly idempotencyKey: string
  readonly recordedAt: string
  readonly correlationId: string
}

export const riskDecisionReceiptV1Schema: z.ZodType<RiskDecisionReceiptV1> = z.strictObject({
  schemaVersion: z.literal(1),
  operation: z.literal('record_risk_decision'),
  assessmentId: assessmentIdSchema,
  assessmentRevision: z.number().int().positive(),
  acceptedState: z.literal('BLOCKED'),
  decisionId: z.string().regex(/^risk-decision-[0-9a-f-]{36}$/),
  finding: z.strictObject({
    recordId: z.string().regex(/^finding-[0-9a-f]{64}$/),
    recordRevision: z.number().int().positive(),
  }),
  decision: z.enum(['DENY', 'ACCEPT']),
  resolution: z.enum(['DENIED', 'ACCEPTED', 'PENDING_DUAL_AUTHORITY']),
  idempotencyKey: z.string().min(1).max(128),
  recordedAt: z.iso.datetime({ offset: true }),
  correlationId: z.string().regex(/^sec-[0-9a-f-]{36}$/),
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
  readonly reason:
    | 'ELIGIBLE_EVIDENCE'
    | 'NO_ELIGIBLE_ANALYZER'
    | 'UNSUPPORTED_SUBJECT'
    | 'ANALYZER_INCOMPLETE'
    | 'EVIDENCE_INELIGIBLE'
}

export const assessmentCoverageResolutionV1Schema: z.ZodType<AssessmentCoverageResolutionV1> = z.strictObject({
  obligationId: boundedBindingId,
  state: z.enum(['SATISFIED', 'GAP']),
  reason: z.enum([
    'ELIGIBLE_EVIDENCE',
    'NO_ELIGIBLE_ANALYZER',
    'UNSUPPORTED_SUBJECT',
    'ANALYZER_INCOMPLETE',
    'EVIDENCE_INELIGIBLE',
  ]),
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

/** Bounded request for the newest authority-visible Assessment identities. */
export interface ListAssessmentsRequest {
  readonly schemaVersion: 1
  readonly limit: number
  readonly cursor?: string | undefined
}

export const listAssessmentsRequestSchema: z.ZodType<ListAssessmentsRequest> = z.strictObject({
  schemaVersion: z.literal(1),
  limit: z.number().int().min(1).max(100),
  cursor: z.string().min(1).max(4096).regex(/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/).optional(),
})

/** Redacted, path-free Assessment identity suitable for selection surfaces. */
export interface AssessmentListItemV1 {
  readonly schemaVersion: 1
  readonly assessmentId: AssessmentId
  readonly assessmentRevision: number
  readonly state: AssessmentState
  readonly repository: {
    readonly repositoryId: RepositoryId
    readonly repositoryRevision: number
  }
  readonly subjectKind: AssessmentSubjectSourceV1['kind']
  readonly policyId: string
  readonly coverageStatus: AssessmentCoverageSnapshotV1['status']
  readonly verdict: SecurityVerdict | null
  readonly createdAt: string
  readonly updatedAt: string
}

export const assessmentListItemV1Schema: z.ZodType<AssessmentListItemV1> = z.strictObject({
  schemaVersion: z.literal(1),
  assessmentId: assessmentIdSchema,
  assessmentRevision: z.number().int().positive(),
  state: assessmentStateSchema,
  repository: z.strictObject({
    repositoryId: repositoryIdSchema,
    repositoryRevision: z.number().int().positive(),
  }),
  subjectKind: z.enum(['git_revision', 'change', 'workspace_snapshot']),
  policyId: boundedBindingId,
  coverageStatus: z.enum(['PENDING', 'COMPLETE', 'GAP']),
  verdict: securityVerdictSchema.nullable(),
  createdAt: z.iso.datetime({ offset: true }),
  updatedAt: z.iso.datetime({ offset: true }),
})

/** One stable keyset page bound to the first page's signed consistency watermark. */
export interface AssessmentListPageV1 {
  readonly schemaVersion: 1
  readonly consistencyWatermark: string
  readonly assessments: readonly AssessmentListItemV1[]
  readonly nextCursor: string | null
}

export const assessmentListPageV1Schema: z.ZodType<AssessmentListPageV1> = z.strictObject({
  schemaVersion: z.literal(1),
  consistencyWatermark: z.string().min(1).max(4096)
    .regex(/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/),
  assessments: z.array(assessmentListItemV1Schema).max(100),
  nextCursor: z.string().min(1).max(4096).nullable(),
})

export type FindingDetailDimensionValueV1 = string | number | boolean

export interface FindingDetailDimensionV1 {
  readonly dimension: string
  readonly value: FindingDetailDimensionValueV1
}

export interface FindingSourceAnchorViewV1 {
  readonly path: string
  readonly fileDigest: DigestEnvelopeV1
  readonly locator: {
    readonly kind: 'JSON_POINTER'
    readonly value: string
  }
}

export interface FindingValidationOutcomeViewV1 {
  readonly state: FindingValidationState
  readonly contractId: string | null
  readonly contractVersion: number | null
  readonly outcomeArtifactId: string | null
  readonly rejectionCondition: string | null
  readonly proofGaps: readonly string[]
  readonly negativeControls: readonly string[]
}

export interface FindingEvidenceLinkMetadataV1 {
  readonly artifactId: string
  readonly schemaId: string
  readonly digest: DigestEnvelopeV1
  readonly purpose: 'VALIDATION_EVIDENCE' | 'COUNTER_EVIDENCE'
  readonly eligibilityDecision: 'ELIGIBLE' | 'INELIGIBLE'
  readonly eligibilityDecisionArtifactId: string
}

export interface FindingDetailViewV1 {
  readonly schemaVersion: 1
  readonly assessmentId: AssessmentId
  readonly assessmentRevision: number
  readonly recordKind: FindingRecordKind
  readonly recordId: string
  readonly candidateId: string
  readonly recordRevision: number
  readonly revisionChain: readonly {
    readonly recordRevision: number
    readonly supersedesRecordRevision: number | null
    readonly isCurrent: boolean
  }[]
  readonly weaknessClassification: FindingWeaknessClassificationV1
  readonly affectedControlId: string | null
  readonly sourceAnchor: FindingSourceAnchorViewV1
  readonly validation: FindingValidationOutcomeViewV1
  readonly technicalSeverity: {
    readonly value: TechnicalSeverity
    readonly methodVersion: string
    readonly inputs: readonly FindingDetailDimensionV1[]
  } | null
  readonly evidenceConfidence: {
    readonly value: EvidenceConfidence
    readonly methodVersion: string
    readonly rubric: readonly FindingDetailDimensionV1[]
  } | null
  readonly policySignificance: PolicySignificance | null
  readonly coverageRelations: readonly AssessmentCoverageResolutionV1[]
  readonly riskDecision:
    | { readonly state: 'NOT_RECORDED' }
    | ({ readonly state: RiskDecisionResolutionV1 } & Omit<
        RiskDecisionRecordV1,
        'schemaVersion' | 'assessmentId' | 'finding' | 'decision' | 'resolution'
      >)
  readonly evidenceLinks: readonly FindingEvidenceLinkMetadataV1[]
  readonly attackPath: { readonly state: 'NOT_AVAILABLE' }
}

const findingDetailDimensionValueV1Schema: z.ZodType<FindingDetailDimensionValueV1> = z.union([
  z.string().min(1).max(128),
  z.number().finite(),
  z.boolean(),
])

const findingDetailDimensionV1Schema: z.ZodType<FindingDetailDimensionV1> = z.strictObject({
  dimension: boundedBindingId,
  value: findingDetailDimensionValueV1Schema,
})

const findingSourceAnchorViewV1Schema: z.ZodType<FindingSourceAnchorViewV1> = z.strictObject({
  path: subjectRelativePathSchema,
  fileDigest: digestEnvelopeV1Schema,
  locator: z.strictObject({
    kind: z.literal('JSON_POINTER'),
    value: z.string().min(1).max(1024).startsWith('/'),
  }),
})

const findingValidationOutcomeViewV1Schema: z.ZodType<FindingValidationOutcomeViewV1> = z.strictObject({
  state: findingValidationStateSchema,
  contractId: boundedBindingId.nullable(),
  contractVersion: z.number().int().positive().nullable(),
  outcomeArtifactId: boundedBindingId.nullable(),
  rejectionCondition: boundedBindingId.nullable(),
  proofGaps: z.array(boundedBindingId).max(32),
  negativeControls: z.array(boundedBindingId).max(32),
})

const findingEvidenceSchemaId = z.string()
  .regex(/^[a-z0-9][a-z0-9._-]*(?:\/[a-z0-9][a-z0-9._-]*){1,7}$/)

const findingEvidenceLinkMetadataV1Schema: z.ZodType<FindingEvidenceLinkMetadataV1> = z.strictObject({
  artifactId: boundedBindingId,
  schemaId: findingEvidenceSchemaId,
  digest: digestEnvelopeV1Schema,
  purpose: z.enum(['VALIDATION_EVIDENCE', 'COUNTER_EVIDENCE']),
  eligibilityDecision: z.enum(['ELIGIBLE', 'INELIGIBLE']),
  eligibilityDecisionArtifactId: boundedBindingId,
})

export const findingDetailViewV1Schema: z.ZodType<FindingDetailViewV1> = z.strictObject({
  schemaVersion: z.literal(1),
  assessmentId: assessmentIdSchema,
  assessmentRevision: z.number().int().positive(),
  recordKind: findingRecordKindSchema,
  recordId: findingRecordIdSchema,
  candidateId: candidateIdSchema,
  recordRevision: z.number().int().positive(),
  revisionChain: z.array(z.strictObject({
    recordRevision: z.number().int().positive(),
    supersedesRecordRevision: z.number().int().positive().nullable(),
    isCurrent: z.boolean(),
  })).min(1).max(128),
  weaknessClassification: findingWeaknessClassificationV1Schema,
  affectedControlId: boundedBindingId.nullable(),
  sourceAnchor: findingSourceAnchorViewV1Schema,
  validation: findingValidationOutcomeViewV1Schema,
  technicalSeverity: z.strictObject({
    value: technicalSeveritySchema,
    methodVersion: boundedBindingId,
    inputs: z.array(findingDetailDimensionV1Schema).max(32),
  }).nullable(),
  evidenceConfidence: z.strictObject({
    value: evidenceConfidenceSchema,
    methodVersion: boundedBindingId,
    rubric: z.array(findingDetailDimensionV1Schema).max(32),
  }).nullable(),
  policySignificance: policySignificanceSchema.nullable(),
  coverageRelations: z.array(assessmentCoverageResolutionV1Schema).max(256),
  riskDecision: z.union([
    z.strictObject({ state: z.literal('NOT_RECORDED') }),
    z.strictObject({
      state: z.enum(['DENIED', 'ACCEPTED', 'PENDING_DUAL_AUTHORITY']),
      decisionId: z.string().regex(/^risk-decision-[0-9a-f-]{36}$/),
      authorizationMode: z.enum(['SINGLE_AUTHORITY', 'CRITICAL_DUAL_AUTHORITY']),
      rationale: z.string().trim().min(20).max(2_000),
      compensatingControls: z.array(z.string().trim().min(3).max(256)).max(16),
      expiresAt: z.iso.datetime({ offset: true }).nullable(),
      decisionMaker: z.strictObject({
        kind: z.enum(['host-operator', 'control-plane']),
        principalId: z.string().regex(/^[a-z0-9][a-z0-9._:-]{0,127}$/i),
      }),
      scope: z.strictObject({
        subjectDigest: digestEnvelopeV1Schema,
        policyDigest: digestEnvelopeV1Schema,
      }).optional(),
      attestations: z.array(riskDecisionAttestationV1Schema).max(2),
      recordedAt: z.iso.datetime({ offset: true }),
    }),
  ]),
  evidenceLinks: z.array(findingEvidenceLinkMetadataV1Schema).max(128),
  attackPath: z.strictObject({ state: z.literal('NOT_AVAILABLE') }),
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

export type AvailableRiskDecisionOptionV1 =
  | {
      readonly decision: 'DENY'
      readonly consequence: 'KEEPS_FINDING_BLOCKING'
    }
  | {
      readonly decision: 'ACCEPT'
      readonly consequence: 'MAKES_FINDING_NON_BLOCKING'
      readonly authorizationMode: 'SINGLE_AUTHORITY'
      readonly minimumCompensatingControls: 1
      readonly maximumLifetimeSeconds: number
      readonly requiredAttestations: 1
      readonly completedAttestations: 0
      readonly exactMatchRequired: false
    }
  | {
      readonly decision: 'ACCEPT'
      readonly consequence: 'REQUIRES_SECOND_AUTHORITY'
      readonly authorizationMode: 'CRITICAL_DUAL_AUTHORITY'
      readonly minimumCompensatingControls: 2
      readonly maximumLifetimeSeconds: 86_400
      readonly requiredAttestations: 2
      readonly completedAttestations: 0
      readonly exactMatchRequired: false
    }
  | {
      readonly decision: 'ACCEPT'
      readonly consequence: 'MAKES_FINDING_NON_BLOCKING'
      readonly authorizationMode: 'CRITICAL_DUAL_AUTHORITY'
      readonly minimumCompensatingControls: 2
      readonly maximumLifetimeSeconds: 86_400
      readonly requiredAttestations: 2
      readonly completedAttestations: 1
      readonly exactMatchRequired: true
    }

export const availableRiskDecisionOptionV1Schema: z.ZodType<AvailableRiskDecisionOptionV1> =
  z.union([
    z.strictObject({
      decision: z.literal('DENY'),
      consequence: z.literal('KEEPS_FINDING_BLOCKING'),
    }),
    z.strictObject({
      decision: z.literal('ACCEPT'),
      consequence: z.literal('MAKES_FINDING_NON_BLOCKING'),
      authorizationMode: z.literal('SINGLE_AUTHORITY'),
      minimumCompensatingControls: z.literal(1),
      maximumLifetimeSeconds: z.number().int().positive().max(30 * 24 * 60 * 60),
      requiredAttestations: z.literal(1),
      completedAttestations: z.literal(0),
      exactMatchRequired: z.literal(false),
    }),
    z.strictObject({
      decision: z.literal('ACCEPT'),
      consequence: z.literal('REQUIRES_SECOND_AUTHORITY'),
      authorizationMode: z.literal('CRITICAL_DUAL_AUTHORITY'),
      minimumCompensatingControls: z.literal(2),
      maximumLifetimeSeconds: z.literal(86_400),
      requiredAttestations: z.literal(2),
      completedAttestations: z.literal(0),
      exactMatchRequired: z.literal(false),
    }),
    z.strictObject({
      decision: z.literal('ACCEPT'),
      consequence: z.literal('MAKES_FINDING_NON_BLOCKING'),
      authorizationMode: z.literal('CRITICAL_DUAL_AUTHORITY'),
      minimumCompensatingControls: z.literal(2),
      maximumLifetimeSeconds: z.literal(86_400),
      requiredAttestations: z.literal(2),
      completedAttestations: z.literal(1),
      exactMatchRequired: z.literal(true),
    }),
  ])

export type AssessmentAvailableActionV1 =
  | {
      readonly kind: 'RESUME_ASSESSMENT'
      readonly expectedAssessmentRevision: number
    }
  | {
      readonly kind: 'CANCEL_ASSESSMENT'
      readonly expectedAssessmentRevision: number
    }
  | {
      readonly kind: 'RECORD_RISK_DECISION'
      readonly expectedAssessmentRevision: number
      readonly finding: {
        readonly recordId: string
        readonly recordRevision: number
      }
      readonly options: readonly AvailableRiskDecisionOptionV1[]
    }

export const assessmentAvailableActionV1Schema: z.ZodType<AssessmentAvailableActionV1> =
  z.discriminatedUnion('kind', [
    z.strictObject({
      kind: z.literal('RESUME_ASSESSMENT'),
      expectedAssessmentRevision: z.number().int().positive(),
    }),
    z.strictObject({
      kind: z.literal('CANCEL_ASSESSMENT'),
      expectedAssessmentRevision: z.number().int().positive(),
    }),
    z.strictObject({
      kind: z.literal('RECORD_RISK_DECISION'),
      expectedAssessmentRevision: z.number().int().positive(),
      finding: z.strictObject({
        recordId: z.string().regex(/^finding-[0-9a-f]{64}$/),
        recordRevision: z.number().int().positive(),
      }),
      options: z.array(availableRiskDecisionOptionV1Schema).min(1).max(2),
    }),
  ])

export interface AssessmentBlockedRecoveryV1 {
  readonly schemaVersion: 1
  readonly blocker: {
    readonly code: string
    readonly phase: 'ASSESSMENT_EXECUTION' | 'RISK_DECISION'
    readonly interruption: 'FAILED' | 'INTERRUPTED' | 'GOVERNANCE_HOLD'
    readonly affectedObligations: readonly {
      readonly obligationId: string
      readonly reason: AssessmentCoverageResolutionV1['reason']
    }[]
  }
  readonly evidence: {
    readonly status: 'RETAINED'
    /** Null means the current public model cannot prove a complete artifact count. */
    readonly publishedArtifactCount: number | null
  }
  readonly recovery: {
    readonly requiredCondition:
      | 'EXPLICIT_RESUME_REQUIRED'
      | 'RISK_DECISION_REQUIRED'
      | 'EXTERNAL_INTERVENTION_REQUIRED'
    readonly remainingExecutionBudget: { readonly status: 'NOT_REPORTED' }
    readonly coverageReconciliation: {
      readonly required: boolean
      readonly possibleVerdict: 'INDETERMINATE' | null
    }
  }
}

export const assessmentBlockedRecoveryV1Schema: z.ZodType<AssessmentBlockedRecoveryV1> =
  z.strictObject({
    schemaVersion: z.literal(1),
    blocker: z.strictObject({
      code: z.string().regex(/^[A-Z][A-Z0-9_]{0,127}$/),
      phase: z.enum(['ASSESSMENT_EXECUTION', 'RISK_DECISION']),
      interruption: z.enum(['FAILED', 'INTERRUPTED', 'GOVERNANCE_HOLD']),
      affectedObligations: z.array(z.strictObject({
        obligationId: boundedBindingId,
        reason: z.enum([
          'ELIGIBLE_EVIDENCE',
          'NO_ELIGIBLE_ANALYZER',
          'UNSUPPORTED_SUBJECT',
          'ANALYZER_INCOMPLETE',
          'EVIDENCE_INELIGIBLE',
        ]),
      })).max(256),
    }),
    evidence: z.strictObject({
      status: z.literal('RETAINED'),
      publishedArtifactCount: z.number().int().nonnegative().max(128).nullable(),
    }),
    recovery: z.strictObject({
      requiredCondition: z.enum([
        'EXPLICIT_RESUME_REQUIRED',
        'RISK_DECISION_REQUIRED',
        'EXTERNAL_INTERVENTION_REQUIRED',
      ]),
      remainingExecutionBudget: z.strictObject({ status: z.literal('NOT_REPORTED') }),
      coverageReconciliation: z.strictObject({
        required: z.boolean(),
        possibleVerdict: z.literal('INDETERMINATE').nullable(),
      }),
    }),
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
  readonly blockedRecovery: AssessmentBlockedRecoveryV1 | null
  readonly availableActions: readonly AssessmentAvailableActionV1[]
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
  blockedRecovery: assessmentBlockedRecoveryV1Schema.nullable(),
  availableActions: z.array(assessmentAvailableActionV1Schema).max(1_026),
  verdict: securityVerdictSchema.nullable(),
  seal: assessmentSealV1Schema.nullable(),
  createdAt: z.iso.datetime({ offset: true }),
  updatedAt: z.iso.datetime({ offset: true }),
}).superRefine((snapshot, context) => {
  if ((snapshot.state === 'BLOCKED') !== (snapshot.blockedRecovery !== null)) {
    context.addIssue({
      code: 'custom',
      path: ['blockedRecovery'],
      message: 'Blocked recovery metadata must exist exactly while the Assessment is BLOCKED',
    })
  }
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

export type EvidenceViewRedactionReasonV1 =
  | 'PROFILE_METADATA_ONLY'
  | 'DISCLOSURE_NOT_AUTHORIZED'
  | 'PURPOSE_NOT_AUTHORIZED'
  | 'PROTECTION_UNAVAILABLE'
  | 'SCHEMA_NOT_DISCLOSABLE'
  | 'PROFILE_BYTE_LIMIT'

export type EvidenceViewContentV1 =
  | {
      readonly kind: 'REDACTED'
      readonly reason: EvidenceViewRedactionReasonV1
    }
  | {
      readonly kind: 'BOUNDED_JSON'
      readonly byteLength: number
      readonly expiresAt: string
      readonly value: SecuritySubmissionJsonV1
    }

export interface EvidenceViewV1 {
  readonly schemaVersion: 1
  readonly assessmentId: AssessmentId
  readonly assessmentRevision: number
  readonly context: {
    readonly kind: 'finding'
    readonly recordId: string
    readonly recordRevision: number
  }
  readonly evidence: {
    readonly artifactId: string
    readonly schemaId: string
    readonly digest: DigestEnvelopeV1
    readonly classification: 'INTERNAL' | 'CONTROL_PLANE'
  }
  readonly link: {
    readonly purpose: 'VALIDATION_EVIDENCE' | 'COUNTER_EVIDENCE'
    readonly eligibilityDecision: 'ELIGIBLE' | 'INELIGIBLE'
    readonly eligibilityDecisionArtifactId: string
  }
  readonly purpose: EvidenceViewPurposeV1
  readonly viewProfileId: EvidenceViewProfileIdV1
  readonly protection: {
    readonly policyId: string
    readonly status: 'AVAILABLE' | 'UNAVAILABLE'
  }
  readonly retention: { readonly status: 'RETAINED' }
  readonly egress: {
    readonly policyId: string
    readonly status: 'LOCAL_ONLY'
  }
  readonly content: EvidenceViewContentV1
}

const evidenceViewContentV1Schema: z.ZodType<EvidenceViewContentV1> = z.discriminatedUnion('kind', [
  z.strictObject({
    kind: z.literal('REDACTED'),
    reason: z.enum([
      'PROFILE_METADATA_ONLY',
      'DISCLOSURE_NOT_AUTHORIZED',
      'PURPOSE_NOT_AUTHORIZED',
      'PROTECTION_UNAVAILABLE',
      'SCHEMA_NOT_DISCLOSABLE',
      'PROFILE_BYTE_LIMIT',
    ]),
  }),
  z.strictObject({
    kind: z.literal('BOUNDED_JSON'),
    byteLength: z.number().int().nonnegative().max(32 * 1024),
    expiresAt: z.iso.datetime({ offset: true }),
    value: securitySubmissionJsonV1Schema,
  }).refine(content => (
    Buffer.byteLength(JSON.stringify(content.value), 'utf8') === content.byteLength
  ), { message: 'bounded Evidence content byteLength does not match its JSON value' }),
])

export const evidenceViewV1Schema: z.ZodType<EvidenceViewV1> = z.strictObject({
  schemaVersion: z.literal(1),
  assessmentId: assessmentIdSchema,
  assessmentRevision: z.number().int().positive(),
  context: z.strictObject({
    kind: z.literal('finding'),
    recordId: findingRecordIdSchema,
    recordRevision: z.number().int().positive(),
  }),
  evidence: z.strictObject({
    artifactId: boundedBindingId,
    schemaId: findingEvidenceSchemaId,
    digest: digestEnvelopeV1Schema,
    classification: z.enum(['INTERNAL', 'CONTROL_PLANE']),
  }),
  link: z.strictObject({
    purpose: z.enum(['VALIDATION_EVIDENCE', 'COUNTER_EVIDENCE']),
    eligibilityDecision: z.enum(['ELIGIBLE', 'INELIGIBLE']),
    eligibilityDecisionArtifactId: boundedBindingId,
  }),
  purpose: z.enum(['FINDING_TRIAGE', 'VALIDATION_REVIEW']),
  viewProfileId: z.enum([
    EVIDENCE_VIEW_METADATA_ONLY_PROFILE_ID,
    EVIDENCE_VIEW_BOUNDED_JSON_PROFILE_ID,
  ]),
  protection: z.strictObject({
    policyId: boundedBindingId,
    status: z.enum(['AVAILABLE', 'UNAVAILABLE']),
  }),
  retention: z.strictObject({ status: z.literal('RETAINED') }),
  egress: z.strictObject({
    policyId: boundedBindingId,
    status: z.literal('LOCAL_ONLY'),
  }),
  content: evidenceViewContentV1Schema,
})

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
    /** Added during v1 development; absent only on legacy pre-Risk-Decision Seals. */
    readonly riskDecisions?: SecuritySubmissionArtifactV1 | undefined
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
    riskDecisions: securitySubmissionArtifactV1Schema.optional(),
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

export const assessmentListResultSchema: z.ZodType<SecurityResult<AssessmentListPageV1>> =
  z.discriminatedUnion('ok', [
    z.strictObject({ ok: z.literal(true), value: assessmentListPageV1Schema }),
    z.strictObject({ ok: z.literal(false), error: publicSecurityErrorSchema }),
  ])

export const findingListResultSchema: z.ZodType<SecurityResult<FindingListPageV1>> =
  z.discriminatedUnion('ok', [
    z.strictObject({ ok: z.literal(true), value: findingListPageV1Schema }),
    z.strictObject({ ok: z.literal(false), error: publicSecurityErrorSchema }),
  ])

export const findingDetailResultSchema: z.ZodType<SecurityResult<FindingDetailViewV1>> =
  z.discriminatedUnion('ok', [
    z.strictObject({ ok: z.literal(true), value: findingDetailViewV1Schema }),
    z.strictObject({ ok: z.literal(false), error: publicSecurityErrorSchema }),
  ])

export const evidenceViewResultSchema: z.ZodType<SecurityResult<EvidenceViewV1>> =
  z.discriminatedUnion('ok', [
    z.strictObject({ ok: z.literal(true), value: evidenceViewV1Schema }),
    z.strictObject({ ok: z.literal(false), error: publicSecurityErrorSchema }),
  ])

export const riskDecisionReceiptResultSchema: z.ZodType<SecurityResult<RiskDecisionReceiptV1>> =
  z.discriminatedUnion('ok', [
    z.strictObject({ ok: z.literal(true), value: riskDecisionReceiptV1Schema }),
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
