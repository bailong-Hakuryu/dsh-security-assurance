import { z } from 'zod'
import type {
  AssessmentId,
  AssessmentRoleCardV1,
  DigestEnvelopeV1,
  SecurityRoleIdV1,
} from '../contracts.ts'
import {
  assessmentIdSchema,
  assessmentRoleCardV1Schema,
  digestEnvelopeV1Schema,
  securityRoleIdV1Schema,
} from '../contracts.ts'
import type { RoleContextGrantV1 } from '../role-context-grant.ts'
import {
  parseRoleContextGrantV1,
  ROLE_CONTEXT_GRANT_MEDIA_TYPE,
} from '../role-context-grant.ts'
import { canonicalJson, structuredDigest } from './canonical.ts'
import { deepFreeze } from './freeze.ts'
import {
  MODEL_INVOCATION_PROMPT_MEDIA_TYPE,
  MODEL_INVOCATION_TOOL_SCHEMA_MEDIA_TYPE,
} from './model-invocation-settlement.ts'
import { SOURCE_SLICE_EGRESS_ATTEMPT_FENCE_MEDIA_TYPE } from './source-slice-egress-invocation.ts'

export const ROLE_ATTEMPT_RECORD_MEDIA_TYPE =
  'application/vnd.dsh.security.role-attempt-record+json'

const boundedIdSchema = z.string().regex(/^[a-z0-9][a-z0-9._/-]{0,127}$/iu)
const roleAttemptIdSchema = z.string().regex(/^role-attempt-[0-9a-f-]{36}$/u)
const semanticVersionSchema = z.string()
  .max(128)
  .regex(/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/u)
const attemptFenceDigestSchema = digestEnvelopeV1Schema.refine(
  digest => digest.mediaType === SOURCE_SLICE_EGRESS_ATTEMPT_FENCE_MEDIA_TYPE,
  'Role Attempts must bind an Attempt fence digest',
)
const contextGrantDigestSchema = digestEnvelopeV1Schema.refine(
  digest => digest.mediaType === ROLE_CONTEXT_GRANT_MEDIA_TYPE,
  'Role Attempts must bind a Context Grant digest',
)
const promptDigestSchema = digestEnvelopeV1Schema.refine(
  digest => digest.mediaType === MODEL_INVOCATION_PROMPT_MEDIA_TYPE,
  'Role Attempts must bind a Role Prompt digest',
)
const toolSchemaDigestSchema = digestEnvelopeV1Schema.refine(
  digest => digest.mediaType === MODEL_INVOCATION_TOOL_SCHEMA_MEDIA_TYPE,
  'Role Attempts must bind a Tool Schema digest',
)
const recordDigestSchema = digestEnvelopeV1Schema.refine(
  digest => digest.mediaType === ROLE_ATTEMPT_RECORD_MEDIA_TYPE,
  'Role Attempt records must use the record media type',
)
const failureCodeSchema = z.string().regex(/^[A-Z][A-Z0-9_]{0,127}$/u)

export interface RoleAttemptStartBindingsV1 {
  readonly generation: number
  readonly fenceDigest: DigestEnvelopeV1
  readonly parentAttemptId: string | null
  readonly independenceClass: AssessmentRoleCardV1['roleDefinition']['independenceClass']
  readonly provider: AssessmentRoleCardV1['provider']
  readonly prompt: {
    readonly promptId: string
    readonly promptVersion: string
    readonly promptDigest: DigestEnvelopeV1
    readonly toolSchemaDigest: DigestEnvelopeV1
  }
  readonly budget: {
    readonly requestLimit: number
    readonly tokenLimit: number
  }
}

export interface RoleAttemptRecordCoreV1 {
  readonly schemaVersion: 1
  readonly assessmentId: AssessmentId
  readonly assessmentRevision: number
  readonly attemptId: string
  readonly parentAttemptId: string | null
  readonly generation: number
  readonly fenceDigest: DigestEnvelopeV1
  readonly contextGrantDigest: DigestEnvelopeV1
  readonly roleDefinition: {
    readonly roleId: SecurityRoleIdV1
    readonly roleVersion: string
    readonly definitionDigest: DigestEnvelopeV1
    readonly independenceClass: AssessmentRoleCardV1['roleDefinition']['independenceClass']
  }
  readonly provider: AssessmentRoleCardV1['provider']
  readonly prompt: RoleAttemptStartBindingsV1['prompt']
  readonly budget: {
    readonly requestLimit: number
    readonly requestsUsed: number
    readonly tokenLimit: number
    readonly tokensUsed: number
  }
  readonly lifecycleState: 'RUNNING' | 'COMPLETED' | 'FAILED' | 'CANCELED'
  readonly startedAt: string
  readonly completedAt: string | null
  readonly completionDisposition: 'NOT_AVAILABLE' | 'COMPLETE' | 'PARTIAL' | 'FAILED' | 'CANCELED'
  readonly failureCode?: string | undefined
  readonly cancellationRevision?: number | undefined
  readonly milestones: AssessmentRoleCardV1['milestones']
  readonly evidenceCount: number
  readonly candidateCount: number
  readonly challengeRelations: AssessmentRoleCardV1['challengeRelations']
}

export interface RoleAttemptRecordV1 extends RoleAttemptRecordCoreV1 {
  readonly recordDigest: DigestEnvelopeV1
}

export interface CompleteRoleAttemptValuesV1 {
  readonly completionDisposition: 'COMPLETE' | 'PARTIAL'
  readonly usage: {
    readonly requestsUsed: number
    readonly tokensUsed: number
  }
  readonly evidenceCount: number
  readonly candidateCount: number
  readonly milestones: AssessmentRoleCardV1['milestones']
}

export interface FailRoleAttemptValuesV1 {
  readonly failureCode: string
  readonly usage: {
    readonly requestsUsed: number
    readonly tokensUsed: number
  }
  readonly evidenceCount: number
  readonly candidateCount: number
  readonly milestones: AssessmentRoleCardV1['milestones']
}

const roleAttemptRecordCoreShape = {
  schemaVersion: z.literal(1),
  assessmentId: assessmentIdSchema,
  assessmentRevision: z.number().int().positive().max(Number.MAX_SAFE_INTEGER),
  attemptId: roleAttemptIdSchema,
  parentAttemptId: roleAttemptIdSchema.nullable(),
  generation: z.number().int().positive().max(Number.MAX_SAFE_INTEGER),
  fenceDigest: attemptFenceDigestSchema,
  contextGrantDigest: contextGrantDigestSchema,
  roleDefinition: z.strictObject({
    roleId: securityRoleIdV1Schema,
    roleVersion: semanticVersionSchema,
    definitionDigest: digestEnvelopeV1Schema,
    independenceClass: z.enum(['NONE', 'DISTINCT_ATTEMPT', 'DISTINCT_PROVIDER_OR_MODEL_FAMILY']),
  }),
  provider: z.strictObject({
    providerId: boundedIdSchema,
    modelId: boundedIdSchema,
    movingProvider: z.boolean(),
  }),
  prompt: z.strictObject({
    promptId: boundedIdSchema,
    promptVersion: semanticVersionSchema,
    promptDigest: promptDigestSchema,
    toolSchemaDigest: toolSchemaDigestSchema,
  }),
  budget: z.strictObject({
    requestLimit: z.number().int().positive().max(1_000_000),
    requestsUsed: z.number().int().nonnegative().max(1_000_000),
    tokenLimit: z.number().int().positive().max(4_000_000),
    tokensUsed: z.number().int().nonnegative().max(4_000_000),
  }),
  lifecycleState: z.enum(['RUNNING', 'COMPLETED', 'FAILED', 'CANCELED']),
  startedAt: z.iso.datetime({ offset: true }),
  completedAt: z.iso.datetime({ offset: true }).nullable(),
  completionDisposition: z.enum(['NOT_AVAILABLE', 'COMPLETE', 'PARTIAL', 'FAILED', 'CANCELED']),
  failureCode: failureCodeSchema.optional(),
  cancellationRevision: z.number().int().positive().max(Number.MAX_SAFE_INTEGER).optional(),
  milestones: z.array(z.strictObject({
    milestoneId: boundedIdSchema,
    state: z.enum(['PENDING', 'REACHED']),
    recordedAt: z.iso.datetime({ offset: true }).nullable(),
  })).max(64),
  evidenceCount: z.number().int().nonnegative().max(1_000_000),
  candidateCount: z.number().int().nonnegative().max(1_000_000),
  challengeRelations: z.array(z.strictObject({
    relatedAttemptId: roleAttemptIdSchema,
    relation: z.enum(['CHALLENGES', 'CHALLENGED_BY']),
  })).max(64),
} as const

function validateRoleAttemptRecord(
  record: RoleAttemptRecordCoreV1,
  context: z.RefinementCtx,
): void {
  if (
    record.parentAttemptId === record.attemptId
    || record.budget.requestsUsed > record.budget.requestLimit
    || record.budget.tokensUsed > record.budget.tokenLimit
    || (record.lifecycleState === 'RUNNING') !== (record.completedAt === null)
    || (record.lifecycleState === 'RUNNING'
      ? record.completionDisposition !== 'NOT_AVAILABLE'
      : record.lifecycleState === 'COMPLETED'
        ? record.completionDisposition !== 'COMPLETE'
          && record.completionDisposition !== 'PARTIAL'
        : record.lifecycleState === 'FAILED'
          ? record.completionDisposition !== 'FAILED'
          : record.completionDisposition !== 'CANCELED')
    || (record.lifecycleState === 'FAILED') !== (record.failureCode !== undefined)
    || (record.lifecycleState === 'CANCELED') !== (record.cancellationRevision !== undefined)
    || (
      record.completedAt !== null
      && Date.parse(record.completedAt) < Date.parse(record.startedAt)
    )
  ) {
    context.addIssue({
      code: 'custom',
      message: 'Role Attempt lifecycle, lineage, or budget is invalid',
    })
  }
}

const roleAttemptRecordCoreV1Schema: z.ZodType<RoleAttemptRecordCoreV1> =
  z.strictObject(roleAttemptRecordCoreShape).superRefine(validateRoleAttemptRecord)

export const roleAttemptRecordV1Schema: z.ZodType<RoleAttemptRecordV1> = z.strictObject({
  ...roleAttemptRecordCoreShape,
  recordDigest: recordDigestSchema,
}).superRefine(validateRoleAttemptRecord)

function sameValue(left: unknown, right: unknown): boolean {
  return canonicalJson(left) === canonicalJson(right)
}

export interface CreateRunningRoleAttemptOptionsV1 extends RoleAttemptStartBindingsV1 {
  readonly assessmentRevision: number
  readonly startedAt: string
  readonly contextGrant: RoleContextGrantV1
}

/** Create one immutable RUNNING Role Attempt before any isolated session starts. */
export function createRunningRoleAttemptV1(
  options: CreateRunningRoleAttemptOptionsV1,
): RoleAttemptRecordV1 {
  const contextGrant = parseRoleContextGrantV1(options.contextGrant)
  const core = roleAttemptRecordCoreV1Schema.parse({
    schemaVersion: 1,
    assessmentId: contextGrant.assessmentId,
    assessmentRevision: options.assessmentRevision,
    attemptId: contextGrant.roleAttemptId,
    parentAttemptId: options.parentAttemptId,
    generation: options.generation,
    fenceDigest: options.fenceDigest,
    contextGrantDigest: contextGrant.grantDigest,
    roleDefinition: {
      ...contextGrant.roleDefinition,
      independenceClass: options.independenceClass,
    },
    provider: options.provider,
    prompt: options.prompt,
    budget: {
      ...options.budget,
      requestsUsed: 0,
      tokensUsed: 0,
    },
    lifecycleState: 'RUNNING',
    startedAt: options.startedAt,
    completedAt: null,
    completionDisposition: 'NOT_AVAILABLE',
    milestones: [],
    evidenceCount: 0,
    candidateCount: 0,
    challengeRelations: [],
  })
  return deepFreeze({
    ...core,
    recordDigest: structuredDigest(ROLE_ATTEMPT_RECORD_MEDIA_TYPE, core),
  })
}

/** Recompute one stored Role Attempt record and detach it from mutable input. */
export function parseRoleAttemptRecordV1(candidate: unknown): RoleAttemptRecordV1 {
  const record = roleAttemptRecordV1Schema.parse(candidate)
  const { recordDigest, ...core } = record
  const parsedCore = roleAttemptRecordCoreV1Schema.parse(core)
  if (!sameValue(
    recordDigest,
    structuredDigest(ROLE_ATTEMPT_RECORD_MEDIA_TYPE, parsedCore),
  )) {
    throw new TypeError('Role Attempt record digest is invalid')
  }
  return deepFreeze({ ...parsedCore, recordDigest })
}

export interface CompleteRoleAttemptOptionsV1 extends CompleteRoleAttemptValuesV1 {
  readonly current: RoleAttemptRecordV1
  readonly assessmentRevision: number
  readonly completedAt: string
}

/** Settle one current generation exactly once without changing its frozen lineage. */
export function completeRoleAttemptV1(
  options: CompleteRoleAttemptOptionsV1,
): RoleAttemptRecordV1 {
  const current = parseRoleAttemptRecordV1(options.current)
  if (current.lifecycleState !== 'RUNNING') {
    throw new TypeError('Only a RUNNING Role Attempt can complete')
  }
  const { recordDigest: _recordDigest, ...currentCore } = current
  const core = roleAttemptRecordCoreV1Schema.parse({
    ...currentCore,
    assessmentRevision: options.assessmentRevision,
    budget: {
      ...current.budget,
      ...options.usage,
    },
    lifecycleState: 'COMPLETED',
    completedAt: options.completedAt,
    completionDisposition: options.completionDisposition,
    milestones: options.milestones,
    evidenceCount: options.evidenceCount,
    candidateCount: options.candidateCount,
  })
  return deepFreeze({
    ...core,
    recordDigest: structuredDigest(ROLE_ATTEMPT_RECORD_MEDIA_TYPE, core),
  })
}

export interface FailRoleAttemptOptionsV1 extends FailRoleAttemptValuesV1 {
  readonly current: RoleAttemptRecordV1
  readonly assessmentRevision: number
  readonly failedAt: string
}

/** Fail one current generation exactly once without discarding its frozen lineage. */
export function failRoleAttemptV1(
  options: FailRoleAttemptOptionsV1,
): RoleAttemptRecordV1 {
  const current = parseRoleAttemptRecordV1(options.current)
  if (current.lifecycleState !== 'RUNNING') {
    throw new TypeError('Only a RUNNING Role Attempt can fail')
  }
  const { recordDigest: _recordDigest, ...currentCore } = current
  const core = roleAttemptRecordCoreV1Schema.parse({
    ...currentCore,
    assessmentRevision: options.assessmentRevision,
    budget: {
      ...current.budget,
      ...options.usage,
    },
    lifecycleState: 'FAILED',
    completedAt: options.failedAt,
    completionDisposition: 'FAILED',
    failureCode: options.failureCode,
    milestones: options.milestones,
    evidenceCount: options.evidenceCount,
    candidateCount: options.candidateCount,
  })
  return deepFreeze({
    ...core,
    recordDigest: structuredDigest(ROLE_ATTEMPT_RECORD_MEDIA_TYPE, core),
  })
}

export interface CancelRoleAttemptOptionsV1 {
  readonly current: RoleAttemptRecordV1
  readonly assessmentRevision: number
  readonly canceledAt: string
  readonly cancellationRevision: number
}

/** Close one RUNNING Role Attempt after Assessment-level quiescence is proved. */
export function cancelRoleAttemptV1(
  options: CancelRoleAttemptOptionsV1,
): RoleAttemptRecordV1 {
  const current = parseRoleAttemptRecordV1(options.current)
  if (current.lifecycleState !== 'RUNNING') {
    throw new TypeError('Only a RUNNING Role Attempt can be canceled')
  }
  const { recordDigest: _recordDigest, ...currentCore } = current
  const core = roleAttemptRecordCoreV1Schema.parse({
    ...currentCore,
    assessmentRevision: options.assessmentRevision,
    lifecycleState: 'CANCELED',
    completedAt: options.canceledAt,
    completionDisposition: 'CANCELED',
    cancellationRevision: options.cancellationRevision,
  })
  return deepFreeze({
    ...core,
    recordDigest: structuredDigest(ROLE_ATTEMPT_RECORD_MEDIA_TYPE, core),
  })
}

/** Project one durable Role Attempt into the existing bounded public Role Card. */
export function projectRoleAttemptCardV1(
  record: RoleAttemptRecordV1,
): AssessmentRoleCardV1 {
  const parsed = parseRoleAttemptRecordV1(record)
  return assessmentRoleCardV1Schema.parse({
    schemaVersion: 1,
    roleDefinition: parsed.roleDefinition,
    attempt: {
      attemptId: parsed.attemptId,
      parentAttemptId: parsed.parentAttemptId,
      lifecycleState: parsed.lifecycleState,
      startedAt: parsed.startedAt,
      completedAt: parsed.completedAt,
    },
    provider: parsed.provider,
    budget: {
      status: 'REPORTED',
      ...parsed.budget,
    },
    milestones: parsed.milestones,
    evidenceCount: parsed.evidenceCount,
    candidateCount: parsed.candidateCount,
    completionDisposition: parsed.completionDisposition,
    challengeRelations: parsed.challengeRelations,
  })
}
