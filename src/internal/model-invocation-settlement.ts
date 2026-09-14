import { z } from 'zod'
import type {
  AssessmentId,
  DigestEnvelopeV1,
  SecurityRoleIdV1,
} from '../contracts.ts'
import {
  assessmentIdSchema,
  digestEnvelopeV1Schema,
  securityRoleIdV1Schema,
} from '../contracts.ts'
import type { RoleContextGrantV1 } from '../role-context-grant.ts'
import {
  parseRoleContextGrantV1,
  ROLE_CONTEXT_GRANT_MEDIA_TYPE,
} from '../role-context-grant.ts'
import type {
  SourceSliceEgressBrokerIdentityV1,
} from './source-slice-egress-authorization.ts'
import {
  SOURCE_SLICE_EGRESS_AUTHORIZATION_MEDIA_TYPE,
  SOURCE_SLICE_EGRESS_BROKER_IMPLEMENTATION_MEDIA_TYPE,
} from './source-slice-egress-authorization.ts'
import type {
  SourceSliceEgressBrokerResponseV1,
  SourceSliceEgressInvocationReceiptV1,
} from './source-slice-egress-invocation.ts'
import {
  parseSourceSliceEgressInvocationReceipt,
  SOURCE_SLICE_EGRESS_ATTEMPT_FENCE_MEDIA_TYPE,
  SOURCE_SLICE_EGRESS_BROKER_REQUEST_MEDIA_TYPE,
  SOURCE_SLICE_EGRESS_INVOCATION_RECEIPT_MEDIA_TYPE,
} from './source-slice-egress-invocation.ts'
import { canonicalJson, structuredDigest } from './canonical.ts'
import { deepFreeze } from './freeze.ts'

export const MODEL_INVOCATION_BUDGET_RESERVATION_MEDIA_TYPE =
  'application/vnd.dsh.security.model-invocation-budget-reservation+json'
export const MODEL_INVOCATION_RECORD_MEDIA_TYPE =
  'application/vnd.dsh.security.model-invocation-record+json'
export const MODEL_INVOCATION_FORMAT_REPAIR_REQUEST_MEDIA_TYPE =
  'application/vnd.dsh.security.model-invocation-format-repair-request+json'
export const MODEL_INVOCATION_PROMPT_MEDIA_TYPE =
  'application/vnd.dsh.security.role-prompt+json'
export const MODEL_INVOCATION_TOOL_SCHEMA_MEDIA_TYPE = 'application/schema+json'

const boundedIdSchema = z.string().regex(/^[a-z0-9][a-z0-9._/-]{0,127}$/iu)
const semanticVersionSchema = z.string()
  .max(128)
  .regex(/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/u)
const diagnosticCodeSchema = z.string().min(1).max(128).regex(/^[A-Z0-9_:-]+$/u)

function sameValue(left: unknown, right: unknown): boolean {
  return canonicalJson(left) === canonicalJson(right)
}

const attemptFenceDigestSchema = digestEnvelopeV1Schema.refine(
  digest => digest.mediaType === SOURCE_SLICE_EGRESS_ATTEMPT_FENCE_MEDIA_TYPE,
  'Model Invocation reservations must bind an Attempt fence digest',
)
const contextGrantDigestSchema = digestEnvelopeV1Schema.refine(
  digest => digest.mediaType === ROLE_CONTEXT_GRANT_MEDIA_TYPE,
  'Model Invocation reservations must bind a Context Grant digest',
)
const egressAuthorizationDigestSchema = digestEnvelopeV1Schema.refine(
  digest => digest.mediaType === SOURCE_SLICE_EGRESS_AUTHORIZATION_MEDIA_TYPE,
  'Model Invocation reservations must bind an egress authorization digest',
)
const brokerRequestDigestSchema = digestEnvelopeV1Schema.refine(
  digest => [
    SOURCE_SLICE_EGRESS_BROKER_REQUEST_MEDIA_TYPE,
    MODEL_INVOCATION_FORMAT_REPAIR_REQUEST_MEDIA_TYPE,
  ].includes(digest.mediaType),
  'Model Invocation reservations must bind a Broker request digest',
)
const reservationDigestSchema = digestEnvelopeV1Schema.refine(
  digest => digest.mediaType === MODEL_INVOCATION_BUDGET_RESERVATION_MEDIA_TYPE,
  'Model Invocation reservation digests must use the reservation media type',
)
const receiptDigestSchema = digestEnvelopeV1Schema.refine(
  digest => digest.mediaType === SOURCE_SLICE_EGRESS_INVOCATION_RECEIPT_MEDIA_TYPE,
  'Model Invocation Records must bind a Broker receipt digest',
)
const promptDigestSchema = digestEnvelopeV1Schema.refine(
  digest => (
    digest.mediaType === MODEL_INVOCATION_PROMPT_MEDIA_TYPE
    && digest.canonicalization === 'dsh-canonical-json-v1'
  ),
  'Model Invocation Records must bind a canonical Role Prompt digest',
)
const toolSchemaDigestSchema = digestEnvelopeV1Schema.refine(
  digest => digest.mediaType === MODEL_INVOCATION_TOOL_SCHEMA_MEDIA_TYPE,
  'Model Invocation Records must bind a Tool Schema digest',
)
const responseDigestSchema = digestEnvelopeV1Schema.refine(
  digest => digest.canonicalization === 'raw-bytes',
  'Model Invocation Records must bind exact response bytes',
)

export interface ModelInvocationBudgetReservationCoreV1 {
  readonly schemaVersion: 1
  readonly reservationId: string
  readonly invocationId: string
  readonly attemptId: string
  readonly attemptGeneration: number
  readonly attemptFenceDigest: DigestEnvelopeV1
  readonly contextGrantDigest: DigestEnvelopeV1
  readonly egressAuthorizationDigest: DigestEnvelopeV1
  readonly brokerRequestDigest: DigestEnvelopeV1
  readonly requestLimit: 1
  readonly tokenLimit: number
  readonly reservedAt: string
  readonly deadlineAt: string
}

const modelInvocationBudgetReservationCoreV1Schema:
  z.ZodType<ModelInvocationBudgetReservationCoreV1> = z.strictObject({
    schemaVersion: z.literal(1),
    reservationId: boundedIdSchema,
    invocationId: boundedIdSchema,
    attemptId: boundedIdSchema,
    attemptGeneration: z.number().int().positive().max(Number.MAX_SAFE_INTEGER),
    attemptFenceDigest: attemptFenceDigestSchema,
    contextGrantDigest: contextGrantDigestSchema,
    egressAuthorizationDigest: egressAuthorizationDigestSchema,
    brokerRequestDigest: brokerRequestDigestSchema,
    requestLimit: z.literal(1),
    tokenLimit: z.number().int().positive().max(4_000_000),
    reservedAt: z.iso.datetime({ offset: true }),
    deadlineAt: z.iso.datetime({ offset: true }),
  }).superRefine((reservation, context) => {
    if (Date.parse(reservation.deadlineAt) <= Date.parse(reservation.reservedAt)) {
      context.addIssue({
        code: 'custom',
        path: ['deadlineAt'],
        message: 'Model Invocation reservation deadline must follow reservation',
      })
    }
  })

export interface ModelInvocationBudgetReservationV1
  extends ModelInvocationBudgetReservationCoreV1 {
  readonly reservationDigest: DigestEnvelopeV1
}

export const modelInvocationBudgetReservationV1Schema:
  z.ZodType<ModelInvocationBudgetReservationV1> = z.strictObject({
    schemaVersion: z.literal(1),
    reservationId: boundedIdSchema,
    invocationId: boundedIdSchema,
    attemptId: boundedIdSchema,
    attemptGeneration: z.number().int().positive().max(Number.MAX_SAFE_INTEGER),
    attemptFenceDigest: attemptFenceDigestSchema,
    contextGrantDigest: contextGrantDigestSchema,
    egressAuthorizationDigest: egressAuthorizationDigestSchema,
    brokerRequestDigest: brokerRequestDigestSchema,
    requestLimit: z.literal(1),
    tokenLimit: z.number().int().positive().max(4_000_000),
    reservedAt: z.iso.datetime({ offset: true }),
    deadlineAt: z.iso.datetime({ offset: true }),
    reservationDigest: reservationDigestSchema,
  }).superRefine((reservation, context) => {
    if (Date.parse(reservation.deadlineAt) <= Date.parse(reservation.reservedAt)) {
      context.addIssue({
        code: 'custom',
        path: ['deadlineAt'],
        message: 'Model Invocation reservation deadline must follow reservation',
      })
    }
  })

/** Create immutable reservation metadata; this function grants no budget authority or capability. */
export function createModelInvocationBudgetReservationV1(
  candidate: unknown,
): ModelInvocationBudgetReservationV1 {
  const core = modelInvocationBudgetReservationCoreV1Schema.parse(candidate)
  return deepFreeze({
    ...core,
    reservationDigest: structuredDigest(MODEL_INVOCATION_BUDGET_RESERVATION_MEDIA_TYPE, core),
  })
}

/** Recompute one Kernel-owned reservation before it may settle an invocation. */
export function parseModelInvocationBudgetReservationV1(
  candidate: unknown,
): ModelInvocationBudgetReservationV1 {
  const reservation = modelInvocationBudgetReservationV1Schema.parse(candidate)
  const { reservationDigest, ...core } = reservation
  const parsedCore = modelInvocationBudgetReservationCoreV1Schema.parse(core)
  if (!sameValue(
    reservationDigest,
    structuredDigest(MODEL_INVOCATION_BUDGET_RESERVATION_MEDIA_TYPE, parsedCore),
  )) {
    throw new TypeError('Model Invocation budget reservation digest is invalid')
  }
  return deepFreeze({ ...parsedCore, reservationDigest })
}

export interface ModelInvocationLineageV1 {
  readonly provider: {
    readonly movingProvider: boolean
  }
  readonly prompt: {
    readonly promptId: string
    readonly promptVersion: string
    readonly promptDigest: DigestEnvelopeV1
    readonly toolSchemaDigest: DigestEnvelopeV1
  }
  readonly parameters: {
    readonly maxOutputTokens: number
    readonly temperature: number | null
    readonly topP: number | null
    readonly randomnessStrategyId: string
  }
}

const modelInvocationPromptV1Schema: z.ZodType<ModelInvocationLineageV1['prompt']> =
  z.strictObject({
    promptId: boundedIdSchema,
    promptVersion: semanticVersionSchema,
    promptDigest: promptDigestSchema,
    toolSchemaDigest: toolSchemaDigestSchema,
  })

const modelInvocationParametersV1Schema: z.ZodType<ModelInvocationLineageV1['parameters']> =
  z.strictObject({
    maxOutputTokens: z.number().int().positive().max(4_000_000),
    temperature: z.number().min(0).max(2).nullable(),
    topP: z.number().positive().max(1).nullable(),
    randomnessStrategyId: boundedIdSchema,
  })

const modelInvocationLineageV1Schema: z.ZodType<ModelInvocationLineageV1> = z.strictObject({
  provider: z.strictObject({
    movingProvider: z.boolean(),
  }),
  prompt: modelInvocationPromptV1Schema,
  parameters: modelInvocationParametersV1Schema,
})

export interface ModelInvocationRecordCoreV1 {
  readonly schemaVersion: 1
  readonly assessmentId: AssessmentId
  readonly invocationId: string
  readonly parentAttempt: {
    readonly attemptId: string
    readonly generation: number
    readonly fenceDigest: DigestEnvelopeV1
  }
  readonly roleDefinition: {
    readonly roleId: SecurityRoleIdV1
    readonly roleVersion: string
    readonly definitionDigest: DigestEnvelopeV1
  }
  readonly provider: {
    readonly providerId: string
    readonly providerRequestId: string
    readonly backendId: string
    readonly deploymentId: string
    readonly modelId: string
    readonly movingProvider: boolean
  }
  readonly broker: SourceSliceEgressBrokerIdentityV1
  readonly prompt: ModelInvocationLineageV1['prompt']
  readonly parameters: ModelInvocationLineageV1['parameters']
  readonly contextGrantDigest: DigestEnvelopeV1
  readonly egress: {
    readonly destinationId: string
    readonly dataEgressPolicyId: string
    readonly auditPolicyId: string
    readonly authorizationDigest: DigestEnvelopeV1
    readonly requestDigest: DigestEnvelopeV1
  }
  readonly timing: {
    readonly startedAt: string
    readonly completedAt: string
  }
  readonly usage: SourceSliceEgressBrokerResponseV1['usage']
  readonly budgetSettlement: {
    readonly reservationId: string
    readonly reservationDigest: DigestEnvelopeV1
    readonly requestLimit: 1
    readonly requestsUsed: 1
    readonly requestsReleased: 0
    readonly tokenLimit: number
    readonly inputTokens: number
    readonly outputTokens: number
    readonly tokensUsed: number
    readonly tokensReleased: number
  }
  readonly responseDigest: DigestEnvelopeV1
  readonly finishReason: SourceSliceEgressBrokerResponseV1['finishReason']
  readonly brokerDiagnosticCodes: readonly string[]
  readonly receiptDigest: DigestEnvelopeV1
}

export interface ModelInvocationRecordV1 extends ModelInvocationRecordCoreV1 {
  readonly recordDigest: DigestEnvelopeV1
}

const brokerIdentityV1Schema: z.ZodType<SourceSliceEgressBrokerIdentityV1> = z.strictObject({
  brokerId: boundedIdSchema,
  brokerVersion: semanticVersionSchema,
  implementationDigest: digestEnvelopeV1Schema.refine(
    digest => digest.mediaType === SOURCE_SLICE_EGRESS_BROKER_IMPLEMENTATION_MEDIA_TYPE,
    'Model Invocation Records must bind a qualified Broker implementation',
  ),
})

const roleDefinitionV1Schema = z.strictObject({
  roleId: securityRoleIdV1Schema,
  roleVersion: semanticVersionSchema,
  definitionDigest: digestEnvelopeV1Schema,
})

const brokerUsageV1Schema = z.strictObject({
  requestCount: z.literal(1),
  requestBytes: z.number().int().nonnegative().max(64 * 1024 * 1024),
  inputTokens: z.number().int().nonnegative().max(4_000_000),
  outputTokens: z.number().int().nonnegative().max(4_000_000),
})

const modelInvocationRecordCoreV1Shape = {
  schemaVersion: z.literal(1),
  assessmentId: assessmentIdSchema,
  invocationId: boundedIdSchema,
  parentAttempt: z.strictObject({
    attemptId: boundedIdSchema,
    generation: z.number().int().positive().max(Number.MAX_SAFE_INTEGER),
    fenceDigest: attemptFenceDigestSchema,
  }),
  roleDefinition: roleDefinitionV1Schema,
  provider: z.strictObject({
    providerId: boundedIdSchema,
    providerRequestId: boundedIdSchema,
    backendId: boundedIdSchema,
    deploymentId: boundedIdSchema,
    modelId: boundedIdSchema,
    movingProvider: z.boolean(),
  }),
  broker: brokerIdentityV1Schema,
  prompt: modelInvocationPromptV1Schema,
  parameters: modelInvocationParametersV1Schema,
  contextGrantDigest: contextGrantDigestSchema,
  egress: z.strictObject({
    destinationId: boundedIdSchema,
    dataEgressPolicyId: boundedIdSchema,
    auditPolicyId: boundedIdSchema,
    authorizationDigest: digestEnvelopeV1Schema.refine(
      digest => digest.mediaType === SOURCE_SLICE_EGRESS_AUTHORIZATION_MEDIA_TYPE,
    ),
    requestDigest: digestEnvelopeV1Schema.refine(
      digest => [
        SOURCE_SLICE_EGRESS_BROKER_REQUEST_MEDIA_TYPE,
        MODEL_INVOCATION_FORMAT_REPAIR_REQUEST_MEDIA_TYPE,
      ].includes(digest.mediaType),
    ),
  }),
  timing: z.strictObject({
    startedAt: z.iso.datetime({ offset: true }),
    completedAt: z.iso.datetime({ offset: true }),
  }),
  usage: brokerUsageV1Schema,
  budgetSettlement: z.strictObject({
    reservationId: boundedIdSchema,
    reservationDigest: reservationDigestSchema,
    requestLimit: z.literal(1),
    requestsUsed: z.literal(1),
    requestsReleased: z.literal(0),
    tokenLimit: z.number().int().positive().max(4_000_000),
    inputTokens: z.number().int().nonnegative().max(4_000_000),
    outputTokens: z.number().int().nonnegative().max(4_000_000),
    tokensUsed: z.number().int().nonnegative().max(4_000_000),
    tokensReleased: z.number().int().nonnegative().max(4_000_000),
  }),
  responseDigest: responseDigestSchema,
  finishReason: z.enum(['STOP', 'LENGTH', 'TOOL_CALLS', 'CONTENT_FILTER']),
  brokerDiagnosticCodes: z.array(diagnosticCodeSchema).max(128),
  receiptDigest: receiptDigestSchema,
} as const

function validateModelInvocationRecord(
  record: ModelInvocationRecordCoreV1,
  context: z.RefinementCtx,
): void {
  const tokensUsed = record.usage.inputTokens + record.usage.outputTokens
  if (
    Date.parse(record.timing.completedAt) < Date.parse(record.timing.startedAt)
    || record.budgetSettlement.inputTokens !== record.usage.inputTokens
    || record.budgetSettlement.outputTokens !== record.usage.outputTokens
    || record.budgetSettlement.tokensUsed !== tokensUsed
    || record.budgetSettlement.tokensReleased
      !== record.budgetSettlement.tokenLimit - tokensUsed
    || tokensUsed > record.budgetSettlement.tokenLimit
    || record.usage.outputTokens > record.parameters.maxOutputTokens
    || record.usage.inputTokens + record.parameters.maxOutputTokens
      > record.budgetSettlement.tokenLimit
  ) {
    context.addIssue({
      code: 'custom',
      message: 'Model Invocation Record usage or settlement is invalid',
    })
  }
  if (
    new Set(record.brokerDiagnosticCodes).size !== record.brokerDiagnosticCodes.length
    || record.brokerDiagnosticCodes.some(
      (value, index) => index > 0 && record.brokerDiagnosticCodes[index - 1]! >= value,
    )
  ) {
    context.addIssue({
      code: 'custom',
      path: ['brokerDiagnosticCodes'],
      message: 'Model Invocation broker diagnostics must be unique and canonical',
    })
  }
}

const modelInvocationRecordCoreV1Schema: z.ZodType<ModelInvocationRecordCoreV1> =
  z.strictObject(modelInvocationRecordCoreV1Shape).superRefine(validateModelInvocationRecord)

export const modelInvocationRecordV1Schema: z.ZodType<ModelInvocationRecordV1> = z.strictObject({
  ...modelInvocationRecordCoreV1Shape,
  recordDigest: digestEnvelopeV1Schema,
}).superRefine(validateModelInvocationRecord)

export interface ModelInvocationRecordBindingsV1 {
  readonly invocationId: string
  readonly attemptId: string
  readonly attemptGeneration: number
  readonly attemptFenceDigest: DigestEnvelopeV1
  readonly contextGrantDigest: DigestEnvelopeV1
  readonly reservationDigest: DigestEnvelopeV1
  readonly receiptDigest: DigestEnvelopeV1
}

/** Recompute one protected lineage record against its exact Attempt and source receipt. */
export function parseModelInvocationRecordV1(
  candidate: unknown,
  expected: ModelInvocationRecordBindingsV1,
): ModelInvocationRecordV1 {
  const parsed = modelInvocationRecordV1Schema.parse(candidate)
  if (
    parsed.invocationId !== expected.invocationId
    || parsed.parentAttempt.attemptId !== expected.attemptId
    || parsed.parentAttempt.generation !== expected.attemptGeneration
    || !sameValue(parsed.parentAttempt.fenceDigest, expected.attemptFenceDigest)
    || !sameValue(parsed.contextGrantDigest, expected.contextGrantDigest)
    || !sameValue(parsed.budgetSettlement.reservationDigest, expected.reservationDigest)
    || !sameValue(parsed.receiptDigest, expected.receiptDigest)
  ) {
    throw new TypeError('Model Invocation Record does not bind its exact Attempt lineage')
  }
  const { recordDigest, ...core } = parsed
  if (
    recordDigest.mediaType !== MODEL_INVOCATION_RECORD_MEDIA_TYPE
    || !sameValue(recordDigest, structuredDigest(MODEL_INVOCATION_RECORD_MEDIA_TYPE, core))
  ) {
    throw new TypeError('Model Invocation Record digest is invalid')
  }
  return deepFreeze({ ...core, recordDigest })
}

export interface SettleSourceSliceModelInvocationOptionsV1 {
  readonly contextGrant: RoleContextGrantV1
  readonly reservation: ModelInvocationBudgetReservationV1
  readonly receipt: SourceSliceEgressInvocationReceiptV1
  readonly lineage: ModelInvocationLineageV1
}

/**
 * Admit a completed Broker receipt, settle its actual usage, and emit one
 * text-free Model Invocation Record. The caller retains all Store authority.
 */
export function settleSourceSliceModelInvocationV1(
  options: SettleSourceSliceModelInvocationOptionsV1,
): ModelInvocationRecordV1 {
  const contextGrant = parseRoleContextGrantV1(options.contextGrant)
  const reservation = parseModelInvocationBudgetReservationV1(options.reservation)
  const lineage = modelInvocationLineageV1Schema.parse(options.lineage)
  const receipt = parseSourceSliceEgressInvocationReceipt(options.receipt, {
    invocationId: reservation.invocationId,
    attemptId: reservation.attemptId,
    attemptGeneration: reservation.attemptGeneration,
    attemptFenceDigest: reservation.attemptFenceDigest,
    egressAuthorizationDigest: reservation.egressAuthorizationDigest,
    brokerRequestDigest: reservation.brokerRequestDigest,
  })
  if (receipt.status !== 'COMPLETED') {
    throw new TypeError('Failed Broker receipts cannot settle a Model Invocation budget')
  }
  if (
    receipt.providerRequestId === null
    || receipt.backendId === null
    || receipt.deploymentId === null
    || receipt.modelId === null
    || receipt.responseDigest === null
    || receipt.finishReason === null
    || receipt.usage === null
  ) {
    throw new TypeError('Completed Broker receipt lacks Model Invocation lineage')
  }
  const tokensRemaining = contextGrant.budget.tokens.limit - contextGrant.budget.tokens.granted
  if (
    reservation.attemptId !== contextGrant.roleAttemptId
    || !sameValue(reservation.contextGrantDigest, contextGrant.grantDigest)
    || receipt.tokenLimit !== reservation.tokenLimit
    || reservation.tokenLimit > tokensRemaining
    || Date.parse(receipt.startedAt) < Date.parse(reservation.reservedAt)
    || Date.parse(receipt.completedAt) >= Date.parse(reservation.deadlineAt)
    || receipt.destinationId !== contextGrant.disclosure.destinationId
    || receipt.dataEgressPolicyId !== contextGrant.disclosure.dataEgressPolicyId
    || receipt.usage.outputTokens > lineage.parameters.maxOutputTokens
    || receipt.usage.inputTokens + lineage.parameters.maxOutputTokens > reservation.tokenLimit
  ) {
    throw new TypeError('Model Invocation receipt exceeds or drifts its exact Attempt reservation')
  }
  const tokensUsed = receipt.usage.inputTokens + receipt.usage.outputTokens
  const core: ModelInvocationRecordCoreV1 = {
    schemaVersion: 1,
    assessmentId: contextGrant.assessmentId,
    invocationId: receipt.invocationId,
    parentAttempt: {
      attemptId: receipt.attemptId,
      generation: receipt.attemptGeneration,
      fenceDigest: receipt.attemptFenceDigest,
    },
    roleDefinition: contextGrant.roleDefinition,
    provider: {
      providerId: receipt.providerId,
      providerRequestId: receipt.providerRequestId,
      backendId: receipt.backendId,
      deploymentId: receipt.deploymentId,
      modelId: receipt.modelId,
      movingProvider: lineage.provider.movingProvider,
    },
    broker: receipt.brokerIdentity,
    prompt: lineage.prompt,
    parameters: lineage.parameters,
    contextGrantDigest: contextGrant.grantDigest,
    egress: {
      destinationId: receipt.destinationId,
      dataEgressPolicyId: receipt.dataEgressPolicyId,
      auditPolicyId: receipt.auditPolicyId,
      authorizationDigest: receipt.egressAuthorizationDigest,
      requestDigest: receipt.brokerRequestDigest,
    },
    timing: {
      startedAt: receipt.startedAt,
      completedAt: receipt.completedAt,
    },
    usage: receipt.usage,
    budgetSettlement: {
      reservationId: reservation.reservationId,
      reservationDigest: reservation.reservationDigest,
      requestLimit: reservation.requestLimit,
      requestsUsed: 1,
      requestsReleased: 0,
      tokenLimit: reservation.tokenLimit,
      inputTokens: receipt.usage.inputTokens,
      outputTokens: receipt.usage.outputTokens,
      tokensUsed,
      tokensReleased: reservation.tokenLimit - tokensUsed,
    },
    responseDigest: receipt.responseDigest,
    finishReason: receipt.finishReason,
    brokerDiagnosticCodes: receipt.diagnosticCodes,
    receiptDigest: receipt.receiptDigest,
  }
  const parsedCore = modelInvocationRecordCoreV1Schema.parse(core)
  return deepFreeze({
    ...parsedCore,
    recordDigest: structuredDigest(MODEL_INVOCATION_RECORD_MEDIA_TYPE, parsedCore),
  })
}
