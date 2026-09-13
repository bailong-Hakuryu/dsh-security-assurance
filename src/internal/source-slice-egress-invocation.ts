import { z } from 'zod'
import type { DigestEnvelopeV1 } from '../contracts.ts'
import { digestEnvelopeV1Schema } from '../contracts.ts'
import type { RoleContextGrantV1 } from '../role-context-grant.ts'
import { parseRoleContextGrantV1 } from '../role-context-grant.ts'
import type { SourceSliceRequestV1 } from '../source-slice-request.ts'
import { parseSourceSliceRequestV1 } from '../source-slice-request.ts'
import { binaryDigest, canonicalJson, structuredDigest } from './canonical.ts'
import { deepFreeze } from './freeze.ts'
import type {
  SourceSliceDestinationAuthorizationV1,
  SourceSliceEgressBrokerIdentityV1,
  SourceSliceEgressBrokerQualificationV1,
} from './source-slice-egress-authorization.ts'
import {
  admitProtectedSourceSliceEgressAuthorization,
  SOURCE_SLICE_EGRESS_AUTHORIZATION_MEDIA_TYPE,
  SOURCE_SLICE_EGRESS_BROKER_IMPLEMENTATION_MEDIA_TYPE,
} from './source-slice-egress-authorization.ts'
import type { ProtectedSourceSliceRedactionV1 } from './source-slice-protection.ts'
import type { ProtectedSourceSliceSecretReviewV1 } from './source-slice-secret-review.ts'
import type { ProtectedSourceSliceMaterialV1 } from './subject-freeze.ts'

export const SOURCE_SLICE_EGRESS_BROKER_REQUEST_MEDIA_TYPE =
  'application/vnd.dsh.security.source-slice-egress-broker-request+json'
export const SOURCE_SLICE_EGRESS_ATTEMPT_FENCE_MEDIA_TYPE =
  'application/vnd.dsh.security.source-slice-egress-attempt-fence+json'
export const SOURCE_SLICE_EGRESS_INVOCATION_RECEIPT_MEDIA_TYPE =
  'application/vnd.dsh.security.source-slice-egress-invocation-receipt+json'

const boundedIdSchema = z.string().regex(/^[a-z0-9][a-z0-9._/-]{0,127}$/iu)
const semanticVersionSchema = z.string().regex(/^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$/u)
const mediaTypeSchema = z.string().max(128).regex(/^application\/[a-z0-9.+-]+$|^text\/[a-z0-9.+-]+$/u)
const diagnosticCodeSchema = z.string().min(1).max(128).regex(/^[A-Z0-9_:-]+$/u)

export interface SourceSliceEgressAttemptV1 {
  readonly attemptId: string
  readonly generation: number
  readonly fencingToken: string
  readonly deadlineAt: string
}

export interface SourceSliceEgressBrokerRequestCoreV1 {
  readonly schemaVersion: 1
  readonly invocationId: string
  readonly attemptId: string
  readonly attemptGeneration: number
  readonly attemptFenceDigest: DigestEnvelopeV1
  readonly egressAuthorizationDigest: DigestEnvelopeV1
  readonly brokerIdentity: SourceSliceEgressBrokerIdentityV1
  readonly providerId: string
  readonly destinationId: string
  readonly dataEgressPolicyId: string
  readonly credentialBindingId: string
  readonly categoryId: string
  readonly auditPolicyId: string
  readonly content: {
    readonly path: string
    readonly mediaType: string
    readonly digest: DigestEnvelopeV1
    readonly byteLength: number
    readonly text: string
  }
  readonly limits: {
    readonly requestByteLimit: number
    readonly requestCountLimit: 1
    readonly tokenLimit: number
    readonly timeoutMilliseconds: number
  }
  readonly issuedAt: string
  readonly deadlineAt: string
}

export interface SourceSliceEgressBrokerRequestV1 extends SourceSliceEgressBrokerRequestCoreV1 {
  readonly brokerRequestDigest: DigestEnvelopeV1
}

export interface SourceSliceEgressBrokerResponseV1 {
  readonly schemaVersion: 1
  readonly brokerIdentity: SourceSliceEgressBrokerIdentityV1
  readonly providerId: string
  readonly destinationId: string
  readonly providerRequestId: string
  readonly backendId: string
  readonly deploymentId: string
  readonly modelId: string
  readonly response: {
    readonly mediaType: string
    readonly text: string
  }
  readonly usage: {
    readonly requestCount: 1
    readonly requestBytes: number
    readonly inputTokens: number
    readonly outputTokens: number
  }
  readonly finishReason: 'STOP' | 'LENGTH' | 'TOOL_CALLS' | 'CONTENT_FILTER'
  readonly diagnostics: readonly string[]
}

export interface SourceSliceEgressBrokerAdapterV1 {
  readonly identity: SourceSliceEgressBrokerIdentityV1
  invoke(
    request: SourceSliceEgressBrokerRequestV1,
    options: { readonly signal: AbortSignal, readonly deadlineAt: string },
  ): Promise<SourceSliceEgressBrokerResponseV1>
}

export type SourceSliceEgressInvocationFailureCodeV1 =
  | 'ATTEMPT_DEADLINE_EXCEEDED'
  | 'ATTEMPT_SETTLED'
  | 'INVOCATION_ABORTED'
  | 'BROKER_FAILED'
  | 'BROKER_RESPONSE_INVALID'
  | 'BROKER_RESPONSE_SCOPE_MISMATCH'
  | 'BROKER_USAGE_EXCEEDED'

export interface SourceSliceEgressInvocationReceiptCoreV1 {
  readonly schemaVersion: 1
  readonly invocationId: string
  readonly attemptId: string
  readonly attemptGeneration: number
  readonly attemptFenceDigest: DigestEnvelopeV1
  readonly egressAuthorizationDigest: DigestEnvelopeV1
  readonly brokerRequestDigest: DigestEnvelopeV1
  readonly brokerIdentity: SourceSliceEgressBrokerIdentityV1
  readonly providerId: string
  readonly destinationId: string
  readonly dataEgressPolicyId: string
  readonly auditPolicyId: string
  readonly requestBytes: number
  readonly tokenLimit: number
  readonly startedAt: string
  readonly completedAt: string
  readonly status: 'COMPLETED' | 'FAILED'
  readonly failureCode: SourceSliceEgressInvocationFailureCodeV1 | null
  readonly providerRequestId: string | null
  readonly backendId: string | null
  readonly deploymentId: string | null
  readonly modelId: string | null
  readonly responseDigest: DigestEnvelopeV1 | null
  readonly finishReason: SourceSliceEgressBrokerResponseV1['finishReason'] | null
  readonly usage: SourceSliceEgressBrokerResponseV1['usage'] | null
  readonly diagnosticCodes: readonly string[]
}

export interface SourceSliceEgressInvocationReceiptV1
  extends SourceSliceEgressInvocationReceiptCoreV1 {
  readonly receiptDigest: DigestEnvelopeV1
}

export interface SourceSliceEgressInvocationReceiptBindingsV1 {
  readonly invocationId: string
  readonly attemptId: string
  readonly attemptGeneration: number
  readonly attemptFenceDigest: DigestEnvelopeV1
  readonly egressAuthorizationDigest: DigestEnvelopeV1
  readonly brokerRequestDigest: DigestEnvelopeV1
}

export type SourceSliceEgressInvocationResultV1 = {
  readonly status: 'COMPLETED'
  readonly response: {
    readonly mediaType: string
    readonly text: string
    readonly digest: DigestEnvelopeV1
  }
  readonly receipt: SourceSliceEgressInvocationReceiptV1
} | {
  readonly status: 'FAILED'
  readonly response: null
  readonly receipt: SourceSliceEgressInvocationReceiptV1
}

export interface AttemptScopedSourceSliceEgressCapabilityV1 {
  invoke(options?: { readonly signal?: AbortSignal }): Promise<SourceSliceEgressInvocationResultV1>
}

export interface IssueAttemptScopedSourceSliceEgressCapabilityOptionsV1 {
  readonly invocationId: string
  readonly attempt: SourceSliceEgressAttemptV1
  readonly contextGrant: RoleContextGrantV1
  readonly request: SourceSliceRequestV1
  readonly material: ProtectedSourceSliceMaterialV1
  readonly redaction: ProtectedSourceSliceRedactionV1
  readonly secretReview: ProtectedSourceSliceSecretReviewV1
  readonly brokerQualification: SourceSliceEgressBrokerQualificationV1
  readonly destinationAuthorization: SourceSliceDestinationAuthorizationV1
  readonly broker: SourceSliceEgressBrokerAdapterV1
  readonly now?: (() => string) | undefined
}

export interface IssuedSourceSliceEgressCapabilityV1 {
  readonly capability: AttemptScopedSourceSliceEgressCapabilityV1
  settle(): void
}

export type SourceSliceEgressCapabilityErrorCodeV1 =
  | 'CAPABILITY_CONSUMED'
  | 'CAPABILITY_SETTLED'

export class SourceSliceEgressCapabilityError extends Error {
  constructor(readonly code: SourceSliceEgressCapabilityErrorCodeV1, message: string) {
    super(message)
    this.name = 'SourceSliceEgressCapabilityError'
  }
}

const brokerIdentityV1Schema: z.ZodType<SourceSliceEgressBrokerIdentityV1> = z.strictObject({
  brokerId: boundedIdSchema,
  brokerVersion: semanticVersionSchema,
  implementationDigest: digestEnvelopeV1Schema,
})

const brokerUsageV1Schema = z.strictObject({
  requestCount: z.literal(1),
  requestBytes: z.number().int().nonnegative().max(64 * 1024 * 1024),
  inputTokens: z.number().int().nonnegative().max(4_000_000),
  outputTokens: z.number().int().nonnegative().max(4_000_000),
})

const brokerResponseV1Schema: z.ZodType<SourceSliceEgressBrokerResponseV1> = z.strictObject({
  schemaVersion: z.literal(1),
  brokerIdentity: brokerIdentityV1Schema,
  providerId: boundedIdSchema,
  destinationId: boundedIdSchema,
  providerRequestId: boundedIdSchema,
  backendId: boundedIdSchema,
  deploymentId: boundedIdSchema,
  modelId: boundedIdSchema,
  response: z.strictObject({
    mediaType: mediaTypeSchema,
    text: z.string().max(8 * 1024 * 1024),
  }),
  usage: brokerUsageV1Schema,
  finishReason: z.enum(['STOP', 'LENGTH', 'TOOL_CALLS', 'CONTENT_FILTER']),
  diagnostics: z.array(diagnosticCodeSchema).max(128),
}).superRefine((response, context) => {
  if (
    new Set(response.diagnostics).size !== response.diagnostics.length
    || response.diagnostics.some((value, index) => index > 0 && response.diagnostics[index - 1]! >= value)
  ) {
    context.addIssue({ code: 'custom', message: 'Broker diagnostics must be unique and canonical' })
  }
})

const attemptV1Schema: z.ZodType<SourceSliceEgressAttemptV1> = z.strictObject({
  attemptId: boundedIdSchema,
  generation: z.number().int().positive().max(Number.MAX_SAFE_INTEGER),
  fencingToken: z.string().min(16).max(256).regex(/^[a-z0-9._/-]+$/iu),
  deadlineAt: z.iso.datetime({ offset: true }),
})

export const sourceSliceEgressInvocationReceiptV1Schema:
  z.ZodType<SourceSliceEgressInvocationReceiptV1> = z.strictObject({
    schemaVersion: z.literal(1),
    invocationId: boundedIdSchema,
    attemptId: boundedIdSchema,
    attemptGeneration: z.number().int().positive().max(Number.MAX_SAFE_INTEGER),
    attemptFenceDigest: digestEnvelopeV1Schema,
    egressAuthorizationDigest: digestEnvelopeV1Schema,
    brokerRequestDigest: digestEnvelopeV1Schema,
    brokerIdentity: brokerIdentityV1Schema,
    providerId: boundedIdSchema,
    destinationId: boundedIdSchema,
    dataEgressPolicyId: boundedIdSchema,
    auditPolicyId: boundedIdSchema,
    requestBytes: z.number().int().nonnegative().max(64 * 1024 * 1024),
    tokenLimit: z.number().int().positive().max(4_000_000),
    startedAt: z.iso.datetime({ offset: true }),
    completedAt: z.iso.datetime({ offset: true }),
    status: z.enum(['COMPLETED', 'FAILED']),
    failureCode: z.enum([
      'ATTEMPT_DEADLINE_EXCEEDED',
      'ATTEMPT_SETTLED',
      'INVOCATION_ABORTED',
      'BROKER_FAILED',
      'BROKER_RESPONSE_INVALID',
      'BROKER_RESPONSE_SCOPE_MISMATCH',
      'BROKER_USAGE_EXCEEDED',
    ]).nullable(),
    providerRequestId: boundedIdSchema.nullable(),
    backendId: boundedIdSchema.nullable(),
    deploymentId: boundedIdSchema.nullable(),
    modelId: boundedIdSchema.nullable(),
    responseDigest: digestEnvelopeV1Schema.nullable(),
    finishReason: z.enum(['STOP', 'LENGTH', 'TOOL_CALLS', 'CONTENT_FILTER']).nullable(),
    usage: brokerUsageV1Schema.nullable(),
    diagnosticCodes: z.array(diagnosticCodeSchema).max(128),
    receiptDigest: digestEnvelopeV1Schema,
  }).superRefine((candidate, context) => {
    const responseFields = [
      candidate.providerRequestId,
      candidate.backendId,
      candidate.deploymentId,
      candidate.modelId,
      candidate.responseDigest,
      candidate.finishReason,
      candidate.usage,
    ]
    if (
      Date.parse(candidate.completedAt) < Date.parse(candidate.startedAt)
      || (candidate.status === 'COMPLETED'
        && (candidate.failureCode !== null || responseFields.some(value => value === null)))
      || (candidate.status === 'FAILED'
        && (candidate.failureCode === null || responseFields.some(value => value !== null)))
      || (candidate.status === 'COMPLETED'
        && candidate.usage !== null
        && (
          candidate.usage.requestBytes !== candidate.requestBytes
          || candidate.usage.inputTokens + candidate.usage.outputTokens > candidate.tokenLimit
        ))
      || new Set(candidate.diagnosticCodes).size !== candidate.diagnosticCodes.length
      || candidate.diagnosticCodes.some((value, index) => index > 0 && candidate.diagnosticCodes[index - 1]! >= value)
    ) {
      context.addIssue({
        code: 'custom',
        message: 'Source Slice egress receipt disposition or usage quota is invalid',
      })
    }
  })

function sameValue(left: unknown, right: unknown): boolean {
  return canonicalJson(left) === canonicalJson(right)
}

function parseInstant(candidate: string): number {
  return Date.parse(z.iso.datetime({ offset: true }).parse(candidate))
}

function receipt(
  core: SourceSliceEgressInvocationReceiptCoreV1,
): SourceSliceEgressInvocationReceiptV1 {
  return deepFreeze({
    ...core,
    receiptDigest: structuredDigest(SOURCE_SLICE_EGRESS_INVOCATION_RECEIPT_MEDIA_TYPE, core),
  })
}

/** Recompute one protected Broker receipt against its exact Attempt and admitted request. */
export function parseSourceSliceEgressInvocationReceipt(
  candidate: unknown,
  expected: SourceSliceEgressInvocationReceiptBindingsV1,
): SourceSliceEgressInvocationReceiptV1 {
  const parsed = sourceSliceEgressInvocationReceiptV1Schema.parse(candidate)
  if (
    parsed.invocationId !== expected.invocationId
    || parsed.attemptId !== expected.attemptId
    || parsed.attemptGeneration !== expected.attemptGeneration
    || !sameValue(parsed.attemptFenceDigest, expected.attemptFenceDigest)
    || !sameValue(parsed.egressAuthorizationDigest, expected.egressAuthorizationDigest)
    || !sameValue(parsed.brokerRequestDigest, expected.brokerRequestDigest)
  ) {
    throw new TypeError('Source Slice egress receipt does not bind its exact invocation')
  }
  if (
    parsed.attemptFenceDigest.mediaType !== SOURCE_SLICE_EGRESS_ATTEMPT_FENCE_MEDIA_TYPE
    || parsed.egressAuthorizationDigest.mediaType !== SOURCE_SLICE_EGRESS_AUTHORIZATION_MEDIA_TYPE
    || parsed.brokerRequestDigest.mediaType !== SOURCE_SLICE_EGRESS_BROKER_REQUEST_MEDIA_TYPE
    || parsed.brokerIdentity.implementationDigest.mediaType
      !== SOURCE_SLICE_EGRESS_BROKER_IMPLEMENTATION_MEDIA_TYPE
  ) {
    throw new TypeError('Source Slice egress receipt digest lineage is invalid')
  }
  const { receiptDigest, ...core } = parsed
  if (
    receiptDigest.mediaType !== SOURCE_SLICE_EGRESS_INVOCATION_RECEIPT_MEDIA_TYPE
    || !sameValue(
      receiptDigest,
      structuredDigest(SOURCE_SLICE_EGRESS_INVOCATION_RECEIPT_MEDIA_TYPE, core),
    )
  ) {
    throw new TypeError('Source Slice egress receipt digest is invalid')
  }
  return deepFreeze({ ...core, receiptDigest })
}

class AttemptScopedSourceSliceEgressCapability implements AttemptScopedSourceSliceEgressCapabilityV1 {
  readonly #request: SourceSliceEgressBrokerRequestV1
  readonly #broker: SourceSliceEgressBrokerAdapterV1
  readonly #now: () => string
  #activeController: AbortController | null = null
  #consumed = false
  #settled = false

  constructor(
    request: SourceSliceEgressBrokerRequestV1,
    broker: SourceSliceEgressBrokerAdapterV1,
    now: () => string,
  ) {
    this.#request = request
    this.#broker = broker
    this.#now = now
  }

  settle(): void {
    this.#settled = true
    this.#activeController?.abort()
  }

  async invoke(options: { readonly signal?: AbortSignal } = {}): Promise<SourceSliceEgressInvocationResultV1> {
    if (this.#settled) {
      throw new SourceSliceEgressCapabilityError(
        'CAPABILITY_SETTLED',
        'Source Slice egress capability is settled',
      )
    }
    if (this.#consumed) {
      throw new SourceSliceEgressCapabilityError(
        'CAPABILITY_CONSUMED',
        'Source Slice egress capability was already consumed',
      )
    }
    this.#consumed = true
    const startedAt = z.iso.datetime({ offset: true }).parse(this.#now())
    const request = this.#request
    if (parseInstant(startedAt) < parseInstant(request.issuedAt)) {
      throw new TypeError('Source Slice egress Host clock moved before capability issuance')
    }
    if (parseInstant(startedAt) >= parseInstant(request.deadlineAt)) {
      const failedReceipt = receipt({
        ...receiptBase(request, startedAt, startedAt),
        status: 'FAILED',
        failureCode: 'ATTEMPT_DEADLINE_EXCEEDED',
        providerRequestId: null,
        backendId: null,
        deploymentId: null,
        modelId: null,
        responseDigest: null,
        finishReason: null,
        usage: null,
        diagnosticCodes: ['ATTEMPT_DEADLINE_EXCEEDED'],
      })
      return deepFreeze({ status: 'FAILED', response: null, receipt: failedReceipt })
    }

    const controller = new AbortController()
    this.#activeController = controller
    const abort = () => controller.abort()
    if (options.signal?.aborted === true) abort()
    else options.signal?.addEventListener('abort', abort, { once: true })
    const remainingMilliseconds = Math.max(1, parseInstant(request.deadlineAt) - parseInstant(startedAt))
    const timer = setTimeout(abort, remainingMilliseconds)
    const abortRace = new Promise<never>((_resolve, reject) => {
      controller.signal.addEventListener(
        'abort',
        () => reject(new Error('Source Slice egress invocation was interrupted')),
        { once: true },
      )
    })
    let rawResponse: unknown
    try {
      if (controller.signal.aborted) {
        const completedAt = z.iso.datetime({ offset: true }).parse(this.#now())
        return failedResult(request, startedAt, completedAt, 'INVOCATION_ABORTED')
      }
      rawResponse = await Promise.race([
        this.#broker.invoke(request, {
          signal: controller.signal,
          deadlineAt: request.deadlineAt,
        }),
        abortRace,
      ])
    } catch {
      const completedAt = z.iso.datetime({ offset: true }).parse(this.#now())
      return failedResult(
        request,
        startedAt,
        completedAt,
        this.#settled
          ? 'ATTEMPT_SETTLED'
          : controller.signal.aborted
            ? (options.signal?.aborted === true ? 'INVOCATION_ABORTED' : 'ATTEMPT_DEADLINE_EXCEEDED')
          : 'BROKER_FAILED',
      )
    } finally {
      clearTimeout(timer)
      options.signal?.removeEventListener('abort', abort)
      if (this.#activeController === controller) this.#activeController = null
    }
    const completedAt = z.iso.datetime({ offset: true }).parse(this.#now())
    const parsedResponse = brokerResponseV1Schema.safeParse(rawResponse)
    if (!parsedResponse.success) {
      return failedResult(request, startedAt, completedAt, 'BROKER_RESPONSE_INVALID')
    }
    const response = parsedResponse.data
    if (
      !sameValue(response.brokerIdentity, request.brokerIdentity)
      || response.providerId !== request.providerId
      || response.destinationId !== request.destinationId
    ) {
      return failedResult(request, startedAt, completedAt, 'BROKER_RESPONSE_SCOPE_MISMATCH')
    }
    if (
      response.usage.requestBytes !== request.content.byteLength
      || response.usage.requestCount !== 1
      || response.usage.inputTokens + response.usage.outputTokens > request.limits.tokenLimit
    ) {
      return failedResult(request, startedAt, completedAt, 'BROKER_USAGE_EXCEEDED')
    }
    if (parseInstant(completedAt) >= parseInstant(request.deadlineAt)) {
      return failedResult(request, startedAt, completedAt, 'ATTEMPT_DEADLINE_EXCEEDED')
    }
    const responseDigest = binaryDigest(
      response.response.mediaType,
      Buffer.from(response.response.text, 'utf8'),
    )
    const completedReceipt = receipt({
      ...receiptBase(request, startedAt, completedAt),
      status: 'COMPLETED',
      failureCode: null,
      providerRequestId: response.providerRequestId,
      backendId: response.backendId,
      deploymentId: response.deploymentId,
      modelId: response.modelId,
      responseDigest,
      finishReason: response.finishReason,
      usage: response.usage,
      diagnosticCodes: response.diagnostics,
    })
    return deepFreeze({
      status: 'COMPLETED',
      response: {
        mediaType: response.response.mediaType,
        text: response.response.text,
        digest: responseDigest,
      },
      receipt: completedReceipt,
    })
  }
}

function receiptBase(
  request: SourceSliceEgressBrokerRequestV1,
  startedAt: string,
  completedAt: string,
): Omit<SourceSliceEgressInvocationReceiptCoreV1,
  | 'status'
  | 'failureCode'
  | 'providerRequestId'
  | 'backendId'
  | 'deploymentId'
  | 'modelId'
  | 'responseDigest'
  | 'finishReason'
  | 'usage'
  | 'diagnosticCodes'> {
  return {
    schemaVersion: 1,
    invocationId: request.invocationId,
    attemptId: request.attemptId,
    attemptGeneration: request.attemptGeneration,
    attemptFenceDigest: request.attemptFenceDigest,
    egressAuthorizationDigest: request.egressAuthorizationDigest,
    brokerRequestDigest: request.brokerRequestDigest,
    brokerIdentity: request.brokerIdentity,
    providerId: request.providerId,
    destinationId: request.destinationId,
    dataEgressPolicyId: request.dataEgressPolicyId,
    auditPolicyId: request.auditPolicyId,
    requestBytes: request.content.byteLength,
    tokenLimit: request.limits.tokenLimit,
    startedAt,
    completedAt,
  }
}

function failedResult(
  request: SourceSliceEgressBrokerRequestV1,
  startedAt: string,
  completedAt: string,
  failureCode: SourceSliceEgressInvocationFailureCodeV1,
): SourceSliceEgressInvocationResultV1 {
  const failedReceipt = receipt({
    ...receiptBase(request, startedAt, completedAt),
    status: 'FAILED',
    failureCode,
    providerRequestId: null,
    backendId: null,
    deploymentId: null,
    modelId: null,
    responseDigest: null,
    finishReason: null,
    usage: null,
    diagnosticCodes: [failureCode],
  })
  return deepFreeze({ status: 'FAILED', response: null, receipt: failedReceipt })
}

/** Issue one non-serializable, one-use Broker capability for an exact admitted Source Slice. */
export function issueAttemptScopedSourceSliceEgressCapability(
  options: IssueAttemptScopedSourceSliceEgressCapabilityOptionsV1,
): IssuedSourceSliceEgressCapabilityV1 {
  const contextGrant = parseRoleContextGrantV1(options.contextGrant)
  const request = parseSourceSliceRequestV1(options.request)
  const attempt = attemptV1Schema.parse(options.attempt)
  const invocationId = boundedIdSchema.parse(options.invocationId)
  const issuedAt = z.iso.datetime({ offset: true }).parse((options.now ?? (() => new Date().toISOString()))())
  if (attempt.attemptId !== contextGrant.roleAttemptId || request.roleAttemptId !== attempt.attemptId) {
    throw new TypeError('Source Slice egress capability does not bind the exact Role Attempt')
  }
  if (parseInstant(attempt.deadlineAt) <= parseInstant(issuedAt)) {
    throw new TypeError('Source Slice egress capability requires a live Attempt deadline')
  }
  const authorization = admitProtectedSourceSliceEgressAuthorization({
    contextGrant,
    request,
    material: options.material,
    redaction: options.redaction,
    secretReview: options.secretReview,
    brokerQualification: options.brokerQualification,
    destinationAuthorization: options.destinationAuthorization,
    evaluatedAt: issuedAt,
  })
  if (
    !sameValue(options.broker.identity, authorization.brokerIdentity)
    || options.broker.identity.implementationDigest.mediaType
      !== SOURCE_SLICE_EGRESS_BROKER_IMPLEMENTATION_MEDIA_TYPE
  ) {
    throw new TypeError('Source Slice egress capability Broker identity is not qualified')
  }
  const deadlineAt = new Date(Math.min(
    parseInstant(attempt.deadlineAt),
    parseInstant(options.brokerQualification.expiresAt),
    parseInstant(options.destinationAuthorization.expiresAt),
    parseInstant(issuedAt) + authorization.timeoutMilliseconds,
  )).toISOString()
  if (parseInstant(deadlineAt) <= parseInstant(issuedAt)) {
    throw new TypeError('Source Slice egress capability deadline is already expired')
  }
  const attemptFenceDigest = structuredDigest(SOURCE_SLICE_EGRESS_ATTEMPT_FENCE_MEDIA_TYPE, {
    attemptId: attempt.attemptId,
    generation: attempt.generation,
    fencingToken: attempt.fencingToken,
  })
  const requestCore: SourceSliceEgressBrokerRequestCoreV1 = {
    schemaVersion: 1,
    invocationId,
    attemptId: attempt.attemptId,
    attemptGeneration: attempt.generation,
    attemptFenceDigest,
    egressAuthorizationDigest: authorization.egressAuthorizationDigest,
    brokerIdentity: authorization.brokerIdentity,
    providerId: authorization.providerId,
    destinationId: authorization.destinationId,
    dataEgressPolicyId: authorization.dataEgressPolicyId,
    credentialBindingId: authorization.credentialBindingId,
    categoryId: authorization.categoryId,
    auditPolicyId: authorization.auditPolicyId,
    content: {
      path: options.redaction.path,
      mediaType: options.redaction.redactedDigest.mediaType,
      digest: options.redaction.redactedDigest,
      byteLength: Buffer.byteLength(options.redaction.redactedText, 'utf8'),
      text: options.redaction.redactedText,
    },
    limits: {
      requestByteLimit: authorization.requestByteLimit,
      requestCountLimit: 1,
      tokenLimit: request.budget.tokens,
      timeoutMilliseconds: authorization.timeoutMilliseconds,
    },
    issuedAt,
    deadlineAt,
  }
  const brokerRequest = deepFreeze({
    ...requestCore,
    brokerRequestDigest: structuredDigest(SOURCE_SLICE_EGRESS_BROKER_REQUEST_MEDIA_TYPE, requestCore),
  })
  const capability = new AttemptScopedSourceSliceEgressCapability(
    brokerRequest,
    options.broker,
    options.now ?? (() => new Date().toISOString()),
  )
  Object.freeze(capability)
  return Object.freeze({
    capability,
    settle: () => capability.settle(),
  })
}
