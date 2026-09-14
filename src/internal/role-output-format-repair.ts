import { z } from 'zod'
import type { DigestEnvelopeV1 } from '../contracts.ts'
import {
  assessmentIdSchema,
  digestEnvelopeV1Schema,
  securityRoleIdV1Schema,
} from '../contracts.ts'
import type { RoleContextGrantV1 } from '../role-context-grant.ts'
import { parseRoleContextGrantV1, ROLE_CONTEXT_GRANT_MEDIA_TYPE } from '../role-context-grant.ts'
import { binaryDigest, canonicalJson, structuredDigest } from './canonical.ts'
import { deepFreeze } from './freeze.ts'
import type { ModelInvocationRecordV1 } from './model-invocation-settlement.ts'
import {
  MODEL_INVOCATION_PROMPT_MEDIA_TYPE,
  MODEL_INVOCATION_FORMAT_REPAIR_REQUEST_MEDIA_TYPE,
  MODEL_INVOCATION_RECORD_MEDIA_TYPE,
  MODEL_INVOCATION_TOOL_SCHEMA_MEDIA_TYPE,
  modelInvocationRecordV1Schema,
  parseModelInvocationRecordV1,
} from './model-invocation-settlement.ts'
import type { RoleContributionV1 } from './role-contribution.ts'
import {
  createRoleContributionFromPayloadV1,
  parseRoleContributionPayloadV1,
  ROLE_CONTRIBUTION_MEDIA_TYPE,
  ROLE_CONTRIBUTION_PAYLOAD_MEDIA_TYPE,
} from './role-contribution.ts'
import { SOURCE_SLICE_EGRESS_ATTEMPT_FENCE_MEDIA_TYPE } from './source-slice-egress-invocation.ts'

export const ROLE_OUTPUT_FORMAT_REPAIR_PLAN_MEDIA_TYPE =
  'application/vnd.dsh.security.role-output-format-repair-plan+json'
export const ROLE_OUTPUT_FORMAT_REPAIR_RECORD_MEDIA_TYPE =
  'application/vnd.dsh.security.role-output-format-repair-record+json'
export const ROLE_OUTPUT_FORMAT_REPAIR_INSTRUCTION_MEDIA_TYPE =
  'application/vnd.dsh.security.role-output-format-repair-instruction+json'
export const ROLE_OUTPUT_SEMANTIC_TOKEN_SEQUENCE_MEDIA_TYPE =
  'application/vnd.dsh.security.role-output-semantic-token-sequence+json'

const MAX_RESPONSE_BYTES = 1024 * 1024
const boundedIdSchema = z.string().regex(/^[a-z0-9][a-z0-9._/-]{0,127}$/iu)
const planIdSchema = z.string().regex(
  /^format-repair-plan-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u,
)
const contributionIdSchema = z.string().regex(
  /^role-contribution-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u,
)
const roleAttemptIdSchema = z.string().regex(
  /^role-attempt-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u,
)
const semanticVersionSchema = z.string()
  .max(128)
  .regex(/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/u)

const formatRepairTargetSchema = deepFreeze({
  schemaId: 'dsh/security/role-contribution-payload/v1',
  mediaType: ROLE_CONTRIBUTION_PAYLOAD_MEDIA_TYPE,
  schemaDigest: structuredDigest(MODEL_INVOCATION_TOOL_SCHEMA_MEDIA_TYPE, {
    schemaId: 'dsh/security/role-contribution-payload/v1',
    schemaVersion: 1,
    authorityFields: 'FORBIDDEN',
    unknownFields: 'REJECTED',
  }),
})

const formatRepairSyntaxInstruction = deepFreeze({
  instructionId: 'dsh/security/syntax-only-role-output-format-repair',
  instructionVersion: '1.0.0',
  instructionDigest: structuredDigest(ROLE_OUTPUT_FORMAT_REPAIR_INSTRUCTION_MEDIA_TYPE, {
    instructionId: 'dsh/security/syntax-only-role-output-format-repair',
    instructionVersion: '1.0.0',
    allowedInputs: ['original-response', 'target-schema', 'syntax-only-instructions'],
    allowedChanges: ['json-structure', 'json-whitespace', 'json-scalar-lexical-normalization'],
    forbiddenChanges: ['semantic-scalar-addition', 'semantic-scalar-removal', 'semantic-scalar-reorder'],
  }),
})

const formatRepairPrompt = deepFreeze({
  promptId: 'dsh/security/role-output-format-repair',
  promptVersion: '1.0.0',
  promptDigest: structuredDigest(MODEL_INVOCATION_PROMPT_MEDIA_TYPE, {
    promptId: 'dsh/security/role-output-format-repair',
    promptVersion: '1.0.0',
    targetSchemaDigest: formatRepairTargetSchema.schemaDigest,
    instructionDigest: formatRepairSyntaxInstruction.instructionDigest,
  }),
  toolSchemaDigest: formatRepairTargetSchema.schemaDigest,
})

const attemptFenceDigestSchema = digestEnvelopeV1Schema.refine(
  digest => digest.mediaType === SOURCE_SLICE_EGRESS_ATTEMPT_FENCE_MEDIA_TYPE,
  'Format Repair plans must bind an Attempt fence digest',
)
const contextGrantDigestSchema = digestEnvelopeV1Schema.refine(
  digest => digest.mediaType === ROLE_CONTEXT_GRANT_MEDIA_TYPE,
  'Format Repair plans must bind a Context Grant digest',
)
const modelInvocationRecordDigestSchema = digestEnvelopeV1Schema.refine(
  digest => digest.mediaType === MODEL_INVOCATION_RECORD_MEDIA_TYPE,
  'Format Repair records must bind a Model Invocation Record digest',
)
const rawResponseDigestSchema = digestEnvelopeV1Schema.refine(
  digest => (
    digest.mediaType === ROLE_CONTRIBUTION_PAYLOAD_MEDIA_TYPE
    && digest.canonicalization === 'raw-bytes'
  ),
  'Format Repair records must bind exact Role Contribution payload bytes',
)

export interface RoleOutputFormatRepairPlanCoreV1 {
  readonly schemaVersion: 1
  readonly planId: string
  readonly contributionId: string
  readonly assessmentId: RoleContextGrantV1['assessmentId']
  readonly subjectDigest: DigestEnvelopeV1
  readonly parentAttempt: {
    readonly attemptId: string
    readonly generation: number
    readonly fenceDigest: DigestEnvelopeV1
  }
  readonly contextGrantDigest: DigestEnvelopeV1
  readonly roleDefinition: RoleContextGrantV1['roleDefinition']
  readonly originalInvocationId: string
  readonly repairInvocation: {
    readonly invocationId: string
    readonly provider: {
      readonly providerId: string
      readonly modelId: string
      readonly movingProvider: boolean
    }
    readonly prompt: typeof formatRepairPrompt
    readonly parameters: {
      readonly maxOutputTokens: number
      readonly temperature: 0
      readonly topP: null
      readonly randomnessStrategyId: 'deterministic-format-repair-v1'
    }
    readonly budget: {
      readonly requestLimit: 1
      readonly tokenLimit: number
    }
  }
  readonly targetSchema: typeof formatRepairTargetSchema
  readonly syntaxInstruction: typeof formatRepairSyntaxInstruction
  readonly declaredAt: string
}

export interface RoleOutputFormatRepairPlanV1 extends RoleOutputFormatRepairPlanCoreV1 {
  readonly planDigest: DigestEnvelopeV1
}

const targetSchemaV1Schema = z.strictObject({
  schemaId: z.literal(formatRepairTargetSchema.schemaId),
  mediaType: z.literal(ROLE_CONTRIBUTION_PAYLOAD_MEDIA_TYPE),
  schemaDigest: digestEnvelopeV1Schema.refine(digest => (
    canonicalJson(digest) === canonicalJson(formatRepairTargetSchema.schemaDigest)
  ), 'Format Repair target schema digest is not the package-owned v1 schema'),
})

const syntaxInstructionV1Schema = z.strictObject({
  instructionId: z.literal(formatRepairSyntaxInstruction.instructionId),
  instructionVersion: z.literal(formatRepairSyntaxInstruction.instructionVersion),
  instructionDigest: digestEnvelopeV1Schema.refine(digest => (
    canonicalJson(digest) === canonicalJson(formatRepairSyntaxInstruction.instructionDigest)
  ), 'Format Repair instruction digest is not the package-owned syntax-only instruction'),
})

const promptV1Schema = z.strictObject({
  promptId: z.literal(formatRepairPrompt.promptId),
  promptVersion: z.literal(formatRepairPrompt.promptVersion),
  promptDigest: digestEnvelopeV1Schema.refine(digest => (
    canonicalJson(digest) === canonicalJson(formatRepairPrompt.promptDigest)
  )),
  toolSchemaDigest: digestEnvelopeV1Schema.refine(digest => (
    canonicalJson(digest) === canonicalJson(formatRepairPrompt.toolSchemaDigest)
  )),
})

const roleOutputFormatRepairPlanCoreShape = {
  schemaVersion: z.literal(1),
  planId: planIdSchema,
  contributionId: contributionIdSchema,
  assessmentId: assessmentIdSchema,
  subjectDigest: digestEnvelopeV1Schema,
  parentAttempt: z.strictObject({
    attemptId: roleAttemptIdSchema,
    generation: z.number().int().positive().max(Number.MAX_SAFE_INTEGER),
    fenceDigest: attemptFenceDigestSchema,
  }),
  contextGrantDigest: contextGrantDigestSchema,
  roleDefinition: z.strictObject({
    roleId: securityRoleIdV1Schema,
    roleVersion: semanticVersionSchema,
    definitionDigest: digestEnvelopeV1Schema,
  }),
  originalInvocationId: boundedIdSchema,
  repairInvocation: z.strictObject({
    invocationId: boundedIdSchema,
    provider: z.strictObject({
      providerId: boundedIdSchema,
      modelId: boundedIdSchema,
      movingProvider: z.boolean(),
    }),
    prompt: promptV1Schema,
    parameters: z.strictObject({
      maxOutputTokens: z.number().int().positive().max(4_000_000),
      temperature: z.literal(0),
      topP: z.null(),
      randomnessStrategyId: z.literal('deterministic-format-repair-v1'),
    }),
    budget: z.strictObject({
      requestLimit: z.literal(1),
      tokenLimit: z.number().int().positive().max(4_000_000),
    }),
  }),
  targetSchema: targetSchemaV1Schema,
  syntaxInstruction: syntaxInstructionV1Schema,
  declaredAt: z.iso.datetime({ offset: true }),
} as const

const roleOutputFormatRepairPlanCoreV1Schema: z.ZodType<RoleOutputFormatRepairPlanCoreV1> =
  z.strictObject(roleOutputFormatRepairPlanCoreShape).superRefine((plan, context) => {
    if (
      plan.originalInvocationId === plan.repairInvocation.invocationId
      || plan.repairInvocation.parameters.maxOutputTokens > plan.repairInvocation.budget.tokenLimit
    ) {
      context.addIssue({
        code: 'custom',
        path: ['repairInvocation'],
        message: 'Format Repair requires one distinct invocation within its declared budget',
      })
    }
  })

const roleOutputFormatRepairPlanV1Schema: z.ZodType<RoleOutputFormatRepairPlanV1> =
  z.strictObject({
    ...roleOutputFormatRepairPlanCoreShape,
    planDigest: digestEnvelopeV1Schema,
  })

export interface CreateRoleOutputFormatRepairPlanOptionsV1 {
  readonly planId: string
  readonly contributionId: string
  readonly contextGrant: RoleContextGrantV1
  readonly parentAttempt: RoleOutputFormatRepairPlanCoreV1['parentAttempt']
  readonly originalInvocationId: string
  readonly repairInvocation: {
    readonly invocationId: string
    readonly providerId: string
    readonly modelId: string
    readonly movingProvider: boolean
    readonly maxOutputTokens: number
    readonly tokenLimit: number
  }
  readonly declaredAt: string
}

/** Predeclare the only syntax-repair call. This value grants no Provider or budget authority. */
export function createRoleOutputFormatRepairPlanV1(
  options: CreateRoleOutputFormatRepairPlanOptionsV1,
): RoleOutputFormatRepairPlanV1 {
  const contextGrant = parseRoleContextGrantV1(options.contextGrant)
  const remainingTokens = contextGrant.budget.tokens.limit - contextGrant.budget.tokens.granted
  if (
    options.parentAttempt.attemptId !== contextGrant.roleAttemptId
    || options.repairInvocation.tokenLimit > remainingTokens
  ) {
    throw new TypeError('Format Repair plan exceeds or drifts its Context Grant')
  }
  const core = roleOutputFormatRepairPlanCoreV1Schema.parse({
    schemaVersion: 1,
    planId: options.planId,
    contributionId: options.contributionId,
    assessmentId: contextGrant.assessmentId,
    subjectDigest: contextGrant.subject.digest,
    parentAttempt: options.parentAttempt,
    contextGrantDigest: contextGrant.grantDigest,
    roleDefinition: contextGrant.roleDefinition,
    originalInvocationId: options.originalInvocationId,
    repairInvocation: {
      invocationId: options.repairInvocation.invocationId,
      provider: {
        providerId: options.repairInvocation.providerId,
        modelId: options.repairInvocation.modelId,
        movingProvider: options.repairInvocation.movingProvider,
      },
      prompt: formatRepairPrompt,
      parameters: {
        maxOutputTokens: options.repairInvocation.maxOutputTokens,
        temperature: 0,
        topP: null,
        randomnessStrategyId: 'deterministic-format-repair-v1',
      },
      budget: {
        requestLimit: 1,
        tokenLimit: options.repairInvocation.tokenLimit,
      },
    },
    targetSchema: formatRepairTargetSchema,
    syntaxInstruction: formatRepairSyntaxInstruction,
    declaredAt: options.declaredAt,
  })
  return deepFreeze({
    ...core,
    planDigest: structuredDigest(ROLE_OUTPUT_FORMAT_REPAIR_PLAN_MEDIA_TYPE, core),
  })
}

export function parseRoleOutputFormatRepairPlanV1(candidate: unknown): RoleOutputFormatRepairPlanV1 {
  const plan = roleOutputFormatRepairPlanV1Schema.parse(candidate)
  const { planDigest, ...candidateCore } = plan
  const core = roleOutputFormatRepairPlanCoreV1Schema.parse(candidateCore)
  if (canonicalJson(planDigest) !== canonicalJson(
    structuredDigest(ROLE_OUTPUT_FORMAT_REPAIR_PLAN_MEDIA_TYPE, core),
  )) {
    throw new TypeError('Role Output Format Repair plan digest is invalid')
  }
  return deepFreeze({ ...core, planDigest })
}

export interface RoleOutputFormatRepairRequestCoreV1 {
  readonly schemaVersion: 1
  readonly planDigest: DigestEnvelopeV1
  readonly originalInvocation: {
    readonly invocationId: string
    readonly recordDigest: DigestEnvelopeV1
    readonly responseDigest: DigestEnvelopeV1
  }
  readonly content: {
    readonly originalResponse: string
    readonly targetSchema: typeof formatRepairTargetSchema
    readonly syntaxInstruction: typeof formatRepairSyntaxInstruction
  }
}

export interface RoleOutputFormatRepairRequestV1 extends RoleOutputFormatRepairRequestCoreV1 {
  readonly requestDigest: DigestEnvelopeV1
}

const roleOutputFormatRepairRequestCoreShape = {
  schemaVersion: z.literal(1),
  planDigest: digestEnvelopeV1Schema.refine(
    digest => digest.mediaType === ROLE_OUTPUT_FORMAT_REPAIR_PLAN_MEDIA_TYPE,
  ),
  originalInvocation: z.strictObject({
    invocationId: boundedIdSchema,
    recordDigest: modelInvocationRecordDigestSchema,
    responseDigest: rawResponseDigestSchema,
  }),
  content: z.strictObject({
    originalResponse: z.string().max(MAX_RESPONSE_BYTES),
    targetSchema: targetSchemaV1Schema,
    syntaxInstruction: syntaxInstructionV1Schema,
  }),
} as const

const roleOutputFormatRepairRequestCoreV1Schema:
z.ZodType<RoleOutputFormatRepairRequestCoreV1> = z.strictObject(
  roleOutputFormatRepairRequestCoreShape,
).superRefine((request, context) => {
  const bytes = Buffer.from(request.content.originalResponse, 'utf8')
  let originalPayloadIsValid = false
  try {
    parseRoleContributionPayloadV1(JSON.parse(request.content.originalResponse) as unknown)
    originalPayloadIsValid = true
  } catch {
    // Only an invalid original payload is eligible for the one repair.
  }
  if (
    bytes.byteLength > MAX_RESPONSE_BYTES
    || !sameValue(
      request.originalInvocation.responseDigest,
      binaryDigest(ROLE_CONTRIBUTION_PAYLOAD_MEDIA_TYPE, bytes),
    )
    || originalPayloadIsValid
  ) {
    context.addIssue({
      code: 'custom',
      path: ['content', 'originalResponse'],
      message: 'Format Repair request requires one exact invalid original payload',
    })
  }
  try {
    tokenizeJsonScalars(request.content.originalResponse)
  } catch {
    context.addIssue({
      code: 'custom',
      path: ['content', 'originalResponse'],
      message: 'Format Repair request original contains non-JSON tokens',
    })
  }
})

const roleOutputFormatRepairRequestV1Schema: z.ZodType<RoleOutputFormatRepairRequestV1> =
  z.strictObject({
    ...roleOutputFormatRepairRequestCoreShape,
    requestDigest: digestEnvelopeV1Schema,
  })

interface SemanticTokenV1 {
  readonly kind: 'string' | 'number' | 'boolean' | 'null'
  readonly value: string
}

function readJsonStringToken(
  text: string,
  start: number,
): { readonly token: string; readonly nextIndex: number } {
  let index = start + 1
  while (index < text.length) {
    const character = text[index]!
    if (character === '"') {
      return { token: text.slice(start, index + 1), nextIndex: index + 1 }
    }
    if (character.charCodeAt(0) <= 0x1f) {
      break
    }
    if (character !== '\\') {
      index += 1
      continue
    }
    const escape = text[index + 1]
    if (escape === undefined) {
      break
    }
    if ('"\\/bfnrt'.includes(escape)) {
      index += 2
      continue
    }
    const unicodeEscape = text.slice(index + 1, index + 6)
    if (/^u[0-9a-fA-F]{4}$/u.test(unicodeEscape)) {
      index += 6
      continue
    }
    break
  }
  throw new TypeError('Role output contains an invalid JSON string token')
}

function tokenizeJsonScalars(text: string): readonly SemanticTokenV1[] {
  const tokens: SemanticTokenV1[] = []
  let index = 0
  while (index < text.length) {
    const rest = text.slice(index)
    if ([0x09, 0x0a, 0x0d, 0x20].includes(text.charCodeAt(index))) {
      index += 1
      continue
    }
    if ('{}[],:'.includes(text[index]!)) {
      index += 1
      continue
    }
    if (text[index] === '"') {
      const stringToken = readJsonStringToken(text, index)
      tokens.push({ kind: 'string', value: JSON.parse(stringToken.token) as string })
      index = stringToken.nextIndex
      continue
    }
    const numberToken = /^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/u.exec(rest)
    if (numberToken) {
      tokens.push({ kind: 'number', value: canonicalJson(JSON.parse(numberToken[0])) })
      index += numberToken[0].length
      continue
    }
    const literalToken = /^(?:true|false|null)/u.exec(rest)
    if (literalToken) {
      const value: unknown = JSON.parse(literalToken[0])
      tokens.push({
        kind: value === null ? 'null' : 'boolean',
        value: canonicalJson(value),
      })
      index += literalToken[0].length
      continue
    }
    throw new TypeError('Role output contains a non-JSON token that cannot be syntax-only repaired')
  }
  return deepFreeze(tokens)
}

function skipJsonWhitespace(text: string, start: number): number {
  let index = start
  while (
    index < text.length
    && [0x09, 0x0a, 0x0d, 0x20].includes(text.charCodeAt(index))
  ) {
    index += 1
  }
  return index
}

function parseStrictJsonValue(text: string, start: number): number {
  let index = skipJsonWhitespace(text, start)
  const character = text[index]
  if (character === '"') {
    return readJsonStringToken(text, index).nextIndex
  }
  if (character === '{') {
    const keys = new Set<string>()
    index = skipJsonWhitespace(text, index + 1)
    if (text[index] === '}') return index + 1
    while (index < text.length) {
      if (text[index] !== '"') {
        throw new TypeError('Role output JSON object keys must be strings')
      }
      const keyToken = readJsonStringToken(text, index)
      const key = JSON.parse(keyToken.token) as string
      if (keys.has(key)) {
        throw new TypeError('Role output JSON contains duplicate object keys')
      }
      keys.add(key)
      index = skipJsonWhitespace(text, keyToken.nextIndex)
      if (text[index] !== ':') {
        throw new TypeError('Role output JSON object key lacks a value separator')
      }
      index = skipJsonWhitespace(text, parseStrictJsonValue(text, index + 1))
      if (text[index] === '}') return index + 1
      if (text[index] !== ',') {
        throw new TypeError('Role output JSON object lacks an entry separator')
      }
      index = skipJsonWhitespace(text, index + 1)
    }
  }
  if (character === '[') {
    index = skipJsonWhitespace(text, index + 1)
    if (text[index] === ']') return index + 1
    while (index < text.length) {
      index = skipJsonWhitespace(text, parseStrictJsonValue(text, index))
      if (text[index] === ']') return index + 1
      if (text[index] !== ',') {
        throw new TypeError('Role output JSON array lacks an entry separator')
      }
      index = skipJsonWhitespace(text, index + 1)
    }
  }
  const rest = text.slice(index)
  const numberToken = /^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/u.exec(rest)
  if (numberToken) return index + numberToken[0].length
  const literalToken = /^(?:true|false|null)/u.exec(rest)
  if (literalToken) return index + literalToken[0].length
  throw new TypeError('Role output is not one strict JSON value')
}

function assertStrictJsonDocument(text: string): void {
  const nextIndex = skipJsonWhitespace(text, parseStrictJsonValue(text, 0))
  if (nextIndex !== text.length) {
    throw new TypeError('Role output contains bytes after its strict JSON value')
  }
}

function decodeResponse(bytes: Uint8Array): string {
  if (bytes.byteLength > MAX_RESPONSE_BYTES) {
    throw new TypeError('Role output exceeds the Format Repair byte budget')
  }
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes)
  } catch {
    throw new TypeError('Role output is not valid UTF-8')
  }
}

function parseInvocationRecord(candidate: unknown): ModelInvocationRecordV1 {
  const parsed = modelInvocationRecordV1Schema.parse(candidate)
  return parseModelInvocationRecordV1(parsed, {
    invocationId: parsed.invocationId,
    attemptId: parsed.parentAttempt.attemptId,
    attemptGeneration: parsed.parentAttempt.generation,
    attemptFenceDigest: parsed.parentAttempt.fenceDigest,
    contextGrantDigest: parsed.contextGrantDigest,
    reservationDigest: parsed.budgetSettlement.reservationDigest,
    receiptDigest: parsed.receiptDigest,
  })
}

function sameValue(left: unknown, right: unknown): boolean {
  return canonicalJson(left) === canonicalJson(right)
}

function assertResponseDigest(record: ModelInvocationRecordV1, bytes: Uint8Array): void {
  if (
    record.responseDigest.mediaType !== ROLE_CONTRIBUTION_PAYLOAD_MEDIA_TYPE
    || !sameValue(record.responseDigest, binaryDigest(ROLE_CONTRIBUTION_PAYLOAD_MEDIA_TYPE, bytes))
  ) {
    throw new TypeError('Format Repair response bytes do not match protected invocation lineage')
  }
}

export interface CreateRoleOutputFormatRepairRequestOptionsV1 {
  readonly plan: RoleOutputFormatRepairPlanV1
  readonly originalInvocationRecord: ModelInvocationRecordV1
  readonly originalResponse: Uint8Array
}

/** Build the exact three-input content allowed to cross the repair Provider boundary. */
export function createRoleOutputFormatRepairRequestV1(
  options: CreateRoleOutputFormatRepairRequestOptionsV1,
): RoleOutputFormatRepairRequestV1 {
  const plan = parseRoleOutputFormatRepairPlanV1(options.plan)
  const originalRecord = parseInvocationRecord(options.originalInvocationRecord)
  if (
    originalRecord.invocationId !== plan.originalInvocationId
    || originalRecord.assessmentId !== plan.assessmentId
    || !sameValue(originalRecord.parentAttempt, plan.parentAttempt)
    || !sameValue(originalRecord.contextGrantDigest, plan.contextGrantDigest)
    || !sameValue(originalRecord.roleDefinition, plan.roleDefinition)
    || Date.parse(originalRecord.timing.startedAt) < Date.parse(plan.declaredAt)
    || !['STOP', 'LENGTH'].includes(originalRecord.finishReason)
  ) {
    throw new TypeError('Format Repair request drifts its original invocation lineage')
  }
  assertResponseDigest(originalRecord, options.originalResponse)
  const originalResponse = decodeResponse(options.originalResponse)
  if (!Buffer.from(originalResponse, 'utf8').equals(Buffer.from(options.originalResponse))) {
    throw new TypeError('Format Repair requires an exact round-trippable UTF-8 response')
  }
  let originalPayloadIsValid = false
  try {
    parseRoleContributionPayloadV1(JSON.parse(originalResponse) as unknown)
    originalPayloadIsValid = true
  } catch {
    // Only an invalid original payload is eligible for the one repair.
  }
  if (originalPayloadIsValid) {
    throw new TypeError('A valid Role Contribution payload must not consume Format Repair')
  }
  tokenizeJsonScalars(originalResponse)
  const core = roleOutputFormatRepairRequestCoreV1Schema.parse({
    schemaVersion: 1,
    planDigest: plan.planDigest,
    originalInvocation: {
      invocationId: originalRecord.invocationId,
      recordDigest: originalRecord.recordDigest,
      responseDigest: originalRecord.responseDigest,
    },
    content: {
      originalResponse,
      targetSchema: plan.targetSchema,
      syntaxInstruction: plan.syntaxInstruction,
    },
  })
  return deepFreeze({
    ...core,
    requestDigest: structuredDigest(MODEL_INVOCATION_FORMAT_REPAIR_REQUEST_MEDIA_TYPE, core),
  })
}

export function parseRoleOutputFormatRepairRequestV1(
  candidate: unknown,
): RoleOutputFormatRepairRequestV1 {
  const request = roleOutputFormatRepairRequestV1Schema.parse(candidate)
  const { requestDigest, ...candidateCore } = request
  const core = roleOutputFormatRepairRequestCoreV1Schema.parse(candidateCore)
  if (canonicalJson(requestDigest) !== canonicalJson(
    structuredDigest(MODEL_INVOCATION_FORMAT_REPAIR_REQUEST_MEDIA_TYPE, core),
  )) {
    throw new TypeError('Role Output Format Repair request digest is invalid')
  }
  return deepFreeze({ ...core, requestDigest })
}

export interface RoleOutputFormatRepairRecordCoreV1 {
  readonly schemaVersion: 1
  readonly assessmentId: RoleContextGrantV1['assessmentId']
  readonly contributionId: string
  readonly parentAttempt: RoleOutputFormatRepairPlanCoreV1['parentAttempt']
  readonly contextGrantDigest: DigestEnvelopeV1
  readonly planDigest: DigestEnvelopeV1
  readonly originalInvocation: {
    readonly invocationId: string
    readonly recordDigest: DigestEnvelopeV1
    readonly responseDigest: DigestEnvelopeV1
  }
  readonly repairInvocation: {
    readonly invocationId: string
    readonly recordDigest: DigestEnvelopeV1
    readonly responseDigest: DigestEnvelopeV1
    readonly inputTokens: number
    readonly outputTokens: number
    readonly tokens: number
  }
  readonly semanticTokenSequenceDigest: DigestEnvelopeV1
  readonly contributionDigest: DigestEnvelopeV1
  readonly completedAt: string
}

export interface RoleOutputFormatRepairRecordV1 extends RoleOutputFormatRepairRecordCoreV1 {
  readonly recordDigest: DigestEnvelopeV1
}

const repairRecordInvocationShape = {
  invocationId: boundedIdSchema,
  recordDigest: modelInvocationRecordDigestSchema,
  responseDigest: rawResponseDigestSchema,
} as const

const roleOutputFormatRepairRecordCoreShape = {
  schemaVersion: z.literal(1),
  assessmentId: roleOutputFormatRepairPlanCoreShape.assessmentId,
  contributionId: contributionIdSchema,
  parentAttempt: roleOutputFormatRepairPlanCoreShape.parentAttempt,
  contextGrantDigest: contextGrantDigestSchema,
  planDigest: digestEnvelopeV1Schema.refine(
    digest => digest.mediaType === ROLE_OUTPUT_FORMAT_REPAIR_PLAN_MEDIA_TYPE,
  ),
  originalInvocation: z.strictObject(repairRecordInvocationShape),
  repairInvocation: z.strictObject({
    ...repairRecordInvocationShape,
    inputTokens: z.number().int().nonnegative().max(4_000_000),
    outputTokens: z.number().int().nonnegative().max(4_000_000),
    tokens: z.number().int().nonnegative().max(4_000_000),
  }),
  semanticTokenSequenceDigest: digestEnvelopeV1Schema.refine(
    digest => digest.mediaType === ROLE_OUTPUT_SEMANTIC_TOKEN_SEQUENCE_MEDIA_TYPE,
  ),
  contributionDigest: digestEnvelopeV1Schema.refine(
    digest => digest.mediaType === ROLE_CONTRIBUTION_MEDIA_TYPE,
  ),
  completedAt: z.iso.datetime({ offset: true }),
} as const

const roleOutputFormatRepairRecordCoreV1Schema: z.ZodType<RoleOutputFormatRepairRecordCoreV1> =
  z.strictObject(roleOutputFormatRepairRecordCoreShape).superRefine((record, context) => {
    if (
      record.originalInvocation.invocationId === record.repairInvocation.invocationId
      || record.repairInvocation.tokens
        !== record.repairInvocation.inputTokens + record.repairInvocation.outputTokens
    ) {
      context.addIssue({
        code: 'custom',
        path: ['repairInvocation'],
        message: 'Format Repair record invocation lineage or usage is invalid',
      })
    }
  })

const roleOutputFormatRepairRecordV1Schema: z.ZodType<RoleOutputFormatRepairRecordV1> =
  z.strictObject({
    ...roleOutputFormatRepairRecordCoreShape,
    recordDigest: digestEnvelopeV1Schema,
  })

export interface AdmitRoleOutputFormatRepairOptionsV1 {
  readonly plan: RoleOutputFormatRepairPlanV1
  readonly contextGrant: RoleContextGrantV1
  readonly originalInvocationRecord: ModelInvocationRecordV1
  readonly repairInvocationRecord: ModelInvocationRecordV1
  readonly repairRequest: RoleOutputFormatRepairRequestV1
  readonly repairedResponse: Uint8Array
}

export interface AdmittedRoleOutputFormatRepairV1 {
  readonly contribution: RoleContributionV1
  readonly repairRecord: RoleOutputFormatRepairRecordV1
}

/**
 * Accept one predeclared syntax-only repair when every semantic scalar is
 * traceable to the original response. This function performs no model call and
 * grants no admission, Provider, Store, or retry authority.
 */
export function admitRoleOutputFormatRepairV1(
  options: AdmitRoleOutputFormatRepairOptionsV1,
): AdmittedRoleOutputFormatRepairV1 {
  const plan = parseRoleOutputFormatRepairPlanV1(options.plan)
  const contextGrant = parseRoleContextGrantV1(options.contextGrant)
  const originalRecord = parseInvocationRecord(options.originalInvocationRecord)
  const repairRecord = parseInvocationRecord(options.repairInvocationRecord)
  const request = parseRoleOutputFormatRepairRequestV1(options.repairRequest)
  if (
    plan.assessmentId !== contextGrant.assessmentId
    || plan.parentAttempt.attemptId !== contextGrant.roleAttemptId
    || !sameValue(plan.contextGrantDigest, contextGrant.grantDigest)
    || !sameValue(plan.subjectDigest, contextGrant.subject.digest)
    || !sameValue(plan.roleDefinition, contextGrant.roleDefinition)
  ) {
    throw new TypeError('Format Repair plan does not bind its exact Context Grant')
  }
  for (const [record, invocationId] of [
    [originalRecord, plan.originalInvocationId],
    [repairRecord, plan.repairInvocation.invocationId],
  ] as const) {
    if (
      record.invocationId !== invocationId
      || record.assessmentId !== plan.assessmentId
      || !sameValue(record.parentAttempt, plan.parentAttempt)
      || !sameValue(record.contextGrantDigest, plan.contextGrantDigest)
      || !sameValue(record.roleDefinition, plan.roleDefinition)
      || record.egress.destinationId !== contextGrant.disclosure.destinationId
      || record.egress.dataEgressPolicyId !== contextGrant.disclosure.dataEgressPolicyId
    ) {
      throw new TypeError('Format Repair invocation drifts its exact Attempt lineage')
    }
  }
  if (
    repairRecord.provider.providerId !== plan.repairInvocation.provider.providerId
    || repairRecord.provider.modelId !== plan.repairInvocation.provider.modelId
    || repairRecord.provider.movingProvider !== plan.repairInvocation.provider.movingProvider
    || !sameValue(repairRecord.prompt, plan.repairInvocation.prompt)
    || !sameValue(repairRecord.parameters, plan.repairInvocation.parameters)
    || !sameValue(repairRecord.egress.requestDigest, request.requestDigest)
    || repairRecord.budgetSettlement.requestLimit !== 1
    || repairRecord.budgetSettlement.tokenLimit !== plan.repairInvocation.budget.tokenLimit
    || repairRecord.finishReason !== 'STOP'
    || !['STOP', 'LENGTH'].includes(originalRecord.finishReason)
    || Date.parse(originalRecord.timing.startedAt) < Date.parse(plan.declaredAt)
    || Date.parse(repairRecord.timing.startedAt) < Date.parse(originalRecord.timing.completedAt)
    || Date.parse(repairRecord.timing.startedAt) < Date.parse(plan.declaredAt)
  ) {
    throw new TypeError('Format Repair invocation exceeds or drifts its predeclared boundary')
  }
  if (
    !sameValue(request.planDigest, plan.planDigest)
    || request.originalInvocation.invocationId !== originalRecord.invocationId
    || !sameValue(request.originalInvocation.recordDigest, originalRecord.recordDigest)
    || !sameValue(request.originalInvocation.responseDigest, originalRecord.responseDigest)
    || !sameValue(request.content.targetSchema, plan.targetSchema)
    || !sameValue(request.content.syntaxInstruction, plan.syntaxInstruction)
  ) {
    throw new TypeError('Format Repair request drifts its predeclared plan or original invocation')
  }
  assertResponseDigest(repairRecord, options.repairedResponse)
  const originalText = request.content.originalResponse
  const repairedText = decodeResponse(options.repairedResponse)
  let repairedPayload: ReturnType<typeof parseRoleContributionPayloadV1>
  try {
    assertStrictJsonDocument(repairedText)
    repairedPayload = parseRoleContributionPayloadV1(JSON.parse(repairedText) as unknown)
  } catch (error) {
    if (error instanceof TypeError && /duplicate object keys/u.test(error.message)) {
      throw error
    }
    throw new TypeError('Repaired Role output still fails strict payload parsing or schema validation')
  }
  const originalTokens = tokenizeJsonScalars(originalText)
  const repairedTokens = tokenizeJsonScalars(repairedText)
  if (!sameValue(originalTokens, repairedTokens)) {
    throw new TypeError('Format Repair changed, added, removed, or reordered semantic scalars')
  }
  const invocationLineage = [originalRecord, repairRecord].map(record => ({
    invocationId: record.invocationId,
    recordDigest: record.recordDigest,
    responseDigest: record.responseDigest,
    inputTokens: record.usage.inputTokens,
    outputTokens: record.usage.outputTokens,
  }))
  const contribution = createRoleContributionFromPayloadV1({
    contributionId: plan.contributionId,
    assessmentId: plan.assessmentId,
    subjectDigest: plan.subjectDigest,
    parentAttempt: plan.parentAttempt,
    contextGrantDigest: plan.contextGrantDigest,
    roleDefinition: plan.roleDefinition,
    modelInvocations: invocationLineage,
    payload: repairedPayload,
  })
  const core = roleOutputFormatRepairRecordCoreV1Schema.parse({
    schemaVersion: 1,
    assessmentId: plan.assessmentId,
    contributionId: plan.contributionId,
    parentAttempt: plan.parentAttempt,
    contextGrantDigest: plan.contextGrantDigest,
    planDigest: plan.planDigest,
    originalInvocation: {
      invocationId: originalRecord.invocationId,
      recordDigest: originalRecord.recordDigest,
      responseDigest: originalRecord.responseDigest,
    },
    repairInvocation: {
      invocationId: repairRecord.invocationId,
      recordDigest: repairRecord.recordDigest,
      responseDigest: repairRecord.responseDigest,
      inputTokens: repairRecord.usage.inputTokens,
      outputTokens: repairRecord.usage.outputTokens,
      tokens: repairRecord.usage.inputTokens + repairRecord.usage.outputTokens,
    },
    semanticTokenSequenceDigest: structuredDigest(
      ROLE_OUTPUT_SEMANTIC_TOKEN_SEQUENCE_MEDIA_TYPE,
      originalTokens,
    ),
    contributionDigest: contribution.contributionDigest,
    completedAt: repairRecord.timing.completedAt,
  })
  return deepFreeze({
    contribution,
    repairRecord: {
      ...core,
      recordDigest: structuredDigest(ROLE_OUTPUT_FORMAT_REPAIR_RECORD_MEDIA_TYPE, core),
    },
  })
}

export function parseRoleOutputFormatRepairRecordV1(
  candidate: unknown,
): RoleOutputFormatRepairRecordV1 {
  const record = roleOutputFormatRepairRecordV1Schema.parse(candidate)
  const { recordDigest, ...candidateCore } = record
  const core = roleOutputFormatRepairRecordCoreV1Schema.parse(candidateCore)
  if (canonicalJson(recordDigest) !== canonicalJson(
    structuredDigest(ROLE_OUTPUT_FORMAT_REPAIR_RECORD_MEDIA_TYPE, core),
  )) {
    throw new TypeError('Role Output Format Repair record digest is invalid')
  }
  return deepFreeze({ ...core, recordDigest })
}
