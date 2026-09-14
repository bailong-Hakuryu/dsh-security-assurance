import { describe, expect, it } from 'vitest'
import { createRoleContextGrantV1 } from '../src/role-context-grant.ts'
import { binaryDigest, structuredDigest } from '../src/internal/canonical.ts'
import {
  SOURCE_SLICE_EGRESS_AUTHORIZATION_MEDIA_TYPE,
  SOURCE_SLICE_EGRESS_BROKER_IMPLEMENTATION_MEDIA_TYPE,
} from '../src/internal/source-slice-egress-authorization.ts'
import {
  SOURCE_SLICE_EGRESS_ATTEMPT_FENCE_MEDIA_TYPE,
  SOURCE_SLICE_EGRESS_BROKER_REQUEST_MEDIA_TYPE,
  SOURCE_SLICE_EGRESS_INVOCATION_RECEIPT_MEDIA_TYPE,
} from '../src/internal/source-slice-egress-invocation.ts'
import type { ModelInvocationRecordCoreV1 } from '../src/internal/model-invocation-settlement.ts'
import {
  MODEL_INVOCATION_BUDGET_RESERVATION_MEDIA_TYPE,
  MODEL_INVOCATION_FORMAT_REPAIR_REQUEST_MEDIA_TYPE,
  MODEL_INVOCATION_PROMPT_MEDIA_TYPE,
  MODEL_INVOCATION_RECORD_MEDIA_TYPE,
  MODEL_INVOCATION_TOOL_SCHEMA_MEDIA_TYPE,
} from '../src/internal/model-invocation-settlement.ts'
import {
  admitRoleOutputFormatRepairV1,
  createRoleOutputFormatRepairRequestV1,
  createRoleOutputFormatRepairPlanV1,
  parseRoleOutputFormatRepairPlanV1,
  parseRoleOutputFormatRepairRequestV1,
  parseRoleOutputFormatRepairRecordV1,
  ROLE_OUTPUT_FORMAT_REPAIR_PLAN_MEDIA_TYPE,
  ROLE_OUTPUT_FORMAT_REPAIR_RECORD_MEDIA_TYPE,
} from '../src/internal/role-output-format-repair.ts'
import {
  parseRoleContributionPayloadV1,
  ROLE_CONTRIBUTION_PAYLOAD_MEDIA_TYPE,
} from '../src/internal/role-contribution.ts'

const ASSESSMENT_ID = 'asm-00000000-0000-0000-0000-000000000177' as const
const ATTEMPT_ID = 'role-attempt-00000000-0000-0000-0000-000000000177'
const PLAN_ID = 'format-repair-plan-00000000-0000-0000-0000-000000000177'
const CONTRIBUTION_ID = 'role-contribution-00000000-0000-0000-0000-000000000177'
const ORIGINAL_INVOCATION_ID = 'invocation/original-0177'
const REPAIR_INVOCATION_ID = 'invocation/format-repair-0177'
const DECLARED_AT = '2026-09-14T00:00:00.000Z'

const attemptFenceDigest = structuredDigest(
  SOURCE_SLICE_EGRESS_ATTEMPT_FENCE_MEDIA_TYPE,
  { attemptId: ATTEMPT_ID, generation: 1, fencingToken: 'fence/0177/1' },
)

function contextGrant() {
  return createRoleContextGrantV1({
    schemaVersion: 1,
    assessmentId: ASSESSMENT_ID,
    roleAttemptId: ATTEMPT_ID,
    roleDefinition: {
      roleId: 'discovery-analyst',
      roleVersion: '1.0.0',
      definitionDigest: structuredDigest(
        'application/vnd.dsh.security.role-definition+json',
        { role: 'discovery-analyst', version: '1.0.0' },
      ),
    },
    purpose: {
      purposeId: 'security/deep-discovery',
      assessmentMode: 'TARGETED',
      assessmentProfileId: 'security/standard',
      targetDigest: structuredDigest(
        'application/vnd.dsh.security.target-selector+json',
        { kind: 'targeted', relativePaths: ['src/provider.ts'] },
      ),
      coverageObligationIds: ['security/source-review'],
      constraintIds: ['security/read-only'],
      peerContributionVisibility: 'NONE',
    },
    subject: {
      digest: structuredDigest(
        'application/vnd.dsh.security.subject-manifest+json',
        { commit: 'a'.repeat(40) },
      ),
      inventory: [{
        artifactId: 'inventory-format-repair-0177',
        schemaId: 'dsh/security-subject-inventory',
        digest: structuredDigest(
          'application/vnd.dsh.security.subject-inventory+json',
          { inventory: 'format-repair-0177' },
        ),
        disclosureCategoryId: 'security/subject-inventory',
      }],
      sourceSlices: [],
    },
    evidenceProjections: [],
    disclosure: {
      dataEgressPolicyId: 'egress/host-qualified-v1',
      destinationId: 'provider/reference',
      categoryIds: ['security/subject-inventory'],
    },
    budget: {
      contextBytes: { limit: 65_536, granted: 0 },
      tokens: { limit: 4_096, granted: 0 },
    },
  })
}

function semanticPayload(limitations: readonly string[] = []) {
  return {
    schemaVersion: 1,
    hypotheses: [],
    candidateFindings: [],
    coverageObservations: [],
    evidenceArtifactIds: [],
    evidenceRequests: [],
    challenges: [],
    uncertainty: [],
    limitations,
    followUpRequests: [],
    completionDisposition: 'COMPLETE',
  } as const
}

function responsePair(payload = semanticPayload()) {
  const repaired = JSON.stringify(payload)
  const original = repaired.replace(',"hypotheses"', '"hypotheses"')
  return {
    original: Buffer.from(original, 'utf8'),
    repaired: Buffer.from(repaired, 'utf8'),
  }
}

function planFixture(grant = contextGrant()) {
  return createRoleOutputFormatRepairPlanV1({
    planId: PLAN_ID,
    contributionId: CONTRIBUTION_ID,
    contextGrant: grant,
    parentAttempt: {
      attemptId: ATTEMPT_ID,
      generation: 1,
      fenceDigest: attemptFenceDigest,
    },
    originalInvocationId: ORIGINAL_INVOCATION_ID,
    repairInvocation: {
      invocationId: REPAIR_INVOCATION_ID,
      providerId: 'provider/reference',
      modelId: 'model/reference',
      movingProvider: false,
      maxOutputTokens: 256,
      tokenLimit: 512,
    },
    declaredAt: DECLARED_AT,
  })
}

interface RecordFixtureOptions {
  readonly invocationId: string
  readonly bytes: Uint8Array
  readonly startedAt: string
  readonly completedAt: string
  readonly prompt: ModelInvocationRecordCoreV1['prompt']
  readonly parameters: ModelInvocationRecordCoreV1['parameters']
  readonly providerId?: string
  readonly modelId?: string
  readonly tokenLimit?: number
  readonly inputTokens?: number
  readonly outputTokens?: number
  readonly finishReason?: ModelInvocationRecordCoreV1['finishReason']
  readonly requestDigest?: ModelInvocationRecordCoreV1['egress']['requestDigest']
}

function invocationRecord(
  grant: ReturnType<typeof contextGrant>,
  options: RecordFixtureOptions,
) {
  const inputTokens = options.inputTokens ?? 32
  const outputTokens = options.outputTokens ?? 16
  const tokenLimit = options.tokenLimit ?? 512
  const core = {
    schemaVersion: 1,
    assessmentId: ASSESSMENT_ID,
    invocationId: options.invocationId,
    parentAttempt: {
      attemptId: ATTEMPT_ID,
      generation: 1,
      fenceDigest: attemptFenceDigest,
    },
    roleDefinition: grant.roleDefinition,
    provider: {
      providerId: options.providerId ?? 'provider/reference',
      providerRequestId: `provider-request/${options.invocationId}`,
      backendId: 'backend/reference',
      deploymentId: 'deployment/reference',
      modelId: options.modelId ?? 'model/reference',
      movingProvider: false,
    },
    broker: {
      brokerId: 'broker/reference',
      brokerVersion: '1.0.0',
      implementationDigest: structuredDigest(
        SOURCE_SLICE_EGRESS_BROKER_IMPLEMENTATION_MEDIA_TYPE,
        { implementation: 'fixture-0177' },
      ),
    },
    prompt: options.prompt,
    parameters: options.parameters,
    contextGrantDigest: grant.grantDigest,
    egress: {
      destinationId: 'provider/reference',
      dataEgressPolicyId: 'egress/host-qualified-v1',
      auditPolicyId: 'audit/model-invocation-v1',
      authorizationDigest: structuredDigest(
        SOURCE_SLICE_EGRESS_AUTHORIZATION_MEDIA_TYPE,
        { authorization: options.invocationId },
      ),
      requestDigest: options.requestDigest ?? structuredDigest(
        SOURCE_SLICE_EGRESS_BROKER_REQUEST_MEDIA_TYPE,
        { request: options.invocationId },
      ),
    },
    timing: {
      startedAt: options.startedAt,
      completedAt: options.completedAt,
    },
    usage: {
      requestCount: 1,
      requestBytes: options.bytes.byteLength,
      inputTokens,
      outputTokens,
    },
    budgetSettlement: {
      reservationId: `reservation/${options.invocationId}`,
      reservationDigest: structuredDigest(
        MODEL_INVOCATION_BUDGET_RESERVATION_MEDIA_TYPE,
        { reservation: options.invocationId },
      ),
      requestLimit: 1,
      requestsUsed: 1,
      requestsReleased: 0,
      tokenLimit,
      inputTokens,
      outputTokens,
      tokensUsed: inputTokens + outputTokens,
      tokensReleased: tokenLimit - inputTokens - outputTokens,
    },
    responseDigest: binaryDigest(ROLE_CONTRIBUTION_PAYLOAD_MEDIA_TYPE, options.bytes),
    finishReason: options.finishReason ?? 'STOP',
    brokerDiagnosticCodes: [],
    receiptDigest: structuredDigest(
      SOURCE_SLICE_EGRESS_INVOCATION_RECEIPT_MEDIA_TYPE,
      { receipt: options.invocationId },
    ),
  } satisfies ModelInvocationRecordCoreV1
  return {
    ...core,
    recordDigest: structuredDigest(MODEL_INVOCATION_RECORD_MEDIA_TYPE, core),
  }
}

function invocationPair(
  grant: ReturnType<typeof contextGrant>,
  plan: ReturnType<typeof planFixture>,
  responses = responsePair(),
) {
  const original = invocationRecord(grant, {
    invocationId: ORIGINAL_INVOCATION_ID,
    bytes: responses.original,
    startedAt: '2026-09-14T00:00:01.000Z',
    completedAt: '2026-09-14T00:00:02.000Z',
    prompt: {
      promptId: 'security/deep-discovery',
      promptVersion: '1.0.0',
      promptDigest: structuredDigest(
        MODEL_INVOCATION_PROMPT_MEDIA_TYPE,
        { prompt: 'original-role-prompt' },
      ),
      toolSchemaDigest: structuredDigest(
        MODEL_INVOCATION_TOOL_SCHEMA_MEDIA_TYPE,
        { schema: 'role-contribution-payload' },
      ),
    },
    parameters: {
      maxOutputTokens: 256,
      temperature: null,
      topP: null,
      randomnessStrategyId: 'provider-default-v1',
    },
  })
  const request = createRoleOutputFormatRepairRequestV1({
    plan,
    originalInvocationRecord: original,
    originalResponse: responses.original,
  })
  return {
    original,
    request,
    repair: invocationRecord(grant, {
      invocationId: REPAIR_INVOCATION_ID,
      bytes: responses.repaired,
      startedAt: '2026-09-14T00:00:03.000Z',
      completedAt: '2026-09-14T00:00:04.000Z',
      prompt: plan.repairInvocation.prompt,
      parameters: plan.repairInvocation.parameters,
      requestDigest: request.requestDigest,
    }),
  }
}

function admitFixture(responses = responsePair()) {
  const grant = contextGrant()
  const plan = planFixture(grant)
  const invocations = invocationPair(grant, plan, responses)
  return admitRoleOutputFormatRepairV1({
    plan,
    contextGrant: grant,
    originalInvocationRecord: invocations.original,
    repairInvocationRecord: invocations.repair,
    repairRequest: invocations.request,
    repairedResponse: responses.repaired,
  })
}

describe('ADR 0177 governed Role output Format Repair', () => {
  it('admits one punctuation-only repair with exact two-call lineage and budget use', () => {
    const admitted = admitFixture()

    expect(admitted.contribution.modelInvocations.map(value => value.invocationId)).toEqual([
      ORIGINAL_INVOCATION_ID,
      REPAIR_INVOCATION_ID,
    ])
    expect(admitted.contribution.resourceUse).toEqual({
      requests: 2,
      inputTokens: 64,
      outputTokens: 32,
      tokens: 96,
    })
    expect(admitted.repairRecord.recordDigest.mediaType)
      .toBe(ROLE_OUTPUT_FORMAT_REPAIR_RECORD_MEDIA_TYPE)
    expect(parseRoleOutputFormatRepairRecordV1(
      structuredClone(admitted.repairRecord),
    )).toEqual(admitted.repairRecord)
    expect(Object.isFrozen(admitted)).toBe(true)
    expect(JSON.stringify(admitted.repairRecord)).not.toContain('hypotheses')
    expect(admitted.repairRecord.repairInvocation.recordDigest.mediaType)
      .toBe(MODEL_INVOCATION_RECORD_MEDIA_TYPE)
  })

  it('creates a frozen digest-bound plan with package-owned syntax instructions', () => {
    const plan = planFixture()

    expect(plan.planDigest.mediaType).toBe(ROLE_OUTPUT_FORMAT_REPAIR_PLAN_MEDIA_TYPE)
    expect(plan.repairInvocation.budget.requestLimit).toBe(1)
    expect(plan.repairInvocation.parameters).toMatchObject({
      temperature: 0,
      topP: null,
      randomnessStrategyId: 'deterministic-format-repair-v1',
    })
    expect(parseRoleOutputFormatRepairPlanV1(structuredClone(plan))).toEqual(plan)
    expect(Object.isFrozen(plan)).toBe(true)

    const tampered = {
      ...structuredClone(plan),
      repairInvocation: {
        ...structuredClone(plan.repairInvocation),
        budget: {
          ...structuredClone(plan.repairInvocation.budget),
          tokenLimit: plan.repairInvocation.budget.tokenLimit + 1,
        },
      },
    }
    expect(() => parseRoleOutputFormatRepairPlanV1(tampered)).toThrow(/digest is invalid/u)
  })

  it('binds the repair Broker request to only the original, target schema, and instruction', () => {
    const responses = responsePair()
    const grant = contextGrant()
    const plan = planFixture(grant)
    const request = invocationPair(grant, plan, responses).request

    expect(Object.keys(request.content)).toEqual([
      'originalResponse',
      'targetSchema',
      'syntaxInstruction',
    ])
    expect(request.requestDigest.mediaType).toBe(MODEL_INVOCATION_FORMAT_REPAIR_REQUEST_MEDIA_TYPE)
    expect(parseRoleOutputFormatRepairRequestV1(structuredClone(request))).toEqual(request)
    expect(() => parseRoleOutputFormatRepairRequestV1({
      ...structuredClone(request),
      content: {
        ...structuredClone(request.content),
        originalResponse: `${request.content.originalResponse} `,
      },
    })).toThrow()
  })

  it('does not spend the repair allowance when the original payload is already valid', () => {
    const bytes = Buffer.from(JSON.stringify(semanticPayload()), 'utf8')
    expect(() => admitFixture({ original: bytes, repaired: bytes }))
      .toThrow(/must not consume Format Repair/u)
  })

  it('fails closed when repair changes a semantic scalar or Evidence reference', () => {
    const originalPayload = semanticPayload(['No network behavior was observed.'])
    const changedPayload = semanticPayload(['Network behavior was observed.'])
    const original = JSON.stringify(originalPayload).replace(',"hypotheses"', '"hypotheses"')
    expect(() => admitFixture({
      original: Buffer.from(original, 'utf8'),
      repaired: Buffer.from(JSON.stringify(changedPayload), 'utf8'),
    })).toThrow(/semantic scalars/u)
  })

  it('rejects authority fields and output that remains malformed', () => {
    const pair = responsePair()
    const authorityBearing = Buffer.from(JSON.stringify({
      ...semanticPayload(),
      securityVerdict: 'SATISFIED',
    }), 'utf8')
    expect(() => admitFixture({ original: pair.original, repaired: authorityBearing }))
      .toThrow(/strict payload parsing/u)
    expect(() => admitFixture({ original: pair.original, repaired: pair.original }))
      .toThrow(/strict payload parsing/u)
  })

  it('rejects duplicate JSON keys before last-value parsing can hide semantics', () => {
    const duplicateKeys = JSON.stringify(semanticPayload()).replace(
      '"limitations":[]',
      '"limitations":[],"limitations":[]',
    )
    const original = duplicateKeys.replace(',"hypotheses"', '"hypotheses"')

    expect(() => admitFixture({
      original: Buffer.from(original, 'utf8'),
      repaired: Buffer.from(duplicateKeys, 'utf8'),
    })).toThrow(/duplicate object keys/u)
  })

  it('rejects non-JSON extraction and mismatched protected response bytes', () => {
    const pair = responsePair()
    const fenced = Buffer.from(`\`\`\`json\n${pair.original.toString('utf8')}\n\`\`\``, 'utf8')
    expect(() => admitFixture({ original: fenced, repaired: pair.repaired }))
      .toThrow(/non-JSON token/u)

    const grant = contextGrant()
    const plan = planFixture(grant)
    const invocations = invocationPair(grant, plan, pair)
    expect(() => admitRoleOutputFormatRepairV1({
      plan,
      contextGrant: grant,
      originalInvocationRecord: invocations.original,
      repairInvocationRecord: invocations.repair,
      repairRequest: invocations.request,
      repairedResponse: pair.repaired,
    })).not.toThrow()
    expect(() => createRoleOutputFormatRepairRequestV1({
      plan,
      originalInvocationRecord: invocations.original,
      originalResponse: Buffer.from(`${pair.original.toString('utf8')} `, 'utf8'),
    })).toThrow(/do not match protected invocation lineage/u)
  })

  it('does not treat content-filtered or tool-call output as a format error', () => {
    const responses = responsePair()
    const grant = contextGrant()
    const plan = planFixture(grant)
    for (const finishReason of ['CONTENT_FILTER', 'TOOL_CALLS'] as const) {
      const original = invocationRecord(grant, {
        invocationId: ORIGINAL_INVOCATION_ID,
        bytes: responses.original,
        startedAt: '2026-09-14T00:00:01.000Z',
        completedAt: '2026-09-14T00:00:02.000Z',
        prompt: {
          promptId: 'security/deep-discovery',
          promptVersion: '1.0.0',
          promptDigest: structuredDigest(MODEL_INVOCATION_PROMPT_MEDIA_TYPE, { prompt: 'original' }),
          toolSchemaDigest: structuredDigest(
            MODEL_INVOCATION_TOOL_SCHEMA_MEDIA_TYPE,
            { schema: 'role-contribution-payload' },
          ),
        },
        parameters: {
          maxOutputTokens: 256,
          temperature: null,
          topP: null,
          randomnessStrategyId: 'provider-default-v1',
        },
        finishReason,
      })
      expect(() => createRoleOutputFormatRepairRequestV1({
        plan,
        originalInvocationRecord: original,
        originalResponse: responses.original,
      })).toThrow(/original invocation lineage/u)
    }
  })

  it('rejects retry identity, provider, prompt, and budget drift', () => {
    const responses = responsePair()
    const grant = contextGrant()
    const plan = planFixture(grant)
    const original = invocationPair(grant, plan, responses).original
    const request = createRoleOutputFormatRepairRequestV1({
      plan,
      originalInvocationRecord: original,
      originalResponse: responses.original,
    })
    const baseRepair = {
      bytes: responses.repaired,
      startedAt: '2026-09-14T00:00:03.000Z',
      completedAt: '2026-09-14T00:00:04.000Z',
      prompt: plan.repairInvocation.prompt,
      parameters: plan.repairInvocation.parameters,
      requestDigest: request.requestDigest,
    } as const
    for (const repair of [
      invocationRecord(grant, { ...baseRepair, invocationId: 'invocation/second-repair-0177' }),
      invocationRecord(grant, {
        ...baseRepair,
        invocationId: REPAIR_INVOCATION_ID,
        providerId: 'provider/drifted',
      }),
      invocationRecord(grant, {
        ...baseRepair,
        invocationId: REPAIR_INVOCATION_ID,
        prompt: { ...plan.repairInvocation.prompt, promptId: 'security/drifted-prompt' },
      }),
      invocationRecord(grant, {
        ...baseRepair,
        invocationId: REPAIR_INVOCATION_ID,
        tokenLimit: 513,
      }),
    ]) {
      expect(() => admitRoleOutputFormatRepairV1({
        plan,
        contextGrant: grant,
        originalInvocationRecord: original,
        repairInvocationRecord: repair,
        repairRequest: request,
        repairedResponse: responses.repaired,
      })).toThrow(/drifts|exceeds/u)
    }
  })

  it('keeps model payloads authority-free and validates their closed references', () => {
    expect(parseRoleContributionPayloadV1(semanticPayload())).toEqual(semanticPayload())
    expect(() => parseRoleContributionPayloadV1({
      ...semanticPayload(),
      contributionId: CONTRIBUTION_ID,
    })).toThrow()
    expect(() => parseRoleContributionPayloadV1({
      ...semanticPayload(),
      challenges: [{
        challengeId: 'challenge/undeclared',
        targetCandidateId: `candidate-${'1'.repeat(64)}`,
        disposition: 'PROOF_GAP',
        evidenceArtifactIds: [],
        rationale: 'No declared candidate exists.',
      }],
    })).toThrow(/declared Candidates/u)
  })
})
