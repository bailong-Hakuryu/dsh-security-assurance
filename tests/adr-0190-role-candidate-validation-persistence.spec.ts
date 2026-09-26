import { afterEach, describe, expect, it } from 'vitest'
import { mkdtemp } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { DatabaseSync } from 'node:sqlite'
import { createRoleContextGrantV1 } from '../src/role-context-grant.ts'
import { binaryDigest, structuredDigest } from '../src/internal/canonical.ts'
import type {
  SourceSliceEgressInvocationReceiptCoreV1,
} from '../src/internal/source-slice-egress-invocation.ts'
import {
  SOURCE_SLICE_EGRESS_ATTEMPT_FENCE_MEDIA_TYPE,
  SOURCE_SLICE_EGRESS_BROKER_REQUEST_MEDIA_TYPE,
  SOURCE_SLICE_EGRESS_INVOCATION_RECEIPT_MEDIA_TYPE,
} from '../src/internal/source-slice-egress-invocation.ts'
import {
  SOURCE_SLICE_EGRESS_AUTHORIZATION_MEDIA_TYPE,
  SOURCE_SLICE_EGRESS_BROKER_IMPLEMENTATION_MEDIA_TYPE,
} from '../src/internal/source-slice-egress-authorization.ts'
import {
  createModelInvocationBudgetReservationV1,
  MODEL_INVOCATION_PROMPT_MEDIA_TYPE,
  MODEL_INVOCATION_TOOL_SCHEMA_MEDIA_TYPE,
  settleSourceSliceModelInvocationV1,
} from '../src/internal/model-invocation-settlement.ts'
import { publishModelInvocationEvidenceV1 } from '../src/internal/model-invocation-evidence.ts'
import { prepareAssessmentContract } from '../src/internal/deterministic-kernel.ts'
import {
  openSecurityPersistence,
  SecurityPersistenceError,
} from '../src/internal/persistence.ts'
import type { SecurityPersistence } from '../src/internal/persistence.ts'
import { createRoleContributionV1 } from '../src/internal/role-contribution.ts'
import type { RoleCandidateAdmissionV1 } from '../src/internal/role-candidate-admission.ts'
import {
  candidateProducerLineageDigestV1,
  createQualifiedRoleCandidateValidationContractV1,
  createRoleCandidateValidationContractV1,
  createRoleCandidateValidationEligibilityDecisionV1,
  createRoleCandidateValidationIndependenceDecisionV1,
  createRoleCandidateValidationProofV1,
} from '../src/internal/role-candidate-validation.ts'
import type {
  QualifiedRoleCandidateValidationContractV1,
  RoleCandidateValidationEvidenceIdentityV1,
  RoleCandidateValidationProofPurpose,
} from '../src/internal/role-candidate-validation.ts'
import { removeTemporaryRoots } from './support/remove-temporary-root.ts'

const temporaryRoots: string[] = []

afterEach(async () => {
  await removeTemporaryRoots(temporaryRoots)
})

const ASSESSMENT_ID = 'asm-00000000-0000-0000-0000-000000000190' as const
const NOW = '2026-09-13T00:00:03.000Z'
/** Caller-supplied Candidate ID reused by two different Contributions. */
const SHARED_CANDIDATE_ID = `candidate-${'2'.repeat(64)}`
const SOURCE_TEXT = '{"scripts":{"preinstall":"node install.js"}}'
const SOURCE_DIGEST = binaryDigest('application/octet-stream', Buffer.from(SOURCE_TEXT, 'utf8'))
const SUBJECT_DIGEST = structuredDigest(
  'application/vnd.dsh.security.subject-manifest+json',
  { commit: 'b'.repeat(40) },
)
const TARGET = { kind: 'targeted' as const, relativePaths: ['package.json'] }
const TARGET_DIGEST = structuredDigest('application/vnd.dsh.security.target-selector+json', TARGET)
const ROLE_DEFINITION = {
  roleId: 'discovery-analyst' as const,
  roleVersion: '1.0.0',
  definitionDigest: structuredDigest(
    'application/vnd.dsh.security.role-definition+json',
    { role: 'discovery-analyst', version: '1.0.0' },
  ),
}
const PROMPT = {
  promptId: 'security/deep-discovery',
  promptVersion: '1.0.0',
  promptDigest: structuredDigest(MODEL_INVOCATION_PROMPT_MEDIA_TYPE, { prompt: 'protected' }),
  toolSchemaDigest: structuredDigest(MODEL_INVOCATION_TOOL_SCHEMA_MEDIA_TYPE, { tool: 'source-slice' }),
}
const VALIDATOR_DEFINITION_DIGEST = structuredDigest(
  'application/vnd.dsh.security.validator-definition+json',
  { validatorId: 'validator/install-script', version: '1.0.0' },
)

type Side = 'A' | 'B'

const SIDES = {
  A: {
    ordinal: '000000000191',
    securityClaim: 'A repository-controlled install script executes during installation.',
  },
  B: {
    ordinal: '000000000192',
    securityClaim: 'A repository-controlled install script rewrites the global npm configuration.',
  },
} as const satisfies Record<Side, { readonly ordinal: string; readonly securityClaim: string }>

function attemptFixture(side: Side) {
  const { ordinal, securityClaim } = SIDES[side]
  const attemptId = `role-attempt-00000000-0000-0000-0000-${ordinal}`
  const invocationId = `egress-invocation-00000000-0000-0000-0000-${ordinal}`
  const contributionId = `role-contribution-00000000-0000-0000-0000-${ordinal}`
  const fenceDigest = structuredDigest(SOURCE_SLICE_EGRESS_ATTEMPT_FENCE_MEDIA_TYPE, {
    attemptId,
    generation: 1,
    fencingToken: `fence/role-attempt-${ordinal}/generation-1`,
  })
  const grant = createRoleContextGrantV1({
    schemaVersion: 1,
    assessmentId: ASSESSMENT_ID,
    roleAttemptId: attemptId,
    roleDefinition: ROLE_DEFINITION,
    purpose: {
      purposeId: 'security/deep-discovery',
      assessmentMode: 'TARGETED',
      assessmentProfileId: 'security/standard',
      targetDigest: TARGET_DIGEST,
      coverageObligationIds: ['security/source-review'],
      constraintIds: ['security/read-only'],
      peerContributionVisibility: 'NONE',
    },
    subject: {
      digest: SUBJECT_DIGEST,
      inventory: [{
        artifactId: 'inventory-role-candidate-validation',
        schemaId: 'dsh/security-subject-inventory',
        digest: structuredDigest(
          'application/vnd.dsh.security.subject-inventory+json',
          { inventory: 'role-candidate-validation-0190' },
        ),
        disclosureCategoryId: 'security/subject-inventory',
      }],
      sourceSlices: [{
        artifactId: 'source-slice-package-json',
        schemaId: 'dsh/security-source-slice',
        digest: structuredDigest(
          'application/vnd.dsh.security.source-slice+json',
          { path: 'package.json', digest: SOURCE_DIGEST },
        ),
        disclosureCategoryId: 'security/source-slice',
      }],
    },
    evidenceProjections: [],
    disclosure: {
      dataEgressPolicyId: 'egress/host-qualified-v1',
      destinationId: 'provider/reference',
      categoryIds: ['security/source-slice', 'security/subject-inventory'],
    },
    budget: {
      contextBytes: { limit: 65_536, granted: 8_192 },
      tokens: { limit: 8_192, granted: 0 },
    },
  })
  const receiptCore = {
    schemaVersion: 1,
    invocationId,
    attemptId,
    attemptGeneration: 1,
    attemptFenceDigest: fenceDigest,
    egressAuthorizationDigest: structuredDigest(
      SOURCE_SLICE_EGRESS_AUTHORIZATION_MEDIA_TYPE,
      { authorization: `fixture-${ordinal}` },
    ),
    brokerRequestDigest: structuredDigest(
      SOURCE_SLICE_EGRESS_BROKER_REQUEST_MEDIA_TYPE,
      { request: `fixture-${ordinal}` },
    ),
    brokerIdentity: {
      brokerId: 'broker/reference',
      brokerVersion: '1.0.0',
      implementationDigest: structuredDigest(
        SOURCE_SLICE_EGRESS_BROKER_IMPLEMENTATION_MEDIA_TYPE,
        { implementation: 'fixture-0190' },
      ),
    },
    providerId: 'provider/reference',
    destinationId: 'provider/reference',
    dataEgressPolicyId: 'egress/host-qualified-v1',
    auditPolicyId: 'audit/model-invocation-v1',
    requestBytes: 256,
    tokenLimit: 128,
    startedAt: '2026-09-13T00:00:01.000Z',
    completedAt: '2026-09-13T00:00:02.000Z',
    status: 'COMPLETED',
    failureCode: null,
    providerRequestId: `provider-request/fixture-${ordinal}`,
    backendId: 'backend/reference',
    deploymentId: 'deployment/reference',
    modelId: 'model/reference',
    responseDigest: binaryDigest('text/plain', Buffer.from(`protected response ${side}`, 'utf8')),
    finishReason: 'STOP',
    usage: { requestCount: 1, requestBytes: 256, inputTokens: 32, outputTokens: 8 },
    diagnosticCodes: ['CACHE_MISS'],
  } satisfies SourceSliceEgressInvocationReceiptCoreV1
  const receipt = {
    ...receiptCore,
    receiptDigest: structuredDigest(SOURCE_SLICE_EGRESS_INVOCATION_RECEIPT_MEDIA_TYPE, receiptCore),
  }
  const reservation = createModelInvocationBudgetReservationV1({
    schemaVersion: 1,
    reservationId: `reservation/model-invocation-${ordinal}`,
    invocationId,
    attemptId,
    attemptGeneration: 1,
    attemptFenceDigest: fenceDigest,
    contextGrantDigest: grant.grantDigest,
    egressAuthorizationDigest: receipt.egressAuthorizationDigest,
    brokerRequestDigest: receipt.brokerRequestDigest,
    requestLimit: 1,
    tokenLimit: 128,
    reservedAt: '2026-09-13T00:00:00.000Z',
    deadlineAt: '2026-09-13T00:01:00.000Z',
  })
  const record = settleSourceSliceModelInvocationV1({
    contextGrant: grant,
    reservation,
    receipt,
    lineage: {
      provider: { movingProvider: false },
      prompt: PROMPT,
      parameters: {
        maxOutputTokens: 64,
        temperature: null,
        topP: null,
        randomnessStrategyId: 'deterministic/provider-default-v1',
      },
    },
  })
  const expected = {
    invocationId,
    attemptId,
    attemptGeneration: 1,
    attemptFenceDigest: fenceDigest,
    contextGrantDigest: grant.grantDigest,
    reservationDigest: reservation.reservationDigest,
    receiptDigest: receipt.receiptDigest,
  }
  return { side, ordinal, securityClaim, attemptId, contributionId, fenceDigest, grant, record, expected }
}

type AttemptFixture = ReturnType<typeof attemptFixture>

async function admitSharedCandidateId(
  persistence: SecurityPersistence,
  securityRoot: string,
  attempt: AttemptFixture,
): Promise<{
  readonly admission: RoleCandidateAdmissionV1
  readonly validationEvidence: RoleCandidateValidationEvidenceIdentityV1
}> {
  const revision = () => persistence.getAssessmentRecord(ASSESSMENT_ID)!.assessmentRevision
  persistence.startRoleAttempt({
    contextGrant: attempt.grant,
    expectedAssessmentRevision: revision(),
    generation: 1,
    fenceDigest: attempt.fenceDigest,
    parentAttemptId: null,
    independenceClass: 'DISTINCT_ATTEMPT',
    provider: { providerId: 'provider/reference', modelId: 'model/reference', movingProvider: false },
    prompt: PROMPT,
    budget: { requestLimit: 1, tokenLimit: 128 },
  })
  const publication = await publishModelInvocationEvidenceV1({
    securityRoot,
    contextGrant: attempt.grant,
    record: attempt.record,
    expected: attempt.expected,
  })
  persistence.linkModelInvocationEvidence({
    contextGrant: attempt.grant,
    expectedAssessmentRevision: revision(),
    receipt: publication,
    record: attempt.record,
    expected: attempt.expected,
  })
  const contribution = createRoleContributionV1({
    schemaVersion: 1,
    contributionId: attempt.contributionId,
    assessmentId: ASSESSMENT_ID,
    subjectDigest: SUBJECT_DIGEST,
    parentAttempt: { attemptId: attempt.attemptId, generation: 1, fenceDigest: attempt.fenceDigest },
    contextGrantDigest: attempt.grant.grantDigest,
    roleDefinition: attempt.grant.roleDefinition,
    modelInvocations: [{
      invocationId: attempt.expected.invocationId,
      recordDigest: attempt.record.recordDigest,
      responseDigest: attempt.record.responseDigest,
      inputTokens: attempt.record.usage.inputTokens,
      outputTokens: attempt.record.usage.outputTokens,
    }],
    hypotheses: [],
    candidateFindings: [{
      schemaVersion: 1,
      candidateId: SHARED_CANDIDATE_ID,
      weaknessClassification: {
        schemaVersion: 1,
        primary: 'cwe/94',
        secondary: ['security/install-lifecycle'],
      },
      affectedControlId: 'security/node-package-lifecycle',
      securityClaim: attempt.securityClaim,
      sourceAnchors: [{
        path: 'package.json',
        fileDigest: SOURCE_DIGEST,
        byteSpan: { start: 0, length: SOURCE_DIGEST.byteLength },
        symbolId: '/scripts/preinstall',
      }],
      evidenceArtifactIds: [publication.artifactId],
    }],
    coverageObservations: [],
    evidenceArtifactIds: [publication.artifactId],
    evidenceRequests: [],
    challenges: [],
    uncertainty: [],
    limitations: [],
    followUpRequests: [],
    resourceUse: {
      requests: 1,
      inputTokens: attempt.record.usage.inputTokens,
      outputTokens: attempt.record.usage.outputTokens,
      tokens: attempt.record.usage.inputTokens + attempt.record.usage.outputTokens,
    },
    completionDisposition: 'COMPLETE',
  })
  persistence.admitRoleContribution({
    contextGrant: attempt.grant,
    expectedAssessmentRevision: revision(),
    contribution,
    modelInvocationRecords: [attempt.record],
  })
  const admitted = persistence.admitRoleCandidates({
    admissionAttemptId: `role-candidate-admission-attempt-00000000-0000-4000-8000-${attempt.ordinal}`,
    assessmentId: ASSESSMENT_ID,
    contributionId: attempt.contributionId,
    expectedAssessmentRevision: revision(),
    contextGrant: attempt.grant,
    sourceSlices: [{
      contextArtifactId: 'source-slice-package-json',
      subjectDigest: SUBJECT_DIGEST,
      path: 'package.json',
      digest: SOURCE_DIGEST,
      text: SOURCE_TEXT,
    }],
    durableEvidenceArtifactIds: [publication.artifactId],
  })
  if (admitted.state !== 'ADMITTED') throw new Error(`Contribution ${attempt.side} was not admitted`)
  return {
    admission: admitted.batch.admissions[0]!,
    validationEvidence: {
      artifactId: publication.artifactId,
      schemaId: publication.schemaId,
      digest: publication.evidenceDigest,
    },
  }
}

async function twoContributionStore() {
  const securityRoot = await mkdtemp(join(tmpdir(), 'dsh-role-candidate-validation-identity-'))
  temporaryRoots.push(securityRoot)
  const databasePath = join(securityRoot, 'security-assurance.sqlite')
  const persistence = await openSecurityPersistence({
    databasePath,
    now: () => NOW,
    nextRepositoryId: () => 'repo-00000000-0000-0000-0000-000000000190',
    nextAssessmentId: () => ASSESSMENT_ID,
    nextCorrelationId: () => 'sec-00000000-0000-0000-0000-000000000190',
  })
  const bindings = {
    policyId: 'security/default',
    assessmentProfileId: 'security/standard',
    evidenceProtectionId: 'evidence/local-protected',
    dataEgressPolicyId: 'egress/deny-by-default',
    platform: process.platform as 'win32' | 'linux' | 'darwin',
    deliveryDestinationIds: [],
  }
  const registered = persistence.registerRepository({
    principalId: 'operator:role-candidate-validation-fixture',
    authorityKind: 'host-operator',
    idempotencyKey: 'role-candidate-validation-repository',
    canonicalRequest: { operation: 'register-role-candidate-validation-fixture' },
    canonicalRoot: 'D:/role-candidate-validation-fixture',
    displayName: 'Role Candidate Validation fixture',
    bindings,
  })
  const repository = persistence.getRepository(registered.repositoryId)!
  const created = persistence.createAssessment({
    principalId: 'operator:role-candidate-validation-fixture',
    authorityKind: 'host-operator',
    idempotencyKey: 'role-candidate-validation-assessment',
    repositoryId: repository.repositoryId,
    expectedRepositoryRevision: repository.repositoryRevision,
    canonicalRequest: { operation: 'start-role-candidate-validation-fixture' },
    subject: { kind: 'workspace_snapshot' },
    subjectDigest: SUBJECT_DIGEST,
    subjectStats: { files: 0, bytes: 0, symbolicLinks: 0, submodules: 0 },
    preparedContract: prepareAssessmentContract({
      policyId: bindings.policyId,
      assessmentMode: 'TARGETED',
      assessmentProfileId: 'security/standard',
      target: TARGET,
      targetDigest: TARGET_DIGEST,
      requestedStrongerControlIds: [],
      analyzerPortfolio: [],
    }),
  })
  if (persistence.beginAssessment(created.assessmentId) === undefined) {
    throw new Error('Assessment fixture did not begin')
  }
  const attemptA = attemptFixture('A')
  const a = { ...attemptA, ...await admitSharedCandidateId(persistence, securityRoot, attemptA) }
  const attemptB = attemptFixture('B')
  const b = { ...attemptB, ...await admitSharedCandidateId(persistence, securityRoot, attemptB) }
  const assessment = persistence.getAssessmentRecord(ASSESSMENT_ID)!
  const contract = createRoleCandidateValidationContractV1({
    schemaVersion: 1,
    contractId: 'security/install-script-validation',
    contractVersion: '1.0.0',
    selectors: {
      policyId: assessment.contract.policy.policyId,
      policyDigest: assessment.contract.policy.digest,
      assessmentMode: assessment.contract.assessmentMode,
      ecosystemId: 'ecosystem/node',
      executionBoundaryId: 'execution/offline-sandbox',
      primaryWeaknessId: 'cwe/94',
      affectedControlId: 'security/node-package-lifecycle',
    },
    claimConditionId: 'condition/install-script-executes',
    claimEvidenceSchemaIds: [a.validationEvidence.schemaId],
    counterEvidence: [{
      rejectionConditionId: 'condition/install-script-unreachable',
      evidenceSchemaIds: [a.validationEvidence.schemaId],
    }],
    requiredNegativeControls: [{
      negativeControlId: 'control/fixture-without-install-script',
      evidenceSchemaIds: [a.validationEvidence.schemaId],
    }],
    independencePolicy: {
      policyId: 'independence/provenance-graph-v1',
      minimumDistinctValidationLineages: 1,
    },
  })
  const qualifiedContract = createQualifiedRoleCandidateValidationContractV1({
    schemaVersion: 1,
    qualificationId: 'qualification/install-script-validator-v1',
    contract,
    validatorCapabilityId: 'validator/install-script',
    validatorVersion: '1.0.0',
    validatorDefinitionDigest: VALIDATOR_DEFINITION_DIGEST,
    executionBoundaryId: 'execution/offline-sandbox',
    qualifiedAt: '2026-09-12T00:00:00.000Z',
    validUntil: '2026-09-14T00:00:00.000Z',
  })
  return { databasePath, persistence, a, b, qualifiedContract }
}

type Store = Awaited<ReturnType<typeof twoContributionStore>>
type Contributor = Store['a']

const CONDITION_BY_PURPOSE = {
  CLAIM_VALIDATION: 'condition/install-script-executes',
  CLAIM_REJECTION: 'condition/install-script-unreachable',
  NEGATIVE_CONTROL: 'control/fixture-without-install-script',
} as const satisfies Record<RoleCandidateValidationProofPurpose, string>

function validationInputs(
  store: Store,
  contributor: Contributor,
  validationOrdinal: string,
  purposes: readonly RoleCandidateValidationProofPurpose[],
) {
  const persistence = store.persistence
  const validationAttemptId =
    `role-candidate-validation-attempt-00000000-0000-4000-8000-${validationOrdinal}`
  const resolutionInput = {
    validationAttemptId,
    assessmentId: ASSESSMENT_ID,
    contributionId: contributor.contributionId,
    candidateId: SHARED_CANDIDATE_ID,
    expectedAssessmentRevision: persistence.getAssessmentRecord(ASSESSMENT_ID)!.assessmentRevision,
    ecosystemId: 'ecosystem/node',
    executionBoundaryId: 'execution/offline-sandbox',
    qualifiedContracts: [store.qualifiedContract] as readonly QualifiedRoleCandidateValidationContractV1[],
  }
  const proofs = purposes.map((purpose, index) => {
    const conditionId = CONDITION_BY_PURPOSE[purpose]
    const validationLineageDigest = structuredDigest(
      'application/vnd.dsh.security.validation-lineage+json',
      { validationAttemptId, purpose },
    )
    return createRoleCandidateValidationProofV1({
      schemaVersion: 1,
      proofId: `role-candidate-validation-proof-00000000-0000-4000-${validationOrdinal.slice(0, 4)}-${validationOrdinal.slice(4)}${String(index).padStart(4, '0')}`,
      purpose,
      conditionId,
      evidence: contributor.validationEvidence,
      result: 'PROVED',
      validator: {
        validatorId: 'validator/install-script',
        validatorVersion: '1.0.0',
        definitionDigest: VALIDATOR_DEFINITION_DIGEST,
      },
      eligibilityDecision: createRoleCandidateValidationEligibilityDecisionV1({
        schemaVersion: 1,
        state: 'ELIGIBLE',
        candidateId: SHARED_CANDIDATE_ID,
        candidateAdmissionDigest: contributor.admission.admissionDigest,
        contractDefinitionDigest: store.qualifiedContract.contract.definitionDigest,
        policyDigest: store.qualifiedContract.contract.selectors.policyDigest,
        purpose,
        conditionId,
        evidence: contributor.validationEvidence,
        reasonCode: 'eligibility/contract-satisfied',
        decidedAt: NOW,
      }),
      independenceDecision: createRoleCandidateValidationIndependenceDecisionV1({
        schemaVersion: 1,
        state: 'INDEPENDENT',
        independencePolicyId: 'independence/provenance-graph-v1',
        candidateProducerLineageDigest: candidateProducerLineageDigestV1(contributor.admission),
        validationLineageDigest,
        provenanceGraphDigest: structuredDigest(
          'application/vnd.dsh.security.provenance-graph+json',
          { validationAttemptId, purpose },
        ),
        reasonCode: 'independence/provenance-graph-separated',
        decidedAt: NOW,
      }),
      observedAt: NOW,
    })
  })
  return {
    resolutionInput,
    outcomeInput: (expectedAssessmentRevision: number) => ({
      validationAttemptId,
      assessmentId: ASSESSMENT_ID,
      contributionId: contributor.contributionId,
      candidateId: SHARED_CANDIDATE_ID,
      expectedAssessmentRevision,
      proofs,
      durableEvidence: [contributor.validationEvidence],
    }),
  }
}

function validate(
  store: Store,
  contributor: Contributor,
  validationOrdinal: string,
  purposes: readonly RoleCandidateValidationProofPurpose[],
) {
  const inputs = validationInputs(store, contributor, validationOrdinal, purposes)
  const resolution = store.persistence.resolveRoleCandidateValidationContract(inputs.resolutionInput)
  const outcomeInput = inputs.outcomeInput(resolution.assessmentRevision)
  return {
    resolutionInput: inputs.resolutionInput,
    outcomeInput,
    durable: store.persistence.recordRoleCandidateValidationOutcome(outcomeInput),
  }
}

function persistenceErrorCode(operation: () => unknown): string | undefined {
  try {
    operation()
  } catch (error) {
    if (error instanceof SecurityPersistenceError) return error.code
    throw error
  }
  return undefined
}

describe('ADR 0181 and 0190 Role Candidate Validation persistence identity', () => {
  it('keeps same-ID Candidates from different Contributions as distinct current Outcomes', async () => {
    const store = await twoContributionStore()
    const { persistence, a, b } = store
    try {
      expect(a.admission.candidateId).toBe(b.admission.candidateId)
      expect(a.admission.securityClaim).not.toBe(b.admission.securityClaim)
      expect(a.admission.admissionDigest).not.toEqual(b.admission.admissionDigest)

      const validatedA = validate(store, a, '000000000291', ['CLAIM_VALIDATION', 'NEGATIVE_CONTROL'])
      const rejectedB = validate(store, b, '000000000292', ['CLAIM_REJECTION', 'NEGATIVE_CONTROL'])
      expect(validatedA.durable.outcome).toMatchObject({
        state: 'VALIDATED',
        candidateAdmissionDigest: a.admission.admissionDigest,
      })
      expect(rejectedB.durable.outcome).toMatchObject({
        state: 'REJECTED',
        candidateAdmissionDigest: b.admission.admissionDigest,
      })

      expect(persistence.getCurrentRoleCandidateValidation(
        ASSESSMENT_ID,
        a.contributionId,
        SHARED_CANDIDATE_ID,
      )).toEqual(validatedA.durable)
      expect(persistence.getCurrentRoleCandidateValidation(
        ASSESSMENT_ID,
        b.contributionId,
        SHARED_CANDIDATE_ID,
      )).toEqual(rejectedB.durable)
      expect(persistence.getCurrentRoleCandidateValidation(
        ASSESSMENT_ID,
        'role-contribution-00000000-0000-0000-0000-000000000199',
        SHARED_CANDIDATE_ID,
      )).toBeUndefined()
    } finally {
      persistence.close()
    }
  })

  it('replays exactly and refuses to bind one Contribution attempt to another Contribution', async () => {
    const store = await twoContributionStore()
    const { persistence, a, b } = store
    try {
      const validatedA = validate(store, a, '000000000291', ['CLAIM_VALIDATION', 'NEGATIVE_CONTROL'])
      const rejectedB = validate(store, b, '000000000292', ['CLAIM_REJECTION', 'NEGATIVE_CONTROL'])
      const revision = persistence.getAssessmentRecord(ASSESSMENT_ID)!.assessmentRevision

      expect(persistence.resolveRoleCandidateValidationContract(validatedA.resolutionInput))
        .toEqual({
          requestDigest: validatedA.durable.resolutionRequestDigest,
          assessmentRevision: validatedA.durable.outcome.assessmentRevision - 1,
          resolution: validatedA.durable.resolution,
        })
      expect(persistence.recordRoleCandidateValidationOutcome(validatedA.outcomeInput))
        .toEqual(validatedA.durable)
      expect(persistence.recordRoleCandidateValidationOutcome(rejectedB.outcomeInput))
        .toEqual(rejectedB.durable)

      expect(persistenceErrorCode(() => persistence.resolveRoleCandidateValidationContract({
        ...validatedA.resolutionInput,
        contributionId: b.contributionId,
      }))).toBe('role_candidate_validation_conflict')
      expect(persistenceErrorCode(() => persistence.recordRoleCandidateValidationOutcome({
        ...validatedA.outcomeInput,
        contributionId: b.contributionId,
      }))).toBe('role_candidate_validation_conflict')

      const unrecordedA = validationInputs(store, a, '000000000293', ['NEGATIVE_CONTROL'])
      const unrecordedResolution = persistence.resolveRoleCandidateValidationContract(
        unrecordedA.resolutionInput,
      )
      expect(persistenceErrorCode(() => persistence.recordRoleCandidateValidationOutcome({
        ...unrecordedA.outcomeInput(unrecordedResolution.assessmentRevision),
        contributionId: b.contributionId,
      }))).toBe('role_candidate_validation_conflict')
      expect(persistence.getAssessmentRecord(ASSESSMENT_ID)!.assessmentRevision)
        .toBe(unrecordedResolution.assessmentRevision)
      expect(unrecordedResolution.assessmentRevision).toBe(revision + 1)
    } finally {
      persistence.close()
    }
  })

  it('keeps per-Contribution history and current Outcomes after a later attempt and reopen', async () => {
    const store = await twoContributionStore()
    const { databasePath, persistence, a, b } = store
    let validatedA: ReturnType<typeof validate>
    let rejectedB: ReturnType<typeof validate>
    let unresolvedA: ReturnType<typeof validate>
    try {
      validatedA = validate(store, a, '000000000291', ['CLAIM_VALIDATION', 'NEGATIVE_CONTROL'])
      rejectedB = validate(store, b, '000000000292', ['CLAIM_REJECTION', 'NEGATIVE_CONTROL'])
      unresolvedA = validate(store, a, '000000000293', ['NEGATIVE_CONTROL'])
      expect(unresolvedA.durable.outcome.state).toBe('UNRESOLVED')
    } finally {
      persistence.close()
    }

    const reopened = await openSecurityPersistence({ databasePath })
    try {
      expect(reopened.getCurrentRoleCandidateValidation(
        ASSESSMENT_ID,
        a.contributionId,
        SHARED_CANDIDATE_ID,
      )).toEqual(unresolvedA.durable)
      expect(reopened.getCurrentRoleCandidateValidation(
        ASSESSMENT_ID,
        b.contributionId,
        SHARED_CANDIDATE_ID,
      )).toEqual(rejectedB.durable)
      expect(reopened.getRoleCandidateValidationByAttempt(
        ASSESSMENT_ID,
        validatedA.durable.outcome.validationAttemptId,
      )).toEqual(validatedA.durable)
    } finally {
      reopened.close()
    }

    const forensic = new DatabaseSync(databasePath, { readOnly: true })
    try {
      expect(forensic.prepare(`
        SELECT r.contribution_id, o.outcome_state
        FROM role_candidate_validation_outcomes o
        JOIN role_candidate_validation_resolutions r
          ON r.assessment_id = o.assessment_id
          AND r.validation_attempt_id = o.validation_attempt_id
        ORDER BY o.assessment_revision
      `).all()).toEqual([
        { contribution_id: a.contributionId, outcome_state: 'VALIDATED' },
        { contribution_id: b.contributionId, outcome_state: 'REJECTED' },
        { contribution_id: a.contributionId, outcome_state: 'UNRESOLVED' },
      ])
    } finally {
      forensic.close()
    }
  })
})
