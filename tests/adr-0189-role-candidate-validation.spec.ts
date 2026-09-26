import { describe, expect, it } from 'vitest'
import { createRoleContextGrantV1 } from '../src/role-context-grant.ts'
import { binaryDigest, structuredDigest } from '../src/internal/canonical.ts'
import {
  createRoleCandidateAdmissionsV1,
} from '../src/internal/role-candidate-admission.ts'
import {
  candidateProducerLineageDigestV1,
  createQualifiedRoleCandidateValidationContractV1,
  createRoleCandidateValidationContractV1,
  createRoleCandidateValidationEligibilityDecisionV1,
  createRoleCandidateValidationIndependenceDecisionV1,
  createRoleCandidateValidationOutcomeV1,
  createRoleCandidateValidationProofV1,
  parseRoleCandidateValidationContractResolutionV1,
  parseRoleCandidateValidationOutcomeV1,
  resolveRoleCandidateValidationContractV1,
  ROLE_CANDIDATE_VALIDATION_OUTCOME_MEDIA_TYPE,
} from '../src/internal/role-candidate-validation.ts'
import type {
  QualifiedRoleCandidateValidationContractV1,
  RoleCandidateValidationContractResolutionV1,
  RoleCandidateValidationEvidenceIdentityV1,
  RoleCandidateValidationProofPurpose,
  RoleCandidateValidationProofV1,
} from '../src/internal/role-candidate-validation.ts'
import {
  createRoleContributionAdmissionLinkV1,
  createRoleContributionV1,
} from '../src/internal/role-contribution.ts'
import { MODEL_INVOCATION_RECORD_MEDIA_TYPE } from '../src/internal/model-invocation-settlement.ts'
import { SOURCE_SLICE_EGRESS_ATTEMPT_FENCE_MEDIA_TYPE } from '../src/internal/source-slice-egress-invocation.ts'

const ASSESSMENT_ID = 'asm-018f1f9a-29a3-7b11-b6de-2f6f7f5b8189' as const
const ATTEMPT_ID = 'role-attempt-018f1f9a-29a3-7b11-b6de-2f6f7f5b8189'
const CONTRIBUTION_ID = 'role-contribution-018f1f9a-29a3-4b11-b6de-2f6f7f5b8189'
const CANDIDATE_ID = `candidate-${'9'.repeat(64)}`
const DECIDED_AT = '2026-09-15T01:00:00.000Z'
const SOURCE_TEXT = '{"scripts":{"preinstall":"node install.js"}}'
const SOURCE_DIGEST = binaryDigest('application/octet-stream', Buffer.from(SOURCE_TEXT, 'utf8'))
const SUBJECT_DIGEST = structuredDigest(
  'application/vnd.dsh.security.subject-manifest+json',
  { assessmentId: ASSESSMENT_ID },
)
const POLICY_DIGEST = structuredDigest('application/vnd.dsh.security.policy+json', {
  policyId: 'security/deep-policy',
  version: '1.0.0',
})
const VALIDATOR_DEFINITION_DIGEST = structuredDigest(
  'application/vnd.dsh.security.validator-definition+json',
  { validatorId: 'validator/install-script', version: '1.0.0' },
)
const VALIDATION_CONTEXT = {
  policyId: 'security/deep-policy',
  policyDigest: POLICY_DIGEST,
  assessmentMode: 'REPOSITORY' as const,
  ecosystemId: 'ecosystem/node',
  executionBoundaryId: 'execution/offline-sandbox',
}
const ROLE_DEFINITION = {
  roleId: 'discovery-analyst' as const,
  roleVersion: '1.0.0',
  definitionDigest: structuredDigest('application/vnd.dsh.security.role-definition+json', {
    roleId: 'discovery-analyst',
    roleVersion: '1.0.0',
  }),
}

function admissionFixture() {
  const contextGrant = createRoleContextGrantV1({
    schemaVersion: 1,
    assessmentId: ASSESSMENT_ID,
    roleAttemptId: ATTEMPT_ID,
    roleDefinition: ROLE_DEFINITION,
    purpose: {
      purposeId: 'security/deep-discovery',
      assessmentMode: 'REPOSITORY',
      assessmentProfileId: 'security/deep',
      targetDigest: structuredDigest('application/vnd.dsh.security.target-selector+json', {
        kind: 'repository',
      }),
      coverageObligationIds: ['security/install-lifecycle'],
      constraintIds: ['security/read-only'],
      peerContributionVisibility: 'NONE',
    },
    subject: {
      digest: SUBJECT_DIGEST,
      inventory: [{
        artifactId: 'subject-inventory',
        schemaId: 'dsh/security-subject-inventory',
        digest: structuredDigest('application/vnd.dsh.security.subject-inventory+json', {
          subjectDigest: SUBJECT_DIGEST,
        }),
        disclosureCategoryId: 'security/subject-inventory',
      }],
      sourceSlices: [{
        artifactId: 'source-slice-package-json',
        schemaId: 'dsh/security-source-slice',
        digest: structuredDigest('application/vnd.dsh.security.source-slice+json', {
          path: 'package.json',
          digest: SOURCE_DIGEST,
        }),
        disclosureCategoryId: 'security/source-slice',
      }],
    },
    evidenceProjections: [],
    disclosure: {
      dataEgressPolicyId: 'egress/deny-by-default',
      destinationId: 'provider/reference',
      categoryIds: ['security/source-slice', 'security/subject-inventory'],
    },
    budget: {
      contextBytes: { limit: 65_536, granted: 8_192 },
      tokens: { limit: 8_192, granted: 4_096 },
    },
  })
  const contribution = createRoleContributionV1({
    schemaVersion: 1,
    contributionId: CONTRIBUTION_ID,
    assessmentId: ASSESSMENT_ID,
    subjectDigest: SUBJECT_DIGEST,
    parentAttempt: {
      attemptId: ATTEMPT_ID,
      generation: 1,
      fenceDigest: structuredDigest(SOURCE_SLICE_EGRESS_ATTEMPT_FENCE_MEDIA_TYPE, {
        attemptId: ATTEMPT_ID,
        generation: 1,
      }),
    },
    contextGrantDigest: contextGrant.grantDigest,
    roleDefinition: ROLE_DEFINITION,
    modelInvocations: [{
      invocationId: 'invocation-role-0189',
      recordDigest: structuredDigest(MODEL_INVOCATION_RECORD_MEDIA_TYPE, {
        invocationId: 'invocation-role-0189',
      }),
      responseDigest: binaryDigest('application/json', Buffer.from('{"ok":true}', 'utf8')),
      inputTokens: 120,
      outputTokens: 80,
    }],
    hypotheses: [],
    candidateFindings: [{
      schemaVersion: 1,
      candidateId: CANDIDATE_ID,
      weaknessClassification: {
        schemaVersion: 1,
        primary: 'cwe/94',
        secondary: ['security/install-lifecycle'],
      },
      affectedControlId: 'security/node-package-lifecycle',
      securityClaim: 'A repository-controlled install script executes during installation.',
      sourceAnchors: [{
        path: 'package.json',
        fileDigest: SOURCE_DIGEST,
        byteSpan: { start: 0, length: SOURCE_DIGEST.byteLength },
        symbolId: '/scripts/preinstall',
      }],
      evidenceArtifactIds: ['candidate-source-trace'],
    }],
    coverageObservations: [],
    evidenceArtifactIds: ['candidate-source-trace'],
    evidenceRequests: [],
    challenges: [],
    uncertainty: [],
    limitations: [],
    followUpRequests: [],
    resourceUse: { requests: 1, inputTokens: 120, outputTokens: 80, tokens: 200 },
    completionDisposition: 'PARTIAL',
  })
  const link = createRoleContributionAdmissionLinkV1({
    contribution,
    assessmentRevision: 12,
    admittedAt: '2026-09-15T00:00:00.000Z',
  })
  return createRoleCandidateAdmissionsV1({
    contextGrant,
    contribution,
    contributionAdmissionLink: link,
    sourceSlices: [{
      contextArtifactId: 'source-slice-package-json',
      subjectDigest: SUBJECT_DIGEST,
      path: 'package.json',
      digest: SOURCE_DIGEST,
      text: SOURCE_TEXT,
    }],
    durableEvidenceArtifactIds: ['candidate-source-trace'],
  })[0]!
}

function qualifiedContract(
  contractVersion = '1.0.0',
  minimumDistinctValidationLineages = 1,
): QualifiedRoleCandidateValidationContractV1 {
  const contract = createRoleCandidateValidationContractV1({
    schemaVersion: 1,
    contractId: 'security/install-script-validation',
    contractVersion,
    selectors: {
      ...VALIDATION_CONTEXT,
      primaryWeaknessId: 'cwe/94',
      affectedControlId: 'security/node-package-lifecycle',
    },
    claimConditionId: 'condition/install-script-executes',
    claimEvidenceSchemaIds: ['evidence/install-script-reproduction'],
    counterEvidence: [{
      rejectionConditionId: 'condition/install-script-unreachable',
      evidenceSchemaIds: ['evidence/install-script-counterexample'],
    }],
    requiredNegativeControls: [{
      negativeControlId: 'control/fixture-without-install-script',
      evidenceSchemaIds: ['evidence/negative-control-result'],
    }],
    independencePolicy: {
      policyId: 'independence/provenance-graph-v1',
      minimumDistinctValidationLineages,
    },
  })
  return createQualifiedRoleCandidateValidationContractV1({
    schemaVersion: 1,
    qualificationId: `qualification/install-script-validator-${contractVersion.replaceAll('.', '-')}`,
    contract,
    validatorCapabilityId: 'validator/install-script',
    validatorVersion: '1.0.0',
    validatorDefinitionDigest: VALIDATOR_DEFINITION_DIGEST,
    executionBoundaryId: VALIDATION_CONTEXT.executionBoundaryId,
    qualifiedAt: '2026-09-14T00:00:00.000Z',
    validUntil: '2026-09-16T00:00:00.000Z',
  })
}

function resolutionFixture(
  contracts: readonly QualifiedRoleCandidateValidationContractV1[] = [qualifiedContract()],
): { admission: ReturnType<typeof admissionFixture>; resolution: RoleCandidateValidationContractResolutionV1 } {
  const admission = admissionFixture()
  return {
    admission,
    resolution: resolveRoleCandidateValidationContractV1({
      admission,
      validationContext: VALIDATION_CONTEXT,
      qualifiedContracts: contracts,
      resolvedAt: DECIDED_AT,
    }),
  }
}

const EVIDENCE_BY_PURPOSE = {
  CLAIM_VALIDATION: {
    artifactId: 'validation-reproduction',
    schemaId: 'evidence/install-script-reproduction',
    digest: structuredDigest('application/vnd.dsh.security.validation-evidence+json', { ok: true }),
  },
  CLAIM_REJECTION: {
    artifactId: 'validation-counterexample',
    schemaId: 'evidence/install-script-counterexample',
    digest: structuredDigest('application/vnd.dsh.security.counter-evidence+json', { ok: true }),
  },
  NEGATIVE_CONTROL: {
    artifactId: 'validation-negative-control',
    schemaId: 'evidence/negative-control-result',
    digest: structuredDigest('application/vnd.dsh.security.negative-control+json', { ok: true }),
  },
} as const satisfies Record<RoleCandidateValidationProofPurpose, RoleCandidateValidationEvidenceIdentityV1>

const CONDITION_BY_PURPOSE = {
  CLAIM_VALIDATION: 'condition/install-script-executes',
  CLAIM_REJECTION: 'condition/install-script-unreachable',
  NEGATIVE_CONTROL: 'control/fixture-without-install-script',
} as const satisfies Record<RoleCandidateValidationProofPurpose, string>

function proofFixture(
  purpose: RoleCandidateValidationProofPurpose,
  values: ReturnType<typeof resolutionFixture>,
  overrides: {
    readonly independenceState?: 'INDEPENDENT' | 'NOT_INDEPENDENT' | 'UNRESOLVED'
    readonly eligibilityState?: 'ELIGIBLE' | 'INELIGIBLE'
    readonly result?: RoleCandidateValidationProofV1['result']
    readonly evidence?: RoleCandidateValidationEvidenceIdentityV1
    readonly suffix?: string
  } = {},
): RoleCandidateValidationProofV1 {
  const contract = values.resolution.contract!
  const evidence = overrides.evidence ?? EVIDENCE_BY_PURPOSE[purpose]
  const conditionId = CONDITION_BY_PURPOSE[purpose]
  const suffix = overrides.suffix ?? (
    purpose === 'CLAIM_VALIDATION' ? '018900000001'
      : purpose === 'CLAIM_REJECTION' ? '018900000002' : '018900000003'
  )
  const eligibilityDecision = createRoleCandidateValidationEligibilityDecisionV1({
    schemaVersion: 1,
    state: overrides.eligibilityState ?? 'ELIGIBLE',
    candidateId: values.admission.candidateId,
    candidateAdmissionDigest: values.admission.admissionDigest,
    contractDefinitionDigest: contract.definitionDigest,
    policyDigest: VALIDATION_CONTEXT.policyDigest,
    purpose,
    conditionId,
    evidence,
    reasonCode: overrides.eligibilityState === 'INELIGIBLE'
      ? 'eligibility/purpose-mismatch'
      : 'eligibility/contract-satisfied',
    decidedAt: DECIDED_AT,
  })
  const independenceDecision = createRoleCandidateValidationIndependenceDecisionV1({
    schemaVersion: 1,
    state: overrides.independenceState ?? 'INDEPENDENT',
    independencePolicyId: contract.independencePolicy.policyId,
    candidateProducerLineageDigest: candidateProducerLineageDigestV1(values.admission),
    validationLineageDigest: structuredDigest(
      'application/vnd.dsh.security.validation-lineage+json',
      { purpose, suffix },
    ),
    provenanceGraphDigest: structuredDigest(
      'application/vnd.dsh.security.provenance-graph+json',
      { candidateId: values.admission.candidateId, purpose, suffix },
    ),
    reasonCode: overrides.independenceState === 'NOT_INDEPENDENT'
      ? 'independence/shared-provenance'
      : 'independence/provenance-graph-separated',
    decidedAt: DECIDED_AT,
  })
  return createRoleCandidateValidationProofV1({
    schemaVersion: 1,
    proofId: `role-candidate-validation-proof-018f1f9a-29a3-4b11-b6de-${suffix}`,
    purpose,
    conditionId,
    evidence,
    result: overrides.result ?? 'PROVED',
    validator: {
      validatorId: 'validator/install-script',
      validatorVersion: '1.0.0',
      definitionDigest: VALIDATOR_DEFINITION_DIGEST,
    },
    eligibilityDecision,
    independenceDecision,
    observedAt: DECIDED_AT,
  })
}

function outcomeFixture(
  values: ReturnType<typeof resolutionFixture>,
  proofs: readonly RoleCandidateValidationProofV1[],
) {
  return createRoleCandidateValidationOutcomeV1({
    validationAttemptId:
      'role-candidate-validation-attempt-018f1f9a-29a3-4b11-b6de-018900000001',
    assessmentRevision: 13,
    admission: values.admission,
    resolution: values.resolution,
    proofs,
    durableEvidence: proofs.map(proof => proof.evidence),
    decidedAt: DECIDED_AT,
  })
}

describe('ADR 0189-0192 Role Candidate Validation', () => {
  it('freezes the one exact, current, qualified Contract before deriving VALIDATED', () => {
    const values = resolutionFixture()
    const claim = proofFixture('CLAIM_VALIDATION', values)
    const negativeControl = proofFixture('NEGATIVE_CONTROL', values)
    const outcome = outcomeFixture(values, [negativeControl, claim])

    expect(values.resolution).toMatchObject({
      state: 'RESOLVED',
      contract: { contractId: 'security/install-script-validation', contractVersion: '1.0.0' },
      qualification: { validatorCapabilityId: 'validator/install-script' },
      unresolvedReason: null,
    })
    expect(outcome).toMatchObject({
      state: 'VALIDATED',
      candidateId: CANDIDATE_ID,
      contractResolutionDigest: values.resolution.resolutionDigest,
      contractDefinitionDigest: values.resolution.contract?.definitionDigest,
      proofGaps: [],
    })
    expect(outcome.qualifyingProofIds).toEqual([claim.proofId, negativeControl.proofId].sort())
    expect(outcome.outcomeDigest.mediaType).toBe(ROLE_CANDIDATE_VALIDATION_OUTCOME_MEDIA_TYPE)
    expect(parseRoleCandidateValidationContractResolutionV1(
      structuredClone(values.resolution),
    )).toEqual(values.resolution)
    expect(parseRoleCandidateValidationOutcomeV1(structuredClone(outcome))).toEqual(outcome)
    expect(Object.isFrozen(outcome.proofs[0]?.eligibilityDecision)).toBe(true)
  })

  it('derives REJECTED only from eligible Counter-Evidence and a satisfied negative control', () => {
    const values = resolutionFixture()
    const counterEvidence = proofFixture('CLAIM_REJECTION', values)
    const negativeControl = proofFixture('NEGATIVE_CONTROL', values)

    expect(outcomeFixture(values, [counterEvidence, negativeControl])).toMatchObject({
      state: 'REJECTED',
      proofGaps: [],
    })
    expect(outcomeFixture(values, [negativeControl])).toMatchObject({
      state: 'UNRESOLVED',
      proofGaps: expect.arrayContaining([
        'ELIGIBLE_CLAIM_PROOF_MISSING',
        'ELIGIBLE_COUNTER_EVIDENCE_MISSING',
      ]),
    })
  })

  it('keeps missing, ambiguous, dependent, and conflicting validation unresolved', () => {
    const noContract = resolutionFixture([])
    expect(outcomeFixture(noContract, [])).toMatchObject({
      state: 'UNRESOLVED',
      proofGaps: ['VALIDATION_CONTRACT_UNAVAILABLE'],
    })

    const ambiguous = resolutionFixture([qualifiedContract('1.0.0'), qualifiedContract('1.0.1')])
    expect(ambiguous.resolution).toMatchObject({
      state: 'UNRESOLVED',
      unresolvedReason: 'AMBIGUOUS_QUALIFIED_CONTRACT',
    })
    expect(outcomeFixture(ambiguous, [])).toMatchObject({
      state: 'UNRESOLVED',
      proofGaps: ['VALIDATION_CONTRACT_AMBIGUOUS'],
    })

    const values = resolutionFixture()
    const dependentClaim = proofFixture('CLAIM_VALIDATION', values, {
      independenceState: 'NOT_INDEPENDENT',
    })
    const negativeControl = proofFixture('NEGATIVE_CONTROL', values)
    expect(outcomeFixture(values, [dependentClaim, negativeControl])).toMatchObject({
      state: 'UNRESOLVED',
      proofGaps: expect.arrayContaining(['INDEPENDENT_VALIDATION_LINEAGE_MISSING']),
    })

    const claim = proofFixture('CLAIM_VALIDATION', values)
    const counterEvidence = proofFixture('CLAIM_REJECTION', values)
    expect(outcomeFixture(values, [claim, counterEvidence, negativeControl])).toMatchObject({
      state: 'UNRESOLVED',
      proofGaps: ['CONFLICTING_ELIGIBLE_PROOF'],
    })
  })

  it('fails closed on post-result Contract selection, phantom Evidence, and digest tampering', () => {
    const values = resolutionFixture()
    const claim = proofFixture('CLAIM_VALIDATION', values)
    const negativeControl = proofFixture('NEGATIVE_CONTROL', values)

    expect(() => createRoleCandidateValidationOutcomeV1({
      validationAttemptId:
        'role-candidate-validation-attempt-018f1f9a-29a3-4b11-b6de-018900000001',
      assessmentRevision: 13,
      admission: values.admission,
      resolution: values.resolution,
      proofs: [claim, negativeControl],
      durableEvidence: [negativeControl.evidence],
      decidedAt: DECIDED_AT,
    })).toThrow(/durable Evidence binding/iu)
    expect(() => createRoleCandidateValidationOutcomeV1({
      validationAttemptId:
        'role-candidate-validation-attempt-018f1f9a-29a3-4b11-b6de-018900000001',
      assessmentRevision: 13,
      admission: values.admission,
      resolution: resolveRoleCandidateValidationContractV1({
        admission: values.admission,
        validationContext: VALIDATION_CONTEXT,
        qualifiedContracts: [],
        resolvedAt: DECIDED_AT,
      }),
      proofs: [claim],
      durableEvidence: [claim.evidence],
      decidedAt: DECIDED_AT,
    })).toThrow(/without a resolved Contract/iu)

    const outcome = outcomeFixture(values, [claim, negativeControl])
    expect(() => parseRoleCandidateValidationOutcomeV1({
      ...structuredClone(outcome),
      state: 'REJECTED',
    })).toThrow(/digest|qualifying proof|inconsistent/iu)
    expect(() => parseRoleCandidateValidationContractResolutionV1({
      ...structuredClone(values.resolution),
      resolutionDigest: { ...values.resolution.resolutionDigest, value: '0'.repeat(64) },
    })).toThrow(/digest/iu)
  })
})

function distinctProof(
  purpose: RoleCandidateValidationProofPurpose,
  values: ReturnType<typeof resolutionFixture>,
  suffix: string,
  overrides: Omit<NonNullable<Parameters<typeof proofFixture>[2]>, 'suffix' | 'evidence'> = {},
): RoleCandidateValidationProofV1 {
  const base = EVIDENCE_BY_PURPOSE[purpose]
  return proofFixture(purpose, values, {
    ...overrides,
    suffix,
    evidence: {
      ...base,
      artifactId: `${base.artifactId}-${suffix}`,
      digest: structuredDigest(
        'application/vnd.dsh.security.validation-evidence+json',
        { purpose, suffix },
      ),
    },
  })
}

describe('ADR 0175 and 0190 conflicting eligible proof', () => {
  const twoLineages = () => resolutionFixture([qualifiedContract('1.0.0', 2)])

  it('keeps two qualifying claim proofs against one qualifying Counter-Evidence UNRESOLVED', () => {
    const values = twoLineages()
    const proofs = [
      distinctProof('CLAIM_VALIDATION', values, '018900000011'),
      distinctProof('CLAIM_VALIDATION', values, '018900000012'),
      distinctProof('CLAIM_REJECTION', values, '018900000021'),
      distinctProof('NEGATIVE_CONTROL', values, '018900000031'),
    ]
    const outcome = outcomeFixture(values, proofs)

    expect(outcome).toMatchObject({
      state: 'UNRESOLVED',
      proofGaps: ['CONFLICTING_ELIGIBLE_PROOF', 'ELIGIBLE_COUNTER_EVIDENCE_MISSING'],
    })
    expect(outcome.qualifyingProofIds).toEqual(proofs.map(proof => proof.proofId).sort())
  })

  it('keeps one qualifying claim proof against two qualifying Counter-Evidence UNRESOLVED', () => {
    const values = twoLineages()
    const outcome = outcomeFixture(values, [
      distinctProof('CLAIM_VALIDATION', values, '018900000011'),
      distinctProof('CLAIM_REJECTION', values, '018900000021'),
      distinctProof('CLAIM_REJECTION', values, '018900000022'),
      distinctProof('NEGATIVE_CONTROL', values, '018900000031'),
    ])

    expect(outcome).toMatchObject({
      state: 'UNRESOLVED',
      proofGaps: ['CONFLICTING_ELIGIBLE_PROOF', 'ELIGIBLE_CLAIM_PROOF_MISSING'],
    })
  })

  it('keeps proof and Counter-Evidence that both meet the lineage minimum UNRESOLVED', () => {
    const values = twoLineages()
    expect(outcomeFixture(values, [
      distinctProof('CLAIM_VALIDATION', values, '018900000011'),
      distinctProof('CLAIM_VALIDATION', values, '018900000012'),
      distinctProof('CLAIM_REJECTION', values, '018900000021'),
      distinctProof('CLAIM_REJECTION', values, '018900000022'),
      distinctProof('NEGATIVE_CONTROL', values, '018900000031'),
    ])).toMatchObject({
      state: 'UNRESOLVED',
      proofGaps: ['CONFLICTING_ELIGIBLE_PROOF'],
    })
  })

  it('reports a qualifying conflict even while a required negative control is missing', () => {
    const values = resolutionFixture()
    expect(outcomeFixture(values, [
      distinctProof('CLAIM_VALIDATION', values, '018900000011'),
      distinctProof('CLAIM_REJECTION', values, '018900000021'),
    ])).toMatchObject({
      state: 'UNRESOLVED',
      proofGaps: ['CONFLICTING_ELIGIBLE_PROOF', 'REQUIRED_NEGATIVE_CONTROL_MISSING'],
    })
  })

  it('decides one direction when only that direction meets the Contract', () => {
    const values = twoLineages()
    const control = distinctProof('NEGATIVE_CONTROL', values, '018900000031')
    expect(outcomeFixture(values, [
      distinctProof('CLAIM_VALIDATION', values, '018900000011'),
      distinctProof('CLAIM_VALIDATION', values, '018900000012'),
      control,
    ])).toMatchObject({ state: 'VALIDATED', proofGaps: [] })
    expect(outcomeFixture(values, [
      distinctProof('CLAIM_REJECTION', values, '018900000021'),
      distinctProof('CLAIM_REJECTION', values, '018900000022'),
      control,
    ])).toMatchObject({ state: 'REJECTED', proofGaps: [] })
  })

  const nonQualifying = [
    ['ineligible', { eligibilityState: 'INELIGIBLE' }],
    ['not independent', { independenceState: 'NOT_INDEPENDENT' }],
    ['independence unresolved', { independenceState: 'UNRESOLVED' }],
    ['not proved', { result: 'NOT_PROVED' }],
    ['inconclusive', { result: 'INCONCLUSIVE' }],
  ] as const

  it.each(nonQualifying)(
    'does not treat %s opposing proof as a qualifying conflict',
    (_label, overrides) => {
      const values = twoLineages()
      const control = distinctProof('NEGATIVE_CONTROL', values, '018900000031')
      const opposingRejection = distinctProof(
        'CLAIM_REJECTION',
        values,
        '018900000021',
        overrides,
      )
      const validated = outcomeFixture(values, [
        distinctProof('CLAIM_VALIDATION', values, '018900000011'),
        distinctProof('CLAIM_VALIDATION', values, '018900000012'),
        opposingRejection,
        control,
      ])
      expect(validated).toMatchObject({ state: 'VALIDATED', proofGaps: [] })
      expect(validated.proofs.map(proof => proof.proofId)).toContain(opposingRejection.proofId)
      expect(validated.qualifyingProofIds).not.toContain(opposingRejection.proofId)

      const opposingClaim = distinctProof('CLAIM_VALIDATION', values, '018900000011', overrides)
      expect(outcomeFixture(values, [
        opposingClaim,
        distinctProof('CLAIM_REJECTION', values, '018900000021'),
        distinctProof('CLAIM_REJECTION', values, '018900000022'),
        control,
      ])).toMatchObject({ state: 'REJECTED', proofGaps: [] })
    },
  )

  it('refuses a re-digested Outcome that hides a qualifying conflict', () => {
    const values = twoLineages()
    const conflicting = outcomeFixture(values, [
      distinctProof('CLAIM_VALIDATION', values, '018900000011'),
      distinctProof('CLAIM_VALIDATION', values, '018900000012'),
      distinctProof('CLAIM_REJECTION', values, '018900000021'),
      distinctProof('NEGATIVE_CONTROL', values, '018900000031'),
    ])
    const { outcomeDigest: _digest, ...core } = structuredClone(conflicting)
    const forgedCore = { ...core, state: 'VALIDATED' as const, proofGaps: [] }

    expect(() => parseRoleCandidateValidationOutcomeV1({
      ...forgedCore,
      outcomeDigest: structuredDigest(ROLE_CANDIDATE_VALIDATION_OUTCOME_MEDIA_TYPE, forgedCore),
    })).toThrow(/conflict/iu)
  })
})
