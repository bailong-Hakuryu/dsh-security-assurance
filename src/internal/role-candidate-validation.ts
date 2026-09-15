import { z } from 'zod'
import type { AssessmentId, AssessmentMode, DigestEnvelopeV1 } from '../contracts.ts'
import {
  assessmentIdSchema,
  assessmentModeSchema,
  digestEnvelopeV1Schema,
} from '../contracts.ts'
import { canonicalJson, structuredDigest } from './canonical.ts'
import { deepFreeze } from './freeze.ts'
import type { RoleCandidateAdmissionV1 } from './role-candidate-admission.ts'
import { parseRoleCandidateAdmissionV1 } from './role-candidate-admission.ts'

export const ROLE_CANDIDATE_VALIDATION_CONTRACT_MEDIA_TYPE =
  'application/vnd.dsh.security.role-candidate-validation-contract+json'
export const ROLE_CANDIDATE_VALIDATION_CONTRACT_QUALIFICATION_MEDIA_TYPE =
  'application/vnd.dsh.security.role-candidate-validation-contract-qualification+json'
export const ROLE_CANDIDATE_VALIDATION_CONTRACT_RESOLUTION_MEDIA_TYPE =
  'application/vnd.dsh.security.role-candidate-validation-contract-resolution+json'
export const ROLE_CANDIDATE_VALIDATION_ELIGIBILITY_DECISION_MEDIA_TYPE =
  'application/vnd.dsh.security.role-candidate-validation-evidence-eligibility+json'
export const ROLE_CANDIDATE_VALIDATION_INDEPENDENCE_DECISION_MEDIA_TYPE =
  'application/vnd.dsh.security.role-candidate-validation-independence+json'
export const ROLE_CANDIDATE_VALIDATION_PROOF_MEDIA_TYPE =
  'application/vnd.dsh.security.role-candidate-validation-proof+json'
export const ROLE_CANDIDATE_VALIDATION_OUTCOME_MEDIA_TYPE =
  'application/vnd.dsh.security.role-candidate-validation-outcome+json'
export const ROLE_CANDIDATE_VALIDATION_OUTCOME_REQUEST_MEDIA_TYPE =
  'application/vnd.dsh.security.role-candidate-validation-outcome-request+json'
export const ROLE_CANDIDATE_VALIDATION_RESOLUTION_REQUEST_MEDIA_TYPE =
  'application/vnd.dsh.security.role-candidate-validation-resolution-request+json'
export const ROLE_CANDIDATE_PRODUCER_LINEAGE_MEDIA_TYPE =
  'application/vnd.dsh.security.role-candidate-producer-lineage+json'

const MAX_CONTRACTS = 64
const MAX_PROOFS = 256
const MAX_NEGATIVE_CONTROLS = 32
const MAX_EVIDENCE_SCHEMAS = 64
const MAX_INDEPENDENT_LINEAGES = 8

const registryIdSchema = z.string()
  .min(3)
  .max(256)
  .regex(/^[a-z0-9][a-z0-9._-]*(?:\/[a-z0-9][a-z0-9._-]*){1,7}$/u)
const artifactIdSchema = z.string().regex(/^[a-z0-9][a-z0-9-]{0,127}$/u)
const candidateIdSchema = z.string().regex(/^candidate-[0-9a-f]{64}$/u)
const validationAttemptIdSchema = z.string().regex(
  /^role-candidate-validation-attempt-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u,
)
const validationProofIdSchema = z.string().regex(
  /^role-candidate-validation-proof-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u,
)
const semanticVersionSchema = z.string()
  .max(128)
  .regex(/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/u)

function digestSchema(mediaType: string, message: string) {
  return digestEnvelopeV1Schema.refine(
    value => value.mediaType === mediaType && value.canonicalization === 'dsh-canonical-json-v1',
    message,
  )
}

const contractDigestSchema = digestSchema(
  ROLE_CANDIDATE_VALIDATION_CONTRACT_MEDIA_TYPE,
  'Role Candidate Validation Contract digest has the wrong media type',
)
const qualificationDigestSchema = digestSchema(
  ROLE_CANDIDATE_VALIDATION_CONTRACT_QUALIFICATION_MEDIA_TYPE,
  'Role Candidate Validation Contract qualification digest has the wrong media type',
)
const resolutionDigestSchema = digestSchema(
  ROLE_CANDIDATE_VALIDATION_CONTRACT_RESOLUTION_MEDIA_TYPE,
  'Role Candidate Validation Contract Resolution digest has the wrong media type',
)
const eligibilityDigestSchema = digestSchema(
  ROLE_CANDIDATE_VALIDATION_ELIGIBILITY_DECISION_MEDIA_TYPE,
  'Role Candidate Validation Evidence Eligibility Decision digest has the wrong media type',
)
const independenceDigestSchema = digestSchema(
  ROLE_CANDIDATE_VALIDATION_INDEPENDENCE_DECISION_MEDIA_TYPE,
  'Role Candidate Validation independence decision digest has the wrong media type',
)
const proofDigestSchema = digestSchema(
  ROLE_CANDIDATE_VALIDATION_PROOF_MEDIA_TYPE,
  'Role Candidate Validation proof digest has the wrong media type',
)
const outcomeDigestSchema = digestSchema(
  ROLE_CANDIDATE_VALIDATION_OUTCOME_MEDIA_TYPE,
  'Role Candidate Validation Outcome digest has the wrong media type',
)

function assertUnique(values: readonly string[], message: string): void {
  if (new Set(values).size !== values.length) throw new Error(message)
}

function same(left: unknown, right: unknown): boolean {
  return canonicalJson(left) === canonicalJson(right)
}

export interface RoleCandidateValidationContextV1 {
  readonly policyId: string
  readonly policyDigest: DigestEnvelopeV1
  readonly assessmentMode: AssessmentMode
  readonly ecosystemId: string
  readonly executionBoundaryId: string
}

const roleCandidateValidationContextV1Shape = {
  policyId: registryIdSchema,
  policyDigest: digestEnvelopeV1Schema,
  assessmentMode: assessmentModeSchema,
  ecosystemId: registryIdSchema,
  executionBoundaryId: registryIdSchema,
} as const
const roleCandidateValidationContextV1Schema: z.ZodType<RoleCandidateValidationContextV1> =
  z.strictObject(roleCandidateValidationContextV1Shape)

export interface RoleCandidateValidationContractCoreV1 {
  readonly schemaVersion: 1
  readonly contractId: string
  readonly contractVersion: string
  readonly selectors: RoleCandidateValidationContextV1 & {
    readonly primaryWeaknessId: string
    readonly affectedControlId: string
  }
  readonly claimConditionId: string
  readonly claimEvidenceSchemaIds: readonly string[]
  readonly counterEvidence: readonly {
    readonly rejectionConditionId: string
    readonly evidenceSchemaIds: readonly string[]
  }[]
  readonly requiredNegativeControls: readonly {
    readonly negativeControlId: string
    readonly evidenceSchemaIds: readonly string[]
  }[]
  readonly independencePolicy: {
    readonly policyId: string
    readonly minimumDistinctValidationLineages: number
  }
}

export interface RoleCandidateValidationContractV1
  extends RoleCandidateValidationContractCoreV1 {
  readonly definitionDigest: DigestEnvelopeV1
}

const evidenceSchemaIdsSchema = z.array(registryIdSchema).min(1).max(MAX_EVIDENCE_SCHEMAS)
const roleCandidateValidationContractCoreV1Shape = {
  schemaVersion: z.literal(1),
  contractId: registryIdSchema,
  contractVersion: semanticVersionSchema,
  selectors: z.strictObject({
    ...roleCandidateValidationContextV1Shape,
    primaryWeaknessId: registryIdSchema,
    affectedControlId: registryIdSchema,
  }),
  claimConditionId: registryIdSchema,
  claimEvidenceSchemaIds: evidenceSchemaIdsSchema,
  counterEvidence: z.array(z.strictObject({
    rejectionConditionId: registryIdSchema,
    evidenceSchemaIds: evidenceSchemaIdsSchema,
  })).max(32),
  requiredNegativeControls: z.array(z.strictObject({
    negativeControlId: registryIdSchema,
    evidenceSchemaIds: evidenceSchemaIdsSchema,
  })).max(MAX_NEGATIVE_CONTROLS),
  independencePolicy: z.strictObject({
    policyId: registryIdSchema,
    minimumDistinctValidationLineages: z.number().int().positive()
      .max(MAX_INDEPENDENT_LINEAGES),
  }),
} as const
const roleCandidateValidationContractCoreV1Schema:
z.ZodType<RoleCandidateValidationContractCoreV1> = z.strictObject(
  roleCandidateValidationContractCoreV1Shape,
).superRefine((contract, context) => {
  const duplicateSets = [
    contract.claimEvidenceSchemaIds,
    contract.counterEvidence.map(item => item.rejectionConditionId),
    contract.requiredNegativeControls.map(item => item.negativeControlId),
    ...contract.counterEvidence.map(item => item.evidenceSchemaIds),
    ...contract.requiredNegativeControls.map(item => item.evidenceSchemaIds),
  ].some(values => new Set(values).size !== values.length)
  if (duplicateSets) {
    context.addIssue({ code: 'custom', message: 'Validation Contract lists duplicate identities' })
  }
  const conditionIds = [
    contract.claimConditionId,
    ...contract.counterEvidence.map(item => item.rejectionConditionId),
    ...contract.requiredNegativeControls.map(item => item.negativeControlId),
  ]
  if (new Set(conditionIds).size !== conditionIds.length) {
    context.addIssue({ code: 'custom', message: 'Validation Contract condition identities overlap' })
  }
})

const roleCandidateValidationContractV1Schema: z.ZodType<RoleCandidateValidationContractV1> =
  z.strictObject({
    ...roleCandidateValidationContractCoreV1Shape,
    definitionDigest: contractDigestSchema,
  })

export function createRoleCandidateValidationContractV1(
  input: RoleCandidateValidationContractCoreV1,
): RoleCandidateValidationContractV1 {
  const core = roleCandidateValidationContractCoreV1Schema.parse(input)
  return deepFreeze({
    ...core,
    definitionDigest: structuredDigest(ROLE_CANDIDATE_VALIDATION_CONTRACT_MEDIA_TYPE, core),
  })
}

export function parseRoleCandidateValidationContractV1(
  input: unknown,
): RoleCandidateValidationContractV1 {
  const contract = roleCandidateValidationContractV1Schema.parse(input)
  const { definitionDigest, ...candidateCore } = contract
  const core = roleCandidateValidationContractCoreV1Schema.parse(candidateCore)
  if (!same(definitionDigest, structuredDigest(ROLE_CANDIDATE_VALIDATION_CONTRACT_MEDIA_TYPE, core))) {
    throw new Error('Role Candidate Validation Contract definition digest does not match')
  }
  return deepFreeze({ ...core, definitionDigest })
}

export interface QualifiedRoleCandidateValidationContractCoreV1 {
  readonly schemaVersion: 1
  readonly qualificationId: string
  readonly contract: RoleCandidateValidationContractV1
  readonly validatorCapabilityId: string
  readonly validatorVersion: string
  readonly validatorDefinitionDigest: DigestEnvelopeV1
  readonly executionBoundaryId: string
  readonly qualifiedAt: string
  readonly validUntil: string
}

export interface QualifiedRoleCandidateValidationContractV1
  extends QualifiedRoleCandidateValidationContractCoreV1 {
  readonly qualificationDigest: DigestEnvelopeV1
}

const qualifiedRoleCandidateValidationContractCoreV1Shape = {
  schemaVersion: z.literal(1),
  qualificationId: registryIdSchema,
  contract: roleCandidateValidationContractV1Schema,
  validatorCapabilityId: registryIdSchema,
  validatorVersion: semanticVersionSchema,
  validatorDefinitionDigest: digestEnvelopeV1Schema,
  executionBoundaryId: registryIdSchema,
  qualifiedAt: z.iso.datetime({ offset: true }),
  validUntil: z.iso.datetime({ offset: true }),
} as const
const qualifiedRoleCandidateValidationContractCoreV1Schema:
z.ZodType<QualifiedRoleCandidateValidationContractCoreV1> = z.strictObject(
  qualifiedRoleCandidateValidationContractCoreV1Shape,
).superRefine((qualification, context) => {
  if (Date.parse(qualification.qualifiedAt) >= Date.parse(qualification.validUntil)) {
    context.addIssue({ code: 'custom', message: 'Validation Contract qualification interval is invalid' })
  }
  if (qualification.executionBoundaryId !== qualification.contract.selectors.executionBoundaryId) {
    context.addIssue({
      code: 'custom',
      message: 'Validation Contract qualification execution boundary does not match its Contract',
    })
  }
})

const qualifiedRoleCandidateValidationContractV1Schema:
z.ZodType<QualifiedRoleCandidateValidationContractV1> = z.strictObject({
  ...qualifiedRoleCandidateValidationContractCoreV1Shape,
  qualificationDigest: qualificationDigestSchema,
})

export function createQualifiedRoleCandidateValidationContractV1(
  input: QualifiedRoleCandidateValidationContractCoreV1,
): QualifiedRoleCandidateValidationContractV1 {
  const parsed = qualifiedRoleCandidateValidationContractCoreV1Schema.parse(input)
  const core = {
    ...parsed,
    contract: parseRoleCandidateValidationContractV1(parsed.contract),
  }
  return deepFreeze({
    ...core,
    qualificationDigest: structuredDigest(
      ROLE_CANDIDATE_VALIDATION_CONTRACT_QUALIFICATION_MEDIA_TYPE,
      core,
    ),
  })
}

export function parseQualifiedRoleCandidateValidationContractV1(
  input: unknown,
): QualifiedRoleCandidateValidationContractV1 {
  const qualification = qualifiedRoleCandidateValidationContractV1Schema.parse(input)
  const { qualificationDigest, ...candidateCore } = qualification
  const core = qualifiedRoleCandidateValidationContractCoreV1Schema.parse({
    ...candidateCore,
    contract: parseRoleCandidateValidationContractV1(candidateCore.contract),
  })
  if (!same(qualificationDigest, structuredDigest(
    ROLE_CANDIDATE_VALIDATION_CONTRACT_QUALIFICATION_MEDIA_TYPE,
    core,
  ))) {
    throw new Error('Role Candidate Validation Contract qualification digest does not match')
  }
  return deepFreeze({ ...core, qualificationDigest })
}

export type RoleCandidateValidationResolutionState = 'RESOLVED' | 'UNRESOLVED'
export type RoleCandidateValidationResolutionReason =
  | 'NO_QUALIFIED_CONTRACT'
  | 'AMBIGUOUS_QUALIFIED_CONTRACT'

export interface RoleCandidateValidationContractResolutionCoreV1 {
  readonly schemaVersion: 1
  readonly assessmentId: AssessmentId
  readonly candidateId: string
  readonly candidateAdmissionDigest: DigestEnvelopeV1
  readonly subjectDigest: DigestEnvelopeV1
  readonly candidateSelectors: {
    readonly primaryWeaknessId: string
    readonly affectedControlId: string
  }
  readonly validationContext: RoleCandidateValidationContextV1
  readonly state: RoleCandidateValidationResolutionState
  readonly contract: RoleCandidateValidationContractV1 | null
  readonly qualification: QualifiedRoleCandidateValidationContractV1 | null
  readonly unresolvedReason: RoleCandidateValidationResolutionReason | null
  readonly consideredQualifications: readonly QualifiedRoleCandidateValidationContractV1[]
  readonly resolvedAt: string
}

export interface RoleCandidateValidationContractResolutionV1
  extends RoleCandidateValidationContractResolutionCoreV1 {
  readonly resolutionDigest: DigestEnvelopeV1
}

const resolutionCoreShape = {
  schemaVersion: z.literal(1),
  assessmentId: assessmentIdSchema,
  candidateId: candidateIdSchema,
  candidateAdmissionDigest: digestEnvelopeV1Schema,
  subjectDigest: digestEnvelopeV1Schema,
  candidateSelectors: z.strictObject({
    primaryWeaknessId: registryIdSchema,
    affectedControlId: registryIdSchema,
  }),
  validationContext: roleCandidateValidationContextV1Schema,
  state: z.enum(['RESOLVED', 'UNRESOLVED']),
  contract: roleCandidateValidationContractV1Schema.nullable(),
  qualification: qualifiedRoleCandidateValidationContractV1Schema.nullable(),
  unresolvedReason: z.enum([
    'NO_QUALIFIED_CONTRACT',
    'AMBIGUOUS_QUALIFIED_CONTRACT',
  ]).nullable(),
  consideredQualifications: z.array(qualifiedRoleCandidateValidationContractV1Schema)
    .max(MAX_CONTRACTS),
  resolvedAt: z.iso.datetime({ offset: true }),
} as const

function validateResolutionCore(
  resolution: RoleCandidateValidationContractResolutionCoreV1,
  context: z.RefinementCtx,
): void {
  const resolved = resolution.state === 'RESOLVED'
  if (
    resolved !== (resolution.contract !== null)
    || resolved !== (resolution.qualification !== null)
    || resolved === (resolution.unresolvedReason !== null)
  ) {
    context.addIssue({ code: 'custom', message: 'Validation Contract Resolution state is inconsistent' })
  }
  if (
    resolution.contract !== null
    && resolution.qualification !== null
    && !same(resolution.contract, resolution.qualification.contract)
  ) {
    context.addIssue({ code: 'custom', message: 'Resolved Contract and qualification do not match' })
  }
  if (new Set(resolution.consideredQualifications.map(
    item => item.qualificationDigest.value,
  )).size !== resolution.consideredQualifications.length) {
    context.addIssue({ code: 'custom', message: 'Contract Resolution repeats a qualification' })
  }
  const qualificationDigests = resolution.consideredQualifications.map(
    item => item.qualificationDigest.value,
  )
  if (canonicalJson(qualificationDigests) !== canonicalJson([...qualificationDigests].sort())) {
    context.addIssue({ code: 'custom', message: 'Contract Resolution catalog is not canonical' })
  }
  const instant = Date.parse(resolution.resolvedAt)
  const applicable = resolution.consideredQualifications.filter(item => (
    exactSelectors(resolution.candidateSelectors, resolution.validationContext, item.contract)
    && Date.parse(item.qualifiedAt) <= instant
    && instant < Date.parse(item.validUntil)
  ))
  const selected = applicable.length === 1 ? applicable[0]! : null
  if (
    (selected === null) !== (resolution.state === 'UNRESOLVED')
    || (selected !== null && !same(selected, resolution.qualification))
    || (selected !== null && !same(selected.contract, resolution.contract))
    || (selected === null && resolution.unresolvedReason !== (
      applicable.length === 0 ? 'NO_QUALIFIED_CONTRACT' : 'AMBIGUOUS_QUALIFIED_CONTRACT'
    ))
  ) {
    context.addIssue({ code: 'custom', message: 'Validation Contract Resolution selection is invalid' })
  }
}

const roleCandidateValidationContractResolutionCoreV1Schema:
z.ZodType<RoleCandidateValidationContractResolutionCoreV1> = z.strictObject(
  resolutionCoreShape,
).superRefine(validateResolutionCore)

const roleCandidateValidationContractResolutionV1Schema:
z.ZodType<RoleCandidateValidationContractResolutionV1> = z.strictObject({
  ...resolutionCoreShape,
  resolutionDigest: resolutionDigestSchema,
}).superRefine(validateResolutionCore)

function exactSelectors(
  candidate: {
    readonly primaryWeaknessId: string
    readonly affectedControlId: string
  },
  context: RoleCandidateValidationContextV1,
  contract: RoleCandidateValidationContractV1,
): boolean {
  return contract.selectors.primaryWeaknessId === candidate.primaryWeaknessId
    && contract.selectors.affectedControlId === candidate.affectedControlId
    && contract.selectors.policyId === context.policyId
    && same(contract.selectors.policyDigest, context.policyDigest)
    && contract.selectors.assessmentMode === context.assessmentMode
    && contract.selectors.ecosystemId === context.ecosystemId
    && contract.selectors.executionBoundaryId === context.executionBoundaryId
}

export interface ResolveRoleCandidateValidationContractOptionsV1 {
  readonly admission: RoleCandidateAdmissionV1
  readonly validationContext: RoleCandidateValidationContextV1
  readonly qualifiedContracts: readonly QualifiedRoleCandidateValidationContractV1[]
  readonly resolvedAt: string
}

export function resolveRoleCandidateValidationContractV1(
  options: ResolveRoleCandidateValidationContractOptionsV1,
): RoleCandidateValidationContractResolutionV1 {
  const admission = parseRoleCandidateAdmissionV1(options.admission)
  const validationContext = roleCandidateValidationContextV1Schema.parse(options.validationContext)
  const resolvedAt = z.iso.datetime({ offset: true }).parse(options.resolvedAt)
  if (options.qualifiedContracts.length > MAX_CONTRACTS) {
    throw new Error('Role Candidate Validation Contract catalog exceeds the v1 limit')
  }
  const qualifiedContracts = options.qualifiedContracts
    .map(parseQualifiedRoleCandidateValidationContractV1)
    .sort((left, right) => left.qualificationDigest.value.localeCompare(
      right.qualificationDigest.value,
    ))
  assertUnique(
    qualifiedContracts.map(item => item.qualificationDigest.value),
    'Role Candidate Validation Contract catalog repeats a qualification',
  )
  const instant = Date.parse(resolvedAt)
  const candidateSelectors = {
    primaryWeaknessId: admission.weaknessClassification.primary,
    affectedControlId: admission.affectedControlId,
  }
  const applicable = qualifiedContracts.filter(item => (
    exactSelectors(candidateSelectors, validationContext, item.contract)
    && Date.parse(item.qualifiedAt) <= instant
    && instant < Date.parse(item.validUntil)
  ))
  const selected = applicable.length === 1 ? applicable[0]! : null
  const core = roleCandidateValidationContractResolutionCoreV1Schema.parse({
    schemaVersion: 1,
    assessmentId: admission.assessmentId,
    candidateId: admission.candidateId,
    candidateAdmissionDigest: admission.admissionDigest,
    subjectDigest: admission.subjectDigest,
    candidateSelectors,
    validationContext,
    state: selected === null ? 'UNRESOLVED' : 'RESOLVED',
    contract: selected?.contract ?? null,
    qualification: selected,
    unresolvedReason: selected === null
      ? applicable.length === 0
        ? 'NO_QUALIFIED_CONTRACT'
        : 'AMBIGUOUS_QUALIFIED_CONTRACT'
      : null,
    consideredQualifications: qualifiedContracts,
    resolvedAt,
  })
  return deepFreeze({
    ...core,
    resolutionDigest: structuredDigest(
      ROLE_CANDIDATE_VALIDATION_CONTRACT_RESOLUTION_MEDIA_TYPE,
      core,
    ),
  })
}

export function parseRoleCandidateValidationContractResolutionV1(
  input: unknown,
): RoleCandidateValidationContractResolutionV1 {
  const resolution = roleCandidateValidationContractResolutionV1Schema.parse(input)
  const { resolutionDigest, ...candidateCore } = resolution
  const core = roleCandidateValidationContractResolutionCoreV1Schema.parse({
    ...candidateCore,
    contract: candidateCore.contract === null
      ? null
      : parseRoleCandidateValidationContractV1(candidateCore.contract),
    qualification: candidateCore.qualification === null
      ? null
      : parseQualifiedRoleCandidateValidationContractV1(candidateCore.qualification),
    consideredQualifications: candidateCore.consideredQualifications
      .map(parseQualifiedRoleCandidateValidationContractV1),
  })
  if (!same(resolutionDigest, structuredDigest(
    ROLE_CANDIDATE_VALIDATION_CONTRACT_RESOLUTION_MEDIA_TYPE,
    core,
  ))) {
    throw new Error('Role Candidate Validation Contract Resolution digest does not match')
  }
  return deepFreeze({ ...core, resolutionDigest })
}

export interface RoleCandidateValidationEvidenceIdentityV1 {
  readonly artifactId: string
  readonly schemaId: string
  readonly digest: DigestEnvelopeV1
}

const evidenceIdentityV1Schema: z.ZodType<RoleCandidateValidationEvidenceIdentityV1> =
  z.strictObject({
    artifactId: artifactIdSchema,
    schemaId: registryIdSchema,
    digest: digestEnvelopeV1Schema,
  })

export type RoleCandidateValidationProofPurpose =
  | 'CLAIM_VALIDATION'
  | 'CLAIM_REJECTION'
  | 'NEGATIVE_CONTROL'

export interface RoleCandidateValidationEligibilityDecisionCoreV1 {
  readonly schemaVersion: 1
  readonly state: 'ELIGIBLE' | 'INELIGIBLE'
  readonly candidateId: string
  readonly candidateAdmissionDigest: DigestEnvelopeV1
  readonly contractDefinitionDigest: DigestEnvelopeV1
  readonly policyDigest: DigestEnvelopeV1
  readonly purpose: RoleCandidateValidationProofPurpose
  readonly conditionId: string
  readonly evidence: RoleCandidateValidationEvidenceIdentityV1
  readonly reasonCode: string
  readonly decidedAt: string
}

export interface RoleCandidateValidationEligibilityDecisionV1
  extends RoleCandidateValidationEligibilityDecisionCoreV1 {
  readonly decisionDigest: DigestEnvelopeV1
}

const eligibilityCoreShape = {
  schemaVersion: z.literal(1),
  state: z.enum(['ELIGIBLE', 'INELIGIBLE']),
  candidateId: candidateIdSchema,
  candidateAdmissionDigest: digestEnvelopeV1Schema,
  contractDefinitionDigest: contractDigestSchema,
  policyDigest: digestEnvelopeV1Schema,
  purpose: z.enum(['CLAIM_VALIDATION', 'CLAIM_REJECTION', 'NEGATIVE_CONTROL']),
  conditionId: registryIdSchema,
  evidence: evidenceIdentityV1Schema,
  reasonCode: registryIdSchema,
  decidedAt: z.iso.datetime({ offset: true }),
} as const
const eligibilityCoreV1Schema: z.ZodType<RoleCandidateValidationEligibilityDecisionCoreV1> =
  z.strictObject(eligibilityCoreShape)
const eligibilityV1Schema: z.ZodType<RoleCandidateValidationEligibilityDecisionV1> =
  z.strictObject({ ...eligibilityCoreShape, decisionDigest: eligibilityDigestSchema })

export function createRoleCandidateValidationEligibilityDecisionV1(
  input: RoleCandidateValidationEligibilityDecisionCoreV1,
): RoleCandidateValidationEligibilityDecisionV1 {
  const core = eligibilityCoreV1Schema.parse(input)
  return deepFreeze({
    ...core,
    decisionDigest: structuredDigest(
      ROLE_CANDIDATE_VALIDATION_ELIGIBILITY_DECISION_MEDIA_TYPE,
      core,
    ),
  })
}

function parseEligibilityDecision(
  input: unknown,
): RoleCandidateValidationEligibilityDecisionV1 {
  const decision = eligibilityV1Schema.parse(input)
  const { decisionDigest, ...candidateCore } = decision
  const core = eligibilityCoreV1Schema.parse(candidateCore)
  if (!same(decisionDigest, structuredDigest(
    ROLE_CANDIDATE_VALIDATION_ELIGIBILITY_DECISION_MEDIA_TYPE,
    core,
  ))) {
    throw new Error('Role Candidate Validation Evidence Eligibility Decision digest does not match')
  }
  return deepFreeze({ ...core, decisionDigest })
}

export interface RoleCandidateValidationIndependenceDecisionCoreV1 {
  readonly schemaVersion: 1
  readonly state: 'INDEPENDENT' | 'NOT_INDEPENDENT' | 'UNRESOLVED'
  readonly independencePolicyId: string
  readonly candidateProducerLineageDigest: DigestEnvelopeV1
  readonly validationLineageDigest: DigestEnvelopeV1
  readonly provenanceGraphDigest: DigestEnvelopeV1
  readonly reasonCode: string
  readonly decidedAt: string
}

export interface RoleCandidateValidationIndependenceDecisionV1
  extends RoleCandidateValidationIndependenceDecisionCoreV1 {
  readonly decisionDigest: DigestEnvelopeV1
}

const independenceCoreShape = {
  schemaVersion: z.literal(1),
  state: z.enum(['INDEPENDENT', 'NOT_INDEPENDENT', 'UNRESOLVED']),
  independencePolicyId: registryIdSchema,
  candidateProducerLineageDigest: digestEnvelopeV1Schema,
  validationLineageDigest: digestEnvelopeV1Schema,
  provenanceGraphDigest: digestEnvelopeV1Schema,
  reasonCode: registryIdSchema,
  decidedAt: z.iso.datetime({ offset: true }),
} as const
const independenceCoreV1Schema: z.ZodType<RoleCandidateValidationIndependenceDecisionCoreV1> =
  z.strictObject(independenceCoreShape).superRefine((decision, context) => {
    if (
      decision.state === 'INDEPENDENT'
      && same(decision.candidateProducerLineageDigest, decision.validationLineageDigest)
    ) {
      context.addIssue({
        code: 'custom',
        message: 'Validation lineage cannot be independent from itself',
      })
    }
  })
const independenceV1Schema: z.ZodType<RoleCandidateValidationIndependenceDecisionV1> =
  z.strictObject({
    ...independenceCoreShape,
    decisionDigest: independenceDigestSchema,
  }).superRefine((decision, context) => {
    if (
      decision.state === 'INDEPENDENT'
      && same(decision.candidateProducerLineageDigest, decision.validationLineageDigest)
    ) {
      context.addIssue({
        code: 'custom',
        message: 'Validation lineage cannot be independent from itself',
      })
    }
  })

export function createRoleCandidateValidationIndependenceDecisionV1(
  input: RoleCandidateValidationIndependenceDecisionCoreV1,
): RoleCandidateValidationIndependenceDecisionV1 {
  const core = independenceCoreV1Schema.parse(input)
  return deepFreeze({
    ...core,
    decisionDigest: structuredDigest(
      ROLE_CANDIDATE_VALIDATION_INDEPENDENCE_DECISION_MEDIA_TYPE,
      core,
    ),
  })
}

function parseIndependenceDecision(
  input: unknown,
): RoleCandidateValidationIndependenceDecisionV1 {
  const decision = independenceV1Schema.parse(input)
  const { decisionDigest, ...candidateCore } = decision
  const core = independenceCoreV1Schema.parse(candidateCore)
  if (!same(decisionDigest, structuredDigest(
    ROLE_CANDIDATE_VALIDATION_INDEPENDENCE_DECISION_MEDIA_TYPE,
    core,
  ))) {
    throw new Error('Role Candidate Validation independence decision digest does not match')
  }
  return deepFreeze({ ...core, decisionDigest })
}

export interface RoleCandidateValidationProofCoreV1 {
  readonly schemaVersion: 1
  readonly proofId: string
  readonly purpose: RoleCandidateValidationProofPurpose
  readonly conditionId: string
  readonly evidence: RoleCandidateValidationEvidenceIdentityV1
  readonly result: 'PROVED' | 'NOT_PROVED' | 'INCONCLUSIVE'
  readonly validator: {
    readonly validatorId: string
    readonly validatorVersion: string
    readonly definitionDigest: DigestEnvelopeV1
  }
  readonly eligibilityDecision: RoleCandidateValidationEligibilityDecisionV1
  readonly independenceDecision: RoleCandidateValidationIndependenceDecisionV1
  readonly observedAt: string
}

export interface RoleCandidateValidationProofV1 extends RoleCandidateValidationProofCoreV1 {
  readonly proofDigest: DigestEnvelopeV1
}

const proofCoreShape = {
  schemaVersion: z.literal(1),
  proofId: validationProofIdSchema,
  purpose: z.enum(['CLAIM_VALIDATION', 'CLAIM_REJECTION', 'NEGATIVE_CONTROL']),
  conditionId: registryIdSchema,
  evidence: evidenceIdentityV1Schema,
  result: z.enum(['PROVED', 'NOT_PROVED', 'INCONCLUSIVE']),
  validator: z.strictObject({
    validatorId: registryIdSchema,
    validatorVersion: semanticVersionSchema,
    definitionDigest: digestEnvelopeV1Schema,
  }),
  eligibilityDecision: eligibilityV1Schema,
  independenceDecision: independenceV1Schema,
  observedAt: z.iso.datetime({ offset: true }),
} as const
const proofCoreV1Schema: z.ZodType<RoleCandidateValidationProofCoreV1> =
  z.strictObject(proofCoreShape)
const proofV1Schema: z.ZodType<RoleCandidateValidationProofV1> = z.strictObject({
  ...proofCoreShape,
  proofDigest: proofDigestSchema,
})

export function createRoleCandidateValidationProofV1(
  input: RoleCandidateValidationProofCoreV1,
): RoleCandidateValidationProofV1 {
  const parsed = proofCoreV1Schema.parse(input)
  const core = proofCoreV1Schema.parse({
    ...parsed,
    eligibilityDecision: parseEligibilityDecision(parsed.eligibilityDecision),
    independenceDecision: parseIndependenceDecision(parsed.independenceDecision),
  })
  if (
    core.purpose !== core.eligibilityDecision.purpose
    || core.conditionId !== core.eligibilityDecision.conditionId
    || !same(core.evidence, core.eligibilityDecision.evidence)
    || Date.parse(core.eligibilityDecision.decidedAt) < Date.parse(core.observedAt)
    || Date.parse(core.independenceDecision.decidedAt) < Date.parse(core.observedAt)
  ) {
    throw new Error('Role Candidate Validation proof and eligibility binding do not match')
  }
  return deepFreeze({
    ...core,
    proofDigest: structuredDigest(ROLE_CANDIDATE_VALIDATION_PROOF_MEDIA_TYPE, core),
  })
}

export function parseRoleCandidateValidationProofV1(
  input: unknown,
): RoleCandidateValidationProofV1 {
  const proof = proofV1Schema.parse(input)
  const { proofDigest, ...candidateCore } = proof
  const core = proofCoreV1Schema.parse({
    ...candidateCore,
    eligibilityDecision: parseEligibilityDecision(candidateCore.eligibilityDecision),
    independenceDecision: parseIndependenceDecision(candidateCore.independenceDecision),
  })
  if (
    core.purpose !== core.eligibilityDecision.purpose
    || core.conditionId !== core.eligibilityDecision.conditionId
    || !same(core.evidence, core.eligibilityDecision.evidence)
    || Date.parse(core.eligibilityDecision.decidedAt) < Date.parse(core.observedAt)
    || Date.parse(core.independenceDecision.decidedAt) < Date.parse(core.observedAt)
    || !same(proofDigest, structuredDigest(ROLE_CANDIDATE_VALIDATION_PROOF_MEDIA_TYPE, core))
  ) {
    throw new Error('Role Candidate Validation proof digest or binding does not match')
  }
  return deepFreeze({ ...core, proofDigest })
}

export type RoleCandidateValidationOutcomeState = 'VALIDATED' | 'REJECTED' | 'UNRESOLVED'
export type RoleCandidateValidationProofGapCode =
  | 'VALIDATION_CONTRACT_UNAVAILABLE'
  | 'VALIDATION_CONTRACT_AMBIGUOUS'
  | 'ELIGIBLE_CLAIM_PROOF_MISSING'
  | 'ELIGIBLE_COUNTER_EVIDENCE_MISSING'
  | 'REQUIRED_NEGATIVE_CONTROL_MISSING'
  | 'INDEPENDENT_VALIDATION_LINEAGE_MISSING'
  | 'CONFLICTING_ELIGIBLE_PROOF'

export interface RoleCandidateValidationOutcomeCoreV1 {
  readonly schemaVersion: 1
  readonly validationAttemptId: string
  readonly assessmentId: AssessmentId
  readonly assessmentRevision: number
  readonly candidateId: string
  readonly candidateAdmissionDigest: DigestEnvelopeV1
  readonly subjectDigest: DigestEnvelopeV1
  readonly contractResolutionDigest: DigestEnvelopeV1
  readonly contractDefinitionDigest: DigestEnvelopeV1 | null
  readonly state: RoleCandidateValidationOutcomeState
  readonly proofs: readonly RoleCandidateValidationProofV1[]
  readonly qualifyingProofIds: readonly string[]
  readonly independentValidationLineageDigests: readonly DigestEnvelopeV1[]
  readonly proofGaps: readonly RoleCandidateValidationProofGapCode[]
  readonly decidedAt: string
}

export interface RoleCandidateValidationOutcomeV1 extends RoleCandidateValidationOutcomeCoreV1 {
  readonly outcomeDigest: DigestEnvelopeV1
}

const proofGapSchema = z.enum([
  'VALIDATION_CONTRACT_UNAVAILABLE',
  'VALIDATION_CONTRACT_AMBIGUOUS',
  'ELIGIBLE_CLAIM_PROOF_MISSING',
  'ELIGIBLE_COUNTER_EVIDENCE_MISSING',
  'REQUIRED_NEGATIVE_CONTROL_MISSING',
  'INDEPENDENT_VALIDATION_LINEAGE_MISSING',
  'CONFLICTING_ELIGIBLE_PROOF',
])
const outcomeCoreShape = {
  schemaVersion: z.literal(1),
  validationAttemptId: validationAttemptIdSchema,
  assessmentId: assessmentIdSchema,
  assessmentRevision: z.number().int().positive().max(Number.MAX_SAFE_INTEGER),
  candidateId: candidateIdSchema,
  candidateAdmissionDigest: digestEnvelopeV1Schema,
  subjectDigest: digestEnvelopeV1Schema,
  contractResolutionDigest: resolutionDigestSchema,
  contractDefinitionDigest: contractDigestSchema.nullable(),
  state: z.enum(['VALIDATED', 'REJECTED', 'UNRESOLVED']),
  proofs: z.array(proofV1Schema).max(MAX_PROOFS),
  qualifyingProofIds: z.array(validationProofIdSchema).max(MAX_PROOFS),
  independentValidationLineageDigests: z.array(digestEnvelopeV1Schema).max(MAX_PROOFS),
  proofGaps: z.array(proofGapSchema).max(7),
  decidedAt: z.iso.datetime({ offset: true }),
} as const
function validateOutcomeCore(
  outcome: RoleCandidateValidationOutcomeCoreV1,
  context: z.RefinementCtx,
): void {
  const proofIds = outcome.proofs.map(proof => proof.proofId)
  const qualifyingProofIds = outcome.qualifyingProofIds
  const lineageKeys = outcome.independentValidationLineageDigests.map(canonicalJson)
  const expectedLineages = [...new Set(outcome.proofs
    .filter(proof => qualifyingProofIds.includes(proof.proofId))
    .map(proof => canonicalJson(proof.independenceDecision.validationLineageDigest)))]
    .sort()
  if (
    new Set(proofIds).size !== proofIds.length
    || canonicalJson(proofIds) !== canonicalJson([...proofIds].sort())
    || new Set(qualifyingProofIds).size !== qualifyingProofIds.length
    || canonicalJson(qualifyingProofIds) !== canonicalJson([...qualifyingProofIds].sort())
    || qualifyingProofIds.some(proofId => !proofIds.includes(proofId))
    || new Set(lineageKeys).size !== lineageKeys.length
    || canonicalJson([...lineageKeys].sort()) !== canonicalJson(expectedLineages)
    || new Set(outcome.proofGaps).size !== outcome.proofGaps.length
    || canonicalJson(outcome.proofGaps) !== canonicalJson([...outcome.proofGaps].sort())
    || (outcome.state === 'UNRESOLVED') !== (outcome.proofGaps.length > 0)
  ) {
    context.addIssue({ code: 'custom', message: 'Validation Outcome reasoning is inconsistent' })
  }
  const qualifyingProofs = outcome.proofs.filter(proof => (
    qualifyingProofIds.includes(proof.proofId)
  ))
  if (
    (outcome.state === 'VALIDATED'
      && !qualifyingProofs.some(proof => proof.purpose === 'CLAIM_VALIDATION'))
    || (outcome.state === 'REJECTED'
      && !qualifyingProofs.some(proof => proof.purpose === 'CLAIM_REJECTION'))
  ) {
    context.addIssue({ code: 'custom', message: 'Validation Outcome state lacks qualifying proof' })
  }
}

const outcomeCoreV1Schema: z.ZodType<RoleCandidateValidationOutcomeCoreV1> =
  z.strictObject(outcomeCoreShape).superRefine(validateOutcomeCore)
const outcomeV1Schema: z.ZodType<RoleCandidateValidationOutcomeV1> = z.strictObject({
  ...outcomeCoreShape,
  outcomeDigest: outcomeDigestSchema,
}).superRefine(validateOutcomeCore)

export function candidateProducerLineageDigestV1(
  admissionInput: RoleCandidateAdmissionV1,
): DigestEnvelopeV1 {
  const admission = parseRoleCandidateAdmissionV1(admissionInput)
  return structuredDigest(ROLE_CANDIDATE_PRODUCER_LINEAGE_MEDIA_TYPE, {
    assessmentId: admission.assessmentId,
    candidateId: admission.candidateId,
    provenance: admission.provenance,
  })
}

function proofCompatibleWithContract(
  proof: RoleCandidateValidationProofV1,
  contract: RoleCandidateValidationContractV1,
): boolean {
  if (proof.purpose === 'CLAIM_VALIDATION') {
    return proof.conditionId === contract.claimConditionId
      && contract.claimEvidenceSchemaIds.includes(proof.evidence.schemaId)
  }
  if (proof.purpose === 'CLAIM_REJECTION') {
    return contract.counterEvidence.some(item => (
      item.rejectionConditionId === proof.conditionId
      && item.evidenceSchemaIds.includes(proof.evidence.schemaId)
    ))
  }
  return contract.requiredNegativeControls.some(item => (
    item.negativeControlId === proof.conditionId
    && item.evidenceSchemaIds.includes(proof.evidence.schemaId)
  ))
}

function evidenceKey(evidence: RoleCandidateValidationEvidenceIdentityV1): string {
  return canonicalJson(evidence)
}

export interface CreateRoleCandidateValidationOutcomeOptionsV1 {
  readonly validationAttemptId: string
  readonly assessmentRevision: number
  readonly admission: RoleCandidateAdmissionV1
  readonly resolution: RoleCandidateValidationContractResolutionV1
  readonly proofs: readonly RoleCandidateValidationProofV1[]
  readonly durableEvidence: readonly RoleCandidateValidationEvidenceIdentityV1[]
  readonly decidedAt: string
}

export function createRoleCandidateValidationOutcomeV1(
  options: CreateRoleCandidateValidationOutcomeOptionsV1,
): RoleCandidateValidationOutcomeV1 {
  const validationAttemptId = validationAttemptIdSchema.parse(options.validationAttemptId)
  const assessmentRevision = z.number().int().positive().max(Number.MAX_SAFE_INTEGER)
    .parse(options.assessmentRevision)
  const admission = parseRoleCandidateAdmissionV1(options.admission)
  const resolution = parseRoleCandidateValidationContractResolutionV1(options.resolution)
  const decidedAt = z.iso.datetime({ offset: true }).parse(options.decidedAt)
  if (
    admission.assessmentId !== resolution.assessmentId
    || admission.candidateId !== resolution.candidateId
    || !same(admission.admissionDigest, resolution.candidateAdmissionDigest)
    || !same(admission.subjectDigest, resolution.subjectDigest)
    || Date.parse(decidedAt) < Date.parse(resolution.resolvedAt)
  ) {
    throw new Error('Role Candidate Validation Outcome lineage does not match its resolution')
  }
  if (options.proofs.length > MAX_PROOFS || options.durableEvidence.length > MAX_PROOFS) {
    throw new Error('Role Candidate Validation proof or Evidence count exceeds the v1 limit')
  }
  const proofs = options.proofs.map(parseRoleCandidateValidationProofV1)
    .sort((left, right) => left.proofId.localeCompare(right.proofId))
  assertUnique(proofs.map(proof => proof.proofId), 'Role Candidate Validation repeats a proof')
  const durableEvidence = options.durableEvidence.map(item => evidenceIdentityV1Schema.parse(item))
    .sort((left, right) => evidenceKey(left).localeCompare(evidenceKey(right)))
  assertUnique(
    durableEvidence.map(evidenceKey),
    'Role Candidate Validation durable Evidence identities must be unique',
  )
  assertUnique(
    durableEvidence.map(item => item.artifactId),
    'Role Candidate Validation binds conflicting durable Evidence identities',
  )

  let state: RoleCandidateValidationOutcomeState = 'UNRESOLVED'
  let qualifyingProofs: readonly RoleCandidateValidationProofV1[] = []
  let proofGaps: RoleCandidateValidationProofGapCode[] = []
  if (resolution.state === 'UNRESOLVED') {
    if (proofs.length !== 0) {
      throw new Error('Role Candidate Validation cannot evaluate proof without a resolved Contract')
    }
    proofGaps = [resolution.unresolvedReason === 'AMBIGUOUS_QUALIFIED_CONTRACT'
      ? 'VALIDATION_CONTRACT_AMBIGUOUS'
      : 'VALIDATION_CONTRACT_UNAVAILABLE']
  } else {
    const contract = resolution.contract!
    const producerLineageDigest = candidateProducerLineageDigestV1(admission)
    for (const proof of proofs) {
      const eligibility = proof.eligibilityDecision
      const independence = proof.independenceDecision
      if (
        eligibility.candidateId !== admission.candidateId
        || !same(eligibility.candidateAdmissionDigest, admission.admissionDigest)
        || !same(eligibility.contractDefinitionDigest, contract.definitionDigest)
        || !same(eligibility.policyDigest, resolution.validationContext.policyDigest)
        || independence.independencePolicyId !== contract.independencePolicy.policyId
        || !same(independence.candidateProducerLineageDigest, producerLineageDigest)
        || proof.validator.validatorId !== resolution.qualification!.validatorCapabilityId
        || proof.validator.validatorVersion !== resolution.qualification!.validatorVersion
        || !same(
          proof.validator.definitionDigest,
          resolution.qualification!.validatorDefinitionDigest,
        )
        || (eligibility.state === 'ELIGIBLE' && (
          Date.parse(proof.observedAt) < Date.parse(resolution.qualification!.qualifiedAt)
          || Date.parse(proof.observedAt) >= Date.parse(resolution.qualification!.validUntil)
        ))
        || Date.parse(proof.observedAt) < Date.parse(resolution.resolvedAt)
        || Date.parse(proof.observedAt) > Date.parse(decidedAt)
        || Date.parse(eligibility.decidedAt) < Date.parse(proof.observedAt)
        || Date.parse(eligibility.decidedAt) > Date.parse(decidedAt)
        || Date.parse(independence.decidedAt) < Date.parse(proof.observedAt)
        || Date.parse(independence.decidedAt) > Date.parse(decidedAt)
        || !durableEvidence.some(item => same(item, proof.evidence))
      ) {
        throw new Error('Role Candidate Validation proof lineage or durable Evidence binding does not match')
      }
      if (eligibility.state === 'ELIGIBLE' && !proofCompatibleWithContract(proof, contract)) {
        throw new Error('Eligible Role Candidate Validation proof is not permitted by its Contract')
      }
    }
    qualifyingProofs = proofs.filter(proof => (
      proof.result === 'PROVED'
      && proof.eligibilityDecision.state === 'ELIGIBLE'
      && proof.independenceDecision.state === 'INDEPENDENT'
      && proofCompatibleWithContract(proof, contract)
    ))
    const requiredControlsSatisfied = contract.requiredNegativeControls.every(control => (
      qualifyingProofs.some(proof => (
        proof.purpose === 'NEGATIVE_CONTROL' && proof.conditionId === control.negativeControlId
      ))
    ))
    const distinctLineageCount = (purpose: RoleCandidateValidationProofPurpose) => new Set(
      qualifyingProofs
        .filter(proof => proof.purpose === purpose)
        .map(proof => proof.independenceDecision.validationLineageDigest.value),
    ).size
    const claimReady = requiredControlsSatisfied
      && distinctLineageCount('CLAIM_VALIDATION')
        >= contract.independencePolicy.minimumDistinctValidationLineages
    const rejectionReady = requiredControlsSatisfied
      && distinctLineageCount('CLAIM_REJECTION')
        >= contract.independencePolicy.minimumDistinctValidationLineages
    if (claimReady && rejectionReady) {
      proofGaps = ['CONFLICTING_ELIGIBLE_PROOF']
    } else if (claimReady) {
      state = 'VALIDATED'
    } else if (rejectionReady) {
      state = 'REJECTED'
    } else {
      if (!requiredControlsSatisfied) proofGaps.push('REQUIRED_NEGATIVE_CONTROL_MISSING')
      if (distinctLineageCount('CLAIM_VALIDATION')
        < contract.independencePolicy.minimumDistinctValidationLineages) {
        proofGaps.push('ELIGIBLE_CLAIM_PROOF_MISSING')
      }
      if (distinctLineageCount('CLAIM_REJECTION')
        < contract.independencePolicy.minimumDistinctValidationLineages) {
        proofGaps.push('ELIGIBLE_COUNTER_EVIDENCE_MISSING')
      }
      const proofBlockedByIndependence = proofs.some(proof => (
        proof.result === 'PROVED'
        && proof.eligibilityDecision.state === 'ELIGIBLE'
        && proof.independenceDecision.state !== 'INDEPENDENT'
      ))
      if (proofBlockedByIndependence) {
        proofGaps.push('INDEPENDENT_VALIDATION_LINEAGE_MISSING')
      }
    }
  }
  const lineages = [...new Map(
    qualifyingProofs.map(proof => [
      proof.independenceDecision.validationLineageDigest.value,
      proof.independenceDecision.validationLineageDigest,
    ]),
  ).values()].sort((left, right) => left.value.localeCompare(right.value))
  const core = outcomeCoreV1Schema.parse({
    schemaVersion: 1,
    validationAttemptId,
    assessmentId: admission.assessmentId,
    assessmentRevision,
    candidateId: admission.candidateId,
    candidateAdmissionDigest: admission.admissionDigest,
    subjectDigest: admission.subjectDigest,
    contractResolutionDigest: resolution.resolutionDigest,
    contractDefinitionDigest: resolution.contract?.definitionDigest ?? null,
    state,
    proofs,
    qualifyingProofIds: qualifyingProofs.map(proof => proof.proofId).sort(),
    independentValidationLineageDigests: lineages,
    proofGaps: [...new Set(proofGaps)].sort(),
    decidedAt,
  })
  return deepFreeze({
    ...core,
    outcomeDigest: structuredDigest(ROLE_CANDIDATE_VALIDATION_OUTCOME_MEDIA_TYPE, core),
  })
}

export function parseRoleCandidateValidationOutcomeV1(
  input: unknown,
): RoleCandidateValidationOutcomeV1 {
  const outcome = outcomeV1Schema.parse(input)
  const { outcomeDigest, ...candidateCore } = outcome
  const core = outcomeCoreV1Schema.parse({
    ...candidateCore,
    proofs: candidateCore.proofs.map(parseRoleCandidateValidationProofV1),
  })
  if (!same(outcomeDigest, structuredDigest(ROLE_CANDIDATE_VALIDATION_OUTCOME_MEDIA_TYPE, core))) {
    throw new Error('Role Candidate Validation Outcome digest does not match')
  }
  assertUnique(core.proofs.map(proof => proof.proofId), 'Role Candidate Validation Outcome repeats a proof')
  return deepFreeze({ ...core, outcomeDigest })
}

export interface CreateRoleCandidateValidationResolutionRequestDigestOptionsV1 {
  readonly validationAttemptId: string
  readonly expectedAssessmentRevision: number
  readonly admission: RoleCandidateAdmissionV1
  readonly validationContext: RoleCandidateValidationContextV1
  readonly qualifiedContracts: readonly QualifiedRoleCandidateValidationContractV1[]
}

export function createRoleCandidateValidationResolutionRequestDigestV1(
  options: CreateRoleCandidateValidationResolutionRequestDigestOptionsV1,
): DigestEnvelopeV1 {
  const validationAttemptId = validationAttemptIdSchema.parse(options.validationAttemptId)
  const expectedAssessmentRevision = z.number().int().positive().max(Number.MAX_SAFE_INTEGER)
    .parse(options.expectedAssessmentRevision)
  const admission = parseRoleCandidateAdmissionV1(options.admission)
  const validationContext = roleCandidateValidationContextV1Schema.parse(options.validationContext)
  const qualifiedContracts = options.qualifiedContracts
    .map(parseQualifiedRoleCandidateValidationContractV1)
    .sort((left, right) => left.qualificationDigest.value.localeCompare(
      right.qualificationDigest.value,
    ))
  assertUnique(
    qualifiedContracts.map(item => item.qualificationDigest.value),
    'Role Candidate Validation Contract catalog repeats a qualification',
  )
  return structuredDigest(ROLE_CANDIDATE_VALIDATION_RESOLUTION_REQUEST_MEDIA_TYPE, {
    schemaVersion: 1,
    validationAttemptId,
    expectedAssessmentRevision,
    candidateId: admission.candidateId,
    candidateAdmissionDigest: admission.admissionDigest,
    validationContext,
    qualifiedContracts,
  })
}

export interface CreateRoleCandidateValidationOutcomeRequestDigestOptionsV1 {
  readonly validationAttemptId: string
  readonly expectedAssessmentRevision: number
  readonly admission: RoleCandidateAdmissionV1
  readonly resolution: RoleCandidateValidationContractResolutionV1
  readonly proofs: readonly RoleCandidateValidationProofV1[]
  readonly durableEvidence: readonly RoleCandidateValidationEvidenceIdentityV1[]
}

export function createRoleCandidateValidationOutcomeRequestDigestV1(
  options: CreateRoleCandidateValidationOutcomeRequestDigestOptionsV1,
): DigestEnvelopeV1 {
  const validationAttemptId = validationAttemptIdSchema.parse(options.validationAttemptId)
  const expectedAssessmentRevision = z.number().int().positive().max(Number.MAX_SAFE_INTEGER)
    .parse(options.expectedAssessmentRevision)
  const admission = parseRoleCandidateAdmissionV1(options.admission)
  const resolution = parseRoleCandidateValidationContractResolutionV1(options.resolution)
  const proofs = options.proofs.map(parseRoleCandidateValidationProofV1)
    .sort((left, right) => left.proofId.localeCompare(right.proofId))
  const durableEvidence = options.durableEvidence.map(item => evidenceIdentityV1Schema.parse(item))
    .sort((left, right) => evidenceKey(left).localeCompare(evidenceKey(right)))
  assertUnique(proofs.map(item => item.proofId), 'Role Candidate Validation repeats a proof')
  assertUnique(
    durableEvidence.map(evidenceKey),
    'Role Candidate Validation durable Evidence identities must be unique',
  )
  assertUnique(
    durableEvidence.map(item => item.artifactId),
    'Role Candidate Validation binds conflicting durable Evidence identities',
  )
  return structuredDigest(ROLE_CANDIDATE_VALIDATION_OUTCOME_REQUEST_MEDIA_TYPE, {
    schemaVersion: 1,
    validationAttemptId,
    expectedAssessmentRevision,
    candidateId: admission.candidateId,
    candidateAdmissionDigest: admission.admissionDigest,
    contractResolutionDigest: resolution.resolutionDigest,
    proofs,
    durableEvidence,
  })
}
