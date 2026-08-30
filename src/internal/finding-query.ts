import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto'
import { z } from 'zod'
import {
  assessmentCoverageSnapshotV1Schema,
  digestEnvelopeV1Schema,
  evidenceConfidenceSchema,
  findingDetailViewV1Schema,
  findingListPageV1Schema,
  policySignificanceSchema,
  riskDecisionRecordV1Schema,
  technicalSeveritySchema,
} from '../contracts.ts'
import type {
  FindingDetailDimensionV1,
  FindingDetailViewV1,
  FindingListPageV1,
  FindingSummaryV1,
  GetFindingRequest,
  ListFindingsRequest,
  AssessmentId,
  RepositoryId,
  SecuritySubmissionArtifactV1,
  SecuritySubmissionJsonV1,
} from '../contracts.ts'
import { canonicalJson, sha256Hex } from './canonical.ts'

const boundedIdentity = z.string().regex(/^[a-z0-9][a-z0-9._/-]{0,127}$/i)
const assessmentIdSchema = z.string().regex(/^asm-[0-9a-f-]{36}$/)
const repositoryIdSchema = z.string().regex(/^repo-[0-9a-f-]{36}$/)
const candidateIdSchema = z.string().regex(/^candidate-[0-9a-f]{64}$/)
const findingIdSchema = z.string().regex(/^finding-[0-9a-f]{64}$/)
const validationStates = ['VALIDATED', 'REJECTED', 'UNRESOLVED'] as const
const validationStateSchema = z.enum(validationStates)
const detailDimensionValueSchema = z.union([
  z.string().min(1).max(128),
  z.number().finite(),
  z.boolean(),
])
const sourceAnchorSchema = z.union([
  z.strictObject({
    path: z.string().min(1).max(1024),
    fileDigest: digestEnvelopeV1Schema,
    locator: z.strictObject({
      kind: z.literal('JSON_POINTER'),
      value: z.string().min(1).max(1024).startsWith('/'),
    }),
  }),
  z.strictObject({
    path: z.string().min(1).max(1024),
    fileDigest: digestEnvelopeV1Schema,
    jsonPointer: z.string().min(1).max(1024).startsWith('/'),
  }),
])

const validatedFindingSchema = z.object({
  findingId: findingIdSchema,
  candidateId: candidateIdSchema,
  weaknessClassification: z.object({
    primary: boundedIdentity,
    secondary: z.array(boundedIdentity).max(16),
  }).optional(),
  weaknessId: boundedIdentity.optional(),
  affectedControlId: boundedIdentity.optional(),
  sourceAnchor: sourceAnchorSchema,
  validation: z.object({
    state: z.literal('VALIDATED'),
    contractId: boundedIdentity,
    contractVersion: z.number().int().positive().optional(),
    evidenceEligibilityArtifactId: boundedIdentity.optional(),
    evidenceArtifactIds: z.array(boundedIdentity).min(1).max(128).optional(),
    evidenceDigest: digestEnvelopeV1Schema.optional(),
    proofGaps: z.array(boundedIdentity).max(32).optional(),
    negativeControls: z.array(boundedIdentity).max(32).optional(),
  }),
  technicalSeverity: z.object({
    value: technicalSeveritySchema,
    methodVersion: boundedIdentity,
    vector: z.record(boundedIdentity, detailDimensionValueSchema).optional(),
  }),
  evidenceConfidence: z.object({
    value: evidenceConfidenceSchema,
    methodVersion: boundedIdentity,
    rubric: z.record(boundedIdentity, detailDimensionValueSchema).optional(),
  }),
  policySignificance: policySignificanceSchema,
}).refine(finding => (
  (finding.weaknessClassification === undefined) !== (finding.weaknessId === undefined)
), { message: 'Finding must contain exactly one weakness representation' }).refine(finding => {
  const builtin = finding.validation.evidenceDigest !== undefined
    && finding.validation.evidenceArtifactIds === undefined
    && finding.validation.evidenceEligibilityArtifactId === undefined
  const external = finding.validation.evidenceDigest === undefined
    && finding.validation.evidenceArtifactIds !== undefined
    && finding.validation.evidenceEligibilityArtifactId !== undefined
  return builtin !== external
}, { message: 'Finding must contain exactly one Evidence Link representation' })

const findingsArtifactValueSchema = z.object({
  schemaVersion: z.literal(1),
  findings: z.array(validatedFindingSchema).max(1024),
})

const candidateAdmissionSchema = z.object({
  schemaVersion: z.literal(1),
  state: z.literal('ADMITTED'),
  candidateId: candidateIdSchema,
  weaknessClassification: z.object({
    primary: boundedIdentity,
    secondary: z.array(boundedIdentity).max(16),
  }),
  affectedControlId: boundedIdentity,
  sourceAnchor: sourceAnchorSchema,
  evidenceArtifactIds: z.array(boundedIdentity).min(1).max(128),
})

const outcomeStateSchema = z.object({
  state: z.enum(['VALIDATED', 'REJECTED', 'UNRESOLVED']),
})

const candidateOutcomeSchema = z.object({
  schemaVersion: z.literal(1),
  candidateId: candidateIdSchema,
  state: z.enum(['REJECTED', 'UNRESOLVED']),
  contractId: boundedIdentity.nullable(),
  contractVersion: z.number().int().positive().optional(),
  evidenceEligibilityArtifactId: boundedIdentity,
  rejectionCondition: boundedIdentity.optional(),
  counterEvidenceArtifactIds: z.array(boundedIdentity).min(1).max(128).optional(),
  proofGaps: z.array(boundedIdentity).max(32),
  negativeControls: z.array(boundedIdentity).max(32).optional(),
})

const externalValidationOutcomeSchema = z.strictObject({
  schemaVersion: z.literal(1),
  candidateId: candidateIdSchema,
  state: z.literal('VALIDATED'),
  contractId: boundedIdentity,
  contractVersion: z.number().int().positive(),
  evidenceEligibilityArtifactId: boundedIdentity,
  evidenceArtifactIds: z.array(boundedIdentity).min(1).max(128),
  proofGaps: z.array(boundedIdentity).max(32),
  negativeControls: z.array(boundedIdentity).max(32),
})

const validationEligibilitySchema = z.object({
  schemaVersion: z.literal(1),
  decision: z.enum(['ELIGIBLE', 'INELIGIBLE']),
  purpose: z.enum(['VALIDATION_EVIDENCE', 'COUNTER_EVIDENCE']),
  candidateId: candidateIdSchema,
  evidenceArtifactIds: z.array(boundedIdentity).min(1).max(128),
  negativeControls: z.array(boundedIdentity).max(32),
})

const builtinEvidenceEligibilitySchema = z.object({
  schemaVersion: z.literal(1),
  decision: z.literal('ELIGIBLE'),
  evidenceDigest: digestEnvelopeV1Schema,
})

const validationContractResolutionSchema = z.object({
  schemaVersion: z.literal(1),
  candidateId: candidateIdSchema,
  state: z.enum(['RESOLVED', 'UNRESOLVED']),
  contractId: boundedIdentity.nullable(),
  contractVersion: z.number().int().positive().nullable(),
}).refine(resolution => (
  resolution.state === 'RESOLVED'
    ? resolution.contractId !== null && resolution.contractVersion !== null
    : resolution.contractId === null && resolution.contractVersion === null
), { message: 'Validation Contract Resolution state and identity disagree' })

const cursorPayloadSchema = z.strictObject({
  schemaVersion: z.literal(1),
  assessmentId: assessmentIdSchema,
  assessmentRevision: z.number().int().positive(),
  repositoryId: repositoryIdSchema,
  authorityDigest: z.string().regex(/^[0-9a-f]{64}$/),
  limit: z.number().int().min(1).max(100),
  validationStates: z.array(validationStateSchema).min(1).max(3),
  afterCandidateId: candidateIdSchema,
})

type CursorPayloadV1 = z.infer<typeof cursorPayloadSchema>

/** Minimum immutable record set required by Finding projections before or after Seal. */
export interface FindingQuerySourceV1 {
  readonly payload: {
    readonly assessment: {
      readonly assessmentId: AssessmentId
      readonly assessmentRevision: number
    }
    readonly binding: { readonly repositoryId: RepositoryId }
    readonly coverage: { readonly value: SecuritySubmissionJsonV1 }
    readonly findings: { readonly value: SecuritySubmissionJsonV1 }
      readonly riskDecisions?: { readonly value: SecuritySubmissionJsonV1 } | undefined
    readonly evidence: readonly SecuritySubmissionArtifactV1[]
  }
}

export interface FindingQueryAuthority {
  readonly kind: 'harness-session' | 'host-operator' | 'control-plane'
  readonly principalId: string
}

function normalizedValidationStates(request: ListFindingsRequest): readonly (
  typeof validationStates[number]
)[] {
  const requested = new Set(request.validationStates ?? validationStates)
  return validationStates.filter(state => requested.has(state))
}

function digestAuthority(authority: FindingQueryAuthority): string {
  return sha256Hex(canonicalJson({
    kind: authority.kind,
    principalId: authority.principalId,
  }))
}

function compareCandidateIdentity(left: FindingSummaryV1, right: FindingSummaryV1): number {
  if (left.candidateId < right.candidateId) return -1
  if (left.candidateId > right.candidateId) return 1
  return 0
}

function findingWeakness(
  finding: z.infer<typeof validatedFindingSchema>,
): FindingSummaryV1['weaknessClassification'] {
  if (finding.weaknessClassification !== undefined) return finding.weaknessClassification
  if (finding.weaknessId === undefined) throw new TypeError('Validated Finding has no weakness identity')
  return { primary: finding.weaknessId, secondary: [] }
}

export class FindingQueryCursorError extends Error {}
export class FindingQueryNotFoundError extends Error {}
export class FindingQueryRevisionError extends Error {}

function normalizedSourceAnchor(
  sourceAnchor: z.infer<typeof sourceAnchorSchema>,
): FindingDetailViewV1['sourceAnchor'] {
  return 'locator' in sourceAnchor
    ? sourceAnchor
    : {
        path: sourceAnchor.path,
        fileDigest: sourceAnchor.fileDigest,
        locator: { kind: 'JSON_POINTER', value: sourceAnchor.jsonPointer },
      }
}

function redactedComponent(
  sourceAnchor: z.infer<typeof sourceAnchorSchema>,
): string {
  const path = normalizedSourceAnchor(sourceAnchor).path
  const separator = path.indexOf('/')
  const component = separator < 0 ? 'repository-root' : path.slice(0, separator)
  // Analyzer paths are untrusted.  Preserve ordinary logical components, but
  // replace absolute/portable-invalid segments with a deterministic opaque ID
  // so one malformed path cannot make the entire Finding page unservable.
  return /^[a-z0-9][a-z0-9._/-]{0,127}$/iu.test(component)
    ? component
    : `component-${sha256Hex(component).slice(0, 32)}`
}

function sortedDimensions(
  values: Readonly<Record<string, string | number | boolean>> | undefined,
): readonly FindingDetailDimensionV1[] {
  return Object.entries(values ?? {})
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([dimension, value]) => ({ dimension, value }))
}

const riskDecisionsArtifactSchema = z.strictObject({
  schemaVersion: z.literal(1),
  decisions: z.array(riskDecisionRecordV1Schema).max(1024),
})

function findingRiskDecision(
  submission: FindingQuerySourceV1,
  recordId: string,
  recordRevision: number,
): FindingDetailViewV1['riskDecision'] {
  const artifact = submission.payload.riskDecisions
  if (artifact === undefined) return { state: 'NOT_RECORDED' }
  const decisions = riskDecisionsArtifactSchema.parse(artifact.value)
    .decisions.filter(decision => (
      decision.finding.recordId === recordId
      && decision.finding.recordRevision === recordRevision
    ))
  const decision = decisions[0]
  if (decision === undefined) return { state: 'NOT_RECORDED' }
  if (decisions.length !== 1) throw new TypeError('Finding has ambiguous Risk Decisions')
  return {
    state: decision.resolution,
    decisionId: decision.decisionId,
    authorizationMode: decision.authorizationMode ?? 'SINGLE_AUTHORITY',
    rationale: decision.rationale,
    compensatingControls: decision.compensatingControls,
    expiresAt: decision.expiresAt,
    decisionMaker: decision.decisionMaker,
    scope: decision.scope,
    attestations: decision.attestations ?? [],
    recordedAt: decision.recordedAt,
  }
}

function builtinValidatedFindingDetail(
  submission: FindingQuerySourceV1,
  finding: z.infer<typeof validatedFindingSchema>,
): FindingDetailViewV1 {
  const evidenceDigest = finding.validation.evidenceDigest
  if (evidenceDigest === undefined) throw new TypeError('Built-in Finding has no Evidence digest')
  const evidenceArtifact = submission.payload.evidence.find(artifact => (
    artifact.schemaId !== 'dsh/security-evidence-eligibility-decision'
    && canonicalJson(artifact.digest) === canonicalJson(evidenceDigest)
  ))
  const eligibilityArtifact = submission.payload.evidence.find(artifact => {
    if (artifact.schemaId !== 'dsh/security-evidence-eligibility-decision') return false
    const parsed = builtinEvidenceEligibilitySchema.safeParse(artifact.value)
    return parsed.success && canonicalJson(parsed.data.evidenceDigest) === canonicalJson(evidenceDigest)
  })
  if (evidenceArtifact === undefined || eligibilityArtifact === undefined) {
    throw new TypeError('Built-in Finding Evidence Link is incomplete')
  }
  const eligibility = builtinEvidenceEligibilitySchema.parse(eligibilityArtifact.value)
  const coverage = assessmentCoverageSnapshotV1Schema.parse(submission.payload.coverage.value)
  return findingDetailViewV1Schema.parse({
    schemaVersion: 1,
    assessmentId: submission.payload.assessment.assessmentId,
    assessmentRevision: submission.payload.assessment.assessmentRevision,
    recordKind: 'FINDING',
    recordId: finding.findingId,
    candidateId: finding.candidateId,
    recordRevision: 1,
    revisionChain: [{
      recordRevision: 1,
      supersedesRecordRevision: null,
      isCurrent: true,
    }],
    weaknessClassification: findingWeakness(finding),
    affectedControlId: finding.affectedControlId ?? null,
    sourceAnchor: normalizedSourceAnchor(finding.sourceAnchor),
    validation: {
      state: 'VALIDATED',
      contractId: finding.validation.contractId,
      contractVersion: finding.validation.contractVersion ?? null,
      outcomeArtifactId: null,
      rejectionCondition: null,
      proofGaps: finding.validation.proofGaps ?? [],
      negativeControls: finding.validation.negativeControls ?? [],
    },
    technicalSeverity: {
      value: finding.technicalSeverity.value,
      methodVersion: finding.technicalSeverity.methodVersion,
      inputs: sortedDimensions(finding.technicalSeverity.vector),
    },
    evidenceConfidence: {
      value: finding.evidenceConfidence.value,
      methodVersion: finding.evidenceConfidence.methodVersion,
      rubric: sortedDimensions(finding.evidenceConfidence.rubric),
    },
    policySignificance: finding.policySignificance,
    coverageRelations: coverage.resolutions,
    riskDecision: findingRiskDecision(submission, finding.findingId, 1),
    evidenceLinks: [{
      artifactId: evidenceArtifact.artifactId,
      schemaId: evidenceArtifact.schemaId,
      digest: evidenceArtifact.digest,
      purpose: 'VALIDATION_EVIDENCE',
      eligibilityDecision: eligibility.decision,
      eligibilityDecisionArtifactId: eligibilityArtifact.artifactId,
    }],
    attackPath: { state: 'NOT_AVAILABLE' },
  })
}

function validatedFindingDetail(
  submission: FindingQuerySourceV1,
  finding: z.infer<typeof validatedFindingSchema>,
): FindingDetailViewV1 {
  if (finding.validation.evidenceDigest !== undefined) {
    return builtinValidatedFindingDetail(submission, finding)
  }
  const outcomeArtifact = submission.payload.evidence.find(artifact => {
    if (artifact.schemaId !== 'dsh/security-validation-outcome') return false
    const parsed = externalValidationOutcomeSchema.safeParse(artifact.value)
    return parsed.success && parsed.data.candidateId === finding.candidateId
  })
  if (outcomeArtifact === undefined) {
    throw new TypeError('Validated Finding has no separate Validation Outcome artifact')
  }
  const outcome = externalValidationOutcomeSchema.parse(outcomeArtifact.value)
  if (
    outcome.contractId !== finding.validation.contractId
    || outcome.evidenceEligibilityArtifactId !== finding.validation.evidenceEligibilityArtifactId
    || canonicalJson(outcome.evidenceArtifactIds) !== canonicalJson(finding.validation.evidenceArtifactIds)
  ) throw new TypeError('Validated Finding disagrees with its Validation Outcome artifact')
  const eligibilityArtifact = submission.payload.evidence.find(
    artifact => (
      artifact.artifactId === outcome.evidenceEligibilityArtifactId
      && artifact.schemaId === 'dsh/security-validation-evidence-eligibility-decision'
    ),
  )
  if (eligibilityArtifact === undefined) {
    throw new TypeError('Validated Finding has no Evidence Eligibility Decision')
  }
  const eligibility = validationEligibilitySchema.parse(eligibilityArtifact.value)
  if (
    eligibility.candidateId !== finding.candidateId
    || canonicalJson(eligibility.evidenceArtifactIds) !== canonicalJson(outcome.evidenceArtifactIds)
  ) throw new TypeError('Evidence Eligibility Decision does not bind the Finding')
  const evidenceLinks = outcome.evidenceArtifactIds.map(artifactId => {
    const artifact = submission.payload.evidence.find(value => value.artifactId === artifactId)
    if (artifact === undefined) throw new TypeError('Finding Evidence Link target is missing')
    return {
      artifactId: artifact.artifactId,
      schemaId: artifact.schemaId,
      digest: artifact.digest,
      purpose: eligibility.purpose,
      eligibilityDecision: eligibility.decision,
      eligibilityDecisionArtifactId: eligibilityArtifact.artifactId,
    }
  })
  const coverage = assessmentCoverageSnapshotV1Schema.parse(submission.payload.coverage.value)
  return findingDetailViewV1Schema.parse({
    schemaVersion: 1,
    assessmentId: submission.payload.assessment.assessmentId,
    assessmentRevision: submission.payload.assessment.assessmentRevision,
    recordKind: 'FINDING',
    recordId: finding.findingId,
    candidateId: finding.candidateId,
    recordRevision: 1,
    revisionChain: [{
      recordRevision: 1,
      supersedesRecordRevision: null,
      isCurrent: true,
    }],
    weaknessClassification: findingWeakness(finding),
    affectedControlId: finding.affectedControlId ?? null,
    sourceAnchor: normalizedSourceAnchor(finding.sourceAnchor),
    validation: {
      state: 'VALIDATED',
      contractId: outcome.contractId,
      contractVersion: outcome.contractVersion,
      outcomeArtifactId: outcomeArtifact.artifactId,
      rejectionCondition: null,
      proofGaps: outcome.proofGaps,
      negativeControls: outcome.negativeControls,
    },
    technicalSeverity: {
      value: finding.technicalSeverity.value,
      methodVersion: finding.technicalSeverity.methodVersion,
      inputs: sortedDimensions(finding.technicalSeverity.vector),
    },
    evidenceConfidence: {
      value: finding.evidenceConfidence.value,
      methodVersion: finding.evidenceConfidence.methodVersion,
      rubric: sortedDimensions(finding.evidenceConfidence.rubric),
    },
    policySignificance: finding.policySignificance,
    coverageRelations: coverage.resolutions,
    riskDecision: findingRiskDecision(submission, finding.findingId, 1),
    evidenceLinks,
    attackPath: { state: 'NOT_AVAILABLE' },
  })
}

function candidateFindingDetail(
  submission: FindingQuerySourceV1,
  admission: z.infer<typeof candidateAdmissionSchema>,
  outcome: z.infer<typeof candidateOutcomeSchema>,
  outcomeArtifactId: string,
): FindingDetailViewV1 {
  const evidenceArtifactIds = outcome.state === 'REJECTED'
    ? outcome.counterEvidenceArtifactIds
    : admission.evidenceArtifactIds
  if (evidenceArtifactIds === undefined) {
    throw new TypeError('Rejected Candidate has no Counter-Evidence Links')
  }
  const eligibilityArtifact = submission.payload.evidence.find(
    artifact => (
      artifact.artifactId === outcome.evidenceEligibilityArtifactId
      && artifact.schemaId === 'dsh/security-validation-evidence-eligibility-decision'
    ),
  )
  if (eligibilityArtifact === undefined) {
    throw new TypeError('Candidate Outcome has no Evidence Eligibility Decision')
  }
  const eligibility = validationEligibilitySchema.parse(eligibilityArtifact.value)
  if (
    eligibility.candidateId !== admission.candidateId
    || canonicalJson(eligibility.evidenceArtifactIds) !== canonicalJson(evidenceArtifactIds)
  ) throw new TypeError('Evidence Eligibility Decision does not bind the Candidate Outcome')
  const resolutionArtifact = submission.payload.evidence.find(artifact => {
    if (artifact.schemaId !== 'dsh/security-validation-contract-resolution') return false
    const parsed = validationContractResolutionSchema.safeParse(artifact.value)
    return parsed.success && parsed.data.candidateId === admission.candidateId
  })
  if (resolutionArtifact === undefined) {
    throw new TypeError('Candidate Outcome has no Validation Contract Resolution')
  }
  const resolution = validationContractResolutionSchema.parse(resolutionArtifact.value)
  if (resolution.contractId !== outcome.contractId) {
    throw new TypeError('Validation Contract Resolution does not bind the Candidate Outcome')
  }
  const evidenceLinks = evidenceArtifactIds.map(artifactId => {
    const artifact = submission.payload.evidence.find(value => value.artifactId === artifactId)
    if (artifact === undefined) throw new TypeError('Candidate Evidence Link target is missing')
    return {
      artifactId: artifact.artifactId,
      schemaId: artifact.schemaId,
      digest: artifact.digest,
      purpose: eligibility.purpose,
      eligibilityDecision: eligibility.decision,
      eligibilityDecisionArtifactId: eligibilityArtifact.artifactId,
    }
  })
  const coverage = assessmentCoverageSnapshotV1Schema.parse(submission.payload.coverage.value)
  return findingDetailViewV1Schema.parse({
    schemaVersion: 1,
    assessmentId: submission.payload.assessment.assessmentId,
    assessmentRevision: submission.payload.assessment.assessmentRevision,
    recordKind: outcome.state === 'REJECTED' ? 'REJECTED_CANDIDATE' : 'UNRESOLVED_CANDIDATE',
    recordId: admission.candidateId,
    candidateId: admission.candidateId,
    recordRevision: 1,
    revisionChain: [{
      recordRevision: 1,
      supersedesRecordRevision: null,
      isCurrent: true,
    }],
    weaknessClassification: admission.weaknessClassification,
    affectedControlId: admission.affectedControlId,
    sourceAnchor: normalizedSourceAnchor(admission.sourceAnchor),
    validation: {
      state: outcome.state,
      contractId: outcome.contractId,
      contractVersion: outcome.contractVersion ?? resolution.contractVersion,
      outcomeArtifactId,
      rejectionCondition: outcome.rejectionCondition ?? null,
      proofGaps: outcome.proofGaps,
      negativeControls: outcome.negativeControls ?? eligibility.negativeControls,
    },
    technicalSeverity: null,
    evidenceConfidence: null,
    policySignificance: null,
    coverageRelations: coverage.resolutions,
    riskDecision: findingRiskDecision(submission, admission.candidateId, 1),
    evidenceLinks,
    attackPath: { state: 'NOT_AVAILABLE' },
  })
}

function projectFindingSummaries(
  submission: FindingQuerySourceV1,
): FindingSummaryV1[] {
  const value = findingsArtifactValueSchema.parse(submission.payload.findings.value)
  const coverage = assessmentCoverageSnapshotV1Schema.parse(submission.payload.coverage.value)
  const coverageRelations = coverage.resolutions.map(relation => ({
    obligationId: relation.obligationId,
    state: relation.state,
  }))
  const findings: FindingSummaryV1[] = value.findings.map(finding => ({
    schemaVersion: 1,
    assessmentId: submission.payload.assessment.assessmentId,
    assessmentRevision: submission.payload.assessment.assessmentRevision,
    recordKind: 'FINDING',
    recordId: finding.findingId,
    candidateId: finding.candidateId,
    recordRevision: 1,
    validationState: 'VALIDATED',
    validationContractId: finding.validation.contractId,
    weaknessClassification: findingWeakness(finding),
    technicalSeverity: finding.technicalSeverity.value,
    evidenceConfidence: finding.evidenceConfidence.value,
    policySignificance: finding.policySignificance,
    component: redactedComponent(finding.sourceAnchor),
    sensitivity: 'PROTECTED_DETAIL',
    coverageRelations,
    hasProtectedDetail: true,
  }))
  const admissions = new Map<string, z.infer<typeof candidateAdmissionSchema>>()
  for (const artifact of submission.payload.evidence) {
    if (artifact.schemaId !== 'dsh/security-candidate-admission') continue
    const admission = candidateAdmissionSchema.parse(artifact.value)
    if (admissions.has(admission.candidateId)) throw new TypeError('Candidate admission is duplicated')
    admissions.set(admission.candidateId, admission)
  }
  for (const artifact of submission.payload.evidence) {
    if (artifact.schemaId !== 'dsh/security-validation-outcome') continue
    const state = outcomeStateSchema.parse(artifact.value).state
    if (state === 'VALIDATED') continue
    const outcome = candidateOutcomeSchema.parse(artifact.value)
    const admission = admissions.get(outcome.candidateId)
    if (admission === undefined) throw new TypeError('Candidate Outcome has no admitted Candidate record')
    findings.push({
      schemaVersion: 1,
      assessmentId: submission.payload.assessment.assessmentId,
      assessmentRevision: submission.payload.assessment.assessmentRevision,
      recordKind: outcome.state === 'REJECTED' ? 'REJECTED_CANDIDATE' : 'UNRESOLVED_CANDIDATE',
      recordId: outcome.candidateId,
      candidateId: outcome.candidateId,
      recordRevision: 1,
      validationState: outcome.state,
      validationContractId: outcome.contractId,
      weaknessClassification: admission.weaknessClassification,
      technicalSeverity: null,
      evidenceConfidence: null,
      policySignificance: null,
      component: redactedComponent(admission.sourceAnchor),
      sensitivity: 'PROTECTED_DETAIL',
      coverageRelations,
      hasProtectedDetail: true,
    })
  }
  findings.sort(compareCandidateIdentity)
  const candidateIds = new Set<string>()
  for (const finding of findings) {
    if (candidateIds.has(finding.candidateId)) throw new TypeError('Candidate has multiple current Finding records')
    candidateIds.add(finding.candidateId)
  }
  return findings
}

/** Deep query Module owning redaction, stable ordering, watermarking, and opaque cursors. */
export class FindingQueryModule {
  readonly #cursorKey = randomBytes(32)

  list(
    submission: FindingQuerySourceV1,
    request: ListFindingsRequest,
    authority: FindingQueryAuthority,
  ): FindingListPageV1 {
    const normalizedStates = normalizedValidationStates(request)
    const permittedStates = new Set(normalizedStates)
    const findings = projectFindingSummaries(submission)
      .filter(finding => permittedStates.has(finding.validationState))
    let start = 0
    if (request.cursor !== undefined) {
      const cursor = this.#decodeCursor(request.cursor)
      if (
        cursor.assessmentId !== submission.payload.assessment.assessmentId
        || cursor.assessmentRevision !== submission.payload.assessment.assessmentRevision
        || cursor.repositoryId !== submission.payload.binding.repositoryId
        || cursor.authorityDigest !== digestAuthority(authority)
        || cursor.limit !== request.limit
        || canonicalJson(cursor.validationStates) !== canonicalJson(normalizedStates)
      ) throw new FindingQueryCursorError('Finding cursor does not match this query')
      const previous = findings.findIndex(finding => finding.candidateId === cursor.afterCandidateId)
      if (previous < 0) throw new FindingQueryCursorError('Finding cursor watermark is invalid')
      start = previous + 1
    }
    const page = findings.slice(start, start + request.limit)
    const last = page.at(-1)
    const nextCursor = last !== undefined && start + page.length < findings.length
      ? this.#encodeCursor({
          schemaVersion: 1,
          assessmentId: submission.payload.assessment.assessmentId,
          assessmentRevision: submission.payload.assessment.assessmentRevision,
          repositoryId: submission.payload.binding.repositoryId,
          authorityDigest: digestAuthority(authority),
          limit: request.limit,
          validationStates: [...normalizedStates],
          afterCandidateId: last.candidateId,
        })
      : null
    return findingListPageV1Schema.parse({
      schemaVersion: 1,
      assessmentId: submission.payload.assessment.assessmentId,
      assessmentRevision: submission.payload.assessment.assessmentRevision,
      findings: page,
      nextCursor,
    })
  }

  get(
    submission: FindingQuerySourceV1,
    request: GetFindingRequest,
  ): FindingDetailViewV1 {
    if (request.assessmentRevision !== submission.payload.assessment.assessmentRevision) {
      throw new FindingQueryRevisionError('Finding query Assessment revision is stale')
    }
    const summary = projectFindingSummaries(submission)
      .find(item => item.recordId === request.recordId)
    if (summary === undefined) throw new FindingQueryNotFoundError('Finding record does not exist')
    if (request.recordRevision !== 1) {
      throw new FindingQueryRevisionError('Finding record revision does not exist')
    }
    if (summary.recordKind === 'FINDING') {
      const value = findingsArtifactValueSchema.parse(submission.payload.findings.value)
      const finding = value.findings.find(item => item.findingId === request.recordId)
      if (finding === undefined) throw new TypeError('Finding Summary has no sealed Finding record')
      return validatedFindingDetail(submission, finding)
    }
    const admissionArtifact = submission.payload.evidence.find(artifact => {
      if (artifact.schemaId !== 'dsh/security-candidate-admission') return false
      const parsed = candidateAdmissionSchema.safeParse(artifact.value)
      return parsed.success && parsed.data.candidateId === summary.candidateId
    })
    const outcomeArtifact = submission.payload.evidence.find(artifact => {
      if (artifact.schemaId !== 'dsh/security-validation-outcome') return false
      const parsed = candidateOutcomeSchema.safeParse(artifact.value)
      return parsed.success && parsed.data.candidateId === summary.candidateId
    })
    if (admissionArtifact === undefined || outcomeArtifact === undefined) {
      throw new TypeError('Candidate Summary has no sealed Admission or Outcome record')
    }
    return candidateFindingDetail(
      submission,
      candidateAdmissionSchema.parse(admissionArtifact.value),
      candidateOutcomeSchema.parse(outcomeArtifact.value),
      outcomeArtifact.artifactId,
    )
  }

  #encodeCursor(payload: CursorPayloadV1): string {
    const body = Buffer.from(canonicalJson(cursorPayloadSchema.parse(payload)), 'utf8').toString('base64url')
    const signature = createHmac('sha256', this.#cursorKey).update(body).digest('base64url')
    return `${body}.${signature}`
  }

  #decodeCursor(cursor: string): CursorPayloadV1 {
    try {
      const parts = cursor.split('.')
      if (parts.length !== 2) throw new Error('invalid cursor framing')
      const [body, encodedSignature] = parts
      if (body === undefined || encodedSignature === undefined) throw new Error('invalid cursor framing')
      const signature = Buffer.from(encodedSignature, 'base64url')
      const expected = createHmac('sha256', this.#cursorKey).update(body).digest()
      if (signature.length !== expected.length || !timingSafeEqual(signature, expected)) {
        throw new Error('invalid cursor signature')
      }
      const decoded: unknown = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'))
      return cursorPayloadSchema.parse(decoded)
    } catch {
      throw new FindingQueryCursorError('Finding cursor is invalid')
    }
  }
}
