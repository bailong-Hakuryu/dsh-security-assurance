import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto'
import { z } from 'zod'
import {
  evidenceConfidenceSchema,
  findingListPageV1Schema,
  policySignificanceSchema,
  technicalSeveritySchema,
} from '../contracts.ts'
import type {
  FindingListPageV1,
  FindingSummaryV1,
  ListFindingsRequest,
  SecurityAssuranceSubmissionV1,
} from '../contracts.ts'
import { canonicalJson, sha256Hex } from './canonical.ts'

const boundedIdentity = z.string().regex(/^[a-z0-9][a-z0-9._/-]{0,127}$/i)
const assessmentIdSchema = z.string().regex(/^asm-[0-9a-f-]{36}$/)
const repositoryIdSchema = z.string().regex(/^repo-[0-9a-f-]{36}$/)
const candidateIdSchema = z.string().regex(/^candidate-[0-9a-f]{64}$/)
const findingIdSchema = z.string().regex(/^finding-[0-9a-f]{64}$/)
const validationStates = ['VALIDATED', 'REJECTED', 'UNRESOLVED'] as const
const validationStateSchema = z.enum(validationStates)

const validatedFindingSchema = z.object({
  findingId: findingIdSchema,
  candidateId: candidateIdSchema,
  weaknessClassification: z.object({
    primary: boundedIdentity,
    secondary: z.array(boundedIdentity).max(16),
  }).optional(),
  weaknessId: boundedIdentity.optional(),
  validation: z.object({
    state: z.literal('VALIDATED'),
    contractId: boundedIdentity,
  }),
  technicalSeverity: z.object({ value: technicalSeveritySchema }),
  evidenceConfidence: z.object({ value: evidenceConfidenceSchema }),
  policySignificance: policySignificanceSchema,
}).refine(finding => (
  (finding.weaknessClassification === undefined) !== (finding.weaknessId === undefined)
), { message: 'Finding must contain exactly one weakness representation' })

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
})

const outcomeStateSchema = z.object({
  state: z.enum(['VALIDATED', 'REJECTED', 'UNRESOLVED']),
})

const candidateOutcomeSchema = z.object({
  schemaVersion: z.literal(1),
  candidateId: candidateIdSchema,
  state: z.enum(['REJECTED', 'UNRESOLVED']),
  contractId: boundedIdentity.nullable(),
})

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

function projectFindingSummaries(
  submission: SecurityAssuranceSubmissionV1,
): FindingSummaryV1[] {
  const value = findingsArtifactValueSchema.parse(submission.payload.findings.value)
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
    submission: SecurityAssuranceSubmissionV1,
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
