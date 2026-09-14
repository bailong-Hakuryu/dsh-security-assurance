import { z } from 'zod'
import type { DigestEnvelopeV1 } from '../contracts.ts'
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
import { binaryDigest, canonicalJson, structuredDigest } from './canonical.ts'
import { deepFreeze } from './freeze.ts'
import type {
  RoleContributionAdmissionLinkV1,
  RoleContributionCandidateFindingV1,
  RoleContributionV1,
} from './role-contribution.ts'
import {
  parseRoleContributionAdmissionLinkV1,
  parseRoleContributionV1,
  ROLE_CONTRIBUTION_ADMISSION_LINK_MEDIA_TYPE,
  ROLE_CONTRIBUTION_MEDIA_TYPE,
  roleContributionCandidateFindingV1Schema,
} from './role-contribution.ts'
import { SOURCE_SLICE_EGRESS_ATTEMPT_FENCE_MEDIA_TYPE } from './source-slice-egress-invocation.ts'

export const ROLE_CANDIDATE_FINDING_MEDIA_TYPE =
  'application/vnd.dsh.security.role-candidate-finding+json'
export const ROLE_CANDIDATE_ADMISSION_MEDIA_TYPE =
  'application/vnd.dsh.security.role-candidate-admission+json'

const MAX_SOURCE_SLICE_COUNT = 256
const MAX_SOURCE_SLICE_BYTES = 64 * 1024 * 1024
const MAX_DURABLE_EVIDENCE_COUNT = 1024

const artifactIdSchema = z.string().regex(/^[a-z0-9][a-z0-9-]{0,127}$/u)
const candidateIdSchema = z.string().regex(/^candidate-[0-9a-f]{64}$/u)
const contributionIdSchema = z.string().regex(
  /^role-contribution-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u,
)
const roleAttemptIdSchema = z.string().regex(
  /^role-attempt-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u,
)
const semanticVersionSchema = z.string()
  .max(128)
  .regex(/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/u)
const sourcePathSchema = z.string().min(1).max(1_024).superRefine((path, context) => {
  if (
    path.startsWith('/')
    || path.startsWith('\\')
    || /^[a-z]:/iu.test(path)
    || path.includes('\\')
    || ['*', '?', '[', ']', '{', '}'].some(character => path.includes(character))
    || path.split('/').some(part => part === '' || part === '.' || part === '..')
  ) {
    context.addIssue({
      code: 'custom',
      message: 'Candidate Admission source material requires canonical Subject-relative paths',
    })
  }
})

const rawBytesDigestSchema = digestEnvelopeV1Schema.refine(
  digest => digest.canonicalization === 'raw-bytes',
  'Candidate Admission source material must bind exact raw bytes',
)
const roleContributionDigestSchema = digestEnvelopeV1Schema.refine(
  digest => (
    digest.mediaType === ROLE_CONTRIBUTION_MEDIA_TYPE
    && digest.canonicalization === 'dsh-canonical-json-v1'
  ),
  'Candidate Admission must bind a Role Contribution digest',
)
const contributionAdmissionLinkDigestSchema = digestEnvelopeV1Schema.refine(
  digest => (
    digest.mediaType === ROLE_CONTRIBUTION_ADMISSION_LINK_MEDIA_TYPE
    && digest.canonicalization === 'dsh-canonical-json-v1'
  ),
  'Candidate Admission must bind a Role Contribution Admission Link digest',
)
const attemptFenceDigestSchema = digestEnvelopeV1Schema.refine(
  digest => digest.mediaType === SOURCE_SLICE_EGRESS_ATTEMPT_FENCE_MEDIA_TYPE,
  'Candidate Admission must bind an Attempt fence digest',
)
const contextGrantDigestSchema = digestEnvelopeV1Schema.refine(
  digest => digest.mediaType === ROLE_CONTEXT_GRANT_MEDIA_TYPE,
  'Candidate Admission must bind a Context Grant digest',
)
const roleCandidateFindingDigestSchema = digestEnvelopeV1Schema.refine(
  digest => (
    digest.mediaType === ROLE_CANDIDATE_FINDING_MEDIA_TYPE
    && digest.canonicalization === 'dsh-canonical-json-v1'
  ),
  'Candidate Admission must bind a Role Candidate Finding digest',
)
const roleCandidateAdmissionDigestSchema = digestEnvelopeV1Schema.refine(
  digest => (
    digest.mediaType === ROLE_CANDIDATE_ADMISSION_MEDIA_TYPE
    && digest.canonicalization === 'dsh-canonical-json-v1'
  ),
  'Candidate Admission must use the Role Candidate Admission media type',
)

export interface RoleCandidateSourceSliceV1 {
  readonly contextArtifactId: string
  readonly subjectDigest: DigestEnvelopeV1
  readonly path: string
  readonly digest: DigestEnvelopeV1
  readonly text: string
}

const roleCandidateSourceSliceV1Schema: z.ZodType<RoleCandidateSourceSliceV1> = z.strictObject({
  contextArtifactId: artifactIdSchema,
  subjectDigest: digestEnvelopeV1Schema,
  path: sourcePathSchema,
  digest: rawBytesDigestSchema,
  text: z.string(),
})

export interface RoleCandidateAdmissionCoreV1 {
  readonly schemaVersion: 1
  readonly state: 'ADMITTED'
  readonly candidateId: string
  readonly candidateDigest: DigestEnvelopeV1
  readonly assessmentId: RoleContributionV1['assessmentId']
  readonly assessmentRevision: number
  readonly subjectDigest: DigestEnvelopeV1
  readonly provenance: {
    readonly roleDefinition: RoleContributionV1['roleDefinition']
    readonly parentAttempt: RoleContributionV1['parentAttempt']
    readonly contextGrantDigest: DigestEnvelopeV1
    readonly contributionId: string
    readonly contributionDigest: DigestEnvelopeV1
    readonly contributionAdmissionLinkDigest: DigestEnvelopeV1
  }
  readonly weaknessClassification: RoleContributionCandidateFindingV1['weaknessClassification']
  readonly affectedControlId: string
  readonly securityClaim: string
  readonly sourceAnchors: RoleContributionCandidateFindingV1['sourceAnchors']
  readonly evidenceArtifactIds: readonly string[]
  readonly admittedAt: string
}

export interface RoleCandidateAdmissionV1 extends RoleCandidateAdmissionCoreV1 {
  readonly admissionDigest: DigestEnvelopeV1
}

const roleCandidateAdmissionCoreV1Shape = {
  schemaVersion: z.literal(1),
  state: z.literal('ADMITTED'),
  candidateId: candidateIdSchema,
  candidateDigest: roleCandidateFindingDigestSchema,
  assessmentId: assessmentIdSchema,
  assessmentRevision: z.number().int().positive().max(Number.MAX_SAFE_INTEGER),
  subjectDigest: digestEnvelopeV1Schema,
  provenance: z.strictObject({
    roleDefinition: z.strictObject({
      roleId: securityRoleIdV1Schema,
      roleVersion: semanticVersionSchema,
      definitionDigest: digestEnvelopeV1Schema,
    }),
    parentAttempt: z.strictObject({
      attemptId: roleAttemptIdSchema,
      generation: z.number().int().positive().max(Number.MAX_SAFE_INTEGER),
      fenceDigest: attemptFenceDigestSchema,
    }),
    contextGrantDigest: contextGrantDigestSchema,
    contributionId: contributionIdSchema,
    contributionDigest: roleContributionDigestSchema,
    contributionAdmissionLinkDigest: contributionAdmissionLinkDigestSchema,
  }),
  weaknessClassification: roleContributionCandidateFindingV1Schema.shape.weaknessClassification,
  affectedControlId: roleContributionCandidateFindingV1Schema.shape.affectedControlId,
  securityClaim: roleContributionCandidateFindingV1Schema.shape.securityClaim,
  sourceAnchors: roleContributionCandidateFindingV1Schema.shape.sourceAnchors,
  evidenceArtifactIds: roleContributionCandidateFindingV1Schema.shape.evidenceArtifactIds,
  admittedAt: z.iso.datetime({ offset: true }),
} as const

function validateRoleCandidateAdmissionCore(
  admission: RoleCandidateAdmissionCoreV1,
  context: z.RefinementCtx,
): void {
  const candidate = {
    schemaVersion: 1,
    candidateId: admission.candidateId,
    weaknessClassification: admission.weaknessClassification,
    affectedControlId: admission.affectedControlId,
    securityClaim: admission.securityClaim,
    sourceAnchors: admission.sourceAnchors,
    evidenceArtifactIds: admission.evidenceArtifactIds,
  }
  if (!roleContributionCandidateFindingV1Schema.safeParse(candidate).success) {
    context.addIssue({
      code: 'custom',
      message: 'Candidate Admission contains an invalid Candidate record',
    })
  }
  if (
    new Set(admission.sourceAnchors.map(anchor => canonicalJson(anchor))).size
      !== admission.sourceAnchors.length
    || admission.weaknessClassification.secondary.includes(
      admission.weaknessClassification.primary,
    )
  ) {
    context.addIssue({
      code: 'custom',
      message: 'Candidate Admission contains ambiguous Candidate semantics',
    })
  }
  if (!same(
    admission.candidateDigest,
    structuredDigest(ROLE_CANDIDATE_FINDING_MEDIA_TYPE, candidate),
  )) {
    context.addIssue({
      code: 'custom',
      path: ['candidateDigest'],
      message: 'Candidate Admission Candidate digest is invalid',
    })
  }
}

export const roleCandidateAdmissionCoreV1Schema: z.ZodType<RoleCandidateAdmissionCoreV1> =
  z.strictObject(roleCandidateAdmissionCoreV1Shape).superRefine(
    validateRoleCandidateAdmissionCore,
  )

export const roleCandidateAdmissionV1Schema: z.ZodType<RoleCandidateAdmissionV1> = z.strictObject({
  ...roleCandidateAdmissionCoreV1Shape,
  admissionDigest: roleCandidateAdmissionDigestSchema,
}).superRefine((admission, context) => {
  validateRoleCandidateAdmissionCore(admission, context)
})

export type RoleCandidateAdmissionErrorCode =
  | 'INVALID_INPUT'
  | 'LINEAGE_MISMATCH'
  | 'SOURCE_MATERIAL_INVALID'
  | 'SOURCE_ANCHOR_UNBOUND'
  | 'EVIDENCE_UNAVAILABLE'
  | 'CANDIDATE_AMBIGUOUS'

/** Fixed-code protected diagnostic; it never includes attacker-controlled claim or source text. */
export class RoleCandidateAdmissionError extends TypeError {
  readonly code: RoleCandidateAdmissionErrorCode
  readonly candidateId: string | null

  constructor(
    code: RoleCandidateAdmissionErrorCode,
    message: string,
    candidateId: string | null = null,
  ) {
    super(message)
    this.name = 'RoleCandidateAdmissionError'
    this.code = code
    this.candidateId = candidateId
  }
}

export interface CreateRoleCandidateAdmissionsOptionsV1 {
  readonly contextGrant: RoleContextGrantV1
  readonly contribution: RoleContributionV1
  readonly contributionAdmissionLink: RoleContributionAdmissionLinkV1
  readonly sourceSlices: readonly RoleCandidateSourceSliceV1[]
  readonly durableEvidenceArtifactIds: readonly string[]
}

function same(left: unknown, right: unknown): boolean {
  return canonicalJson(left) === canonicalJson(right)
}

function parseInputs(options: CreateRoleCandidateAdmissionsOptionsV1): {
  readonly contextGrant: RoleContextGrantV1
  readonly contribution: RoleContributionV1
  readonly link: RoleContributionAdmissionLinkV1
  readonly sourceSlices: readonly RoleCandidateSourceSliceV1[]
  readonly durableEvidenceArtifactIds: readonly string[]
} {
  try {
    return {
      contextGrant: parseRoleContextGrantV1(options.contextGrant),
      contribution: parseRoleContributionV1(options.contribution),
      link: parseRoleContributionAdmissionLinkV1(options.contributionAdmissionLink),
      sourceSlices: z.array(roleCandidateSourceSliceV1Schema)
        .max(MAX_SOURCE_SLICE_COUNT)
        .parse(options.sourceSlices),
      durableEvidenceArtifactIds: z.array(artifactIdSchema)
        .max(MAX_DURABLE_EVIDENCE_COUNT)
        .parse(options.durableEvidenceArtifactIds),
    }
  } catch {
    throw new RoleCandidateAdmissionError(
      'INVALID_INPUT',
      'Candidate Admission input failed strict schema or digest validation',
    )
  }
}

function validateLineage(
  contextGrant: RoleContextGrantV1,
  contribution: RoleContributionV1,
  link: RoleContributionAdmissionLinkV1,
): void {
  if (
    contribution.assessmentId !== contextGrant.assessmentId
    || contribution.assessmentId !== link.assessmentId
    || !same(contribution.subjectDigest, contextGrant.subject.digest)
    || contribution.parentAttempt.attemptId !== contextGrant.roleAttemptId
    || !same(contribution.contextGrantDigest, contextGrant.grantDigest)
    || !same(contribution.roleDefinition, contextGrant.roleDefinition)
    || contribution.contributionId !== link.contributionId
    || !same(contribution.contributionDigest, link.contributionDigest)
    || !same(contribution.parentAttempt, link.parentAttempt)
    || !same(contribution.contextGrantDigest, link.contextGrantDigest)
    || !same(
      contribution.modelInvocations.map(invocation => invocation.invocationId),
      link.modelInvocationIds,
    )
    || contribution.completionDisposition !== link.completionDisposition
    || !same(contribution.resourceUse, link.resourceUse)
    || contribution.evidenceArtifactIds.length !== link.evidenceCount
    || contribution.candidateFindings.length !== link.candidateCount
  ) {
    throw new RoleCandidateAdmissionError(
      'LINEAGE_MISMATCH',
      'Candidate Admission does not bind one exact admitted Role Contribution lineage',
    )
  }
}

function validateSourceSlices(
  contextGrant: RoleContextGrantV1,
  subjectDigest: DigestEnvelopeV1,
  sourceSlices: readonly RoleCandidateSourceSliceV1[],
): ReadonlyMap<string, RoleCandidateSourceSliceV1> {
  const byPath = new Map<string, RoleCandidateSourceSliceV1>()
  const usedContextArtifacts = new Set<string>()
  const grantedContextArtifacts = new Set(
    contextGrant.subject.sourceSlices.map(reference => reference.artifactId),
  )
  let aggregateBytes = 0
  for (const slice of sourceSlices) {
    const bytes = Buffer.from(slice.text, 'utf8')
    aggregateBytes += bytes.byteLength
    if (
      aggregateBytes > MAX_SOURCE_SLICE_BYTES
      || aggregateBytes > contextGrant.budget.contextBytes.granted
      || !same(slice.subjectDigest, subjectDigest)
      || !same(binaryDigest(slice.digest.mediaType, bytes), slice.digest)
      || !grantedContextArtifacts.has(slice.contextArtifactId)
      || usedContextArtifacts.has(slice.contextArtifactId)
      || byPath.has(slice.path)
    ) {
      throw new RoleCandidateAdmissionError(
        'SOURCE_MATERIAL_INVALID',
        'Candidate Admission source material is ambiguous, drifted, or outside the Subject',
      )
    }
    usedContextArtifacts.add(slice.contextArtifactId)
    byPath.set(slice.path, slice)
  }
  return byPath
}

function validateCandidate(
  candidate: RoleContributionCandidateFindingV1,
  sourceSlices: ReadonlyMap<string, RoleCandidateSourceSliceV1>,
  durableEvidenceArtifactIds: ReadonlySet<string>,
): void {
  if (
    new Set(candidate.sourceAnchors.map(anchor => canonicalJson(anchor))).size
      !== candidate.sourceAnchors.length
    || candidate.weaknessClassification.secondary.includes(
      candidate.weaknessClassification.primary,
    )
  ) {
    throw new RoleCandidateAdmissionError(
      'CANDIDATE_AMBIGUOUS',
      'Candidate Admission rejects ambiguous weakness or Source Anchor records',
      candidate.candidateId,
    )
  }
  for (const anchor of candidate.sourceAnchors) {
    const slice = sourceSlices.get(anchor.path)
    if (
      slice === undefined
      || !same(slice.digest, anchor.fileDigest)
      || anchor.byteSpan.start + anchor.byteSpan.length > slice.digest.byteLength
    ) {
      throw new RoleCandidateAdmissionError(
        'SOURCE_ANCHOR_UNBOUND',
        'Candidate Admission could not bind a Source Anchor to exact Subject bytes',
        candidate.candidateId,
      )
    }
  }
  if (candidate.evidenceArtifactIds.some(id => !durableEvidenceArtifactIds.has(id))) {
    throw new RoleCandidateAdmissionError(
      'EVIDENCE_UNAVAILABLE',
      'Candidate Admission requires every referenced Evidence object to be durable',
      candidate.candidateId,
    )
  }
}

/**
 * Admit every Candidate in one already-admitted Role Contribution atomically.
 * The result grants no validation, Finding, Coverage, Verdict, or Evidence-merging authority.
 */
export function createRoleCandidateAdmissionsV1(
  options: CreateRoleCandidateAdmissionsOptionsV1,
): readonly RoleCandidateAdmissionV1[] {
  const {
    contextGrant,
    contribution,
    link,
    sourceSlices,
    durableEvidenceArtifactIds,
  } = parseInputs(options)
  validateLineage(contextGrant, contribution, link)

  if (new Set(durableEvidenceArtifactIds).size !== durableEvidenceArtifactIds.length) {
    throw new RoleCandidateAdmissionError(
      'EVIDENCE_UNAVAILABLE',
      'Candidate Admission durable Evidence identities must be unique',
    )
  }
  const sourcesByPath = validateSourceSlices(
    contextGrant,
    contribution.subjectDigest,
    sourceSlices,
  )
  const durableEvidence = new Set(durableEvidenceArtifactIds)
  const admissions = [...contribution.candidateFindings]
    .sort((left, right) => (
      left.candidateId < right.candidateId ? -1 : left.candidateId > right.candidateId ? 1 : 0
    ))
    .map(candidate => {
      validateCandidate(candidate, sourcesByPath, durableEvidence)
      const core = roleCandidateAdmissionCoreV1Schema.parse({
        schemaVersion: 1,
        state: 'ADMITTED',
        candidateId: candidate.candidateId,
        candidateDigest: structuredDigest(ROLE_CANDIDATE_FINDING_MEDIA_TYPE, candidate),
        assessmentId: contribution.assessmentId,
        assessmentRevision: link.assessmentRevision,
        subjectDigest: contribution.subjectDigest,
        provenance: {
          roleDefinition: contribution.roleDefinition,
          parentAttempt: contribution.parentAttempt,
          contextGrantDigest: contribution.contextGrantDigest,
          contributionId: contribution.contributionId,
          contributionDigest: contribution.contributionDigest,
          contributionAdmissionLinkDigest: link.linkDigest,
        },
        weaknessClassification: candidate.weaknessClassification,
        affectedControlId: candidate.affectedControlId,
        securityClaim: candidate.securityClaim,
        sourceAnchors: candidate.sourceAnchors,
        evidenceArtifactIds: candidate.evidenceArtifactIds,
        admittedAt: link.admittedAt,
      })
      return {
        ...core,
        admissionDigest: structuredDigest(ROLE_CANDIDATE_ADMISSION_MEDIA_TYPE, core),
      }
    })
  return deepFreeze(admissions)
}

/** Recompute one immutable Candidate Admission before validation or persistence use. */
export function parseRoleCandidateAdmissionV1(candidate: unknown): RoleCandidateAdmissionV1 {
  const admission = roleCandidateAdmissionV1Schema.parse(candidate)
  const { admissionDigest, ...candidateCore } = admission
  const core = roleCandidateAdmissionCoreV1Schema.parse(candidateCore)
  if (!same(
    admissionDigest,
    structuredDigest(ROLE_CANDIDATE_ADMISSION_MEDIA_TYPE, core),
  )) {
    throw new TypeError('Role Candidate Admission digest is invalid')
  }
  return deepFreeze({ ...core, admissionDigest })
}
