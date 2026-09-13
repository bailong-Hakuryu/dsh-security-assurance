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
import { ROLE_CONTEXT_GRANT_MEDIA_TYPE } from '../role-context-grant.ts'
import { canonicalJson, structuredDigest } from './canonical.ts'
import { deepFreeze } from './freeze.ts'
import { MODEL_INVOCATION_RECORD_MEDIA_TYPE } from './model-invocation-settlement.ts'
import { SOURCE_SLICE_EGRESS_ATTEMPT_FENCE_MEDIA_TYPE } from './source-slice-egress-invocation.ts'

export const ROLE_CONTRIBUTION_MEDIA_TYPE =
  'application/vnd.dsh.security.role-contribution+json'

const MAX_CONTRIBUTION_BYTES = 1024 * 1024
const boundedIdSchema = z.string().regex(/^[a-z0-9][a-z0-9._/-]{0,127}$/iu)
const artifactIdSchema = z.string().regex(/^[a-z0-9][a-z0-9-]{0,127}$/u)
const candidateIdSchema = z.string().regex(/^candidate-[0-9a-f]{64}$/u)
const contributionIdSchema = z.string().regex(
  /^role-contribution-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u,
)
const followUpRequestIdSchema = z.string().regex(
  /^follow-up-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u,
)
const evidenceRequestIdSchema = z.string().regex(
  /^evidence-request-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u,
)
const roleAttemptIdSchema = z.string().regex(
  /^role-attempt-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u,
)
const semanticVersionSchema = z.string()
  .max(128)
  .regex(/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/u)
const boundedTextSchema = z.string().min(1).max(2_048)
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
      message: 'Role Contribution Source Anchors require canonical Subject-relative paths',
    })
  }
})

const attemptFenceDigestSchema = digestEnvelopeV1Schema.refine(
  digest => digest.mediaType === SOURCE_SLICE_EGRESS_ATTEMPT_FENCE_MEDIA_TYPE,
  'Role Contributions must bind an Attempt fence digest',
)
const contextGrantDigestSchema = digestEnvelopeV1Schema.refine(
  digest => digest.mediaType === ROLE_CONTEXT_GRANT_MEDIA_TYPE,
  'Role Contributions must bind a Context Grant digest',
)
const invocationRecordDigestSchema = digestEnvelopeV1Schema.refine(
  digest => (
    digest.mediaType === MODEL_INVOCATION_RECORD_MEDIA_TYPE
    && digest.canonicalization === 'dsh-canonical-json-v1'
  ),
  'Role Contributions must bind canonical Model Invocation Records',
)
const rawBytesDigestSchema = digestEnvelopeV1Schema.refine(
  digest => digest.canonicalization === 'raw-bytes',
  'Role Contributions must bind exact raw bytes',
)
const contributionDigestSchema = digestEnvelopeV1Schema.refine(
  digest => (
    digest.mediaType === ROLE_CONTRIBUTION_MEDIA_TYPE
    && digest.canonicalization === 'dsh-canonical-json-v1'
  ),
  'Role Contributions must use the contribution media type',
)

export interface RoleContributionSourceAnchorV1 {
  readonly path: string
  readonly fileDigest: DigestEnvelopeV1
  readonly byteSpan: {
    readonly start: number
    readonly length: number
  }
  readonly symbolId: string | null
}

const sourceAnchorSchema: z.ZodType<RoleContributionSourceAnchorV1> = z.strictObject({
  path: sourcePathSchema,
  fileDigest: rawBytesDigestSchema,
  byteSpan: z.strictObject({
    start: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER),
    length: z.number().int().positive().max(Number.MAX_SAFE_INTEGER),
  }),
  symbolId: z.string().min(1).max(256).nullable(),
}).superRefine((anchor, context) => {
  if (!Number.isSafeInteger(anchor.byteSpan.start + anchor.byteSpan.length)) {
    context.addIssue({
      code: 'custom',
      path: ['byteSpan'],
      message: 'Role Contribution Source Anchor byte span exceeds the safe range',
    })
  }
})

export interface RoleContributionCandidateFindingV1 {
  readonly schemaVersion: 1
  readonly candidateId: string
  readonly weaknessClassification: {
    readonly schemaVersion: 1
    readonly primary: string
    readonly secondary: readonly string[]
  }
  readonly affectedControlId: string
  readonly securityClaim: string
  readonly sourceAnchors: readonly RoleContributionSourceAnchorV1[]
  readonly evidenceArtifactIds: readonly string[]
}

const candidateFindingSchema: z.ZodType<RoleContributionCandidateFindingV1> = z.strictObject({
  schemaVersion: z.literal(1),
  candidateId: candidateIdSchema,
  weaknessClassification: z.strictObject({
    schemaVersion: z.literal(1),
    primary: boundedIdSchema,
    secondary: z.array(boundedIdSchema).max(16),
  }),
  affectedControlId: boundedIdSchema,
  securityClaim: boundedTextSchema,
  sourceAnchors: z.array(sourceAnchorSchema).min(1).max(32),
  evidenceArtifactIds: z.array(artifactIdSchema).min(1).max(32),
}).superRefine((candidate, context) => {
  if (!unique(candidate.weaknessClassification.secondary)) {
    context.addIssue({
      code: 'custom',
      path: ['weaknessClassification', 'secondary'],
      message: 'Role Contribution secondary weaknesses must be unique',
    })
  }
  if (!unique(candidate.evidenceArtifactIds)) {
    context.addIssue({
      code: 'custom',
      path: ['evidenceArtifactIds'],
      message: 'Role Contribution Candidate Evidence references must be unique',
    })
  }
})

export interface RoleContributionCoreV1 {
  readonly schemaVersion: 1
  readonly contributionId: string
  readonly assessmentId: AssessmentId
  readonly subjectDigest: DigestEnvelopeV1
  readonly parentAttempt: {
    readonly attemptId: string
    readonly generation: number
    readonly fenceDigest: DigestEnvelopeV1
  }
  readonly contextGrantDigest: DigestEnvelopeV1
  readonly roleDefinition: {
    readonly roleId: SecurityRoleIdV1
    readonly roleVersion: string
    readonly definitionDigest: DigestEnvelopeV1
  }
  readonly modelInvocations: readonly {
    readonly invocationId: string
    readonly recordDigest: DigestEnvelopeV1
    readonly responseDigest: DigestEnvelopeV1
    readonly inputTokens: number
    readonly outputTokens: number
  }[]
  readonly hypotheses: readonly {
    readonly hypothesisId: string
    readonly securityClaim: string
    readonly evidenceArtifactIds: readonly string[]
  }[]
  readonly candidateFindings: readonly RoleContributionCandidateFindingV1[]
  readonly coverageObservations: readonly {
    readonly obligationId: string
    readonly state: 'SUPPORTED' | 'GAP' | 'UNRESOLVED'
    readonly evidenceArtifactIds: readonly string[]
    readonly explanation: string
  }[]
  readonly evidenceArtifactIds: readonly string[]
  readonly evidenceRequests: readonly {
    readonly requestId: string
    readonly evidenceKindId: string
    readonly purpose: string
    readonly relatedCandidateIds: readonly string[]
  }[]
  readonly challenges: readonly {
    readonly challengeId: string
    readonly targetCandidateId: string
    readonly disposition: 'CORROBORATES' | 'DISPUTES' | 'PROOF_GAP' | 'FOLLOW_UP_REQUESTED'
    readonly evidenceArtifactIds: readonly string[]
    readonly rationale: string
  }[]
  readonly uncertainty: readonly string[]
  readonly limitations: readonly string[]
  readonly followUpRequests: readonly {
    readonly requestId: string
    readonly unresolvedObligationId: string
    readonly requestedRoleId: SecurityRoleIdV1
    readonly requiredCapabilityId: string
    readonly evidenceArtifactIds: readonly string[]
    readonly reason: string
  }[]
  readonly resourceUse: {
    readonly requests: number
    readonly inputTokens: number
    readonly outputTokens: number
    readonly tokens: number
  }
  readonly completionDisposition: 'COMPLETE' | 'PARTIAL'
}

const roleContributionCoreShape = {
  schemaVersion: z.literal(1),
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
  modelInvocations: z.array(z.strictObject({
    invocationId: boundedIdSchema,
    recordDigest: invocationRecordDigestSchema,
    responseDigest: rawBytesDigestSchema,
    inputTokens: z.number().int().nonnegative().max(4_000_000),
    outputTokens: z.number().int().nonnegative().max(4_000_000),
  })).min(1).max(64),
  hypotheses: z.array(z.strictObject({
    hypothesisId: boundedIdSchema,
    securityClaim: boundedTextSchema,
    evidenceArtifactIds: z.array(artifactIdSchema).max(32),
  })).max(128),
  candidateFindings: z.array(candidateFindingSchema).max(256),
  coverageObservations: z.array(z.strictObject({
    obligationId: boundedIdSchema,
    state: z.enum(['SUPPORTED', 'GAP', 'UNRESOLVED']),
    evidenceArtifactIds: z.array(artifactIdSchema).max(32),
    explanation: boundedTextSchema,
  })).max(256),
  evidenceArtifactIds: z.array(artifactIdSchema).max(256),
  evidenceRequests: z.array(z.strictObject({
    requestId: evidenceRequestIdSchema,
    evidenceKindId: boundedIdSchema,
    purpose: boundedTextSchema,
    relatedCandidateIds: z.array(candidateIdSchema).max(32),
  })).max(128),
  challenges: z.array(z.strictObject({
    challengeId: boundedIdSchema,
    targetCandidateId: candidateIdSchema,
    disposition: z.enum(['CORROBORATES', 'DISPUTES', 'PROOF_GAP', 'FOLLOW_UP_REQUESTED']),
    evidenceArtifactIds: z.array(artifactIdSchema).max(32),
    rationale: boundedTextSchema,
  })).max(128),
  uncertainty: z.array(boundedTextSchema).max(128),
  limitations: z.array(boundedTextSchema).max(128),
  followUpRequests: z.array(z.strictObject({
    requestId: followUpRequestIdSchema,
    unresolvedObligationId: boundedIdSchema,
    requestedRoleId: securityRoleIdV1Schema,
    requiredCapabilityId: boundedIdSchema,
    evidenceArtifactIds: z.array(artifactIdSchema).max(64),
    reason: boundedTextSchema,
  })).max(64),
  resourceUse: z.strictObject({
    requests: z.number().int().positive().max(64),
    inputTokens: z.number().int().nonnegative().max(4_000_000),
    outputTokens: z.number().int().nonnegative().max(4_000_000),
    tokens: z.number().int().nonnegative().max(4_000_000),
  }),
  completionDisposition: z.enum(['COMPLETE', 'PARTIAL']),
} as const

function unique(values: readonly string[]): boolean {
  return new Set(values).size === values.length
}

function validateReferences(
  values: RoleContributionCoreV1,
  context: z.RefinementCtx,
): void {
  const uniqueCollections: readonly [readonly string[], (string | number)[]][] = [
    [values.modelInvocations.map(value => value.invocationId), ['modelInvocations']],
    [values.hypotheses.map(value => value.hypothesisId), ['hypotheses']],
    [values.candidateFindings.map(value => value.candidateId), ['candidateFindings']],
    [values.coverageObservations.map(value => value.obligationId), ['coverageObservations']],
    [values.evidenceArtifactIds, ['evidenceArtifactIds']],
    [values.evidenceRequests.map(value => value.requestId), ['evidenceRequests']],
    [values.challenges.map(value => value.challengeId), ['challenges']],
    [values.followUpRequests.map(value => value.requestId), ['followUpRequests']],
  ]
  for (const [identities, path] of uniqueCollections) {
    if (!unique(identities)) {
      context.addIssue({
        code: 'custom',
        path,
        message: 'Role Contribution identities and references must be unique',
      })
    }
  }

  const evidence = new Set(values.evidenceArtifactIds)
  const nestedEvidenceReferences = [
    ...values.hypotheses.map(value => value.evidenceArtifactIds),
    ...values.coverageObservations.map(value => value.evidenceArtifactIds),
    ...values.challenges.map(value => value.evidenceArtifactIds),
    ...values.followUpRequests.map(value => value.evidenceArtifactIds),
  ]
  if (nestedEvidenceReferences.some(references => !unique(references))) {
    context.addIssue({
      code: 'custom',
      path: ['evidenceArtifactIds'],
      message: 'Role Contribution nested Evidence references must be unique',
    })
  }
  const referencedEvidence = [
    ...values.hypotheses.flatMap(value => value.evidenceArtifactIds),
    ...values.candidateFindings.flatMap(value => value.evidenceArtifactIds),
    ...values.coverageObservations.flatMap(value => value.evidenceArtifactIds),
    ...values.challenges.flatMap(value => value.evidenceArtifactIds),
    ...values.followUpRequests.flatMap(value => value.evidenceArtifactIds),
  ]
  if (referencedEvidence.some(artifactId => !evidence.has(artifactId))) {
    context.addIssue({
      code: 'custom',
      path: ['evidenceArtifactIds'],
      message: 'Role Contribution semantic records must reference declared Evidence context',
    })
  }

  const candidates = new Set(values.candidateFindings.map(value => value.candidateId))
  if (
    values.evidenceRequests.some(request => (
      !unique(request.relatedCandidateIds)
      || request.relatedCandidateIds.some(candidateId => !candidates.has(candidateId))
    ))
    || values.challenges.some(challenge => !candidates.has(challenge.targetCandidateId))
  ) {
    context.addIssue({
      code: 'custom',
      path: ['candidateFindings'],
      message: 'Role Contribution requests and challenges must reference declared Candidates',
    })
  }

  const invocationTokens = values.modelInvocations.reduce(
    (usage, invocation) => ({
      input: usage.input + invocation.inputTokens,
      output: usage.output + invocation.outputTokens,
    }),
    { input: 0, output: 0 },
  )
  if (
    values.resourceUse.requests !== values.modelInvocations.length
    || values.resourceUse.inputTokens !== invocationTokens.input
    || values.resourceUse.outputTokens !== invocationTokens.output
    || values.resourceUse.tokens !== invocationTokens.input + invocationTokens.output
  ) {
    context.addIssue({
      code: 'custom',
      path: ['resourceUse'],
      message: 'Role Contribution resource use must equal its exact Model Invocation lineage',
    })
  }

  const coreForSize = { ...values } as Record<string, unknown>
  delete coreForSize.contributionDigest
  if (Buffer.byteLength(canonicalJson(coreForSize), 'utf8') > MAX_CONTRIBUTION_BYTES) {
    context.addIssue({
      code: 'custom',
      message: 'Role Contribution exceeds the v1 aggregate byte budget',
    })
  }
}

export const roleContributionCoreV1Schema: z.ZodType<RoleContributionCoreV1> =
  z.strictObject(roleContributionCoreShape).superRefine(validateReferences)

export interface RoleContributionV1 extends RoleContributionCoreV1 {
  readonly contributionDigest: DigestEnvelopeV1
}

export const roleContributionV1Schema: z.ZodType<RoleContributionV1> = z.strictObject({
  ...roleContributionCoreShape,
  contributionDigest: contributionDigestSchema,
}).superRefine(validateReferences)

/** Create one immutable terminal proposal. This function grants no admission or mutation authority. */
export function createRoleContributionV1(candidate: unknown): RoleContributionV1 {
  const core = roleContributionCoreV1Schema.parse(candidate)
  return deepFreeze({
    ...core,
    contributionDigest: structuredDigest(ROLE_CONTRIBUTION_MEDIA_TYPE, core),
  })
}

/** Recompute one protected terminal proposal before any Service admission. */
export function parseRoleContributionV1(candidate: unknown): RoleContributionV1 {
  const contribution = roleContributionV1Schema.parse(candidate)
  const { contributionDigest, ...candidateCore } = contribution
  const core = roleContributionCoreV1Schema.parse(candidateCore)
  if (canonicalJson(
    contributionDigest,
  ) !== canonicalJson(structuredDigest(ROLE_CONTRIBUTION_MEDIA_TYPE, core))) {
    throw new TypeError('Role Contribution digest is invalid')
  }
  return deepFreeze({ ...core, contributionDigest })
}
