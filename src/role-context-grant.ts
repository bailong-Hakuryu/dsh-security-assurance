import { z } from 'zod'
import type {
  AssessmentId,
  AssessmentMode,
  AssessmentProfileId,
  DigestEnvelopeV1,
  SecurityRoleIdV1,
} from './contracts.ts'
import {
  assessmentIdSchema,
  assessmentModeSchema,
  assessmentProfileIdSchema,
  digestEnvelopeV1Schema,
  securityRoleIdV1Schema,
} from './contracts.ts'
import { canonicalJson, structuredDigest } from './internal/canonical.ts'
import { deepFreeze } from './internal/freeze.ts'

export const ROLE_CONTEXT_GRANT_MEDIA_TYPE = 'application/vnd.dsh.security.role-context-grant+json'

const boundedGrantIdSchema = z.string().regex(/^[a-z0-9][a-z0-9._/-]{0,127}$/i)
const artifactIdSchema = z.string().regex(/^[a-z0-9][a-z0-9-]{0,127}$/)
const roleAttemptIdSchema = z.string().regex(/^role-attempt-[0-9a-f-]{36}$/)
const semanticVersionSchema = z.string()
  .max(128)
  .regex(/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/)

function unique(values: readonly string[]): boolean {
  return new Set(values).size === values.length
}

export interface RoleContextArtifactReferenceV1 {
  readonly artifactId: string
  readonly schemaId: string
  readonly digest: DigestEnvelopeV1
  readonly disclosureCategoryId: string
}

const roleContextArtifactReferenceV1Schema: z.ZodType<RoleContextArtifactReferenceV1> =
  z.strictObject({
    artifactId: artifactIdSchema,
    schemaId: boundedGrantIdSchema,
    digest: digestEnvelopeV1Schema,
    disclosureCategoryId: boundedGrantIdSchema,
  })

export interface RoleContextGrantCoreV1 {
  readonly schemaVersion: 1
  readonly assessmentId: AssessmentId
  readonly roleAttemptId: string
  readonly roleDefinition: {
    readonly roleId: SecurityRoleIdV1
    readonly roleVersion: string
    readonly definitionDigest: DigestEnvelopeV1
  }
  readonly purpose: {
    readonly purposeId: string
    readonly assessmentMode: AssessmentMode
    readonly assessmentProfileId: AssessmentProfileId
    readonly targetDigest: DigestEnvelopeV1
    readonly coverageObligationIds: readonly string[]
    readonly constraintIds: readonly string[]
    readonly peerContributionVisibility: 'NONE' | 'FROZEN_CONTRIBUTIONS_ONLY'
  }
  readonly subject: {
    readonly digest: DigestEnvelopeV1
    readonly inventory: readonly RoleContextArtifactReferenceV1[]
    readonly sourceSlices: readonly RoleContextArtifactReferenceV1[]
  }
  readonly evidenceProjections: readonly RoleContextArtifactReferenceV1[]
  readonly disclosure: {
    readonly dataEgressPolicyId: string
    readonly destinationId: string
    readonly categoryIds: readonly string[]
  }
  readonly budget: {
    readonly contextBytes: { readonly limit: number; readonly granted: number }
    readonly tokens: { readonly limit: number; readonly granted: number }
  }
}

const roleContextGrantCoreV1Shape = {
  schemaVersion: z.literal(1),
  assessmentId: assessmentIdSchema,
  roleAttemptId: roleAttemptIdSchema,
  roleDefinition: z.strictObject({
    roleId: securityRoleIdV1Schema,
    roleVersion: semanticVersionSchema,
    definitionDigest: digestEnvelopeV1Schema,
  }),
  purpose: z.strictObject({
    purposeId: boundedGrantIdSchema,
    assessmentMode: assessmentModeSchema,
    assessmentProfileId: assessmentProfileIdSchema,
    targetDigest: digestEnvelopeV1Schema,
    coverageObligationIds: z.array(boundedGrantIdSchema).min(1).max(128),
    constraintIds: z.array(boundedGrantIdSchema).max(64),
    peerContributionVisibility: z.enum(['NONE', 'FROZEN_CONTRIBUTIONS_ONLY']),
  }),
  subject: z.strictObject({
    digest: digestEnvelopeV1Schema,
    inventory: z.array(roleContextArtifactReferenceV1Schema).min(1).max(32),
    sourceSlices: z.array(roleContextArtifactReferenceV1Schema).max(256),
  }),
  evidenceProjections: z.array(roleContextArtifactReferenceV1Schema).max(256),
  disclosure: z.strictObject({
    dataEgressPolicyId: boundedGrantIdSchema,
    destinationId: boundedGrantIdSchema,
    categoryIds: z.array(boundedGrantIdSchema).min(1).max(64),
  }),
  budget: z.strictObject({
    contextBytes: z.strictObject({
      limit: z.number().int().positive().max(64 * 1024 * 1024),
      granted: z.number().int().nonnegative().max(64 * 1024 * 1024),
    }),
    tokens: z.strictObject({
      limit: z.number().int().positive().max(4_000_000),
      granted: z.number().int().nonnegative().max(4_000_000),
    }),
  }),
} as const

function validateRoleContextGrantCore(
  grant: RoleContextGrantCoreV1,
  context: z.RefinementCtx,
): void {
  if (
    grant.budget.contextBytes.granted > grant.budget.contextBytes.limit
    || grant.budget.tokens.granted > grant.budget.tokens.limit
  ) {
    context.addIssue({
      code: 'custom',
      path: ['budget'],
      message: 'Role Context Grant exceeds its frozen budget',
    })
  }
  for (const values of [
    grant.purpose.coverageObligationIds,
    grant.purpose.constraintIds,
    grant.disclosure.categoryIds,
  ]) {
    if (!unique(values)) {
      context.addIssue({
        code: 'custom',
        message: 'Role Context Grant identifier arrays must be unique',
      })
    }
  }
  const references = [
    ...grant.subject.inventory,
    ...grant.subject.sourceSlices,
    ...grant.evidenceProjections,
  ]
  if (!unique(references.map(reference => reference.artifactId))) {
    context.addIssue({
      code: 'custom',
      message: 'Role Context Grant artifact references must be unique',
    })
  }
  const disclosedCategories = new Set(grant.disclosure.categoryIds)
  if (references.some(reference => !disclosedCategories.has(reference.disclosureCategoryId))) {
    context.addIssue({
      code: 'custom',
      path: ['disclosure', 'categoryIds'],
      message: 'Role Context Grant contains an artifact outside its disclosure categories',
    })
  }
}

export const roleContextGrantCoreV1Schema: z.ZodType<RoleContextGrantCoreV1> =
  z.strictObject(roleContextGrantCoreV1Shape).superRefine(validateRoleContextGrantCore)

export interface RoleContextGrantV1 extends RoleContextGrantCoreV1 {
  readonly grantDigest: DigestEnvelopeV1
}

export const roleContextGrantV1Schema: z.ZodType<RoleContextGrantV1> = z.strictObject({
  ...roleContextGrantCoreV1Shape,
  grantDigest: digestEnvelopeV1Schema,
}).superRefine(validateRoleContextGrantCore)

/** Create immutable authority-free context metadata; this function grants no capability. */
export function createRoleContextGrantV1(candidate: unknown): RoleContextGrantV1 {
  const core = roleContextGrantCoreV1Schema.parse(candidate)
  return deepFreeze({
    ...core,
    grantDigest: structuredDigest(ROLE_CONTEXT_GRANT_MEDIA_TYPE, core),
  })
}

/** Validate exact Context Grant content and detach it from the caller's mutable value. */
export function parseRoleContextGrantV1(candidate: unknown): RoleContextGrantV1 {
  const grant = roleContextGrantV1Schema.parse(candidate)
  const { grantDigest, ...core } = grant
  const parsedCore = roleContextGrantCoreV1Schema.parse(core)
  const observedDigest = structuredDigest(ROLE_CONTEXT_GRANT_MEDIA_TYPE, parsedCore)
  if (
    grantDigest.mediaType !== ROLE_CONTEXT_GRANT_MEDIA_TYPE
    || canonicalJson(grantDigest) !== canonicalJson(observedDigest)
  ) {
    throw new TypeError('Role Context Grant digest does not bind its canonical content')
  }
  return deepFreeze({ ...parsedCore, grantDigest })
}
