import { z } from 'zod'

import { digestEnvelopeV1Schema } from './digest-envelope.ts'

export const RELEASE_PROMOTION_HANDOFF_ENGINE_ID =
  'security/release-promotion-handoff/v1' as const

const boundedPathSchema = z.string().min(1).max(4_096)
const packageNameSchema = z.string()
  .min(1)
  .max(214)
  .regex(/^(?:@[a-z0-9][a-z0-9._~-]*\/[a-z0-9][a-z0-9._~-]*|[a-z0-9][a-z0-9._~-]*)$/u)
const semanticBase = String.raw`(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)`
const stableVersionSchema = z.string().regex(new RegExp(`^${semanticBase}$`, 'u')).max(128)
const candidateVersionSchema = z.string().regex(new RegExp(
  `^${semanticBase}-[0-9A-Za-z-]+(?:\\.[0-9A-Za-z-]+)*(?:\\+[0-9A-Za-z-]+(?:\\.[0-9A-Za-z-]+)*)?$`,
  'u',
)).max(128)
const packagePathSchema = z.string()
  .min(1)
  .max(4_096)
  .regex(/^package\/[^\\]+$/u)
  .refine(
    path => path.split('/').every(segment => segment.length > 0 && segment !== '.' && segment !== '..'),
    'Promotion handoff paths must be normalized package-relative paths.',
  )
const rawFileDigestSchema = digestEnvelopeV1Schema.refine(
  value => value.canonicalization === 'raw-bytes',
  'Promotion handoff files must be raw-byte bound.',
)

const artifactInputSchema = z.strictObject({
  path: boundedPathSchema,
  mediaType: z.literal('application/gzip'),
})

export const releasePromotionHandoffInputV1Schema = z.strictObject({
  schemaVersion: z.literal(1),
  qualificationOutputPath: boundedPathSchema,
  qualifiedCandidateArtifact: artifactInputSchema,
  proposedStableArtifact: artifactInputSchema,
  expectedStableVersion: stableVersionSchema,
})

export type ReleasePromotionHandoffInputV1 = z.infer<
  typeof releasePromotionHandoffInputV1Schema
>

const qualificationPortfolioDigestSchema = z.strictObject({
  manifest: rawFileDigestSchema.refine(value => value.mediaType === 'application/json'),
  publicScorecard: rawFileDigestSchema.refine(value => value.mediaType === 'application/json'),
  verdict: rawFileDigestSchema.refine(value => value.mediaType === 'application/json'),
})

const gzipArtifactDigestSchema = rawFileDigestSchema.refine(
  value => value.mediaType === 'application/gzip',
)

export const releasePromotionHandoffV1Schema = z.strictObject({
  schemaVersion: z.literal(1),
  engineId: z.literal(RELEASE_PROMOTION_HANDOFF_ENGINE_ID),
  evaluatedAtEpochMs: z.number().int().nonnegative(),
  sourceRevision: z.string().regex(/^(?:[0-9a-f]{40}|[0-9a-f]{64})$/u),
  manifestId: z.string().min(1).max(128),
  releaseCandidateId: z.string().min(1).max(128),
  packageName: packageNameSchema,
  candidateVersion: candidateVersionSchema,
  stableVersion: stableVersionSchema,
  qualificationPortfolioDigests: qualificationPortfolioDigestSchema,
  qualifiedCandidateArtifactDigest: gzipArtifactDigestSchema,
  proposedStableArtifactDigest: gzipArtifactDigestSchema,
  comparedEntryCount: z.number().int().positive().max(10_000),
  versionChangedEntryPaths: z.array(packagePathSchema).min(1).max(10_000),
  releaseMetadataChangedEntryPaths: z.array(packagePathSchema).max(2),
  equivalence: z.literal('EXACT_VERSION_TOKEN_REPLACEMENT_V1'),
  verification: z.literal('BEHAVIOR_EQUIVALENT'),
  authorization: z.literal('NOT_GRANTED'),
}).superRefine((value, context) => {
  const candidateBase = value.candidateVersion.split('-', 1)[0]
  const expectedVersionPaths = [...new Set(value.versionChangedEntryPaths)].sort()
  const expectedMetadataPaths = [...new Set(value.releaseMetadataChangedEntryPaths)].sort()
  if (
    candidateBase !== value.stableVersion
    || JSON.stringify(value.versionChangedEntryPaths) !== JSON.stringify(expectedVersionPaths)
    || JSON.stringify(value.releaseMetadataChangedEntryPaths) !== JSON.stringify(expectedMetadataPaths)
    || value.versionChangedEntryPaths.some(path => value.releaseMetadataChangedEntryPaths.includes(path))
  ) {
    context.addIssue({ code: 'custom', message: 'Inconsistent promotion handoff receipt.' })
  }
})

export type ReleasePromotionHandoffV1 = z.infer<
  typeof releasePromotionHandoffV1Schema
>
