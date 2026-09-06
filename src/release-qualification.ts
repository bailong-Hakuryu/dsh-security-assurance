import { z } from 'zod'

import { digestEnvelopeV1Schema } from './digest-envelope.ts'
import {
  releaseEvidenceManifestRequestV1Schema,
  type ReleaseEvidenceManifestRequestV1,
} from './evaluation.ts'

export const RELEASE_QUALIFICATION_CLI_ENGINE_ID =
  'security/release-qualification-cli/v1' as const

const boundedReleasePathSchema = z.string().min(1).max(4_096)

export const releaseQualificationVerdictV1Schema = z.strictObject({
  schemaVersion: z.literal(1),
  engineId: z.literal(RELEASE_QUALIFICATION_CLI_ENGINE_ID),
  evaluatedAtEpochMs: z.number().int().nonnegative(),
  sourceRevision: z.string().regex(/^(?:[0-9a-f]{40}|[0-9a-f]{64})$/),
  manifestId: z.string().min(1).max(128),
  releaseCandidateId: z.string().min(1).max(128),
  candidateArtifactDigest: digestEnvelopeV1Schema,
  releaseDecision: z.enum(['PROMOTE', 'BLOCKED', 'INCONCLUSIVE']),
  manifestVerification: z.enum(['VERIFIED', 'BLOCKED', 'INCONCLUSIVE']),
  qualification: z.enum(['PROMOTE', 'BLOCKED', 'INCONCLUSIVE']),
})

export type ReleaseQualificationVerdictV1 = z.infer<
  typeof releaseQualificationVerdictV1Schema
>

export interface ReleaseQualificationInputV1 {
  readonly schemaVersion: 1
  readonly releaseFileBindingsPath: string
  readonly releaseEvidence: ReleaseEvidenceManifestRequestV1
}

export const releaseQualificationInputV1Schema: z.ZodType<ReleaseQualificationInputV1> = z.strictObject({
  schemaVersion: z.literal(1),
  releaseFileBindingsPath: boundedReleasePathSchema,
  releaseEvidence: releaseEvidenceManifestRequestV1Schema,
})

export interface ReleaseQualificationAssemblyInputV1 extends ReleaseQualificationInputV1 {
  readonly releaseProofIndexPath: string
}

export const releaseQualificationAssemblyInputV1Schema: z.ZodType<
  ReleaseQualificationAssemblyInputV1
> = z.strictObject({
  schemaVersion: z.literal(1),
  releaseProofIndexPath: boundedReleasePathSchema,
  releaseFileBindingsPath: boundedReleasePathSchema,
  releaseEvidence: releaseEvidenceManifestRequestV1Schema,
})
