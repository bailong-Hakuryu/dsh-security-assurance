import { z } from 'zod'

import {
  releaseEvidenceManifestRequestV1Schema,
  type ReleaseEvidenceManifestRequestV1,
} from './evaluation.ts'

const boundedReleasePathSchema = z.string().min(1).max(4_096)

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
