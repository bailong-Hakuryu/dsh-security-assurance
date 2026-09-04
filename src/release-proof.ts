import { z } from 'zod'

import { digestEnvelopeV1Schema } from './digest-envelope.ts'

export const RELEASE_EVIDENCE_PROOF_KINDS = [
  'ARTIFACT_IDENTITY',
  'CAPABILITY_CONFORMANCE',
  'WINDOWS_PLATFORM',
  'LINUX_PLATFORM',
  'MACOS_PLATFORM',
  'WORKBENCH',
  'LIFECYCLE',
  'FAULT',
  'RACE',
  'MUTATION',
  'RESOURCE',
  'EFFECTIVENESS',
  'UTILITY',
  'NON_INFERIORITY',
  'DOGFOOD',
  'SELF_SECURITY',
  'GROUND_TRUTH_AIR_GAP',
  'DETERMINISTIC_FAILURES',
  'SECURITY_SUPPORT_MATRIX',
  'RISK_ACCEPTANCES',
  'EVALUATION_RUN_BUNDLE',
  'PUBLIC_SCORECARD',
  'RELEASE_CONSTITUTION',
] as const

export type ReleaseEvidenceProofKind = typeof RELEASE_EVIDENCE_PROOF_KINDS[number]

export const releaseEvidenceReportedStatusV1Schema = z.enum([
  'PASSED',
  'FAILED',
  'INCONCLUSIVE',
])

export const releaseEvidenceProofV1Schema = z.strictObject({
  proofKind: z.enum(RELEASE_EVIDENCE_PROOF_KINDS),
  evidenceId: z.string().regex(/^[a-z0-9][a-z0-9._:/-]{0,127}$/u),
  evidenceDigest: digestEnvelopeV1Schema,
  reportedStatus: releaseEvidenceReportedStatusV1Schema,
  candidateArtifactDigest: digestEnvelopeV1Schema,
  completedAtEpochMs: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER),
})

export type ReleaseEvidenceProofV1 = z.infer<typeof releaseEvidenceProofV1Schema>

export const RELEASE_PROOF_RECORD_ENGINE_ID = 'security/release-proof-record/v1' as const

const releaseProofProducerV1Schema = z.enum([
  'PACKED_HARNESS_PROFILE_SMOKE',
  'PACKED_BROWSER_E2E',
])

const releaseProofEnvironmentV1Schema = z.strictObject({
  platform: z.enum(['WINDOWS', 'LINUX', 'MACOS']),
  architecture: z.string().regex(/^[a-z0-9][a-z0-9._-]{0,31}$/u),
  nodeVersion: z.string()
    .regex(/^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-[0-9a-z.-]+)?$/u),
  harnessVersion: z.string()
    .regex(/^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-[0-9a-z.-]+)?(?:\+[0-9a-z.-]+)?$/u),
})

const releaseProofProducerVersionV1Schema = z.string()
  .regex(/^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-[0-9a-z.-]+)?(?:\+[0-9a-z.-]+)?$/u)

export const releaseProofRecordV1Schema = z.strictObject({
  schemaVersion: z.literal(1),
  engineId: z.literal(RELEASE_PROOF_RECORD_ENGINE_ID),
  proofRecordId: z.string().regex(/^[a-z0-9][a-z0-9._:/-]{0,127}$/u),
  proofKind: z.enum(RELEASE_EVIDENCE_PROOF_KINDS),
  producer: releaseProofProducerV1Schema,
  producerVersion: releaseProofProducerVersionV1Schema,
  reportedStatus: releaseEvidenceReportedStatusV1Schema,
  candidateArtifactDigest: digestEnvelopeV1Schema.refine(
    value => value.canonicalization === 'raw-bytes',
    'Release proof candidates must be raw-byte bound.',
  ),
  completedAtEpochMs: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER),
  environment: releaseProofEnvironmentV1Schema,
  assertions: z.array(z.strictObject({
    assertionId: z.string().regex(/^[A-Z][A-Z0-9_]{0,63}$/u),
    status: releaseEvidenceReportedStatusV1Schema,
  })).min(1).max(64),
}).superRefine((value, context) => {
  const assertionIds = value.assertions.map(assertion => assertion.assertionId)
  const derivedStatus = value.assertions.some(assertion => assertion.status === 'FAILED')
    ? 'FAILED'
    : value.assertions.some(assertion => assertion.status === 'INCONCLUSIVE')
      ? 'INCONCLUSIVE'
      : 'PASSED'
  const expectedProofKind = `${value.environment.platform}_PLATFORM`
  if (
    new Set(assertionIds).size !== assertionIds.length
    || value.reportedStatus !== derivedStatus
    || (value.producer === 'PACKED_HARNESS_PROFILE_SMOKE'
      && value.proofKind !== expectedProofKind)
    || (value.producer === 'PACKED_BROWSER_E2E' && (
      value.proofKind !== 'WORKBENCH'
      || !assertionIds.includes('WORKBENCH_CLIENT_SHIPPED')
    ))
  ) {
    context.addIssue({ code: 'custom', message: 'Inconsistent Release Proof Record.' })
  }
})

export type ReleaseProofRecordV1 = z.infer<typeof releaseProofRecordV1Schema>

export const RELEASE_PROOF_INDEX_ENGINE_ID = 'security/release-proof-index/v1' as const

const boundedReleasePathSchema = z.string().min(1).max(4_096)
const rawJsonDigestSchema = digestEnvelopeV1Schema.refine(
  value => value.canonicalization === 'raw-bytes' && value.mediaType === 'application/json',
  'Release proof index JSON digests must cover raw bytes.',
)

export const releaseProofCollectionInputV1Schema = z.strictObject({
  schemaVersion: z.literal(1),
  releaseFileBindingsPath: boundedReleasePathSchema,
  proofFiles: z.array(boundedReleasePathSchema).min(1).max(RELEASE_EVIDENCE_PROOF_KINDS.length),
}).superRefine((value, context) => {
  if (new Set(value.proofFiles).size !== value.proofFiles.length) {
    context.addIssue({ code: 'custom', message: 'Duplicate Release Proof Record path.' })
  }
})

export type ReleaseProofCollectionInputV1 = z.infer<typeof releaseProofCollectionInputV1Schema>

export const releaseProofIndexRecordV1Schema = z.strictObject({
  recordPath: boundedReleasePathSchema,
  producer: releaseProofProducerV1Schema,
  producerVersion: releaseProofProducerVersionV1Schema,
  environment: releaseProofEnvironmentV1Schema,
  proof: releaseEvidenceProofV1Schema.extend({
    evidenceDigest: rawJsonDigestSchema,
  }),
})

export const releaseProofIndexV1Schema = z.strictObject({
  schemaVersion: z.literal(1),
  engineId: z.literal(RELEASE_PROOF_INDEX_ENGINE_ID),
  releaseFileBindingsPath: boundedReleasePathSchema,
  releaseFileBindingsDigest: rawJsonDigestSchema,
  candidateArtifactDigest: digestEnvelopeV1Schema.refine(
    value => value.canonicalization === 'raw-bytes',
    'Release proof index candidates must be raw-byte bound.',
  ),
  records: z.array(releaseProofIndexRecordV1Schema)
    .min(1)
    .max(RELEASE_EVIDENCE_PROOF_KINDS.length),
}).superRefine((value, context) => {
  const proofKinds = value.records.map(record => record.proof.proofKind)
  const evidenceIds = value.records.map(record => record.proof.evidenceId)
  const recordPaths = value.records.map(record => record.recordPath)
  const orderedProofKinds = [...proofKinds].sort((left, right) => (
    RELEASE_EVIDENCE_PROOF_KINDS.indexOf(left) - RELEASE_EVIDENCE_PROOF_KINDS.indexOf(right)
  ))
  const candidateDigest = JSON.stringify(value.candidateArtifactDigest)
  if (
    new Set(proofKinds).size !== proofKinds.length
    || new Set(evidenceIds).size !== evidenceIds.length
    || new Set(recordPaths).size !== recordPaths.length
    || JSON.stringify(proofKinds) !== JSON.stringify(orderedProofKinds)
    || value.records.some(record => (
      JSON.stringify(record.proof.candidateArtifactDigest) !== candidateDigest
    ))
  ) {
    context.addIssue({ code: 'custom', message: 'Inconsistent Release Proof Index.' })
  }
})

export type ReleaseProofIndexV1 = z.infer<typeof releaseProofIndexV1Schema>
