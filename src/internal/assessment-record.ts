import { z } from 'zod'
import {
  assessmentIdSchema,
  assessmentStateSchema,
  assessmentSubjectSourceV1Schema,
  bundleManifestV1Schema,
  digestEnvelopeV1Schema,
  repositoryBindingsV1Schema,
  repositoryIdSchema,
  securityAssuranceSubmissionV1Schema,
  securitySubmissionJsonV1Schema,
  securityVerdictSchema,
  assessmentCoverageSnapshotV1Schema,
  assessmentModeSchema,
  assessmentProfileIdSchema,
  assessmentTargetSelectorV1Schema,
  assessmentSealV1Schema,
  assessmentOperatorReasonV1Schema,
} from '../contracts.ts'
import type {
  AssessmentSnapshotV1,
} from '../contracts.ts'
import { analyzerPortfolioEntryV1Schema } from '../analyzer.ts'

const preparedContractV1Schema = z.strictObject({
  schemaVersion: z.literal(1),
  assessmentMode: assessmentModeSchema,
  assessmentProfileId: assessmentProfileIdSchema,
  target: assessmentTargetSelectorV1Schema,
  requestedStrongerControlIds: z.array(z.string()).max(16),
  policy: z.strictObject({
    policyId: z.string(),
    digest: digestEnvelopeV1Schema,
    value: securitySubmissionJsonV1Schema,
  }),
  analyzerPortfolio: z.array(analyzerPortfolioEntryV1Schema).max(64).default([]),
  coverage: assessmentCoverageSnapshotV1Schema,
})

export const internalAssessmentRecordV1Schema = z.strictObject({
  schemaVersion: z.literal(1),
  assessmentId: assessmentIdSchema,
  assessmentRevision: z.number().int().positive(),
  state: assessmentStateSchema,
  repository: z.strictObject({
    repositoryId: repositoryIdSchema,
    repositoryRevision: z.number().int().positive(),
    rootIdentityDigest: z.string(),
    bindings: repositoryBindingsV1Schema,
  }),
  subject: z.strictObject({
    source: assessmentSubjectSourceV1Schema,
    digest: digestEnvelopeV1Schema,
    stats: z.strictObject({
      files: z.number().int().nonnegative(),
      bytes: z.number().int().nonnegative(),
      symbolicLinks: z.number().int().nonnegative(),
      submodules: z.number().int().nonnegative(),
    }),
  }),
  contract: preparedContractV1Schema,
  coverage: assessmentCoverageSnapshotV1Schema,
  findings: z.array(securitySubmissionJsonV1Schema).max(10_000),
  evaluationTrace: securitySubmissionJsonV1Schema.nullable(),
  verdict: securityVerdictSchema.nullable(),
  seal: assessmentSealV1Schema.nullable(),
  bundleManifest: bundleManifestV1Schema.nullable(),
  submission: securityAssuranceSubmissionV1Schema.nullable(),
  publicationDigest: digestEnvelopeV1Schema.nullable(),
  failureCode: z.string().nullable(),
  operatorActions: z.array(z.strictObject({
    operation: z.enum(['resume_assessment', 'cancel_assessment']),
    principalId: z.string().min(1).max(128),
    authorityKind: z.string().min(1).max(64),
    reason: assessmentOperatorReasonV1Schema,
    recordedAt: z.iso.datetime({ offset: true }),
  })).max(256).default([]),
  pendingCancellation: z.strictObject({
    requestRevision: z.number().int().positive(),
    requestedAt: z.iso.datetime({ offset: true }),
  }).nullable().default(null),
  createdAt: z.iso.datetime({ offset: true }),
  updatedAt: z.iso.datetime({ offset: true }),
})

export type InternalAssessmentRecordV1 = z.infer<typeof internalAssessmentRecordV1Schema>

export function publicAssessmentSnapshot(record: InternalAssessmentRecordV1): AssessmentSnapshotV1 {
  return {
    schemaVersion: 1,
    assessmentId: record.assessmentId,
    assessmentRevision: record.assessmentRevision,
    state: record.state,
    repository: {
      repositoryId: record.repository.repositoryId,
      repositoryRevision: record.repository.repositoryRevision,
    },
    subject: {
      kind: record.subject.source.kind,
      digest: record.subject.digest,
    },
    policy: {
      policyId: record.contract.policy.policyId,
      digest: record.contract.policy.digest,
    },
    coverage: record.coverage,
    verdict: record.verdict,
    seal: record.seal,
    createdAt: record.createdAt,
    updatedAt: record.updatedAt,
  }
}
