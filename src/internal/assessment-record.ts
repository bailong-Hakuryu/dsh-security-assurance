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
  riskDecisionRecordV1Schema,
} from '../contracts.ts'
import type {
  AssessmentAvailableActionV1,
  AssessmentSnapshotV1,
} from '../contracts.ts'
import { analyzerPortfolioEntryV1Schema } from '../analyzer.ts'

const preparedContractV1Schema = z.strictObject({
  schemaVersion: z.literal(1),
  assessmentMode: assessmentModeSchema,
  assessmentProfileId: assessmentProfileIdSchema,
  target: assessmentTargetSelectorV1Schema,
  targetDigest: digestEnvelopeV1Schema,
  requestedStrongerControlIds: z.array(z.string()).max(16),
  policy: z.strictObject({
    policyId: z.string(),
    digest: digestEnvelopeV1Schema,
    value: securitySubmissionJsonV1Schema,
  }),
  analyzerPortfolio: z.array(analyzerPortfolioEntryV1Schema).max(64).default([]),
  coverage: assessmentCoverageSnapshotV1Schema,
})

const riskDecisionWindowV1Schema = z.strictObject({
  schemaVersion: z.literal(1),
  state: z.enum(['OPEN', 'RESOLVED']),
  controlId: z.literal('security/risk-decision-window-v1'),
  openedAt: z.iso.datetime({ offset: true }),
  evaluationInstant: z.iso.datetime({ offset: true }),
  proposedVerdict: securityVerdictSchema,
  findingRecordIds: z.array(z.string().regex(/^finding-[0-9a-f]{64}$/)).min(1).max(1024),
  providerComposition: securitySubmissionJsonV1Schema,
  evidenceReceipts: z.array(z.strictObject({
    schemaVersion: z.literal(1),
    artifactId: z.string().regex(/^[a-z0-9][a-z0-9-]{0,127}$/u),
    schemaId: z.string().regex(/^[a-z0-9][a-z0-9._-]*(?:\/[a-z0-9][a-z0-9._-]*){1,7}$/),
    digest: digestEnvelopeV1Schema,
  })).min(1).max(128),
  resolvedAt: z.iso.datetime({ offset: true }).nullable(),
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
  riskDecisionWindow: riskDecisionWindowV1Schema.nullable().default(null),
  riskDecisions: z.array(riskDecisionRecordV1Schema).max(1024).default([]),
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

export function publicAssessmentSnapshot(
  record: InternalAssessmentRecordV1,
  availableActions: readonly AssessmentAvailableActionV1[],
): AssessmentSnapshotV1 {
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
    contract: {
      schemaVersion: 1,
      assessmentMode: record.contract.assessmentMode,
      assessmentProfileId: record.contract.assessmentProfileId,
      target: record.contract.target,
      targetDigest: record.contract.targetDigest,
      requestedStrongerControlIds: record.contract.requestedStrongerControlIds,
    },
    policy: {
      policyId: record.contract.policy.policyId,
      digest: record.contract.policy.digest,
    },
    coverage: record.coverage,
    blockedRecovery: projectBlockedRecovery(record),
    availableActions,
    verdict: record.verdict,
    seal: record.seal,
    createdAt: record.createdAt,
    updatedAt: record.updatedAt,
  }
}

function projectBlockedRecovery(
  record: InternalAssessmentRecordV1,
): AssessmentSnapshotV1['blockedRecovery'] {
  if (record.state !== 'BLOCKED') return null
  if (record.failureCode === null) {
    throw new TypeError('BLOCKED Assessment has no durable failure code')
  }
  const riskDecision = record.failureCode === 'RISK_DECISION_WINDOW'
  const hostRestart = record.failureCode === 'HOST_RESTART_DURING_EVALUATION'
  const coverageReconciliationRequired = record.coverage.status === 'GAP'
  return {
    schemaVersion: 1,
    blocker: {
      code: record.failureCode,
      phase: riskDecision ? 'RISK_DECISION' : 'ASSESSMENT_EXECUTION',
      interruption: riskDecision
        ? 'GOVERNANCE_HOLD'
        : hostRestart ? 'INTERRUPTED' : 'FAILED',
      affectedObligations: record.coverage.resolutions
        .filter(resolution => resolution.state === 'GAP')
        .map(resolution => ({
          obligationId: resolution.obligationId,
          reason: resolution.reason,
        })),
    },
    evidence: {
      status: 'RETAINED',
      publishedArtifactCount: record.riskDecisionWindow?.evidenceReceipts.length ?? null,
    },
    recovery: {
      requiredCondition: riskDecision
        ? 'RISK_DECISION_REQUIRED'
        : record.failureCode === 'ASSESSMENT_EXECUTION_FAILED' || hostRestart
          ? 'EXPLICIT_RESUME_REQUIRED'
          : 'EXTERNAL_INTERVENTION_REQUIRED',
      remainingExecutionBudget: { status: 'NOT_REPORTED' },
      coverageReconciliation: {
        required: coverageReconciliationRequired,
        possibleVerdict: coverageReconciliationRequired ? 'INDETERMINATE' : null,
      },
    },
  }
}
