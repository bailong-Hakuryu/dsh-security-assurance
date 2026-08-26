import { describe, expect, it } from 'vitest'
import SecurityAssuranceService from '../src/index.js'
import type {
  AssessmentCancellationReceiptV1,
  AssessmentListPageV1,
  AssessmentReceiptV1,
  AssessmentResumeReceiptV1,
  AssessmentRevisionSignalV1,
  AssessmentSnapshotV1,
  BundleManifestV1,
  EvidenceViewV1,
  ExportRequestReceiptV1,
  ExportViewV1,
  FindingDetailViewV1,
  FindingListPageV1,
  RepositoryCommandReceiptV1,
  RepositoryListSnapshotV1,
  RepositorySnapshotV1,
  RiskDecisionReceiptV1,
  RuntimeHealthSnapshot,
  SecurityAssuranceSubmissionV1,
  SecurityCatalogSnapshotV1,
  SecurityResult,
} from '../src/contracts.js'

type Equal<Left, Right> =
  (<Value>() => Value extends Left ? 1 : 2) extends
  (<Value>() => Value extends Right ? 1 : 2)
    ? true
    : false

type OperationValue<Name extends keyof SecurityAssuranceService> =
  SecurityAssuranceService[Name] extends (...args: infer _Arguments) => infer Result
    ? Awaited<Result> extends SecurityResult<infer Value>
      ? Value
      : never
    : never

interface CommandValues {
  readonly registerRepository: RepositoryCommandReceiptV1
  readonly updateRepository: RepositoryCommandReceiptV1
  readonly disableRepository: RepositoryCommandReceiptV1
  readonly startAssessment: AssessmentReceiptV1
  readonly resumeAssessment: AssessmentResumeReceiptV1
  readonly cancelAssessment: AssessmentCancellationReceiptV1
  readonly recordRiskDecision: RiskDecisionReceiptV1
  readonly requestExport: ExportRequestReceiptV1
}

interface QueryValues {
  readonly getHealth: RuntimeHealthSnapshot
  readonly getCatalog: SecurityCatalogSnapshotV1
  readonly getRepository: RepositorySnapshotV1
  readonly listRepositories: RepositoryListSnapshotV1
  readonly listAssessments: AssessmentListPageV1
  readonly getAssessment: AssessmentSnapshotV1
  readonly listFindings: FindingListPageV1
  readonly getFinding: FindingDetailViewV1
  readonly getEvidenceView: EvidenceViewV1
  readonly waitForAssessmentRevision: AssessmentRevisionSignalV1
  readonly getBundleManifest: BundleManifestV1
  readonly getAssuranceSubmission: SecurityAssuranceSubmissionV1
  readonly getExport: ExportViewV1
}

type CommandContractChecks = {
  [Name in keyof CommandValues]: Equal<OperationValue<Name>, CommandValues[Name]>
}[keyof CommandValues]

type QueryContractChecks = {
  [Name in keyof QueryValues]: Equal<OperationValue<Name>, QueryValues[Name]>
}[keyof QueryValues]

const allCommandsReturnTheirReviewedReceipt: CommandContractChecks = true
const allQueriesReturnTheirReviewedSnapshotOrView: QueryContractChecks = true

describe('ADR 0248: Commands return Receipts and queries return immutable Snapshots', () => {
  it('maps all 8 public commands to their reviewed versioned Receipt types', () => {
    expect(allCommandsReturnTheirReviewedReceipt).toBe(true)
  })

  it('maps all 13 public queries to their reviewed Snapshot or View types', () => {
    expect(allQueriesReturnTheirReviewedSnapshotOrView).toBe(true)
  })
})
