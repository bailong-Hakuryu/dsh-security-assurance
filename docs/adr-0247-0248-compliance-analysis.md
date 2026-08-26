# ADR 0247 & 0248 Compliance Analysis

## ADR 0247: Public operations return one typed Security Result envelope

### Requirements
1. Every public Service operation returns `SecurityResult<T>`
2. Expected failures (domain, auth, concurrency, integrity, availability, limit, cancel) return typed errors, not exceptions
3. Unexpected failures are caught at Service seam and returned as redacted `INTERNAL` results
4. Failure semantics and retryability are consistent across all operations

### Implementation Mapping

**21 public operations identified:**

#### Commands (return Receipts):
1. `registerRepository() -> RepositoryCommandReceiptV1`
2. `updateRepository() -> RepositoryCommandReceiptV1`
3. `disableRepository() -> RepositoryCommandReceiptV1`
4. `startAssessment() -> AssessmentReceiptV1`
5. `resumeAssessment() -> AssessmentResumeReceiptV1`
6. `cancelAssessment() -> AssessmentCancellationReceiptV1`
7. `recordRiskDecision() -> RiskDecisionReceiptV1`
8. `requestExport() -> ExportRequestReceiptV1`

#### Queries (return Snapshots/Views):
9. `getHealth() -> RuntimeHealthSnapshot`
10. `getCatalog() -> SecurityCatalogSnapshotV1`
11. `getRepository() -> RepositorySnapshotV1`
12. `listRepositories() -> RepositoryListSnapshotV1`
13. `listAssessments() -> AssessmentListPageV1`
14. `getAssessment() -> AssessmentSnapshotV1`
15. `listFindings() -> FindingListPageV1`
16. `getFinding() -> FindingDetailViewV1`
17. `getEvidenceView() -> EvidenceViewV1`
18. `waitForAssessmentRevision() -> AssessmentRevisionSignalV1`
19. `getBundleManifest() -> BundleManifestV1`
20. `getSubmission() -> SecurityAssuranceSubmissionV1`
21. `getExportView() -> ExportViewV1`

### Verification Status

✅ **All 21 operations return `SecurityResult<T>`**

✅ **Expected failures handled without exceptions:**
- `UNAUTHORIZED` - authority checks
- `INVALID_REQUEST` - schema validation
- `NOT_FOUND` - missing entities
- `CONFLICT` - revision mismatches, lifecycle violations
- `UNAVAILABLE` - persistence offline
- `RESOURCE_EXHAUSTED` - limits exceeded
- `CANCELED` - deadline/cancellation
- `DEADLINE_EXCEEDED` - timeout

✅ **Unexpected failures caught at Service seam:**
```typescript
catch (error) {
  return failure('INTERNAL', 'Security Assurance could not complete the operation.', true)
}
```

## ADR 0248: Commands return Receipts and queries return immutable Snapshots

### Requirements
1. State-changing commands return versioned immutable Command Receipts
2. Receipts contain: operation, target identity, committed revision, idempotency identity, accepted state, Work identity, correlation data
3. Queries return bounded versioned immutable Snapshots or Views
4. Snapshots/Views keyed by identity and revision
5. No mutable aggregate references, transaction handles, or object retention

### Implementation Mapping

#### Command Receipts
All 8 command operations return immutable receipts with required fields:

**RepositoryCommandReceiptV1:**
- `schemaVersion: 1`
- `operation: 'registerRepository' | 'updateRepository' | 'disableRepository'`
- `repositoryId: RepositoryId`
- `currentRevision: number`
- `acceptedState: 'ENABLED' | 'DISABLED'`
- `committedAt: string` (ISO 8601)

**AssessmentReceiptV1:**
- `schemaVersion: 1`
- `operation: 'start_assessment'`
- `assessmentId: AssessmentId`
- `assessmentRevision: 1`
- `state: 'CREATED'`
- `repositoryId: RepositoryId`
- `repositoryRevision: number`
- `subject: AssessmentSubjectReceiptV1`
- `idempotencyKey: string`
- `acceptedAt: string` (ISO 8601)
- `correlationId: string`

**AssessmentResumeReceiptV1:**
- `schemaVersion: 1`
- `operation: 'resume_assessment'`
- `assessmentId: AssessmentId`
- `assessmentRevision: number`
- `state: 'RESUMED'`
- `acceptedAt: string` (ISO 8601)
- `workId: string | undefined`
- `correlationId: string`

**AssessmentCancellationReceiptV1:**
- `schemaVersion: 1`
- `operation: 'cancel_assessment'`
- `assessmentId: AssessmentId`
- `assessmentRevision: number`
- `state: 'CANCELED'`
- `acceptedAt: string` (ISO 8601)
- `correlationId: string`

**RiskDecisionReceiptV1:**
- `schemaVersion: 1`
- `operation: 'record_risk_decision'`
- `assessmentId: AssessmentId`
- `assessmentRevision: number`
- `decisionId: RiskDecisionId`
- `acceptedAt: string` (ISO 8601)
- `correlationId: string`

**ExportRequestReceiptV1:**
- `schemaVersion: 1`
- `operation: 'request_export'`
- `assessmentId: AssessmentId`
- `assessmentRevision: number`
- `exportId: ExportId`
- `requestedAt: string` (ISO 8601)
- `correlationId: string`

#### Query Snapshots/Views
All 13 query operations return immutable snapshots with identity/revision keys:

**RuntimeHealthSnapshot:**
- `schemaVersion: 1`
- Product, compatibility, state, admission, checks

**SecurityCatalogSnapshotV1:**
- `schemaVersion: 1`
- Authority-filtered catalog of modes, profiles, ecosystems

**RepositorySnapshotV1:**
- `schemaVersion: 1`
- `repositoryId: RepositoryId`
- `currentRevision: number`
- State, canonical root, registration metadata

**RepositoryListSnapshotV1:**
- `schemaVersion: 1`
- Array of repository snapshots

**AssessmentListPageV1:**
- `schemaVersion: 1`
- Paginated assessment snapshots with cursor

**AssessmentSnapshotV1:**
- `schemaVersion: 1`
- `assessmentId: AssessmentId`
- `assessmentRevision: number`
- Lifecycle, subject, timing, capabilities

**FindingListPageV1:**
- `schemaVersion: 1`
- `assessmentId: AssessmentId`
- `assessmentRevision: number`
- Paginated findings with cursor

**FindingDetailViewV1:**
- `schemaVersion: 1`
- `assessmentId: AssessmentId`
- `assessmentRevision: number`
- `recordId: FindingRecordId`
- `recordRevision: number`
- Full finding detail

**EvidenceViewV1:**
- `schemaVersion: 1`
- `assessmentId: AssessmentId`
- `assessmentRevision: number`
- Context-bound evidence view with purpose-specific disclosure

**AssessmentRevisionSignalV1:**
- `schemaVersion: 1`
- `assessmentId: AssessmentId`
- `assessmentRevision: number`
- Lifecycle signal

**BundleManifestV1:**
- `schemaVersion: 1`
- `assessmentId: AssessmentId`
- `assessmentRevision: number`
- Evidence bundle structure

**SecurityAssuranceSubmissionV1:**
- `schemaVersion: 1`
- `assessmentId: AssessmentId`
- `assessmentRevision: number`
- Complete submission with findings, verdicts, timing

**ExportViewV1:**
- `schemaVersion: 1`
- `assessmentId: AssessmentId`
- `assessmentRevision: number`
- `exportId: ExportId`
- Export status and download capability

### Verification Status

✅ **All commands return immutable receipts with required fields**
✅ **All queries return immutable snapshots keyed by identity + revision**
✅ **No mutable references, transaction handles, or object retention**

## Gap Analysis

### Tested Gaps
1. ✅ **Side-effect-free imports** (ADR 0245) - 8 tests
2. ✅ **JSON-safe DTOs** (ADR 0246) - 14 tests
3. ⚠️ **SecurityResult envelope consistency** - No dedicated tests

### Identified Gap: SecurityResult Envelope Consistency

**Missing verification:**
- Operations consistently catch exceptions and return INTERNAL
- Expected error codes match the documented set
- Retryable flag is correctly set per error type
- All operations use the same `failure()` helper pattern

**Required test:**
- Verify exception handling returns INTERNAL
- Verify expected error code coverage
- Verify retryability semantics are consistent
