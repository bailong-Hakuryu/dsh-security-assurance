---
status: accepted
---

# Deterministic Failures Cannot Be Erased by Reruns

After a qualification Assessment produces a deterministic failure (incorrect Finding, missed vulnerability, false negative), a diagnostic rerun that achieves PASS against the same artifact does not erase that failure. The original failure remains in the historical proof ledger, preserved for release decision and non-inferiority analysis. Only an explicit resolution chain—investigation Evidence, remediation Evidence, a distinct candidate artifact digest, and a new qualification Assessment PASS against that new artifact—can mark a deterministic failure as resolved. Diagnostic reruns serve as investigative Evidence and must not overwrite Ground Truth.

## Implementation

Implemented in `src/evaluation.ts` as `evaluateDeterministicFailureHistoryV1()`. This pure function accepts a versioned request containing:

- Qualification runs (original assessment outcomes bound to artifact digests)
- Diagnostic reruns (investigative runs, also bound to artifact digests)
- Optional resolution Evidence (investigation + remediation + new artifact)

Returns an immutable `DeterministicFailureHistoryV1` ledger containing:

- `unresolvedDeterministicFailures`: failures with no valid resolution chain
- `resolvedDeterministicFailures`: failures with complete resolution Evidence
- `diagnosticInvestigations`: PASS diagnostic runs preserved as Evidence, never used to cancel original failures

Integrated into `evaluateReleaseConstitutionV1()` for release promotion decisions. Callers cannot forge the failure count—the Constitution accepts only the raw history request and recomputes the ledger internally.

## Release Evaluation Architectural Boundary

**Important**: Release evaluation functions (`evaluateReleaseConstitutionV1`, `renderPublicSecurityScorecardV1`, `assembleReleaseEvidenceManifestV1`) are **pure offline evaluation tools** for external release automation, NOT runtime SecurityAssuranceService operations.

These functions require inputs that the Service does not persist:
- Release candidate IDs, evidence set IDs/digests
- Holdout completion timestamps  
- Artifact digests (candidate, qualified, promotion)
- Constitution definitions, support matrix versions
- Cross-assessment aggregated release Evidence

The Service persists per-assessment runtime data (findings, sealed submissions, risk decisions). Release evaluation aggregates Evidence from multiple assessments, holdout runs, and policy documents in an external CI/CD or release tooling context.

Do not attempt to expose release evaluation as Service operations without first implementing a release metadata persistence layer and defining the ownership boundary between per-assessment Evidence and cross-release aggregate proof.
