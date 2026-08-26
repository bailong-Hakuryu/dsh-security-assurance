# ADR 0247 and 0248 Audit Correction

Date: 2026-08-26

Review baseline: `19b2090...3f1bab0`

## Outcome

The implementation already had broad public-operation coverage, but the newly
added compliance proof and its reports were not complete or internally
consistent. The audit found both verification defects and one implementation
defect. The working-tree correction now makes the reviewed claims directly
checkable without treating a passing Vitest run as a substitute for TypeScript
test compilation.

## Findings before correction

- `npm test` passed 234 tests, but `npm run typecheck` failed seven times in the
  new ADR 0246 and ADR 0247 test files.
- The ADR 0247 suite called only five unique operations and no commands while
  claiming coverage of all 21 public operations.
- The ADR 0247 suite did not explicitly prove unexpected exceptions become
  redacted `INTERNAL` results.
- ADR 0248 had no dedicated operation-catalog proof. The cited 14 tests belonged
  to ADR 0246 and constructed only a small sample of DTOs.
- The reports named `getSubmission` and `getExportView`; the public operations
  are `getAssuranceSubmission` and `getExport`.
- The reports listed `RESOURCE_EXHAUSTED`, which is not in the current public
  error-code contract.
- ADR 0249 was incorrectly described as an idempotency decision. Its accepted
  title is "Repository Administration is explicit, versioned, and
  non-destructive".

## Corrections

### ADR 0247

`tests/adr-0247-security-result-envelope.spec.ts` now maintains the exact
reviewed catalog of 21 asynchronous public Service operations and proves:

- every signature resolves to `SecurityResult<T>` at test typecheck time;
- every operation returns a runtime-validated `UNAUTHORIZED` envelope for an
  invalid Security Invocation; and
- an unexpected request failure at every Service seam returns a redacted,
  retryable `INTERNAL` envelope without exposing the hostile marker.

That last proof exposed a real implementation bug: artifact-reading queries
classified every thrown `Error` as artifact unavailability. The Service now
uses a package-private `SecurityArtifactIntegrityError` to reserve
`UNAVAILABLE` for verified artifact-integrity failures and maps unrelated
unexpected exceptions to `INTERNAL`. Export failure mapping likewise reserves
expected public failures for typed `ExportDeliveryError` and persistence
errors.

### ADR 0248

`tests/adr-0248-command-receipts-and-query-snapshots.spec.ts` now provides a
compile-checked catalog mapping all eight public commands to their reviewed
Receipt types and all thirteen public queries to their reviewed Snapshot or
View types. Existing public-seam tests remain the behavioral proof for concrete
receipt contents, recursive freezing, JSON-safe by-value transfer, revision
binding, and absence of private repository paths.

### ADR 0246 test repair

The DTO test fixtures now match the current schemas and declarations:
`PublicSecurityError` includes schema and correlation identity, Repository DTOs
use current revision and binding fields, repository operation literals use
snake case, and the test no longer claims a nonexistent `FindingRecordId`
export.

## Correct ADR numbering for follow-up work

- ADR 0249: Repository Administration is explicit, versioned, and
  non-destructive.
- Cross-command idempotency semantics are primarily ADR 0137, ADR 0261, and ADR
  0273, and already have public-seam coverage in repository, assessment, export,
  Workbench, and tool tests.

The next development slice must therefore be selected from the actual accepted
ADR or product roadmap; it must not be created under the false "ADR 0249
idempotency" label.

## Verification after correction

- Security `npm run typecheck -- --pretty false`: PASS.
- Security `npm test`: PASS twice, 20 files and 238 tests.
- Security `npm run build`: PASS.
- Security `npm run pack:dry-run`: PASS, 47 public files.
- Dual-plugin `npm run pack:smoke`: PASS, including packed imports, lifecycle,
  Workbench, model tools, Provider/Gate integration, failure mapping, and
  unload/restart.
- Control Plane `pnpm typecheck`, `pnpm build`, and `pnpm lint`: PASS.
- Control Plane `pnpm test`: PASS twice, 27 files and 128 tests, including one
  run under concurrent build load.

## Post-audit cross-plugin stabilization

The original Control Plane full-suite timeout came from a `750ms` wall-clock
race in the Provider composition test, not from the accepted Provider protocol.
The test now waits for both the durable `begun` state and the observed Reference
Provider call through the existing public Service seam. The exact case passed
10 consecutive isolated runs before both full-suite runs passed.

The renewed dual-plugin run then exposed a second timing-sensitive test. Its
checkpoint paused only the Provider return path while the background Security
Assessment could still seal. The cancellation test now registers a deterministic
blocking Analyzer through the public startup composition seam, proves that the
Assessment is `RUNNING`, and verifies cancellation of that exact Assessment.
The case passed 10 consecutive isolated runs and both Security full-suite runs.
