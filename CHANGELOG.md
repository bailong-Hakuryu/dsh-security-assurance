# Changelog

## [Unreleased]

- Support DeepSeek Harness `0.1.2-alpha.2` through `0.1.2-alpha.4` alongside
  the primary `0.1.2-alpha.1` target as an explicit, verified set: the
  composition invariant admits one coherent supported release, rejects mixed
  supported-package versions, and keeps failing closed on any other Harness
  runtime; peer declarations list the exact versions.
- Read the live Session event log through a capability-tolerant seam that
  accepts both the `Session.events` getter (`0.1.2-alpha.1` to
  `0.1.2-alpha.3`) and its `snapshotEvents()` successor (`0.1.2-alpha.4`),
  failing closed when neither shape is present, and accept both legacy and
  `gateway/`-namespaced typert gateway error codes in Workbench Remote
  negative-path assertions (`0.1.2-alpha.2` namespaced them).
- Add the scheduled Harness Compatibility workflow: daily discovery of the
  official Harness tags feeds an auditable, peeled-commit-pinned matrix that
  also runs for product-code changes and executes the dual-plugin
  joint E2E (Mission, Developer workspace change, CHANGE Assessment, sealed
  submission, Quality Gate with SATISFIED / FAILED / INDETERMINATE
  propagation) plus a packed dual-tarball fresh-profile installation and Web
  probe, across Ubuntu, macOS, and Windows on the primary target and Ubuntu
  on the remaining versions, on Node 22 and 24. Newly published Harness tags
  enter verification automatically and fail closed until admitted; a manual
  dispatch accepts one Harness ref for debugging.
- Run Control Plane-owned Mission assessments as Host-bound `CHANGE` against
  the exact produced workspace, independently verifying branch, baseline HEAD,
  Git status fingerprint, byte-exact produced-change fingerprint, and the full
  resulting tree before any Assessment is created.
- Support exact-commit `CHANGE` Assessments for the bundled Node lifecycle and
  npm audit policies by evaluating the complete frozen head tree as a safe
  superset of the Policy impact cone.
- Build the linked Control Plane and generated Security Assurance package
  entries before fresh-checkout typechecking, removing reliance on stale local
  `lib` artifacts across Linux, macOS, and Windows CI.
- Restore writable modes only while reaping system-temporary test fixtures so
  immutable Subject snapshots remain enforced without causing POSIX teardown
  failures; linked directories are removed without traversing their targets.
- Canonicalize cross-platform Export fixture roots, observe asynchronous
  Delivery to its terminal status, and give shared-runner integration tests
  explicit bounded timeout budgets.
- Make temporary-fixture teardown idempotent under concurrent background
  staging reaping, and keep Assessment-list pagination fixtures sequential.
- Add a bundled PURE npm audit JSON normalization adapter that consumes
  digest-verified `npm-audit.json` Subject slices without executing
  npm or using network authority.
- Independently re-derive npm audit Candidate fields and Coverage from the
  frozen report, bind Evidence producer/path/digest/entries, accept verified
  clean zero-Candidate reports, and fail closed on missing or fabricated input.
- Add public Linux, macOS, and Windows CI with a fresh packed-profile
  installation and live Web probe, and make linting part of the release gate.
- Retry transient Windows directory locks while reaping abandoned Subject
  staging trees, with deterministic regression coverage.
- Derive the packed-profile provider-version assertion from the package
  manifest and align the current Harness qualification documentation.

## [0.1.0-rc.10] - 2026-08-31

- Route Subject Freeze Git operations through the Harness-managed subprocess
  capability, including credential-scrubbed environment inheritance,
  tree-scoped cancellation, bounded output and quiescent teardown.
- Preserve configuration and health redaction coverage while constructing
  explicitly fake credential fixtures at test runtime.

## [0.1.0-rc.9] - 2026-08-31

- Route explicit top-level security audit requests through the catalog-first
  Security tool workflow while avoiding duplicate standalone assessments for
  Control Plane-owned work.
- Add the `/security [scope]` Web/CLI command, which submits a normalized
  standalone Assessment request and rejects delegated-role invocation.

## [0.1.0-rc.8] - 2026-08-30

- Re-derive coverage digests and Policy bindings at the seal-readiness seam.
- Bound private evidence and sealed-artifact reads through regular-file handles.
- Reap abandoned Subject staging trees and retry transient Windows publication
  locks without misclassifying them as collisions.
- Enforce evidence-link eligibility and expiry before bounded disclosure.
- Harden evaluation identity/uncertainty bounds, risk-acceptance expiry at the
  actual seal-finalization instant, SQLite schema constraints, and duplicate
  lifecycle-key parsing.

## [0.1.0-rc.7] - 2026-08-30

- Bind Control Plane Assessment start idempotency to the configured Repository
  so a provider reconfiguration cannot alias or orphan another start identity.
- Require explicit Critical and High benchmark strata before effectiveness or
  non-inferiority evidence can be measured.
- Reject multiplicative air-gapped evaluation inputs under one combined work
  budget and replace nested adjudication scans with indexed identity lookups.

## [0.1.0-rc.6] - 2026-08-30

- Keep generic external Analyzer clean claims advisory until an independent
  Evidence verifier can bind their content to the frozen Subject and Policy.
- Derive omitted Host Repository idempotency keys from the full canonical root
  with SHA-256, avoiding truncated reversible path identities.
- Canonicalize and validate Host Repository roots before registration.

## [0.1.0-rc.5] - 2026-08-30

- Reject workspace snapshots that traverse ancestor symlinks/junctions and
  bound file reads to the Subject byte limit.
- Fence all revision-advancing writes and recovery around pending cancellation.
- Recompute release paired comparisons, require pre-registered non-inferiority
  plans, and reject a vacuous margin of `1.0`.
- Require package-issued authority channels and invariant owners; bootstrap
  failures now install a required fail-closed health check.

## [0.1.0-rc.4] - 2026-08-30

- Align the direct-use pair with Engineering Control Plane `0.1.3`, whose
  qualified Web role policies use only tools registered by Harness
  `0.1.2-alpha.1`.

## [0.1.0-rc.3] - 2026-08-30

- Fence direct-use invariant activation on durable Host repository bootstrap.
- Make the Host Repository Provider activation promise reflect registration
  success or failure instead of reporting an active Loader row prematurely.
- Extend the packed Web-profile smoke gate to require one enabled
  `current-workspace` Repository in the real Security persistence store.

## [0.1.0-rc.2] - 2026-08-30

- Add a direct-use Harness bundle for the launcher cwd and enable the Host,
  invariant, Repository Provider, tool, and optional Control Plane rows.
- Resolve Control Plane integration through stable Host repository binding IDs.
- Add bounded Repository selection and Security Catalog model tools.
- Export a Schemastery `Config` schema and qualify Harness `0.1.2-alpha.1`.

All notable changes to this project are documented in this file.

## [0.1.0-rc.1] - 2026-08-29

### Added

- Evidence-backed Security Assessment lifecycle with versioned public
  contracts, immutable receipts and snapshots, revision CAS, idempotency,
  bounded waits, cancellation, restart recovery, and fail-closed persistence.
- Governed analyzer, role, evidence, finding, risk-decision, export, sealed
  bundle, and Assurance Submission flows.
- Dormant-by-default Harness bundle entries, model tools, Typert remote
  adapter, bilingual browser Workbench, runtime invariant, and optional
  Engineering Control Plane provider integration.
- Pure evaluation, release-constitution, public scorecard, evidence-manifest,
  and capability-conformance modules.
- Packed fresh-consumer smoke coverage and packed real-browser Harness E2E.

### Release status

- This is the first v0.1 acceptance candidate. Stable `0.1.0` remains pending
  the manual and platform qualification described in `docs/release-v0.1.md`.
