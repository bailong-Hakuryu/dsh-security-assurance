# Changelog

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
