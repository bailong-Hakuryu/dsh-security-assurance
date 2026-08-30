# Changelog

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
