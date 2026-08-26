# ADR 0249 Compliance Report

## Decision

ADR 0249 requires Repository Administration to be explicit, versioned, separately authorized, bounded, and non-destructive. Repository updates apply only to future Assessments; disabling a Repository blocks new starts without invalidating prior frozen contracts.

## Requirement mapping

| Requirement | Public implementation seam | Verification |
| --- | --- | --- |
| Explicit registration | `registerRepository` resolves a canonical root and creates Repository revision 1 | Canonical, path-free Snapshot test |
| Versioned update and disable | `updateRepository` and `disableRepository` require exact revision CAS and append a revision | Equal replay, stale CAS, update, and disable tests |
| Separate authorization | Commands require `repository:admin`; queries require `repository:read` | Permission-isolation test for all five operations |
| Bounded queries | `listRepositories` requires a limit from 1 through 100 and reports truncation | Limit-1 truncation and limit-101 rejection test |
| Updates affect only future Assessments | Assessment creation freezes the selected Repository revision | Pre-update Assessment remains on revision 1; post-update Assessment uses revision 2 |
| Disable blocks only new starts | New starts reject a disabled Repository while exact retries return the committed start Receipt | Disable/replay/new-start test |
| No implicit registration | `startAssessment` accepts a Repository ID, not a path, and requires an existing Registry entry | Unknown ID and extra-root rejection test; Registry remains empty |
| No destructive mutation surface | The Service exposes named register, update, and disable operations only | Public-surface absence checks for delete and raw mutation operations |

## Genuine implementation gap fixed

`startAssessment` previously resolved the current Repository and enforced its current state and profile binding before looking for an existing durable start replay. Consequently, an exact retry of a previously accepted start failed after the Repository was disabled or its profile binding changed.

The Service now resolves a durable idempotent replay first. A matching committed start returns its original Receipt and resumes its frozen Assessment contract. Only requests without a committed replay proceed through current Repository admission checks.

## Verification

- Repository Administration suite: 9 passing tests.
- Security Assurance full suite: 20 files, 243 passing tests.
- Security Assurance typecheck and build: passing.
- Packed consumer smoke: all package, lifecycle, Provider, gate, publication, and restart checks passing.
- Engineering Control Plane: typecheck, lint, build, and 27 files / 128 tests passing.

## Assessment

ADR 0249 is complete for the v0.1 public Service surface. The change preserves ADR 0137, ADR 0261, and ADR 0273 idempotency/CAS semantics while enforcing ADR 0249's distinction between a new start and replay of an already accepted frozen contract.
