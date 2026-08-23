# DSH Security Assurance

DSH Security Assurance is an independent DeepSeek Harness plugin for
evidence-backed application-security assessment. It integrates through public
Harness and Cordis seams and does not modify Harness Core.

## Current implementation status

This repository is under active vertical-slice development, not at the
`0.1.0-rc.1` release candidate. The current private development package proves:

- dormant bundle installation metadata;
- real Cordis registration at `ctx.securityAssurance`;
- an opaque, runtime-verified Security Invocation boundary;
- authorized Runtime Health, Repository Registry, Assessment start/query/wait,
  Bundle Manifest, and Assurance Submission operations;
- versioned Zod-validated public contracts;
- one `SecurityResult<T>` success/failure envelope;
- redacted authorization, validation, cancellation, deadline, and internal
  failures;
- a plugin-private SQLite Registry with immutable revisions, idempotent
  Receipts, exact Revision CAS, fail-closed startup validation, and restart
  recovery;
- explicit register, get, list, update, and non-destructive disable behavior;
- exact Git revision, Change, and Workspace Snapshot Subject selectors;
- bounded content-addressed Subject materialization below
  `$DSH_HOME/security-assurance/subjects`, with canonical manifests and no
  ordinary hard links to source content;
- non-expanding symlink and submodule inventory; and
- atomic ordering in which Subject Freeze succeeds before an Assessment ID and
  durable creation Receipt are committed;
- a deterministic package-private Assessment path with durable
  `CREATED → RUNNING → SEALED` revisions;
- a pure Policy Evaluator and independent seal-readiness check;
- honest mandatory Coverage reconciliation: because no qualified Analyzer is
  registered in this slice, the default obligation resolves to `GAP` and the
  Security Verdict is `INDETERMINATE`, never a fabricated success;
- atomic persistence of Verdict, Assessment Seal, Bundle Manifest, and
  self-contained Assurance Submission at terminal revision 3;
- content-addressed private Bundle publication with verification on every
  official read; and
- fail-closed restart and integrity behavior: interrupted `RUNNING` work becomes
  `BLOCKED`, sealed work is not rerun, and modified publication bytes are not
  served.

Real Analyzer execution, validated Findings, the complete Evidence Store,
Control Plane integration, tools, and Workbench are deliberately not claimed as
implemented yet. The current deterministic path is a contract and lifecycle
slice: it proves that missing verdict-eligible analysis produces a sealed
`INDETERMINATE` result whose Coverage gap is explicit and digest-bound.

## Implemented service surface

The root plugin is dormant until activated through Cordis and then exposes the
sole business Interface at `ctx.securityAssurance`. Implemented operations are:

- `getHealth`
- `registerRepository`
- `updateRepository`
- `disableRepository`
- `getRepository`
- `listRepositories`
- `startAssessment`
- `getAssessment`
- `waitForAssessmentRevision`
- `getBundleManifest`
- `getAssuranceSubmission`

Repository roots remain private. Query Snapshots and command Receipts are
versioned, JSON-safe, recursively immutable, bounded, and path-free.

`startAssessment` returns the durable revision-1 `CREATED` Receipt; it does not
transfer ownership of the continuing run to the caller. The Engine persists
`RUNNING` before evaluation and exposes official Bundle or Submission values
only after all terminal records commit together as `SEALED`. The Bundle
Manifest is a view. The Assurance Submission carries its required artifacts by
value so a future Control Plane Adapter does not need access to Security
Assurance storage.

## Development

Requirements:

- Node `^22.19.0 || >=24.0.0`
- pnpm
- the qualified read-only Harness reference at
  `D:\Deepseek\deepseek-harness-master` for local Cordis development linking

Commands:

```text
pnpm install
pnpm typecheck
pnpm test
pnpm build
pnpm pack:dry-run
pnpm pack:smoke
```

The bundle row in `cordis.patch.yml` is disabled by default. Installation alone
does not activate a security authority.

## Design authority

- `CONTEXT.md` defines the domain language.
- `docs/adr/` contains the accepted decisions.
- `docs/implementation-specification.md` maps those decisions to implementation
  phases and acceptance evidence.
- `docs/deepseek-harness-plugin-surface-study.md` records the read-only Harness
  source facts used by the design.

Conformance proves that the product behaves according to its contract. It does
not by itself prove that the product finds real vulnerabilities effectively;
Security Effectiveness has a separate preregistered evaluation track.
