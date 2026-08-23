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
- authorized `getHealth`, Repository Registry, and `startAssessment`
  operations;
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
  durable creation Receipt are committed.

Assessment Engine execution, analyzers, Findings, Evidence persistence,
Verdicts, sealed Bundles/Submissions, Control Plane integration, tools, and
Workbench are deliberately not claimed as implemented yet. Newly created
Assessments remain in `CREATED`; the next slice will implement the smallest
deterministic Assessment-to-Submission path.

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

Repository roots remain private. Query Snapshots and command Receipts are
versioned, JSON-safe, recursively immutable, bounded, and path-free.

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
