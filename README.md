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
- one versioned, built-in Pure Analyzer for the explicitly scoped
  `security/node-package-lifecycle` Policy, with a frozen Descriptor,
  development Qualification, bounded authority-free source slices, and no
  process, network, model, credential, or workspace access;
- staged, content-addressed publication of Analyzer Contribution, redacted Node
  package-manifest Evidence, and Evidence Eligibility Decision before sealing;
- deterministic tri-state results for that scoped Policy: complete eligible
  Evidence with no forbidden install lifecycle script is `SATISFIED`, a
  validated forbidden `preinstall/install/postinstall` control is `FAILED`, and
  unsupported or malformed inputs remain `INDETERMINATE`;
- blocking-Finding precedence over incomplete Coverage while every remaining
  Coverage Gap stays visible;
- honest default-Policy reconciliation: because the general application-
  security obligation still has no complete qualified Analyzer portfolio, it
  remains `INDETERMINATE`, never a fabricated success;
- atomic persistence of Verdict, Assessment Seal, Bundle Manifest, and
  self-contained Assurance Submission at one terminal revision;
- content-addressed private Bundle publication with verification on every
  official read;
- fail-closed restart and integrity behavior: interrupted `RUNNING` work becomes
  `BLOCKED`, sealed work is not rerun, and modified publication bytes are not
  served;
- explicit revision-bound, idempotent `resumeAssessment` and `cancelAssessment`
  commands: resume admits a replacement execution without changing Subject or
  Policy, while cancellation persists intent before quiescence and commits
  `CANCELED` only afterward;
- an optional `dsh-security-assurance/control-plane-provider` Cordis entry that
  registers exact Provider identity `dsh/security-assurance`, starts and waits
  for the same private Assessment Engine, and returns a Control Plane transport
  Submission by value; and
- real dual-plugin Gate coverage proving `SATISFIED → requirement satisfied`,
  `FAILED → REWORK_REQUIRED`, `INDETERMINATE → BLOCKED`, and a missing Repository
  binding → fail-closed `BLOCKED`; and
- real dual-plugin cancellation coverage proving explicit Mission cancellation
  records the external Assessment identity and leaves that same Assessment
  `CANCELED` without Verdict or Seal.

External Analyzer registration, process or agent Analyzers, general Node and
application-security coverage, the complete protected Evidence Store, tools,
and Workbench are deliberately not claimed as
implemented yet. The built-in Analyzer's development Qualification applies only
to the exact Node package install-lifecycle key-presence contract; a
`SATISFIED` Verdict under that Policy is not a claim that the Subject is broadly
secure.

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
- `resumeAssessment`
- `cancelAssessment`
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
value so the Control Plane Adapter does not need access to Security Assurance
storage.

Interrupted evaluation is never restarted during service initialization or by
replaying `startAssessment`. An authorized caller must submit
`resumeAssessment` against the exact `BLOCKED` revision with a bounded operator
reason. `cancelAssessment` first returns the durable cancellation-request
Receipt after the Service has quiesced local work and finalized the Assessment;
that Receipt identifies the request revision and does not misrepresent it as
the later terminal revision.

## Optional Control Plane integration

The root plugin remains independently installable. The optional
`dsh-security-assurance/control-plane-provider` entry activates only when both
`ctx.securityAssurance` and `ctx.engineeringControlPlane` exist. The Host binds
one Control Plane repository mapping to an already registered Security
Repository using public identifier configuration:

```yaml
assuranceProviders:
  - providerId: dsh/security-assurance
    providerVersion: 0.0.0-development
    activation: required
    configuration:
      repositoryId: repo-00000000-0000-4000-8000-000000000000
```

The Adapter receives no repository path, database, Evidence directory, Gate,
or credentials. It resolves an internal `control-plane` Security Invocation,
starts a Workspace Snapshot Assessment against that exact Repository ID,
retrieves the verified sealed Security Submission, and embeds its canonical
value plus source digest in the provider-neutral Control Plane Submission. If a
durably begun Control Plane invocation is explicitly resumed after both hosts
restart, the Adapter reuses the exact Assessment start identity, explicitly
resumes that Assessment when it is `BLOCKED`, and returns the same sealed value
through `recover()` without replaying Provider `assess()`. The Control Plane
copies and revalidates that value and remains the sole owner of Mission
Assurance Results and the Quality Gate. The two plugins never share SQLite
files, writable Evidence paths, transactions, or Kernel objects.

On explicit Mission cancellation, the Adapter's separate `cancel()` operation
uses a package-private, authority-checked lookup for the existing
`startAssessment` idempotency record. It never creates an Assessment merely to
cancel it. If the Assessment exists and is not terminal, the Adapter invokes
the public revision-bound `cancelAssessment`, verifies `CANCELED`, and returns
the external Assessment ID for Control Plane audit. Host disposal does not call
this operation, so restart recovery remains distinct from cancellation.

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

Both bundle rows in `cordis.patch.yml` are disabled by default. Installation
alone does not activate a security authority or the optional Control Plane
Provider.

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
