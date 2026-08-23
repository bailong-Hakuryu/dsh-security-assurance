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
- a trusted `dsh-security-assurance/host-repository-provider` composition entry
  that registers Host configuration through the root Service and resolves only
  immutable path-free Repository bindings;
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
- a side-effect-free `dsh-security-assurance/analyzer` Contract Entry and a
  local startup-composition Registry keyed by exact Analyzer ID and version;
- frozen external Analyzer Descriptors, per-Assessment portfolios, bounded
  path-free Inputs, Attempt-scoped instances, and mandatory instance disposal;
- fail-closed external Contribution admission: identity, Subject digest,
  Coverage obligation, and Evidence schema mismatches block the Assessment;
- sealed advisory Evidence from unqualified external Pure Analyzers while
  mandatory Coverage remains a visible `EVIDENCE_INELIGIBLE` Gap and the
  Verdict remains `INDETERMINATE`;
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
  `CANCELED` without Verdict or Seal, including restart reconciliation when the
  Security commit precedes Control Plane Invocation termination; and
- fresh packed Harness `0.1.1-rc.2` profile proof for `disabled`, absent
  `when-available`, absent `required`, valid required integration, Adapter
  unload, and full profile restart; and
- packed fail-closed Gate proof for a real Security `FAILED → REWORK_REQUIRED`,
  a real Security `INDETERMINATE → BLOCKED`, a digest-tampered Submission that
  is rejected before Evidence import, and a frozen Provider that disappears
  mid-Attempt without falling back to another registered version.

Qualified Gate-bearing external Analyzers, process or agent Analyzers, general
Node and application-security coverage, the complete protected Evidence Store,
tools, and Workbench are deliberately not claimed as implemented yet. The
built-in Analyzer's development Qualification applies only to the exact Node
package install-lifecycle key-presence contract; a
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

Local Host composition additionally has the synchronous
`registerAnalyzer(descriptor, factory)` method. It is not a model, browser, or
Remote operation. Registration closes when Assessment admission first freezes
the startup-composed portfolio; Factories, instances, disposal handles, and
cancellation handles are never persisted.

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

## Host Repository composition

The optional `dsh-security-assurance/host-repository-provider` entry is a
trusted Host Adapter for deployment-owned Repository configuration. It injects
`ctx.securityAssurance`, validates every configured registration before the
first mutation, and invokes the root Service with package-owned Host authority:

```yaml
repositories:
  - schemaVersion: 1
    bindingId: mission-repository
    idempotencyKey: host-repository-provider:mission-repository:v1
    root: /absolute/host/repository
    displayName: Mission Repository
    bindings:
      policyId: security/node-package-lifecycle
      assessmentProfileId: security/standard
      evidenceProtectionId: evidence/local-protected
      dataEgressPolicyId: egress/deny-by-default
      platform: linux
      deliveryDestinationIds: []
```

After activation, trusted Host composition may call
`ctx.securityAssuranceHostRepositories.resolve(bindingId)` to obtain the
immutable `repositoryId`, revision, and state. The result contains no root,
credential, Store handle, or Security Invocation. Disposing the Provider removes
only its Cordis Service; durable Repository Registry history remains owned by
the root Security Service, so an equal restart resolves the same Repository ID.
Conflicting replay fails loudly instead of updating Host policy implicitly.

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
or credentials. A Repository ID alone is not binding proof: before Assessment
start, the root Security Service resolves that ID inside its private Registry
and invokes the Control Plane Context's process-local repository assertion.
The canonical root is never returned to the Adapter or serialized. A mismatch
returns terminal `repository_binding_mismatch` External Assessment Failure and
starts no Assessment. After binding succeeds, the Adapter resolves an internal
`control-plane` Security Invocation, starts a Workspace Snapshot Assessment,
retrieves the verified sealed Security Submission, and embeds its canonical
value plus source digest in the provider-neutral Control Plane Submission. If a
sealed Submission cannot be supplied, the Adapter returns the Control Plane's
strict provider-neutral External Assessment Failure value. Configuration or
external blocking, cancellation, and runtime failure therefore settle the
Control Plane Invocation as indeterminate and block its Gate without exposing
Security internals or fabricating Evidence. If a
durably begun Control Plane invocation is explicitly resumed after both hosts
restart, the Adapter reuses the exact Assessment start identity, explicitly
resumes that Assessment when it is `BLOCKED`, and returns the same sealed value
through `recover()` without replaying Provider `assess()`. The Control Plane
copies and revalidates that value and remains the sole owner of Mission
Assurance Results and the Quality Gate. The two plugins never share SQLite
files, writable Evidence paths, transactions, or Kernel objects.

Control Plane Assurance Retry is distinct from that same-Invocation recovery.
After a retryable `blocked` or `canceled` external outcome blocks the Gate,
explicit Mission Resume creates a successor Control Plane Invocation. Its new
Invocation identity gives the Adapter a new idempotent Assessment start
identity, so Security Assurance creates a distinct Assessment and preserves
the blocked, canceled, or failed predecessor unchanged. If the repository
content is unchanged, Subject Freeze
may reuse the existing private content-addressed Snapshot only after complete
Manifest and file-digest verification; Windows rename collision codes grant no
authority by themselves. Dual-plugin conformance proves the first Assessment
remains `CANCELED`, the successor seals independently, and only the Control
Plane recomputes its current Assurance Result and Gate.

On explicit Mission cancellation, the Adapter's separate `cancel()` operation
uses a package-private, authority-checked lookup for the existing
`startAssessment` idempotency record. It never creates an Assessment merely to
cancel it. If the Assessment exists and is not terminal, the Adapter invokes
the public revision-bound `cancelAssessment`, verifies `CANCELED`, and returns
the external Assessment ID for Control Plane audit. Host disposal does not call
this operation, so restart recovery remains distinct from cancellation. If the
host stops after Security commits `CANCELED` but before Control Plane records
its proof, the next explicit Mission cancellation resolves the stable start
identity, observes the same Assessment as terminal, and returns that same ID;
it does not create, resume, or replace an Assessment.

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

All three bundle rows in `cordis.patch.yml` are disabled by default.
Installation alone does not activate a security authority, Host Repository
Provider, or optional Control Plane Provider.

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
