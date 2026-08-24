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
  Finding Summary and Detail, purpose-bound Evidence View, Bundle Manifest,
  and Assurance Submission operations;
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
- Host-trusted, canonical-digest-bound external Analyzer Qualification Records
  covering exact Analyzer build, Policy, Mode, Coverage, Evidence schemas,
  execution backend, Provider, egress, platform, issuance, and expiry;
- frozen per-Assessment Eligibility Decisions: a precisely qualified complete
  Reference Analyzer may satisfy its one declared obligation, while missing,
  scope-incompatible, not-yet-valid, or expired Qualification remains Advisory;
- versioned external Candidate Finding contracts with bounded weakness,
  Security Claim, Source Anchor, JSON Pointer, and contributed-Evidence links;
- one exact deterministic Conformance Validation Contract that independently
  verifies immutable Subject and file digests, unique JSON security keys, the
  declared JSON Pointer, and the exact reference-control state against matching
  validation Evidence or Counter-Evidence;
- separate Candidate Admission, Validation Contract Resolution, validation
  Evidence Eligibility, Validation Outcome, Technical Severity, Evidence
  Confidence, and Policy Significance records; and
- immutable Candidate tri-state resolution under that Contract: eligible proof
  of `VIOLATED` produces `VALIDATED` and a blocking Finding, eligible
  Counter-Evidence proving `SATISFIED` produces `REJECTED` without a Finding,
  and contradictory or otherwise ineligible Evidence produces `UNRESOLVED`
  with an explicit Proof Gap and `INDETERMINATE` Verdict;
- versioned `listFindings` projections that keep validated Findings, Rejected
  Candidates, and Unresolved Candidates visibly distinct while omitting Source
  Anchors, Security Claims, and Evidence payloads; Validation-state filtering
  occurs before bounded pagination, and HMAC-protected cursors bind the exact
  Assessment, Repository, sealed revision, page size, filter, and Security
  Principal;
- revision-bound `getFinding` Detail Views that project canonical Subject-
  relative Source Anchors, exact tri-state Validation Outcome and Contract
  lineage, separate Severity/Confidence/Policy dimensions, Coverage and Risk
  status, and digest-bound Evidence Link metadata without returning Evidence
  values or read capabilities;
- an opt-in frozen `security/risk-decision-window-v1` stronger control that
  persists validated Findings and verified Evidence before opening an explicit
  pre-Seal `BLOCKED` window. Authorized `recordRiskDecision` commands bind the
  exact Assessment and Finding revisions, derive the decision maker only from
  the opaque Security Invocation, commit immutable idempotent Receipts, and
  prevent `resumeAssessment` from bypassing the window;
- deterministic ordinary Risk Denial and non-Critical Risk Acceptance: denial
  preserves the blocking Policy Significance and `FAILED` Verdict, while an
  eligible time-bounded acceptance requires compensating controls, retains
  Technical Severity, changes only Policy Significance to `NON_BLOCKING`, and
  may produce `SATISFIED` only with complete mandatory Coverage. Risk Decision
  records are digest-bound into the final Seal, Bundle, and Submission;
- separately enabled Critical break-glass under the frozen
  `security/critical-break-glass-v1` stronger control. The first qualified
  human approval records only a durable `PENDING_DUAL_AUTHORITY` attestation;
  acceptance becomes effective only after a second independently authenticated
  Host Operator with a distinct principal submits the exact same rationale,
  controls, expiry, Assessment revision successor, and Finding identity. Both
  authorization attestations and the exact Subject/Policy scope survive restart
  and are bound into the final Seal;
- revision-bound `getEvidenceView` projections that require exact Assessment,
  consuming Finding revision, Evidence artifact, and digest identity. The
  metadata-only Profile needs Assessment read authority and always redacts
  content; the bounded-json Profile additionally requires the purpose-specific
  `evidence:disclose:validation-review` authority, `VALIDATION_REVIEW` purpose,
  an available frozen protection policy, an allowlisted Evidence schema, and a
  32 KiB canonical JSON limit. Denied or unavailable content remains a
  structured redacted View without Store paths, keys, unrestricted sources, or
  reusable read capabilities;
- blocking-Finding precedence proving a qualified validated Reference Candidate
  seals as `FAILED` with complete Coverage without allowing the Analyzer to set
  Finding, Severity, Significance, or Verdict directly;
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

Production-qualified external Analyzers, process or agent Analyzers, general
Node and application-security coverage, the complete protected Evidence Store,
tools, and Workbench are deliberately not claimed as implemented yet. This
repository ships no production external Qualification or external Analyzer
effectiveness claim. Its external Candidate Validation path is deliberately
limited to the exact `dsh/conformance/reference-control-validation-v1`
Conformance contract and is not a general weakness validator. The built-in
Analyzer's development Qualification applies only to the exact Node package
install-lifecycle key-presence contract; a
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
- `listFindings`
- `getFinding`
- `getEvidenceView`
- `recordRiskDecision`
- `waitForAssessmentRevision`
- `getBundleManifest`
- `getAssuranceSubmission`

Local Host composition additionally has the synchronous
`registerAnalyzer(descriptor, factory)` and
`registerAnalyzerQualification(record)` methods. They are not model, browser,
or Remote operations. Registration closes when Assessment admission first
freezes the startup-composed portfolio and its Eligibility Decisions;
Factories, instances, disposal handles, and cancellation handles are never
persisted.

Repository roots remain private. Query Snapshots and command Receipts are
versioned, JSON-safe, recursively immutable, and bounded. Assessment and list
projections are path-free; a Finding Detail View may contain only a canonical
Subject-relative Source Anchor and never an absolute Host or Store path.

`listFindings` is available after the Assessment is sealed and during an
explicit pre-Seal Risk Decision Window. It returns no total count and no Source
or Evidence content. Its process-local cursor key is rotated when the Service
restarts, so clients must restart pagination from the first page after
reconnect instead of treating cursors as durable records.

`getFinding` is available in those same two states and requires the exact
`assessmentRevision`, `recordId`, and `recordRevision` returned by
`listFindings`. A mismatched revision fails with `CONFLICT`; an unknown record
fails with `NOT_FOUND`.
Evidence Links carry only artifact identity, schema, digest, purpose, and the
bound Eligibility Decision. They never contain the Evidence payload and are
not reusable disclosure capabilities.

`recordRiskDecision` is available only when the frozen stronger-control set
contains `security/risk-decision-window-v1` and the Assessment is in its exact
pre-Seal window revision. The request carries no identity field: the Service
accepts only trusted Host Operator or Control Plane Decision Authority with
`risk:decide`, and records the resolved principal from the opaque Invocation.
Denial cannot carry controls or expiry. Ordinary acceptance requires at least
one compensating control and a future expiry; High severity is capped at seven
days and other currently admitted non-Critical severities at thirty days.
Critical acceptance additionally requires both frozen stronger controls,
Host-derived `risk:break-glass` authority, at least two compensating controls,
and an expiry of at most 24 hours. The first approval remains visibly pending
and cannot seal. Completion requires a new Security Invocation for a different
qualified Host principal and an exactly matching decision form; repeated
sessions for one principal, Control Plane authority, mismatched fields, or an
expired first attestation fail closed without advancing the revision. Critical
denial remains an ordinary `risk:decide` operation and never requires
break-glass authority. Exact replay returns each authority's original Receipt
even after sealing; key reuse with different content returns
`IDEMPOTENCY_CONFLICT`.

`getEvidenceView` is also SEALED-only. Its request repeats the exact Assessment
and Finding revisions plus the linked Evidence artifact ID and digest, then
declares one viewing purpose and one named Profile. Cross-Finding links,
mismatched digests, unknown Profiles, and stale revisions fail closed. The
`security/evidence-view/metadata-only-v1` Profile returns classification,
protection, retention, Egress, and Eligibility metadata with redacted content.
The `security/evidence-view/bounded-json-v1` Profile may return at most 32 KiB
of JSON only for `VALIDATION_REVIEW`, only under the dedicated trusted-channel
permission, and only for currently allowlisted safe Evidence schemas. A
missing permission, incompatible purpose, unavailable protection policy,
unknown schema, or byte-limit breach produces a redacted View rather than a
payload or read handle.

`getAssuranceSubmission` uses the separate `assurance-submission:read`
authority held by the Control Plane Adapter and explicitly trusted Host
composition. Generic Assessment read authority cannot use the self-contained
Control Plane transport Submission to bypass Evidence View authorization.

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
