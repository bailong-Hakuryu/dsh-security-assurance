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
  effective Security Catalog and digest-bound Start Preflight, Finding Summary
  and Detail, purpose-bound Evidence View, Bundle Manifest, and Assurance
  Submission operations;
- an independently activatable `dsh-security-assurance/tools` Consumer with
  bounded `security_assessment_start`, read-only `security_assessment_status`
  and `security_assessment_findings`, and revision-bound
  `security_assessment_resume` and `security_assessment_cancel`, plus bounded
  `security_assessment_export` model tools. They derive the exact live Harness
  session outside model arguments, mint one operation-specific permission, and
  delegate all Assessment validation, pagination, redaction, recovery,
  cancellation, delivery, and state transitions to the root Service;
- versioned Zod-validated public contracts;
- a side-effect-free `dsh-security-assurance/evaluation` entry containing the
  first pure versioned Metrics Engine slice. It calculates Critical/High and
  severity-weighted Validated Recall, Validated Precision, Unsafe Satisfaction
  Rate, and Coverage Honesty Rate from strict independently adjudicated
  Evaluation evidence;
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
- a package-owned `dsh-security-assurance/workbench-remote` Host Adapter plus
  generated strict `dsh-security-assurance/typert` and
  `dsh-security-assurance/remote` artifacts. Its headless Workbench slice
  exposes authority-projected Runtime Health, Repository and Assessment selection,
  effective `getHealth`, `getCatalog`, digest-bound `startAssessment`, exact `getAssessment`,
  integrity-verified `getBundleManifest`, path-free `getRepository`,
  revision-bound Finding queries, strict metadata-only
  `getEvidenceView`, separate expiring `discloseEvidence`, bounded
  `waitForAssessmentRevision`, and revision-bound, idempotent
  `recordRiskDecision`, `resumeAssessment`, and `cancelAssessment` without putting a Principal, permissions, or Security
  Invocation on the wire;
- a package-owned `dsh-security-assurance/client` browser entry that mounts the
  generated Remote contribution and provides one transient
  `ctx.securityAssuranceWorkbench` Controller. It opens authenticated Runtime Health,
  redacted Repository and Assessment selectors, builds the New Assessment Wizard only
  from Catalog choices, confirms immutable Start Preflight proposals, fetches immutable Snapshots,
  follows committed revisions through cancellable long-polling, fences stale
  responses and disclosure attempts, opens metadata only from an exact Finding
  Evidence Link, separately reauthorizes purpose-bound bounded content,
  validates every returned identity, byte, and expiry binding, and submits only
  exact Service-projected Risk Decision options with fresh idempotency before
  refetching committed truth, and renders verified SEALED Bundle metadata with
  registered Delivery Destination IDs. It erases its authority context and Assessment
  payload on close.
  The same entry contributes an additive bilingual launcher at
  `sidebar.footer.action` and a responsive Assessment surface at
  `shell.overlay`; the browser renders Service-projected state, Coverage,
  Verdict, available actions, bounded Evidence disclosure, and the governed
  Risk Decision form without accepting a browser-authored decision-maker. A
  `BLOCKED` Snapshot also carries bounded recovery metadata for the durable
  blocker, affected obligations, retained Evidence, required recovery
  condition, unreported execution budget, and possible Coverage
  Reconciliation; Resume and Cancel forms exist only when the corresponding
  Service action is projected;
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
- authority- and revision-specific `availableActions` on every
  `getAssessment` Snapshot. Read-only callers and terminal Assessments receive
  no mutation actions; currently admissible Resume, Cancel, ordinary Risk
  Decision, Critical first-attestation, and distinct-principal second-
  attestation actions carry exact expected revisions and Finding identities.
  Risk options state their effect, authorization mode, control minimum, expiry
  ceiling, completed/required attestations, and whether the pending form must
  match exactly. The Workbench renders these Service projections directly;
  they are not browser-inferred authority or a model Risk Acceptance tool;
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
  mid-Attempt without falling back to another registered version; and
- a fresh packed Harness `0.1.1-rc.2` Reference Host driven through a real
  Chrome-family browser. The scenario proves Host-authenticated selection,
  keyboard/focus behavior, Runtime Health, digest-bound start, `BLOCKED` Risk
  Denial, sealed metadata-first Evidence and explicit bounded disclosure,
  bilingual responsive rendering, reload, offline/reconnect, denied authority,
  browser-state and remote-resource redaction, and Host lifecycle shutdown.

Production-qualified external Analyzers, process or agent Analyzers, general
Node and application-security coverage, the complete protected Evidence Store,
and the complete Workbench information architecture are deliberately not
claimed as implemented yet. The Workbench Host Remote, authenticated redacted Assessment selection
with stable cursor continuation, generated Client contract, transient browser
Controller, Runtime Health, Repositories and digest-bound New Assessment flow, read-only Assessment Detail, multidimensional Finding triage,
revision-bound Finding Detail navigation, bilingual metadata-first Evidence,
explicit expiring bounded-content disclosure, a governed Risk Decision form
with Critical Dual Authority completion, and a read-only SEALED Bundle/Export
readiness view are implemented. Service-derived Export Preview, `requestExport`,
owner-bound `getExport` status, and durable delivery through the frozen
`delivery/local-audit` adapter are also implemented. Persisted attempt metadata,
bounded backoff, startup recovery of unfinished work, terminal failure, and
lifecycle-owned worker shutdown keep Delivery independent of the browser. An
expiry reaper also persists an owner-bound digest tombstone, denies access,
deletes only the exact governed artifact file, and records physical purge
completion. Offline expiry and interrupted cleanup are reconciled at startup. An
explicit Workbench download resolves current Host authority again, atomically
consumes a process-local 60-second one-use capability, verifies the exact
artifact digest, and discards content from Workbench state after invoking the
browser download.
This repository ships no production external
Qualification or external Analyzer
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
- `getCatalog`
- `registerRepository`
- `updateRepository`
- `disableRepository`
- `getRepository`
- `listRepositories`
- `startAssessment`
- `resumeAssessment`
- `cancelAssessment`
- `getAssessment`
- `listAssessments`
- `listFindings`
- `getFinding`
- `getEvidenceView`
- `recordRiskDecision`
- `waitForAssessmentRevision`
- `getBundleManifest`
- `getAssuranceSubmission`
- `requestExport`
- `getExport`

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
payload or read handle. Successful bounded JSON carries a Service-issued
five-minute expiry; Clients must discard the value no later than that instant.

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

## Effectiveness evaluation

The `dsh-security-assurance/evaluation` entry is independent of the runtime
Security Service and has no authority, Store, Subject, network, model, browser,
or filesystem access. `calculateEffectivenessMetricsV1` accepts only strict
Evaluation case identities, frozen severity weights, Ground Truth defect
metadata, predeclared Stratum definitions, preclassified benchmark disposition
or product failure, completed Assessment outcomes, and independently
adjudicated Finding matches.

The engine enforces unique Case, defect, and Finding identities plus one-to-one
matches. Benchmark-invalid Cases are excluded uniformly; product timeout,
budget exhaustion, crash, and incorrect outcome remain included measured
results. Missing denominators and unadjudicated Findings produce explicit
`INCONCLUSIVE` reasons rather than a fabricated zero or passing conclusion.
The engine also requires predeclared sample floors across Severity, Weakness
Family, Assessment Mode, and Supported Ecosystem. It derives case or Ground
Truth defect sample units itself, excludes Benchmark-invalid Cases uniformly,
counts product failures, and makes every deficient Stratum explicitly
`INCONCLUSIVE`. Results are canonically ordered, strict, recursively immutable,
and calculated by the same pure implementation consumed by packed release
tooling.

These slices are not an Effectiveness or release claim. Independent
repetitions, uncertainty requirements, paired Arms, matched-budget comparison,
Utility, non-inferiority, Ground Truth air-gap execution, Release Constitution
thresholds, Scorecards, and the Release Evidence Manifest remain separate
future proof slices.

## Model-facing Assessment operations

The optional `dsh-security-assurance/tools` entry registers the current
`security_assessment_start` -> `security_assessment_status` ->
`security_assessment_findings` -> `security_assessment_resume` plus
`security_assessment_cancel` and `security_assessment_export` through the
Harness Tool Registry. All six
operations require the exact
registered, running Agent in its active open turn and derive a process-local
`harness-session` Invocation outside model arguments. Caller Principal,
permissions, channel, Repository paths, arbitrary Policy content, and hidden
idempotency state are never accepted from the model.

`security_assessment_start` takes an explicit idempotency key, Repository ID,
Subject, Assessment mode and profile, matching Target, optional stronger Control
IDs, and an optional Start Preflight digest. It carries only `assessment:start`
and delegates schema validation, Repository and Catalog binding, Preflight
freshness, Subject freezing, idempotency, persistence, and execution to
`startAssessment`. Its bounded Receipt contains only the Assessment ID, revision
`1`, `CREATED` state, operation, schema version, and the caller's idempotency key.

`security_assessment_status` takes only `assessment_id`, carries only
`assessment:read`, and delegates to `getAssessment`. Its canonical result
contains the Assessment ID and revision, state, the four bounded Coverage
summary fields, and `verdict` (`null` until the Service has sealed the
Assessment). It deliberately omits Repository and Subject bindings, Policy and
Evidence digests, Coverage resolutions, recovery internals, available actions,
timestamps, Seal metadata, Findings, attack paths, export locations, and
authority metadata.

`security_assessment_findings` takes an Assessment ID, a Service-bounded page
limit, an optional opaque cursor, and an optional unique Validation-state
filter. It carries only `assessment:read` and delegates to `listFindings` so the
Service remains the owner of stable ordering, query/session-bound cursor
validation, pagination, and redaction. Each returned Summary keeps only record
identity and revision, Validation state and contract, weakness classification,
Technical Severity, Evidence Confidence, Policy Significance, and the protected-
detail availability flag. Finding Detail, Source Anchors, Evidence links or
content, attack paths, Risk Decisions, credentials, and authority metadata are
excluded.

`security_assessment_resume` takes an exact BLOCKED Assessment ID and revision,
an explicit idempotency key, and a bounded structured operator reason. It
carries only `assessment:resume` and delegates to `resumeAssessment`; only the
Service may decide whether the revision and state are resumable and create
eligible new Attempts under the original frozen Subject, Policy, Coverage Plan,
Provider Composition, and budget. The bounded Receipt omits the operator reason,
timestamps, correlation, recovery internals, and all frozen semantic inputs.

`security_assessment_cancel` takes an exact nonterminal Assessment ID and
revision, an explicit idempotency key, and a bounded structured operator reason.
It carries only `assessment:cancel` and delegates persistence, quiescence, and
terminal transition to `cancelAssessment`. Its bounded Receipt identifies the
state and revision at which cancellation intent was accepted but deliberately
does not claim `CANCELED`; callers must read current status for terminal truth.
Force completion, cleanup bypass, Evidence deletion, Verdict injection, reason,
timestamps, correlation, and cancellation internals are excluded.

`security_assessment_export` takes an exact SEALED Assessment ID and revision,
an explicit idempotency key, the fixed supported Export Profile, and a Delivery
Destination frozen into the Assessment contract. It carries only
`export:request` and delegates sealed-state, profile, destination, owner,
idempotency, and durable delivery handling to `requestExport`. The bounded
`PENDING` Receipt contains an owner-bound Export ID but excludes preview or
artifact content, digests, paths, URLs, credentials, destination options,
download capabilities, timestamps, and correlation. It does not grant
`export:read` or `export:download`. The entry is lifecycle-owned: unloading it
removes all six tools
without stopping the root Security Service.

The transport conformance suite locks each tool's exact model-visible input and
top-level output fields, required-argument set, closed canonical output, single
operation-specific Service dispatch, and unmodified live execution signal. This
keeps future tool additions from silently widening authority or disclosure.

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

## Workbench Remote, New Assessment, bounded Evidence, and governed actions

The optional `dsh-security-assurance/workbench-remote` entry is a Host Adapter,
not an authentication provider and not a second business Service. It injects
the root `ctx.securityAssurance` Service and the Host Typert registry. On every
call, Typert resolves the browser's bounded opaque
`securityAssuranceWorkbenchContextId` through
the deployment-supplied `resolveAuthorityContext` function. Only that Host
function may return the current authenticated operator's principal and exact
permissions; the Adapter then mints a process-local, non-serializable Security
Invocation and delegates one operation to the root Service.

```ts
import SecurityAssuranceWorkbenchRemote from
  'dsh-security-assurance/workbench-remote'

await ctx.plugin(SecurityAssuranceWorkbenchRemote, {
  async resolveAuthorityContext(authorityContextId) {
    // Deployment-owned authentication/session registry. Return undefined when
    // the context is missing, expired, logged out, or otherwise ambiguous.
    return hostOperatorSessions.resolve(authorityContextId)
  },
})
```

Harness `0.1.1-rc.2` protects `trusted-host` Remote traffic against Host-header,
DNS-rebinding, and cross-site confusion, but that transport fence is explicitly
not user authentication and does not supply an Operator identity to a Remote
method. Consequently this Adapter has no anonymous or fixed-superuser fallback:
activation without a real Host resolver fails, an unknown or malformed context
fails closed, and the dormant bundle row must not be enabled for an anonymous
LAN deployment.

The generated Host contribution is published at `./typert`; the generated
Client contribution is published at `./remote`. All sixteen operations use strict
generated request/result codecs. Cancellation is forwarded to the root Service,
mutation retries retain the caller's original idempotency key, and Adapter
disposal withdraws its lookup and Remote Service without altering Assessments
or the root plugin.

The package also publishes a Harness-discoverable `./client` entry. It mounts
`./remote` through `ctx.remote.$mount()` and provides the browser-local
`ctx.securityAssuranceWorkbench` Controller with twenty-eight public operations:
`openAssessmentSelection`, `loadMoreAssessments`, `selectAssessment`,
`openRuntimeHealth`, `refreshRuntimeHealth`, `openRepositories`, `selectRepository`, `requestStartPreflight`,
`cancelStartPreflight`, `confirmStartAssessment`, `backToAssessmentSelection`,
`openAssessment`, `openBundle`, `backToAssessmentDetail`, `openFindings`, `loadMoreFindings`, `selectFinding`,
`backToFindingList`, `recordRiskDecision`, `resumeAssessment`, `cancelAssessment`,
`selectEvidence`, `discloseEvidence`,
`hideEvidenceDisclosure`, `backToFindingDetail`, `closeAssessment`, `getState`,
and `subscribe`. The Host
passes its current opaque authority-context ID to `openAssessmentSelection`;
the browser receives a bounded page of redacted, authority-visible identities
and can append continuation pages from the same signed consistency window.
Only one continuation is admitted at a time, and a changed watermark fails
closed without retaining the accumulated identities. The browser can open only
an ID from the currently loaded window. No credential, Principal, permission
set, or Security Invocation is accepted by the selector. `openAssessment`
remains the direct Host seam when the Assessment ID is already known. Either open path
loads the current immutable Snapshot and internally follows
`waitForAssessmentRevision`; `CHANGED` fetches the next Snapshot, `TIMED_OUT`
continues from the same committed revision, and close or Client disposal aborts
the outstanding wait. The opaque authority context remains only in the live
in-memory Workbench session so terminal Assessment Finding queries can be
authorized; it is absent from observable state and is erased on close, failure,
replacement, or Client disposal.

This Controller owns no security decision or durable continuation state. The
authority context is transient authentication material, and the implementation
contains no `localStorage`, `sessionStorage`, IndexedDB, Service Worker cache,
URL, or logging persistence for it, Findings, Evidence, rationale, or full
Snapshots. Bounded content is retained only in the current observable state and
is discarded on explicit hide, Evidence navigation, close, replacement,
authority failure, or Service expiry. Those navigation and lifecycle exits also
abort any in-flight Evidence request before the stale-response fence is applied.
Remote or Security failures fail closed
to a payload-free `FAILED` state; reopening re-fetches Service truth by opaque
Assessment ID. From the selector, the Controller can fetch or explicitly refresh
the Service-owned Runtime Health Snapshot. Each read reuses current Host authority;
the browser renders the exact overall state, compatibility, admission booleans,
and redacted checks without deriving health or exposing repair/bypass actions.
The Controller can also list path-free
Repository Snapshots, resolve a repository-specific Security Catalog, and
submit only the exact Catalog selection for a Service-derived Start Preflight.
Confirmation adds a fresh idempotency identity and the proposal digest to the
unchanged selection; a matching Receipt is required before the newly committed
Assessment is opened. Changing a selection cancels the proposal and requires a
new preflight.

For a SEALED Snapshot, `openBundle` separately reauthorizes an integrity-verified
Bundle Manifest read and an exact Repository binding read. The Controller accepts
the result only when Assessment, revision, Verdict, Seal, Repository ID, and
Repository revision match the retained Service Snapshot. The view exposes
canonical record identities, schemas, classifications, digests, omissions, and
stable registered Delivery Destination IDs, but no private path, Bundle bytes,
credential, or browser-generated report. From one exact frozen destination the
Controller may request the fixed `security/export/internal-json-v1` Preview,
which is entirely Service-derived and explicitly names included categories,
mandatory redactions, warnings, audience, format, media type, destination, and
expiry. A matching Preview can be submitted with a fresh idempotency identity;
the browser accepts only a bound Receipt and owner-bound `getExport` status. The
current local-audit adapter writes a digest-bound artifact beneath the private
Service home. Transient artifact I/O and sealed-source reads remain `PENDING`
under a five-attempt Service-owned retry policy; status discloses bounded attempt
count, last safe failure category, timestamps, and next retry time. The
Workbench can explicitly refresh that status but never initiates a retry.
At expiry it observes `PURGE_PENDING` or `PURGED` plus a path-free digest
tombstone; the browser never performs cleanup. Canonical-byte conflicts are
terminal. Status projects `HOST_MANAGED` access unless current authority also
has `export:download`; only then does it project `ONE_USE_DOWNLOAD`. The explicit
download action reauthorizes through the Host Remote, binds Export, artifact, and
Digest Envelope, mints and consumes a non-serializable process-local capability
inside the same Service invocation, and returns an artifact of at most 16 MiB as
verified base64. The Client verifies byte length and SHA-256 again before using a
bounded Blob URL to invoke the browser download, then retains only filename,
digest, size, and consumed time. No capability token, private path, credential,
content, or Blob
URL enters Workbench state, browser history, or storage.

The Client entry also registers two additive Harness UI contributions. A
launcher in `sidebar.footer.action` opens a frame-wide dialog in
`shell.overlay`; neither replaces a single-owner Host shell slot. The overlay
subscribes to the Controller through the Slot renderer's observable seam and
renders `CLOSED`, `SELECTION_LOADING`, `SELECTION_READY`,
`SELECTION_LOADING_MORE`, Runtime Health, Bundle/Export readiness, Export
Preview/request/status/one-use download,
Repository/Catalog/Preflight/Wizard states, `LOADING`,
`READY`, and `FAILED` without duplicating
Remote, polling, authorization, or revision logic. `READY` shows canonical machine IDs
unchanged together with revision, state, Verdict, repository and policy
bindings, mandatory Coverage, and the Service Snapshot's `availableActions`.
Its nested Finding states load redacted Summary pages against the rendered
Assessment revision, admit one cursor continuation at a time, and open Detail
only from an exact listed record revision. Triage keeps record kind, Validation,
Technical Severity, Evidence Confidence, Policy Significance, weakness, and
sensitivity visibly separate. Detail exposes canonical Subject-relative Source
Anchor and Evidence Link metadata without Evidence payloads or read
capabilities. Selecting one exact listed Evidence artifact derives the
Assessment, Finding, artifact, and digest bindings from the retained Detail and
fixes the viewing purpose and Profile to `FINDING_TRIAGE` and
`security/evidence-view/metadata-only-v1`; the Controller rejects arbitrary
identities or mismatched responses and initially renders only the metadata-only
View, including its complete Digest Envelope and explicit redaction reason.
A separate explicit action invokes `discloseEvidence` with the exact retained
bindings, fixed `VALIDATION_REVIEW` purpose, and
`security/evidence-view/bounded-json-v1` Profile. The Host resolves current
authority again for that invocation. The Controller accepts only a matching
structured redaction or at most 32 KiB of byte-consistent JSON with a future
Service expiry, fences late responses, and schedules cleanup without retaining
the bounded View in the timer closure. Hiding, leaving Evidence, closing, or
replacing the session aborts any in-flight disclosure before its result is
discarded. The bilingual UI marks the content as
sensitive and time-limited, renders purpose, Profile, size, and expiry, and
provides an explicit hide-and-discard control. Evidence transitions move focus
to the new panel, return it to the metadata action after hide or expiry, and
return it to the originating Link after leaving Evidence.
The Risk Decision form appears only beside an exact Finding Detail with a
matching `RECORD_RISK_DECISION` action in the current Snapshot. It renders the
immutable Finding and revisions, every exact consequence, authority mode,
compensating-control minimum, expiry ceiling, and completed/required
attestations. The browser selects only a projected decision and supplies its
rationale, controls, and expiry; the
Controller derives Assessment and Finding bindings from retained Service truth,
generates a fresh idempotency identity, and never accepts a Principal or
permission. Critical second authority shows the first immutable attestation and
submits only its exact rationale, controls, and expiry through a separately
resolved Host context. A matching receipt is followed by an Assessment refetch,
and local form input is discarded. BLOCKED recovery submits Resume and Cancel
only when those exact revision-bound actions are projected by the Service;
receipts are followed by a fresh Snapshot and cancellation is never presented
as terminal before durable quiescence is observed.

The surface ships complete English and Simplified Chinese copy, semantic dialog
and status roles, keyboard dismissal and focus return, responsive layout, and
text-bearing state indicators. It loads no third-party scripts, fonts, remote
content, trackers, or analytics. Opening the selector still belongs to an
authenticated Host integration calling `openAssessmentSelection`; the launcher
does not accept, infer, persist, or mint an authority context. Selection buttons
only forward identities already projected by the Security Service.

```ts
await ctx.securityAssuranceWorkbench.openAssessmentSelection({
  securityAssuranceWorkbenchContextId: currentHostSession.workbenchContextId,
})
```

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
pnpm pack:browser-e2e
```

`pack:smoke` installs the packed artifact into a fresh temporary consumer and
opens a real Harness Agent turn over the installed entry. It proves the bounded
Start -> Status -> Findings -> Export lifecycle, including SEALED polling,
canonical rendering, Export idempotency replay, and disclosure exclusions.

`pack:browser-e2e` packs the current Security artifact, installs the exact
registry Harness release into a fresh temporary profile, adds a temporary
test-only Reference Host authority layer, and drives a locally installed Chrome
or Edge through the assembled Client. It does not modify Harness or ship that
test authority layer. Shared Web HMR remains disabled in the qualified Harness
reference, so this command deliberately makes no HMR coverage claim.

All five bundle rows in `cordis.patch.yml` are disabled by default.
Installation alone does not activate a security authority, Host Repository
Provider, model tool, Workbench Remote, or optional Control Plane Provider.

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
