# DSH Security Assurance v0.1 Implementation Specification

Status: implementation baseline derived from accepted ADRs 0001-0294

This document turns the accepted product decisions into one executable build
plan. It does not replace the ADRs: when this document and an accepted ADR
appear to disagree, the ADR is authoritative and this document must be fixed.

## 1. Product boundary

DSH Security Assurance is an independent DeepSeek Harness plugin and npm
product. It performs evidence-backed, read-only application-security
assessments and can provide a sealed Assurance Submission to DSH Engineering
Control Plane. It does not own Mission approval.

The implementation MUST:

- live under `D:\Deepseek\DSH  Security Assurance`;
- integrate through public Harness and Cordis seams;
- expose `ctx.securityAssurance` as its sole external business Interface;
- route every authoritative state change through that Service;
- keep the Security Assessment Kernel, Engine, stores, scheduler, and
  transaction machinery package-private;
- install every runtime entry dormant by default; and
- qualify the exact Harness version `0.1.2-alpha.1` on Node
  `^22.19.0 || >=24.0.0`.

The implementation MUST NOT:

- modify or copy any source from `D:\Deepseek\deepseek-harness-master`;
- patch Harness Core or `agent-loop`;
- make Workbench, tools, role agents, analyzers, or Control Plane adapters into
  an alternative mutation authority;
- use Harness session logs as the Assessment Store;
- introduce a generic execute/query/CRUD/SQL operation; or
- claim effectiveness from conformance tests alone.

Primary boundary decisions: ADR 0001, 0002, 0100, 0101, 0235, and 0236.

## 2. Package and runtime identity

| Item | v0.1 value |
| --- | --- |
| npm package | `dsh-security-assurance` |
| Cordis Service key | `securityAssurance` |
| Context property | `ctx.securityAssurance` |
| Remote namespace | `securityAssurance` |
| qualified Harness target | `0.1.2-alpha.1` exactly |
| Node range | `^22.19.0 || >=24.0.0` |
| first public candidate | `0.1.0-rc.1` |
| current candidate package version | `0.1.0-rc.11` |
| module format | ESM |
| JavaScript target | ES2024 |

Development builds remain private and MUST NOT claim the public RC version.
The qualified candidate uses `0.1.0-rc.11`; promotion to stable `0.1.0` follows
ADR 0087 and changes only version, signature, and release metadata.
The final package is one installation unit with independent entry points:

| Export | Responsibility | Side effects on import |
| --- | --- | --- |
| `.` | Security Service and Engine provider | none until Cordis activation |
| `./tools` | model-facing Consumer | none until Cordis activation |
| `./control-plane-provider` | Assurance Provider adapter | none until Cordis activation |
| `./client` | Workbench Client plugin | none until Cordis activation |
| `./invariant` | composition and compatibility checks | none until Cordis activation |
| `./contracts` | public DTOs, schemas, Results, and types | none |
| `./analyzer` | Analyzer extension contract | none |
| `./conformance` | public contract suites and reference fakes | none |
| `./typert` | generated Host contracts | none |
| `./remote` | generated Client contracts | none |

Exports are added to the development manifest only when their vertical slice
exists. The release candidate MUST contain the complete map above. One
`cordis.patch.yml` contributes independently activatable Host and Client rows,
all with `disabled: true`.

Primary packaging decisions: ADR 0081, 0088-0090, 0117, and 0244-0245.

## 3. Module architecture

```text
Harness channels
  tools / Workbench Remote / Control Plane Provider / trusted Host adapters
                                |
                                v
                    Security Authority Resolver
                                |
                    opaque Security Invocation
                                |
                                v
                  ctx.securityAssurance Service
                /          |          |          \
               v           v          v           v
       Assessment      SQLite      Evidence      external seams
         Engine      Persistence  Persistence    (Analyzer/Provider,
            |             |           |           Key Provider,
            v             |           |           Egress Broker,
       pure Security <----+-----------+           Host Clock)
     Assessment Kernel
```

Dependencies point inward. Domain values and the pure Kernel know no Cordis,
SQLite, filesystem, subprocess, browser, or transport concepts.

### 3.1 Security Service — public deep Module

The Service owns the complete external semantic boundary:

- authority resolution and authorization;
- runtime schema validation;
- revision compare-and-set and idempotency admission;
- lifecycle and health admission;
- transaction and Evidence coordination;
- calls into pure Kernel decisions;
- redaction, pagination, cancellation, and bounded deadlines; and
- conversion of expected and unexpected failures into `SecurityResult<T>`.

No internal Store, transaction, phase, scheduler, or Kernel object crosses this
Interface.

### 3.2 Security Assessment Kernel — package-private pure deep Module

The Kernel receives immutable values and returns deterministic decisions. Its
initial narrow Interface is:

- `applyAssessmentCommand`
- `compileCoveragePlan`
- `evaluatePolicy`
- `checkSealReadiness`

It owns transition legality, Evidence admission semantics, coverage
reconciliation, policy traces, verdict eligibility, and sealing readiness. It
does not perform I/O or own time.

### 3.3 Assessment Engine — package-private orchestration Module

The Engine hides phase scheduling, recovery, leases, fencing, retries,
quiescence, and run-to-stable behavior. It advances only committed work and
admits an attempt result at most once. Crash recovery never silently resumes an
interrupted analyzer attempt; a user-authorized `resumeAssessment` is required.

### 3.4 SQLite Persistence — package-private durable Module

One SQLite boundary owns migrations, revision journal, current projections,
transactional outbox, idempotency records, compare-and-set, leases, fencing,
and bounded query watermarks. Migrations are monotonic, verified, and
fail-closed.

### 3.5 Evidence Persistence — package-private durable Module

Evidence uses staged, digest-verified publication. This Module owns canonical
envelopes, encryption metadata, key-provider interaction, retention, tombstones,
and garbage collection. Subject material and Evidence storage remain separate;
secrets are never retained.

### 3.6 True external seams

A seam exists only where multiple adapters are expected:

- Analyzer/Provider;
- Evidence Key Provider;
- governed Egress Broker; and
- Host Clock.

Reference fakes implement these same seams. They do not receive test-only
authority or mutation shortcuts.

Primary architecture decisions: ADR 0238-0243.

## 4. Public contract rules

Every public DTO has an explicit schema version, bounded fields, canonical
optional-value semantics, runtime validation, and JSON-safe values only.
Identifiers are opaque branded strings. Public DTOs never contain class
instances, `Date`, `Map`, `Set`, `BigInt`, raw `Error`, paths, handles,
capability objects, mutable aggregate references, or SQLite rows.

Every runtime operation has an Interface equivalent to:

```ts
operation(
  invocation: SecurityInvocation,
  request: VersionedJsonRequest,
  options?: InvocationOptions,
): Promise<SecurityResult<VersionedJsonValue>>
```

`SecurityInvocation` is opaque, non-serializable, and minted only from a real
trusted caller channel by the Security Authority Resolver. Principal,
permissions, transport headers, capability claims, and Host paths never appear
in request DTOs. `InvocationOptions` contains only process-local cancellation
and a bounded caller deadline.

`SecurityResult<T>` is discriminated:

```ts
type SecurityResult<T> =
  | { readonly ok: true; readonly value: T }
  | { readonly ok: false; readonly error: PublicSecurityError }
```

Expected failures return a stable redacted `PublicSecurityError`; unexpected
exceptions are correlated internally and returned as redacted `INTERNAL`
results. Raw exceptions do not cross runtime operation boundaries.

The only exception is local composition-only
`registerAnalyzer(descriptor, factory)`. It is synchronous, validates loudly,
is unavailable to Remote/browser/model payloads, and returns a Fiber-owned
disposer.

Primary contract decisions: ADR 0246-0248 and 0255-0274.

## 5. Fixed v0.1 Service operation catalog

The public catalog is exactly:

### Health and capability

- `getHealth`
- `getCatalog`

### Repository Registry

- `registerRepository`
- `updateRepository`
- `disableRepository`
- `getRepository`
- `listRepositories`

### Assessment lifecycle

- `startAssessment`
- `getAssessment`
- `listAssessments`
- `waitForAssessmentRevision`
- `resumeAssessment`
- `cancelAssessment`

### Findings and Evidence

- `listFindings`
- `getFinding`
- `getEvidenceView`

### Decisions and sealed artifacts

- `recordRiskDecision`
- `getBundleManifest`
- `getAssuranceSubmission`

### Export

- `requestExport`
- `getExport`

### Local composition

- `registerAnalyzer`

Adding an operation requires contract review and a new ADR or an accepted ADR
amendment.

## 6. Runtime health

`getHealth` returns an authorized, bounded, immutable Runtime Health Snapshot.
Its states are:

- `READY`: admission checks permit configured operations;
- `READ_ONLY_SAFE`: bounded metadata remains trustworthy but mutation is
  fail-closed;
- `QUIESCING`: shutdown or replacement is draining owned effects; and
- `STOPPED`: the runtime no longer admits work.

The Snapshot identifies its schema version, product version, exact Harness
compatibility target, current state, admission status, and redacted named
checks. Missing keys/providers, migration or integrity failures, and incompatible
composition enter `READ_ONLY_SAFE` when trustworthy bounded reads remain
possible.

## 7. Durable Assessment model

An Assessment binds an immutable Subject, frozen Security Policy, Coverage
Plan, Provider/Analyzer composition, execution context, budgets, and exact
recorded policy instant. Operational Assessment State and Security Verdict are
separate.

Assessment states are `CREATED`, `RUNNING`, `BLOCKED`, `SEALED`, and
`CANCELED`. Security Verdicts are tri-state and fail-closed. Commands publish
durable receipts; externally visible transactions advance one Assessment
Revision. Idempotency binds caller authority, operation, target, and canonical
request. Pagination cursors bind query, authority, and watermark.

Seal, Verdict, canonical Assessment Bundle, and Assurance Submission commit
atomically. Only a sealed Assessment may yield an official export or Assurance
Submission. Risk acceptance is explicit, authorized, immutable, scoped, and
non-destructive; critical break-glass requires two independent operator
invocations.

## 8. Analyzer and role-agent execution

Analyzers register versioned immutable descriptors and attempt-scoped factories.
Descriptors state capability but grant no permission. Each Analyzer receives
only immutable bounded Subject views and attempt-scoped capability handles.
Gate-bearing work requires a qualified execution class; unsupported isolation
or egress reduces a contribution to advisory status rather than silently
claiming verdict eligibility.

Role agents are governed analyzers, not authorities. v0.1 has fixed roles:

- threat modeler;
- discovery analyst;
- validation analyst;
- attack-path analyst; and
- challenge analyst.

Each role attempt uses a fresh isolated subagent session, a fixed least-
privilege tool manifest, minimal context grants, and structured immutable output.
Agents cannot approve, accept risk, mutate the Store, or decide a Verdict.

## 9. Workbench

The Workbench is an additive Service client. It contributes a launcher at
`sidebar.footer.action` and its full UI at `shell.overlay`; it never replaces a
single-owner Harness shell slot.

The fixed v0.1 information architecture is:

- Overview
- Repositories
- New Assessment
- Assessment Detail
- Findings
- Evidence
- Risk Decisions
- Exports
- Runtime Health

Available actions come from Service-projected snapshots, not browser inference.
Progress uses revision-bound long polling. Browser route state contains only
low-sensitivity identifiers, and sensitive Assessment payloads are not persisted
in browser storage. The UI inherits Host CSP, supports keyboard/focus/accessibility
requirements, and ships English and Simplified Chinese.

Primary Workbench decisions: ADR 0275-0294.

## 10. Delivery phases

Each phase is a vertical slice through a real public Interface. A phase is not
complete merely because its internal classes exist.

### Phase 0 — package and health tracer

- private development package, TypeScript, Vitest, tsdown, and dormant bundle;
- side-effect-free contracts entry;
- Cordis registration of `ctx.securityAssurance`;
- production-shaped authority Resolver seam with no request-body authority;
- `getHealth` returning a versioned `READY` Result;
- disposal removes the Service from the owning Context;
- typecheck, tests, build, pack, and packed-import smoke proof.

### Phase 1 — Repository Registry

- register/get/list/update/disable vertical slices;
- revision CAS and idempotency;
- Host-resolved policy, key, execution, and export references;
- SQLite migration and restart proof.

### Phase 2 — immutable Subject and Assessment start

- Git revision, change, and workspace snapshot selectors;
- content-addressed Subject Manifest and private read-only materialization;
- atomic subject freeze plus Assessment receipt;
- hostile filesystem and mutation-after-freeze tests.

### Phase 3 — deterministic Kernel and durable Engine

- declarative transition table;
- revision journal, projections, outbox, leases, and fencing;
- explicit resume/cancel/quiescence behavior;
- crash checkpoints and multiprocess race proof.

### Phase 4 — Analyzer portfolio and governed role agents

- Analyzer SPI, qualification, attempt capabilities, budgets, cancellation;
- first complete TypeScript/JavaScript/Node ecosystem portfolio;
- fixed role catalog and subagent orchestration;
- malformed, timeout, fenced-late-result, and budget-overrun conformance.

### Phase 5 — Evidence, coverage, policy, and sealing

- staged verified Evidence publication and protected payloads;
- Coverage Plan and obligation reconciliation;
- pure policy evaluator and complete trace;
- independent seal-readiness check and atomic sealed artifacts.

### Phase 6 — adapters and Workbench

- bounded model tools;
- Host Repository Provider for declarative packed-profile composition;
- Control Plane Assurance Provider with pre-Assessment Repository Binding;
- Typert Remote and Client Workbench;
- semantic parity across Service, tools, Remote, and Provider;
- real-browser authorization and HMR/disposal journeys.

### Phase 7 — release proof

- pack the exact npm artifact;
- install into a fresh unmodified Harness `0.1.2-alpha.1` profile;
- activate only declared rows;
- run lifecycle, compatibility, filesystem, subprocess, sandbox, crash,
  migration, and cross-platform suites;
- bind the exact artifact and results in a Release Evidence Manifest;
- run separate preregistered Security Effectiveness evaluation before making
  effectiveness claims.

## 11. Test and proof strategy

Implementation follows red-green-refactor. The first failing test is written at
the public Service seam, followed by only enough implementation to pass. Pure
Kernel tests may use its package-private deterministic seam. Persistence is
proven through public behavior plus a separate read-only forensic reader; tests
never mutate the Store directly.

Required proof layers are cumulative:

1. schema and pure Kernel tests;
2. public Service contract and lifecycle tests using real Cordis composition;
3. official-seam reference-fake conformance;
4. SQLite restart, crash, CAS, lease, fencing, and migration tests;
5. hostile Subject/filesystem/subprocess/sandbox tests;
6. surface semantic-parity tests;
7. packed fresh-Harness installation and import-side-effect tests;
8. real-browser Workbench journeys;
9. conformance mutants and resource/leak tests; and
10. independent, preregistered Security Effectiveness evaluation.

An Analyzer or agent statement that a check passed is data, not proof. Release
assertions inspect external effects and sealed records.

Primary proof decisions: ADR 0057-0087 and 0216-0234.

## 12. Phase 0 acceptance contract

The first tracer is accepted only when all of the following are observable:

- importing `./contracts` causes no I/O, timers, registration, or mutation;
- activating the root plugin through `Context.plugin()` installs exactly one
  `ctx.securityAssurance` Service;
- a Resolver-issued Invocation can call `getHealth` through that public Service;
- `getHealth` resolves to `SecurityResult<RuntimeHealthSnapshot>` and the first
  Snapshot is schema version 1 with state `READY`;
- an absent, foreign, copied, or deserialized Invocation is rejected as a
  redacted `UNAUTHORIZED` Result;
- no raw exception crosses `getHealth`;
- disposing the owning Cordis Fiber removes the Service;
- TypeScript strict checking, unit tests, JavaScript build, declaration build,
  npm packing, and clean packed-import smoke all pass; and
- the Harness checkout has no changed files.

This contract intentionally proves the architecture before adding an Assessment
Store. It is not yet a claim that assessments, analyzers, Evidence, Workbench,
or Control Plane integration are implemented.
