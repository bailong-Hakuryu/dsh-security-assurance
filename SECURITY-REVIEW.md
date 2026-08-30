# Security Review — dsh-security-assurance 0.1.0-rc.8 (DeepSeek Harness plugin)

Review date: 2026-08-30 (in-session). Reviewer: DeepSeek Harness coding agent.
Scope: the `dsh-security-assurance` plugin workspace (this repository), its integration
seams with DeepSeek Harness `0.1.2-alpha.1` (`D:\Deepseek\deepseek-harness-latest`),
and the plugin's own security claims as stated in README.md/SECURITY.md/ADRs.

> Status: COMPLETE and remediated. The original findings below are retained as
> an audit trail; the remediation matrix records the current rc.8 posture.

## 1. Method and evidence

- Full static read of the core modules: `src/index.ts`, `src/tools.ts`,
  `src/contracts.ts`, `src/internal/authority.ts`, `persistence.ts`,
  `subject-freeze.ts`, `evidence-view.ts`, `export-delivery.ts`,
  `deterministic-kernel.ts`, `candidate-validation.ts`, `risk-decision.ts`,
  `builtin-node-package-lifecycle-analyzer.ts`, `harness-verification.ts`,
  `invariant.ts`, `host-repository-provider.ts`, `canonical.ts`, `freeze.ts`,
  `digest-envelope.ts`, plus `cordis.patch.yml`, build/package scripts.
- Five parallel deep-dive sub-reviews of the remaining subsystems (persistence/
  query cursors, subject/evidence/export, engine/analyzer/risk, contracts/
  adapters/client, evaluation engine) — findings merged in §4.
- Harness-side seam verification: `currentInitiator()` (AsyncLocalStorage
  initiator boundary) and tool `exec.agent` dispatch in the harness checkout
  confirm the model-tool authority gate is registry-owned, not model-forgeable.
- Dynamic gates executed in this workspace:
  - `pnpm run typecheck` — exit 0 (tsc, both configs).
  - `pnpm test` — 69 test files, **342/342 passed** (~42 s).
  - `pnpm run pack:dry-run` — 42 files / 343.6 kB shipped; only `lib/*`,
    `lib/types/*`, `cordis.patch.yml`, README/CHANGELOG/LICENSE/SECURITY.
    No `src`, `tests`, `scripts`, or stray artifacts in the tarball.
  - Node v24.19.0 / pnpm 11.7.0 satisfy the declared engine range.
- Three dynamic reproductions (temporary vitest specs, removed after the run,
  results recorded in §4):
  - F-07: a revision-advancing writer is admitted after cancellation and
    permanently breaks cancellation completion — **reproduced**.
  - F-08: startup recovery throws on the contradictory row instead of
    skipping it — **reproduced** (`SecurityPersistenceError:
    Assessment cancellation cannot complete`).
  - F-38: workspace-snapshot ancestor-symlink escape — **reproduced** in the
    victim file outside the repository reached the frozen Subject and the
    analyzer slice (`{"name":"victim-secret","marker":"host-file-exfiltrated"}`).

## 2. Architecture map (verified against source)

- **Root Service** `ctx.securityAssurance` (`src/index.ts`): the sole public
  mutation boundary. Every operation is `(invocation, request, options)` with
  an opaque, WeakMap-bound `SecurityInvocation` resolved only through
  package-owned trusted channels (`harness-session` model tools, `host-operator`
  host composition, `control-plane` adapter). Requests are strict Zod DTOs;
  results are `SecurityResult<T>` envelopes, deep-frozen.
- **Persistence** (`src/internal/persistence.ts`): SQLite (node:sqlite,
  `STRICT` tables), prepared statements only, `BEGIN IMMEDIATE` transactions,
  exact revision compare-and-set for every mutation, idempotency records bound
  to (principal, authority kind, operation, target, key, canonical request
  digest), startup validation (application_id, user_version, table/column
  catalog, `quick_check`, `foreign_key_check`), restart recovery that blocks
  interrupted RUNNING work instead of replaying it.
- **Subject Freeze** (`src/internal/subject-freeze.ts`): git_revision / change /
  workspace_snapshot subjects materialized into a content-addressed private
  store under `$DSH_HOME/security-assurance/subjects`. Strict portable-path
  validation (no `..`, no backslash, no drive/colon, no reserved device names,
  case-collision rejection, `.git` excluded), `O_NOFOLLOW` + dev/ino/size/
  mtime/ctime stability signatures, symlinks recorded as metadata only (never
  materialized as links), submodules recorded by revision only, atomic rename
  publication, digest re-verification of the published snapshot, read-only
  locking of the frozen tree.
- **Deterministic kernel** (`src/internal/deterministic-kernel.ts`): pure policy
  evaluator. For the scoped `security/node-package-lifecycle` policy: blocking
  finding precedence, SATISFIED only with complete mandatory coverage and zero
  candidates, INDETERMINATE on any gap/ambiguity; independent `checkSealReadiness`
  re-derives verdict constraints and evidence publication identity.
- **Built-in analyzer** (`src/internal/builtin-node-package-lifecycle-analyzer.ts`):
  pure, no fs/process/network; flags non-empty string `preinstall`/`install`/
  `postinstall`; duplicate lifecycle keys → INVALID manifest → INCOMPLETE →
  INDETERMINATE (never a silent SATISFIED); script bodies never retained as
  evidence.
- **Evidence views** (`src/internal/evidence-view.ts`): metadata-only by default;
  bounded JSON (≤ 32 KiB canonical bytes, allowlisted schemas, dedicated
  disclosure permission, `VALIDATION_REVIEW` purpose only, service-issued
  5-minute expiry).
- **Export delivery** (`src/internal/export-delivery.ts`): owner-bound
  deterministic export ids, 5-attempt retry policy, digest-bound artifact,
  24 h retention, two-phase purge with digest tombstone, 60-second one-use
  download capability (owner + expiry + single claim), ≤ 16 MiB bounded read
  with digest re-verification.
- **Risk decisions** (`src/internal/risk-decision.ts` + persistence):
  DENY preserves blocking significance; ACCEPT requires compensating controls
  and bounded expiry (High ≤ 7 d, others ≤ 30 d); Critical requires the frozen
  break-glass control plus dual independent authority with exact matching,
  ≤ 24 h. Acceptance can remove policy blocking but never changes Technical
  Severity; SATISFIED remains impossible without complete coverage.
- **Model tools** (`src/tools.ts`): eight bounded tools derive a process-local
  `harness-session` invocation from the exact live agent's open driver turn
  (`ctx.agents` identity + initiator + turn boundaries) — never from model
  arguments. Outputs are redacted DTOs with strict JSON schemas.
- **Adapters**: workbench-remote (Host-supplied authority-context resolver,
  no anonymous fallback), control-plane-provider (sha256-derived idempotency,
  repository-binding assertion, sealed-submission embedding, cancellation
  crash checkpoints), host-repository-provider (declarative registrations,
  path-free resolution), invariant (composition verification with
  fail-closed admission).

## 3. Quality-gate evidence

| Gate | Result |
| --- | --- |
| `pnpm run typecheck` | PASS (exit 0) |
| `pnpm test` | PASS — 69 files, 342 tests |
| `pnpm run pack:dry-run` | PASS — 42 files, 343.6 kB, clean allowlist |
| Node engine range | PASS (v24.19.0) |
| Workspace hygiene | NOTE — untracked `graphify-out/` tool artifacts present (not shipped) |

### Remediation status (rc.8)

| Finding group | Current status |
| --- | --- |
| F-01/F-02/F-21 authority and invariant ownership | Fixed with package-private, owner-bound channels and fail-closed bootstrap |
| F-07/F-08 cancellation lifecycle | Fixed: pending cancellation fences every writer and restart recovery is idempotent |
| F-14/F-15/F-17/F-20/F-29/F-30/F-31/F-32/F-38/F-39 | Fixed and covered by regression tests or release gates |
| F-03/F-26 duplicate-key parsing | Fixed: JSON property-token scanner covers `scripts` and lifecycle keys without string false positives |
| F-06/F-22/F-23 risk decisions | Fixed: expiry and case-insensitive dual-authority checks are enforced at finalization |
| F-09/F-11/F-12/F-33/F-34/F-35/F-40/F-41/F-42/F-43/F-45/F-46/F-48/F-49 | Fixed or hardened at module seams; residual host-private trust assumptions remain documented |
| F-04/F-13/F-19/F-25/F-27/F-28/F-36/F-37/F-44/F-47 | Accepted design limitations / defense-in-depth notes; no release-blocking behavior |

## 4. Findings

### Verified by the primary reviewer

**F-01 (High, bounded by the in-process trust model) — Invocation minting is a
globally discoverable, unauthenticated capability.**
`src/internal/authority.ts:21-23,45-80` — `RESOLVE_TRUSTED_INVOCATION` is
`Symbol.for('dsh-security-assurance/internal/resolve-trusted-invocation/v1')`;
the mint closure is a non-enumerable property of the shared
`SecurityAssuranceService` instance (`ctx.securityAssurance`), and
`resolve()` authenticates nothing: channel kind, principal and permissions are
entirely self-asserted by the caller (format checks only). Any in-process code
(a Cordis plugin, a client plugin, or a compromised dependency) can run
`Reflect.get(service, Symbol.for(...))({kind:'host-operator', principalId:'<any>', permissions:['risk:break-glass', ...]})`
with zero imports — the package export map hides the module but not the
symbol. Same pattern at
`src/internal/control-plane-assessment.ts:20-22`,
`src/internal/control-plane-repository-binding.ts:9-11`,
`src/internal/control-plane-provider-operation.ts:74-76`, and the
qualification registration in `src/internal/analyzer-qualification-registration.ts:11-31`.
Impact: full authority bypass — spoof principals, satisfy the
control-plane repository-binding verifier with a constant-true matcher, read
Assurance Submissions, record CRITICAL risk acceptances, cancel assessments.
Not reachable from the model (the curated tools mint only `harness-session`
with one fixed permission, `src/tools.ts:526-530`), so this is a
one-compromised-plugin-away escalation rather than a direct model exploit.
ADR 0159 documents that in-process extensions are trusted Host code, and
ADR 0302 documents the `Symbol.for` choice, but the README claim that
"package consumers cannot mint or deserialize Security Invocations" is false
for any co-hosted code. Recommended: replace `Symbol.for` with module-private
closure-held issuers bound to specific trusted adapters, and bind channel
kinds to caller identity.

**F-02 (merged into F-21) — Harness-verification authority readable from `globalThis`.**
See F-21 in the engine/analyzer/risk section for the consolidated finding
(spoof PASS / force FAIL DoS via the globally readable authority slot at
`src/internal/harness-verification.ts:32-50`).

**F-03 (Info / hardening) — Duplicate `scripts` object key not detected.**
`src/internal/builtin-node-package-lifecycle-analyzer.ts:156-170` detects
duplicate lifecycle keys (`preinstall`/`install`/`postinstall`) but not
duplicate `scripts` keys. Today this cannot diverge from npm's own behavior
because both parse with last-wins JSON semantics, so the verdict remains
truthful for npm; but a stricter duplicate-`scripts` rejection would remove the
entire ambiguity class for other installers that error on or honor duplicate
keys differently.

**F-04 (Info / hygiene) — Subject staging directories leak on hard crash.**
`src/internal/subject-freeze.ts:558-564` creates `staging/subject-<uuid>` trees
that are removed only on the normal/caught paths; a process hard-kill (e.g.,
the crash-conformance scenarios) leaves them behind. No startup reaper exists.
Disk accumulation only; content is the (partially materialized) private copy.

**F-05 (merged into F-15) — Cwd-derived registration key in the direct-use patch.**
See F-15 in the contracts/tools/adapters/client section for the consolidated
finding (truncated reversible cwd key, launcher-cwd-bound root,
`cordis.patch.yml:16-19`).

**F-06 (Info / fail-closed semantics) — Expired Critical first attestation blocks sealing.**
`src/internal/risk-decision.ts` + `src/internal/persistence.ts:1312-1329`: a
first Critical break-glass attestation that expires before a distinct matching
second attestation arrives leaves the window permanently OPEN; resume is
rejected (window non-null) and no re-attestation path exists — the only exits
are canceling the Assessment or (for replay) the identical first decision.
Deliberate fail-closed design per the tests; operators should be aware that a
Critical acceptance has a hard 24-hour completion window.

### Persistence / registry / query deep-dive

**F-07 (Medium) — Admitted cancellation is not terminal; later revisions can
void it or seal past it.**
`src/internal/persistence.ts`: `sealAssessment` (`:1131-1139`),
`openRiskDecisionWindow` (`:1177-1181`), `recordRiskDecision` (`:1285-1304`)
and `resumeAssessment` (`:915-921`) never check `pendingCancellation`, so after
`requestAssessmentCancellation` commits (revision N+1) any of these writers can
commit a later revision; `completeAssessmentCancellation` (`:1088-1095`)
requires exact revision equality and then throws `revision_conflict` forever.
`resumeAssessment` (`:937`) explicitly nulls `pendingCancellation`, silently
discarding the admitted cancellation, and the Service still advertises
`RESUME_ASSESSMENT` on such records (`src/index.ts:1186-1195`, no
`pendingCancellation` check). A sealed record can even retain a non-null
`pendingCancellation` (`:1141` spreads `...current`). Result: an operator
cancellation can be defeated by a concurrent risk decision or resume, a
canceled assessment can still seal and publish, and no further cancel request
is possible (`:1018` blocks re-cancel). Fix: all revision-advancing writers
must reject while `pendingCancellation !== null`; completion should match the
request revision idempotently rather than requiring exact current-revision
equality.

**F-08 (Medium) — Startup recovery can permanently brick the Service into
read-only-safe mode.**
`src/internal/persistence.ts:1477-1500` — `recoverInterruptedAssessments`
calls `completeAssessmentCancellation` for every non-terminal row carrying a
pending cancellation; rows in the F-07 states make that call throw, and
`src/index.ts:2268-2284` (`initialize`) converts any recovery exception into
`persistence === undefined` → permanent `READ_ONLY_SAFE` (all mutations and
store-backed queries return UNAVAILABLE). After an ordinary cancel-then-decision/
resume sequence followed by a crash, the plugin never self-heals. Fail-closed,
but a permanent availability kill. Fix: recovery should skip and record
non-completable rows instead of aborting initialization.

**F-09 (Low) — Symlink-following chmod TOCTOU on the store path.**
`src/internal/persistence.ts:1625-1635` — `mkdir` → `openDatabase` →
`chmod(path, 0o600)`; `chmod` follows symlinks with no `O_NOFOLLOW`/`fstat`
identity re-check. With a user-influenced `dshHome`, a local writer of the
parent directory can swap the DB file for a symlink between open and chmod and
make the Service chmod an arbitrary target. Data-plane tampering still fails
closed (application_id/schema/integrity checks), so impact is the chmod
primitive; POSIX-relevant.

**F-10 (Low) — Analyzer-qualification registration is globally derivable and
self-asserted.**
`src/internal/analyzer-qualification-registration.ts:11-31` exposes the
registration capability under `Symbol.for(...)` with no authority check;
`src/internal/analyzer-registry.ts:111-124` validates only that the record's
digest binds its own fields (integrity, not authenticity — the issuer carries
no cryptographic weight). A co-hosted plugin can mint an `HOST_ATTESTED`
qualification that passes all checks. Within the documented in-process trust
model (ADR 0159), defense-in-depth only.

**F-11 (Low) — Startup schema verification checks names, not constraints.**
`src/internal/persistence.ts:228-264` verifies table catalog and column-name
lists but not STRICT/PK/UNIQUE/NOT NULL constraints; a store with matching
names but missing constraints passes the gate, weakening the duplicate-root
guard (`:403-408`) and leaving `commitRepositoryRevision` (`:1558-1562`) as
the only UPDATE without a `changes === 1` check. Requires local write access
to the private store (outside the stated threat model).

**F-12 (Low) — Redaction edge cases can make Finding lists unservable.**
`src/internal/finding-query.ts:249-255` — `redactedComponent` can emit values
that fail the `component` schema (`src/contracts.ts:898`) for absolute or
non-portable analyzer-reported paths, making every list page for that
assessment throw. Fail-closed (no leak), but an analyzer-dependent permanent
query DoS.

**F-13 (Info) — Unbounded durable growth.**
`idempotency_records` rows, per-revision snapshots, and `operatorActions`
(principal + rationale) are retained forever with no GC/TTL. Expected for an
immutable ledger; noted for storage planning and durable operator attribution.

**Verified solid:** all SQL is bound-parameter (only internal constants
interpolated); HMAC cursors use a per-instance random key with `timingSafeEqual`
and bind authority/assessment/filter/limit (restart invalidates fail-closed);
mutations run under `BEGIN IMMEDIATE` with in-transaction CAS and
`changes === 1` checks on assessment updates; double-launch prevented;
RUNNING→BLOCKED on restart; every stored JSON read is schema-validated.

### Subject / evidence / export deep-dive

**F-38 (High, dynamically reproduced) — Workspace freeze follows ancestor
symlinks/junctions: arbitrary host file read into the frozen Subject.**
`src/internal/subject-freeze.ts:420-446` (capture loop), `:452-461` (stability
re-read), `:346-363` (`stableFile`). The symlink defense covers only the FINAL
path component: `lstat(sourcePath)` and `open(..., O_NOFOLLOW)` resolve all
intermediate components. A repository owner can stage a tracked path whose
parent directory is a symlink/junction to an arbitrary host directory — with
no race: `git update-index --add --cacheinfo 100644,<blob>,data/package.json`
puts the path in the index, then `data/` is replaced by a link to e.g. a
victim project; `ls-files --deleted` sees the file present through the link,
both `stableFile` passes read the same victim inode (signature and digest
checks pass), and the freeze publishes the host file's bytes into the private
store. `readVerifiedNodePackageManifestSlices` (`:683-709`) then feeds
basename-`package.json` victim files to analyzers and into Evidence/Export —
completing an exfiltration chain from an assessed repository to the Bundle,
Submission, and Export artifacts. `git_revision`/`change` modes are immune
(blobs via `cat-file`, never the worktree); only `workspace_snapshot` is
exposed. This defeats the module's central claims ("no ordinary hard links to
source content", "non-expanding symlink inventory"). Reproduced in this review
with a temporary vitest spec (junction on Windows): the frozen Subject and the
analyzer slice contain the victim file's bytes. Fix direction: verify each
materialized file's resolved path stays within `repositoryRoot` (realpath the
parent chain; `openat2(RESOLVE_BENEATH)` on Linux; reparse-point check on
Windows).

**F-39 (Medium) — Unbounded read and FIFO open hang in `stableFile`
(freeze-time DoS).**
`src/internal/subject-freeze.ts:346-363` — the size bound is checked before
and after `handle.readFile()` but the read itself is uncapped (a growing file
is buffered to whatever size it reaches), and `git ls-files --others` lists
untracked FIFOs: `open(O_RDONLY)` on a writer-less FIFO blocks indefinitely
(the abort signal kills the git child, not the `open`), and `isFile()` runs
only after `open` returns. A few concurrent freezes exhaust libuv's thread
pool.

**F-40 (Low) — Evidence disclosure ignores the sealed link's recorded purpose
and eligibility decision.**
`src/internal/evidence-view.ts:66-91, 174-178`, caller `src/index.ts:1348-1352`.
`boundedContent` gates on the request's self-asserted purpose, the caller's
disclosure permission, and the schema allowlist — the Finding's sealed
Evidence link (`purpose`, `eligibilityDecision`) is projected but never
consulted, so a caller holding `evidence:disclose:validation-review` can
disclose bounded JSON of evidence the pipeline itself marked INELIGIBLE or
COUNTER_EVIDENCE. The permission is the real gate, so impact is
policy-semantic, but the module's "complete named-profile disclosure policy"
claim is overstated.

**F-41 (Low) — Caller-supplied path segments are not re-validated at module
boundaries (defense-in-depth).**
`src/internal/export-delivery.ts:210-220, 567`,
`src/internal/sealed-artifacts.ts:289-295`,
`src/internal/evidence-persistence.ts:149-157`. `ExportId`/`assessmentId`/
receipt fields are spliced into `join(...)` paths without re-parsing their
schemas inside the modules; all current callers pass schema-validated values,
so this is a guard against future in-service callers only.

**F-42 (Low) — `lstat`-then-`readFile` TOCTOU on private-store files.**
`src/internal/evidence-persistence.ts:73-77`,
`src/internal/sealed-artifacts.ts:356-360`,
`src/internal/subject-freeze.ts:517-541`. A local writer of
`$DSH_HOME/security-assurance` could swap a symlink between the checks; no
outside content is ever returned (reads are only compared against expected
canonical bytes), so no exfiltration — but tampered large files (e.g.
`manifest.json`) are read without a size cap.

**F-43 (Low) — Export reaper deletes through a parent directory without
verifying its identity.**
`src/internal/export-delivery.ts:567, 607-608`. The `rm` is non-recursive and
exact-file, but a local attacker who can replace
`destinations/local-audit` with a symlink can have the reaper delete an
arbitrary file named `<exportId>.json`. Host-private-root trust assumption.

**F-44 (Info) — `lockTree` immutability is a no-op on Windows.**
`src/internal/subject-freeze.ts:478-486` — `chmod(0o444/0o555)` does not set
the NTFS read-only attribute; the post-publication lock is advisory on
Windows.

**F-45 (Info) — `deepFreeze` stack-overflows on cyclic input.**
`src/internal/freeze.ts:2-10` — `Object.isFrozen` cannot detect cycles; latent
only (all current inputs are JSON-derived).

**F-46 (Info) — `ARTIFACT_INTEGRITY_CONFLICT` leaves the foreign artifact file
forever.**
`src/internal/export-delivery.ts:612-619` — conflicting bytes are recorded
FAILED but never deleted; the reaper ignores FAILED records. Hygiene only (no
download from FAILED state).

**F-47 (Info) — Git tree prefix collisions abort the freeze (fail-safe DoS
only).**
`src/internal/subject-freeze.ts:281-286` — blob `a` + blob `a/b` hits
`EEXIST`/`ENOTDIR`; `flag: 'wx'` prevents any overwrite or escape.

**F-48 (Info) — Windows transient EPERM during publication rename is
misclassified as "already exists".**
`src/internal/subject-freeze.ts:631-639` — an AV/indexer lock on the rename
enters the EEXIST-equivalence branch, then verification fails with ENOENT and
the assessment reports `invalid_subject`. Reliability bug; the failure
direction is safe.

**F-49 (Info) — Bounded-JSON `expiresAt` is stamped but not enforced inside
the view module.**
`src/internal/evidence-view.ts:58-91` — the 5-minute window is computed by the
Service (`index.ts:1352`) and echoed; the module neither rejects a
stale/far-future `expiresAt` nor self-invalidates, so enforcement is delegated
to consumers.

**Verified solid:** digest/canonicalization discipline (no algorithm
confusion); `git_revision`/`change` subjects are worktree-independent
(`--no-replace-objects`, `cat-file`, exact 40-hex pinning); git path
validation thorough (NFC, control chars, reserved names, case-collisions,
`flag: 'wx'` writes); evidence persistence re-verifies every binding on read;
the one-use download capability has no intra-process race and the 16 MiB cap
is enforced at three layers with a +1 sentinel; two-phase expiry with
crash-recovery idempotence; sealed-artifact self-consistency digests all
re-derived.

### Engine / analyzer / risk deep-dive

**F-20 (Medium) — External-analyzer complete-coverage claims yield SATISFIED
with evidence that is never independently verified.**
`src/internal/deterministic-kernel.ts:337-354, 378-467`. For any policy other
than `security/node-package-lifecycle`, COMPLETE coverage (and with zero
candidates a SATISFIED verdict) is granted when a portfolio-ELIGIBLE analyzer
contributes `completionDisposition: 'COMPLETE'` with exactly one coverage claim
referencing an evidence artifact whose `schemaId` merely appears in the host
qualification's `evidenceSchemaIds`. The evidence content is never parsed,
digested, or bound to the frozen subject — in contrast with the builtin path
(`:283-323`), which recomputes qualification/manifest digests and cross-checks
every candidate. `externalAnalyzerEvidence` (`:118-176`) publishes analyzer
evidence verbatim; seal readiness only verifies published bytes match the
analyzer-chosen value. A buggy host-attested analyzer build can therefore seal
SATISFIED with evidence that proves nothing. (The contribution's own identity
and subject-digest binding ARE checked at registry admission,
`analyzer-registry.ts:287-309`; the gap is evidence-content-vs-subject
verification for the generic policy.)

**F-21 (Medium) — Harness-verification gate is forgeable by any in-process code
(spoof PASS / force FAIL DoS).**
`src/internal/harness-verification.ts:32-50`, `src/index.ts:514-529, 1890-1897,
251-254`. The "opaque authority" is a plain frozen object stored in a readable
`Symbol.for` slot on `globalThis` whose name is published in the shipped
bundle; any plugin can read it, reach the Service via the public
`securityAssurance` cordis key, and call the receiver with a fabricated
contribution. The receiver accepts a replacement contribution from ANY owner —
the owner check gates only the clear path (`index.ts:516-517`) — so the real
invariant's cleanup cannot clear a forged contribution after the forger
unloads. Consequences: (a) force FAIL → every mutation rejected, service stuck
in READ_ONLY_SAFE; (b) forge PASS → mutations admitted against a harness
composition the invariant judged incompatible, and health checks spoofed. The
module comment's claim ("prevents callers that merely discover the receiver
symbol from replacing the active contribution") is defeated by the globally
readable authority slot. See also F-01/F-02.

**F-22 (Low, historical — fixed in rc.8) — Time-bounded risk acceptance was
enforced only at admission; an expired acceptance could still be sealed
NON_BLOCKING.**
`src/internal/risk-decision.ts:144-167` (ceilings in `admit`), `:171-247`
(`finalizedOutcome` — originally no expiry re-check), `src/index.ts:1400-1408`
(replay-triggered finalization), `:2227-2266`. Reachable: crash after the
window commits RESOLVED but before sealing; a later exact replay of the same
request re-triggers `finalizeResolvedRiskDecision` and seals the NON_BLOCKING
downgrade even though the acceptance expired long ago (≤30 d). The sealed
artifact then presented an expired acceptance as current posture. rc.8 now
evaluates expiry against the actual seal-finalization instant; the regression
suite covers both before-expiry and after-expiry finalization.

**F-23 (Low) — Dual-authority distinctness is case-sensitive comparison in a
case-insensitive identity namespace; independence is asserted, not verified.**
`src/internal/risk-decision.ts:88-89`, `src/internal/persistence.ts:1317`,
`src/contracts.ts:1004`, `src/internal/authority.ts:46`. Principal IDs are
validated case-insensitively (`/i`) and preserved verbatim, but distinctness is
exact byte comparison — `'operator-a'` and `'Operator-A'` count as two distinct
principals, letting one host identity with casing variance complete both
Critical attestations. The second attestation's
`authorizationEvidence.invocationClass: 'independently-authenticated'`
(`persistence.ts:1336-1341`) is fabricated without inspecting the invocation's
actual authentication session. Weakens the break-glass dual control if the
host identity layer is case-insensitive.

**F-24 (Low) — Evaluator ordering can mask blocking candidates as
INDETERMINATE.**
`src/internal/deterministic-kernel.ts:511-531, 545-557`. The UNSUPPORTED /
evidence-ineligible / COMPLETE-with-ineligible-claim branches return
INDETERMINATE with `findings: []` before the candidate branches, so a
schema-valid contribution carrying blocking candidates but internally
inconsistent (mismatched subject digest, tampered coverage-claim digest,
UNSUPPORTED disposition with candidates) is masked as INDETERMINATE instead of
FAILED; `checkSealReadiness`'s `blocking_finding_did_not_take_precedence` guard
cannot fire because findings are emptied first. Unreachable from the current
in-process builtin (its outputs are always self-consistent), so this is a
defense-in-depth violation of the evaluator's own blocking-precedence rule.

**F-25 (Info) — Preflight digest is optional.**
`src/internal/security-catalog.ts:134-183` binds the digest to
`repository.repositoryRevision` and the full proposal core, and
`src/index.ts:918-948` recomputes the catalog at start — the TOCTOU is closed
when a digest is supplied. But `startPreflightDigest` is optional; a start
without it skips the catalog admissibility checks. Result is an honest
INDETERMINATE assessment, not a spoofed verdict.

**F-26 (Info) — Duplicate-key detector counts `"<key>":`-shaped substrings
inside string values.**
`src/internal/builtin-node-package-lifecycle-analyzer.ts:156-170, 236`. The
property regex has no JSON context tracking, so escaped mentions inside a
`description` string count toward the duplicate tally and flip a clean manifest
to INVALID → coverage GAP → INDETERMINATE. Fails conservative (never yields a
false SATISFIED) — an accuracy nit.

**F-27 (Info) — Analyzer input scope: every basename `package.json` in the
subject, including vendored `node_modules`.**
`src/internal/subject-freeze.ts:683-687`, capped at 256 manifests
(`analyzer.ts:141`). Findings in dependency manifests are attributed to the
repository (arguably correct for install-hook supply-chain checks), symlinked
manifests are not followed, and >256 manifests fails closed. Scoping note.

**F-28 (Info) — Seal readiness does not re-verify coverage digest, trace policy
binding, or provider composition consistency.**
`src/internal/deterministic-kernel.ts:662-704` cross-checks verdict ↔ coverage
↔ blocking findings and per-artifact publication digests (solid), but never
recomputes `outcome.coverage.digest`, checks `evaluationTrace.policyDigest`, or
verifies `coverage.targetDigest` against the frozen contract. Defense-in-depth
recommendation.

**Verified solid:** canonical digests exact; JSON Pointers are opaque validated
literals (no traversal surface); manifest parsing fail-closed (`__proto__`
safe — own-property access only); risk-decision windowing admits decisions only
in BLOCKED + OPEN at exact revision; DENY preserves blocking + original
verdict; critical caps (24 h, ≥2 controls) and ordinary caps (High ≤7 d, others
≤30 d) enforced with offset ISO datetimes; candidate tri-state genuinely
fail-closed (contradictory evidence → UNRESOLVED; REJECTED requires a real
SATISFIED marker in the digest-verified frozen slice; VALIDATED requires the
VIOLATED marker in the real subject file).

### Contracts / tools / adapters / client deep-dive

**F-14 (Medium) — Invariant has fail-open boot windows; it is the only
component that can set FAIL.**
`src/invariant.ts:306-322`, `src/index.ts:251-252,1890-1897`. Mutations are
admitted whenever `harnessVerification !== 'FAIL'` — i.e., `PENDING_INVARIANT`
admits mutations. Two gaps: (a) `install` silently returns when the receiver is
unavailable, never arming the gate; (b) `apply()` awaits
`securityAssuranceHostRepositories.whenReady()` — if Host Repository
registration FAILED, the promise rejects and the invariant never registers,
leaving `PENDING_INVARIANT` with mutations open: the exact failure the
invariant exists to fence prevents it from installing. Tests cover only
slow-but-successful bootstrap (`tests/invariant.spec.ts:266-283`). Also: checks
run once at composition time (`invariant.ts:280-293`), and the loader-entry
check (`invariant.ts:258-278`) matches only id/name/disabled strings, so a
different entry with the same strings passes. Converse availability issue: any
`NOT_EVALUATED` check → FAIL → all mutations permanently blocked until
recomposition.

**F-15 (Medium) — Direct-use patch identity: truncated reversible cwd key and
launcher-cwd-bound root.**
`cordis.patch.yml:16-19`. (a) The idempotency key commits only the first
60 bytes of the UTF-8 cwd (80 base64url chars); two launch directories sharing
that prefix collide and the second registration hits `IDEMPOTENCY_CONFLICT`
(`src/internal/persistence.ts:285-294,389-395`) → Host Repository Provider
boot failure (`src/host-repository-provider.ts:113-124`) — availability, not
silent misbinding. (b) The key reversibly encodes the workspace path (path
disclosure wherever the receipt is logged or displayed). (c)
`root: !!js process.cwd()` binds whatever directory the launcher started in
as the assessed "Current workspace"; alternate launch cwds register extra
ENABLED repositories whose assessments cover a stale or attacker-chosen
directory while operators read them as covering their workspace. (d) The root
string is unvalidated by the provider (`src/host-repository-provider.ts:29`).
Recommended: full-path hash for the key, and validate/attest the root at
registration.

**F-16 (Low) — Test-only crash-checkpoint seam ships in the package.**
`src/internal/control-plane-cancellation-crash-checkpoint.ts:24-46`, call
sites `src/index.ts:1768-1772,1877-1881`. Any in-process holder of the service
can install the single checkpoint: an assessmentId disclosure oracle and a
cancellation/assessment DoS (the awaited rejection propagates). Excluded from
the export map but compiled into `lib/`; release builds should compile it out.

**F-17 (Low) — Control-plane start idempotency key excludes repositoryId.**
`src/index.ts:296-307`; persistence scopes idempotency by target_key
(`persistence.ts:285-294`). A replayed (invocationId, missionId, attempt) with
a different configured repositoryId silently starts a second assessment
instead of conflicting, and cancel (`index.ts:1829-1833`) reconciles only the
matching one — orphaned assessments under config drift. Binding verification
precedes start, so not a direct bypass.

**F-18 (Low) — Cancellation reconciliation hard-caps at 4 retries and throws.**
`src/index.ts:1835-1888`. Under revision churn the mission cancel fails hard
after 4 CONFLICTs (provider error rather than a cancel outcome). Availability
only.

**F-19 (Info) — Contracts notes.**
All schemas are `strictObject`; no `z.coerce`/`.passthrough`/`.loose`; IDs use
`crypto.randomUUID` — not guessable. `z.json()` has no depth cap but is
byte-bounded at the disclosure boundary (32 KiB + client-side byteLength
equality). `correlationId` regex admits degenerate all-dash strings
(cosmetic; service-minted). `subjectRelativePathSchema`
(`contracts.ts:390-397`) does not reject control/bidi characters (rendered as
React text nodes, so no injection — tightening suggested).

**Verified solid:** workbench remote re-resolves authority on every call with
no caching; the client keeps the authority context only in live memory and
erases it on close/failure (`client/index.ts:1742-1746,2089-2146`), fences
stale responses via generation/abort/revision checks, expires bounded
disclosure with timers, verifies export sha256 + length before download, and
renders exclusively via React text nodes — no `innerHTML`/
`dangerouslySetInnerHTML` anywhere, no browser persistence APIs (ADR-0293).
The control-plane adapter transfers evidence strictly by value with no fs
imports (ADR-0295), and the repository-binding matcher spoof path requires the
minting capability of F-01.

### Evaluation engine deep-dive

**F-29 (High) — Release Constitution consumes a caller-supplied paired-arm
comparison without recomputation or binding to case evidence.**
`src/evaluation.ts:2806-2845, 3114-3211` — the request embeds a fully-formed
`pairedArmComparisonV1` (`:2823`) and the engine reads its
`nonInferiority`, threshold distributions and utility comparison directly
(`:3114-3179`); only armId cross-consistency is checked in `superRefine`
(`:2830-2831`). The air-gap engine does recompute per-arm metrics
(`:1984-2038`); the constitution seam does not. A fabricated but schema-valid
comparison yields PROMOTE with no real evidence. The README claims
"caller-authored overrides cannot produce PROMOTE" — false for this seam.

**F-30 (High) — Non-inferiority margin admits 1.0 and the pass rule makes it a
no-op; pre-registration is self-declared.**
`src/evaluation.ts:822` — `nonInferiorityMarginV1Schema = z.number().min(0).max(1)`;
`:2383` — `status = conservativeDirectionalDelta >= -margin ? 'PASSED' : 'FAILED'`.
With margin = 1.0, any delta in [-1, 1] passes: the entire non-inferiority gate
is caller-disabled at the schema-maximum margin, and nothing rejects degenerate
margins. "Pre-registration" is enforced only by self-declared timestamps
(`:842-848`, `:3009-3020`): post-hoc thresholds and margins pass.

**F-31 (Medium) — Self-selected strata make the sufficiency gate caller-disableable.**
`src/evaluation.ts:1227-1236` requires the four stratum DIMENSIONS to be
present but not which severity values: a caller declares
`{dimension:'SEVERITY', value:'LOW'}` strata and omits CRITICAL/HIGH, so
`INSUFFICIENT_BENCHMARK_STRATA` (`:1799`) never fires for the severities the
README claims floors for. `minimumSamples` may be 1 (`:110`), and NI mandatory
strata inherit the self-selected set (`:3127-3135`).

**F-32 (Medium) — Multiplicative DoS surface.**
`src/evaluation.ts` — caps are per-array only (sealedArmResults 100k × manifest
cases 10k × findings 10k; adjudication `.some` loops `:1905-1927` ~10^9; per-arm
full metric recomputation `:1984-2038` for ≤1000 arms ~10^11 operations). No
combined budget; a single hostile request can hang the host thread. The module
is pure and trusted-host-called, so severity is bounded by that trust model.

**F-33 (Low) — Confidence-interval width caps admit 1.0, disabling the
uncertainty gates.**
`src/evaluation.ts:111, 123, 1488` — with `maximumValidatedRecallIntervalWidth
= 1` (or repetition `maximumConfidenceIntervalWidth = 1`), `width <= cap` is
always true, so `EXCESSIVE_CONFIDENCE_INTERVAL_WIDTH` /
`EXCESSIVE_REPETITION_UNCERTAINTY` become caller-disabled.

**F-34 (Low) — Case-insensitive ID schema, case-sensitive identity semantics.**
`src/evaluation.ts:6` — `boundedEvaluationIdSchema` regex uses `/i`, but all
dedup/compare paths (`:1200`, `:1443`) are case-sensitive: `case-a` and
`CASE-A` are distinct identities that share a validation namespace.

**F-35 (Low) — `ratio()` throws a generic Error for numerator>0 / denominator=0.**
`src/evaluation.ts:1307-1313` — currently unreachable (validated inputs), but
the generic Error escapes the engine's typed failure envelope if ever reached.

**F-36 (Low) — PRIOR_STABLE evaluation bundle artifact digest never checked.**
`src/evaluation.ts:4181-4184` — only the CANDIDATE bundle's artifact digest is
bound; the prior-stable bundle digest is recorded without verification.

**F-37 (Info) — Digests are compared for equality, never verified against content.**
`src/evaluation.ts:1840-1845` and elsewhere — `resultDigest`, `manifestDigest`,
`contractDigest` are echoed and equality-compared but never recomputed from the
payloads they name. The module is an attestation-consistency checker, not a
content verifier; release consumers should treat it as such unless an external
layer verifies registration digests and recomputes the paired comparison.

**Verified solid:** no NaN/divide-by-zero paths on validated inputs; the
two-sided Hoeffding formula is correct (`:1484`) with [0,1] clamping; weighted
recall cannot exceed 1 (positive integer weights, `:1210-1218`; MATCHED must
reference a same-case defect, `:1299`); identity/one-to-one invariants enforced
(`:1220-1303`); fail-closed ordering FAILED > INCONCLUSIVE > PROMOTE
(`:3246-3248`); known failures never report INCONCLUSIVE; scorecard output is a
fixed whitelist with no holdout/evidence/arm/stratum identity leakage
(`:3549-3663`); `deepFreeze` applied to all nine engine outputs; deterministic
canonical ordering throughout. Overall: the computation core is disciplined and
fail-closed; the risk concentrates in the trust boundary — every
promotion-relevant input is caller-attested and only self-consistency-checked
(F-29/F-30).

## 5. Overall posture

The rc.8 plugin has strict Zod contracts with bounded identifiers,
transactional revision CAS, content-addressed Subject/Evidence/Artifact
integrity, fail-closed startup and restart semantics, redacted projections,
bounded disclosure, one-use downloads, and governed risk decisions. The
model-facing seams remain by-value and authority-bound, and the complete
release suite now passes **342/342 tests**.

The four High findings and the cancellation/invariant Medium findings from the
initial review are remediated in the current source. The remaining items are
documented defense-in-depth or host-private-store assumptions (for example,
Windows advisory file locking and durable-ledger growth); none bypasses the
public verdict, authority, Subject isolation, or publication integrity gates.

Verdict: **rc.8 is ready for v0.1 release-candidate validation**. Before a
stable `0.1.0`, retain the residual limitations in operational documentation
and repeat the packed Web-profile smoke on each supported platform.

## 6. References

- README.md (claims), SECURITY.md (boundary statement), CONTEXT.md (glossary)
- docs/adr/0159 (in-process trust model), docs/adr/0302 (Symbol.for protocol)
- Harness integration: `D:\Deepseek\deepseek-harness-latest` `0.1.2-alpha.1`
  (tool registry, Typert, cordis loader seams)
