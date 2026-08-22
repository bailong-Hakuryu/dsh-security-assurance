# DSH Security Assurance

DSH Security Assurance is an independent application-security context spanning read-only assessment, governed remediation, and governed delivery. It can operate on its own and can contribute security assurance to an Engineering Control Plane Mission without owning that Mission's engineering approval.

## Language

**Security Assessment**:
A bounded evaluation of a declared Assessment Subject against an explicit security policy and scope, producing reproducible Security Evidence, Assessment Coverage, and a Security Verdict.
_Avoid_: Mission, generic scan, security approval

**Assessment Engine**:
The single authority that executes and recovers Security Assessments for both standalone and Control Plane Provider entry points.
_Avoid_: CLI workflow, Provider-specific pipeline, scanner

**Security Assessment Kernel**:
The read-only deep module that owns Security Assessment state, Evidence acceptance, coverage reconciliation, Policy evaluation, and Assessment sealing without owning remediation or external delivery effects.
_Avoid_: Security Remediation Workflow, Security Delivery Workflow, Mission Kernel

**Security Assurance Plugin Boundary**:
The independent installable boundary through which Security Assurance uses only public Harness Services, events, tools, Remote, Client slots, and bundle composition without modifying Harness Core or copying Harness source into the product.
_Avoid_: Harness fork, agent-loop patch, vendored Harness subsystem

**Security Service**:
The sole public mutation boundary `ctx.securityAssurance`, exposing explicit typed Assessment, Remediation, and Delivery commands and queries while keeping every Store adapter and Kernel mutation private.
_Avoid_: Workbench Store access, generic execute action, multiple mutation authorities

**Assessment State**:
The operational condition `CREATED`, `RUNNING`, `BLOCKED`, `SEALED`, or `CANCELED` of a Security Assessment, kept separate from its Security Verdict.
_Avoid_: Security Verdict, process status, finding outcome

**Assessment Receipt**:
The durable acknowledgement that an Assessment command committed, carrying its opaque Assessment identity, resulting revision, and accepted state without transferring ownership of the continuing Engine run to the caller.
_Avoid_: Live process handle, Security Verdict, tool-call result ownership

**Assessment Revision**:
The monotonically increasing committed version used with expected-revision comparison to reject stale Assessment mutations and reconstruct exact Workbench views.
_Avoid_: Database row version, timestamp, Provider version

**Assessment Execution Lease**:
The time-bounded, fencing-token-protected authority allowing one process to advance one Assessment while other processes may continue reading committed revisions.
_Avoid_: Database lock, Workbench ownership, silent recovery permission

**Assessment Workflow**:
The durable dependency graph that turns Subject Inventory, threat analysis, discovery, validation, attack-path analysis, coverage reconciliation, and policy evaluation into an Assessment Seal.
_Avoid_: One agent conversation, scanner command sequence, Codex workflow copy

**Assessment Mode**:
The Policy-governed declaration that an Assessment covers a complete repository, an exact change, or an explicit target without implying broader coverage than its Subject and Scope support.
_Avoid_: Prompt wording, scan depth, arbitrary path list

**Assessment Profile**:
The frozen Standard or Deep execution strategy that sets independent analysis breadth, convergence criteria, concurrency, and budgets without changing Security Policy or Verdict meaning.
_Avoid_: Assessment Mode, Security Policy, reasoning effort alone

**Supported Ecosystem**:
A language and runtime environment for which the product has a tested Analyzer set and complete declared Coverage Contracts rather than relying only on generic model understanding.
_Avoid_: File extension recognition, best-effort analysis, universal language support

**Assessment Control Surface**:
The standalone operations for starting, observing, resuming, canceling, and explicitly exporting a Security Assessment without introducing a Mission or Quality Gate.
_Avoid_: Mission tools, scanner CLI, second Assessment Engine

**Assessment Subject**:
The immutable codebase revision, change set, or sealed worktree snapshot whose security properties are being evaluated.
_Avoid_: Repository name alone, live working directory, unspecified target

**Git Revision Subject**:
An Assessment Subject identified by an exact repository object and materialized from committed Git content without reading later working-tree changes.
_Avoid_: Branch name, current HEAD, live checkout

**Change Subject**:
An Assessment Subject binding an exact base, resulting revision or frozen workspace state, declared diff, and materialized resulting tree for Change Impact Cone analysis.
_Avoid_: Diff text alone, pull-request number, moving branch

**Workspace Snapshot Subject**:
An Assessment Subject explicitly capturing the current tracked and permitted untracked workspace bytes before analysis, independent of later workspace mutation.
_Avoid_: Live workspace, implicit dirty tree, temporary scan path

**Subject Snapshot**:
The plugin-private read-only materialization consumed by every Analyzer, created through copy, reflink, or archive extraction and never through an ordinary mutable hard link to the source workspace.
_Avoid_: Working directory, Evidence export, analyzer cache

**Subject Manifest**:
The canonical content-addressed inventory binding relative paths, byte digests, file modes, link metadata, sub-Subjects, exclusions, and the root digest of a Subject Snapshot.
_Avoid_: Directory listing, Git status, archive index alone

**Assessment Scope**:
The declared boundaries, policy obligations, and exclusions that determine what one Security Assessment claims to evaluate.
_Avoid_: Whole system by implication, scanner defaults, informal checklist

**Assessment Coverage**:
The Evidence-backed account of which declared security obligations and subject boundaries were evaluated, which were not, and why.
_Avoid_: Number of scans, zero findings, tool success

**Subject Inventory**:
The Evidence-backed description of security-relevant components and boundaries present in an Assessment Subject from which mandatory coverage is derived.
_Avoid_: Directory listing, model guess, scanner target list

**Coverage Plan**:
The frozen set of security obligations and Subject boundaries whose eligible Coverage Claims are required before a Security Verdict can be satisfied.
_Avoid_: Analyzer checklist, coverage percentage, optional suggestions

**Security Policy**:
The versioned, host-selected set of mandatory security obligations and verdict rules frozen for one Security Assessment; permitted repository policy may strengthen but never weaken its baseline.
_Avoid_: Model-generated checklist, scanner defaults, mutable configuration

**Baseline Policy Profile**:
The default Policy mapping that blocks Critical and High Findings, conditionally blocks security-significant Medium Findings, reports lower severities, and treats material unresolved candidates as indeterminate.
_Avoid_: Strict Policy Profile, severity score alone, permissive mode

**Strict Policy Profile**:
The strengthened Policy mapping that makes every validated Medium-or-higher Finding blocking without changing its Technical Severity.
_Avoid_: Baseline Policy Profile, Deep Assessment Profile, zero-tolerance marketing

**Threat Model**:
The Evidence-backed account of protected assets, trust boundaries, entry points, attacker capabilities, and abuse paths relevant to an Assessment Subject and Scope.
_Avoid_: Generic threat list, model brainstorm, Finding report

**Security Role Agent**:
A governed specialist that contributes threat, discovery, validation, or attack-path analysis within the Assessment Workflow without owning Security Policy or Verdict authority.
_Avoid_: Assessment Engine, Policy Evaluator, free-form subagent

**Analyzer Registry**:
The startup-composed, versioned catalog of eligible Analyzers and their supported modes, coverage dimensions, Evidence contracts, budgets, and runtime conditions.
_Avoid_: Dynamic tool discovery, installed executables, model-selected plugin list

**Analyzer Portfolio**:
The frozen set of complementary deterministic, process, agent, and external Analyzers selected to satisfy one Coverage Plan rather than treating any single technique as complete security analysis.
_Avoid_: Analyzer Registry, scanner list, model roster

**Analyzer Execution Class**:
The frozen trust and mechanism category governing which capabilities, isolation probes, Evidence contracts, and verdict eligibility apply to an Analyzer.
_Avoid_: Technical Severity, Assessment Profile, Provider name

**Pure Analyzer**:
A trusted deterministic Analyzer that receives only bounded immutable data and capability objects, starts no process, performs no network action, and invokes no model.
_Avoid_: In-process arbitrary plugin, static scanner process, Security Role Agent

**Constrained Process Analyzer**:
A trusted registered Analyzer executed with structured argv, a scrubbed environment, read-only Subject access, bounded output and time, process-tree cleanup, and a probed confinement contract without executing Subject code.
_Avoid_: Arbitrary shell, repository lifecycle script, unqualified scanner binary

**Execution Backend Probe**:
The startup and pre-run Evidence establishing which filesystem, process, network, isolation, and cleanup guarantees an execution backend can actually enforce on the current host.
_Avoid_: Configuration claim, operating-system name, successful command

**Verdict-eligible Analyzer**:
An Analyzer whose frozen execution class, Provider identity, Backend Probe, Evidence Contract, Coverage Contract, and Data Egress Contract satisfy Policy for contributing to Security Verdict and Assurance Submission.
_Avoid_: Registered Analyzer, Advisory Finding source, successful Analyzer Run

**Analyzer Run**:
One bounded execution that contributes Findings, Coverage Claims, and Security Evidence to a Security Assessment without deciding its Security Verdict.
_Avoid_: Security Assessment, Verdict, successful process

**Analyzer Attempt**:
One durable, budget-charged execution attempt for an Analyzer Run whose failure and outputs are retained rather than overwritten by a retry.
_Avoid_: Silent retry, process id, replacement Assessment

**Coverage Claim**:
An Evidence-backed statement that one declared part of the Assessment Scope was evaluated, not evaluated, or only partially evaluated.
_Avoid_: Analyzer success, confidence score, implied coverage

**Change Impact Cone**:
The Evidence-backed expansion from an exact change into security-relevant callers, callees, entry points, trust boundaries, permissions, dependencies, configuration, and tests that may be affected.
_Avoid_: Diff lines alone, whole repository by default, model intuition

**Policy Evaluator**:
The deterministic authority that derives a Security Verdict from the frozen Security Policy, eligible Findings, Assessment Coverage, and operational state.
_Avoid_: Analyzer, security agent opinion, Quality Gate

**Security Remediation Proposal**:
A non-authoritative description of a possible correction for a Finding that never modifies the Assessment Subject or serves as proof that the Finding is resolved.
_Avoid_: Applied fix, Rework Attempt, automatic remediation

**Security Remediation Workflow**:
The separately authorized deep module that turns one accepted Security Finding into a bounded Patch Artifact and verification Evidence while preserving the original Assessment Subject and Verdict.
_Avoid_: Assessment phase, automatic fix, Finding closure

**Patch Artifact**:
An immutable digest-bound proposed change generated in private staging for one Remediation Case and exact source Subject, requiring separate authorization before application.
_Avoid_: Working-tree edit, Security Remediation Proposal, applied fix

**Remediation Authority**:
Host-derived authorization to apply one exact Patch Artifact to one compatible target workspace, never implied by Assessment, Finding, or general write access.
_Avoid_: Model approval, Risk Acceptance, Repository path possession

**Fix Verification**:
The Evidence-backed evaluation of a patched immutable Subject against the original defect, safe reproducer, regression behavior, nearby bypasses, Change Impact Cone, and relevant repository tests.
_Avoid_: Patch applied, Finding closed, test command success alone

**Finding Resolution**:
The cross-Assessment conclusion that a new sealed Subject no longer exhibits a prior Security Finding under eligible Fix Verification, represented through Finding Lineage rather than mutation of the original Finding.
_Avoid_: Patch application, manual close, deleted Finding

**Security Delivery Workflow**:
The separately authorized deep module that derives reports, hardening guidance, portable exports, or approval-gated external tracking payloads from sealed security records without changing their meaning.
_Avoid_: Assessment Seal, Quality Gate, unreviewed external write

**Security Capability Envelope**:
The publicly documented Codex Security workflow breadth used as a functional reference for DSH-owned assessment, remediation, delivery, workbench, CLI, SDK, batch, and CI capabilities without copying private implementation or authority boundaries.
_Avoid_: Codex runtime dependency, feature clone, Assessment Scope

**Candidate Finding**:
A plausible security defect awaiting Validation and therefore unable by itself to become a confirmed Security Finding or failed Verdict.
_Avoid_: Security Finding, scanner alert, confirmed vulnerability

**Security Finding**:
A Candidate Finding validated under an eligible Evidence Contract and retained with its affected Subject, weakness, path, impact, severity, confidence, and remediation Evidence.
_Avoid_: Candidate Finding, Review Finding, unverified alert

**Finding Fingerprint**:
The deterministic normalized identity of one Finding's weakness, affected control or sink, path, location, and proof within an Assessment, independent of a scanner-assigned identifier.
_Avoid_: File and line alone, issue number, fuzzy similarity score

**Finding Lineage**:
An Evidence-backed relationship between Findings across immutable Subjects recording persistence, resolution, reintroduction, or unresolved correspondence without rewriting either Assessment.
_Avoid_: Finding Fingerprint, automatic fuzzy deduplication, mutable Finding id

**Rejected Candidate**:
A Candidate Finding whose claimed defect, path, or impact is contradicted by retained validation Evidence and an explicit rejection reason.
_Avoid_: Deleted alert, ignored Finding, Risk Acceptance

**Unresolved Candidate**:
A Candidate Finding for which required validation could not establish or reject the claimed defect; material unresolved candidates prevent a satisfied Verdict when Policy requires resolution.
_Avoid_: Rejected Candidate, Security Finding, low confidence dismissal

**Validation Contract**:
The versioned weakness-specific rules for eligible proof, negative controls, safe reproduction, independence, and permitted Proof Gaps required to validate or reject a Candidate Finding.
_Avoid_: Model confidence threshold, scanner alert, informal reviewer judgment

**Proof Gap**:
An explicit Evidence-backed limit on what validation or fix verification could safely or practically establish, preserved rather than inferred away.
_Avoid_: Missing note, automatic rejection, assumed safety

**Safe Reproducer**:
A minimal validation procedure constrained to an isolated Subject, synthetic data, bounded resources, and Policy-permitted effects without reaching production systems or real credentials.
_Avoid_: Live exploit, destructive test, proof by assertion

**Attack Path**:
An Evidence-backed graph connecting entry conditions, attacker capabilities, trust boundaries, control bypasses, dangerous sinks, and impact for one Candidate or Security Finding.
_Avoid_: Exploit narrative, severity label, generic threat scenario

**Remediation Case**:
The bounded workflow record for one primary validated Security Finding and any explicitly linked same-root-cause Findings, preserving separate validation and closure for every Finding.
_Avoid_: Batch fix, Rework Attempt, Security Assessment

**Hardening Portfolio**:
An Evidence-backed set of structural security options, tradeoffs, architectural deltas, migration steps, and implementation handoffs that neither modifies the Subject nor closes Findings.
_Avoid_: Applied remediation, generic best practices, Security Verdict

**Security Evidence**:
The reproducible, attributable records supporting a Security Verdict for one Assessment Subject and Assessment Scope.
_Avoid_: Unbound report, model confidence, prose conclusion

**Security Verdict**:
The fail-closed `SATISFIED`, `FAILED`, or `INDETERMINATE` conclusion of one Security Assessment; it is not an Engineering Control Plane Mission approval or Quality Gate decision.
_Avoid_: Approved, Assurance Result, scan completion, security score

**Assessment Seal**:
The immutable integrity record binding a sealed Assessment's Subject, Scope, Policy, Provider Composition, workflow outputs, coverage, Evidence, Findings, and Security Verdict.
_Avoid_: Report, archive file, successful completion flag

**Canonical Assessment Bundle**:
The schema-versioned, manifest-sealed collection of machine records for Subject, Policy, Threat Model, Coverage, Findings, Verdict, provenance, and every referenced Evidence artifact.
_Avoid_: report.md, exported issue, loose scan directory

**Normalized Bundle View**:
A derived, provenance-bound representation of an immutable older Bundle in a reader-supported schema without rewriting its original records or Verdict.
_Avoid_: In-place migration, canonical replacement, lossy import

**Technical Severity**:
The normalized `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, or `INFORMATIONAL` Evidence-backed impact and exploitability of a Finding, independent of confidence and the current Policy's blocking rules.
_Avoid_: Confidence, priority, Policy Significance

**Evidence Confidence**:
The strength and reproducibility of the Evidence supporting a security observation, independent of its potential impact.
_Avoid_: Technical Severity, model confidence alone, Policy Significance

**Policy Significance**:
The deterministic treatment of a Finding as blocking, non-blocking, or advisory under one frozen Security Policy.
_Avoid_: Technical Severity, scanner priority, reviewer preference

**Risk Acceptance**:
An authorized, immutable, reasoned, and expiry-bound decision that may alter a Finding's Policy Significance for an exact Subject and Scope without deleting the Finding or changing its Technical Severity.
_Avoid_: Analyzer suppression, model waiver, false positive

**Break-glass Risk Acceptance**:
A separately enabled exceptional decision for otherwise non-acceptable Critical risk requiring distinct authorities, compensating controls, rationale, and tightly bounded expiry.
_Avoid_: Ordinary Risk Acceptance, emergency model choice, permanent waiver

**Security Evidence Store**:
The plugin-owned authority for durable Security Assessment records and Evidence, kept outside the Assessment Subject unless a user explicitly exports a copy.
_Avoid_: Target repository, terminal output, Control Plane database

**Sensitive Evidence**:
Security Evidence whose source content, vulnerability detail, identity, or operational data requires restricted disclosure and protected storage even when it contains no raw secret value.
_Avoid_: Raw credential, public report, all metadata

**Evidence Protection Policy**:
The host-selected requirements for Evidence access, redaction, encryption, key availability, export, and failure behavior throughout its retained lifetime.
_Avoid_: Filesystem permission alone, Data Egress Contract, Retention Policy

**Evidence Key Provider**:
The explicitly configured capability that supplies or unwraps encryption keys for Sensitive Evidence without storing plaintext key material in the Security database.
_Avoid_: Auto-generated database key, model credential, fixed operating-system dependency

**Read-only Safe Mode**:
The fail-closed Service condition that permits bounded metadata inspection but rejects new or mutating operations when Store integrity, schema, Key Provider, or another mandatory startup dependency cannot be proven safe.
_Avoid_: Degraded write mode, automatic repair, ignored startup warning

**Retention Policy**:
The host-selected lifetime, legal hold, and authorized deletion rules for Security records and encrypted Evidence payloads.
_Avoid_: Cache eviction, repository cleanup, Evidence Protection Policy

**Evidence Tombstone**:
The minimal retained identity, digest, deletion authority, time, and reason proving that an expired Evidence payload was deliberately removed without pretending it never existed.
_Avoid_: Empty artifact, deleted Assessment, Evidence View

**Assurance Submission**:
An immutable, digest-bound export of a Security Assessment's subject, policy, coverage, Findings, Verdict, Evidence references, and provenance for validation by an external assurance consumer.
_Avoid_: Shared database row, report path, Quality Gate decision

**Assurance Provider Capability**:
A non-authorizing declaration of the Assurance Requirements, assessment modes, Evidence contracts, coverage dimensions, resource needs, and backend conditions a Provider supports.
_Avoid_: Execution Capability, permission, marketing feature list

**Assurance Execution Context**:
The bounded environment through which a Provider may read its immutable Subject, write private staging artifacts, and request policy-mediated process or network actions.
_Avoid_: Host filesystem access, arbitrary shell, Provider-owned authorization

**Provider Composition**:
The integrity-bound identity of the Provider package, implementation, capability descriptor, schemas, backend adapter, analyzers, rules, models, prompts, and execution lineage used by a Security Assessment.
_Avoid_: Package version alone, display name, latest backend

**Advisory Finding**:
A security observation from a backend whose execution, identity, coverage, or Evidence cannot satisfy the frozen Policy; it may inform users but cannot support a Gate-bearing Assurance Submission.
_Avoid_: Validated Finding, blocking result, ignored result

**Data Egress Contract**:
The frozen declaration of what source and Evidence categories an Analyzer may disclose to which external destination and for what assessment purpose.
_Avoid_: General network permission, privacy policy link, Analyzer discretion

**Source Slice**:
The smallest purpose-bound, redacted, digest-recorded subset of Subject content disclosed to one governed model or external Analyzer under a frozen Data Egress Contract.
_Avoid_: Repository upload, arbitrary context window, untracked prompt attachment

**Repository Content Boundary**:
The invariant that every Subject byte, comment, document, filename, generated text, and Analyzer-discovered instruction is untrusted data and can never register capabilities, weaken Policy, or alter Security Role instructions.
_Avoid_: Prompt trust, repository-owned Analyzer, documentation authority

**Dependency Advisory Snapshot**:
The signed, versioned, locally available vulnerability intelligence dataset explicitly updated outside an Assessment and digest-frozen into Provider Composition for reproducible dependency analysis.
_Avoid_: Live latest API, package-manager warning, unversioned cache

**Export Profile**:
The versioned field and redaction contract for producing Internal, Team, or Public portable Views from sealed security records for a declared audience and purpose.
_Avoid_: Canonical Assessment Bundle, ad hoc model summary, destination permission

**Assessment Evidence Reuse**:
The explicit incorporation of prior Security Evidence after its contract verifies Subject lineage, content identity, Policy, Provider Composition, schema, validity period, and impact compatibility.
_Avoid_: Cache hit, same path, copied report

**Tracking Operation**:
A single destination-specific, duplicate-aware, explicitly authorized external write prepared from selected sealed Findings and completed with a durable external receipt.
_Avoid_: Automatic issue creation, export, general network permission

**Security Workbench**:
The local projection and control surface for repositories, Assessments, Findings, remediation, and delivery that uses the same public service contract as every other product surface.
_Avoid_: Second state machine, direct Store editor, chat transcript

**Security Remote Contract**:
The package-owned generated Typert projection through which the Workbench invokes authorized Security Service operations and waits for revision changes without extending Harness's central API or exposing Store access.
_Avoid_: Direct SQLite API, ad hoc REST mirror, browser-side mutation authority

**Capability Conformance**:
The deterministic proof program showing that product commands, state transitions, Policy, authorization, Evidence, recovery, and artifact contracts behave as specified.
_Avoid_: Security Effectiveness, product demo, live-model anecdote

**Security Effectiveness**:
The independently grounded proof program measuring whether the product discovers, validates, prioritizes, and helps resolve real security defects with controlled misses, false positives, and operating cost.
_Avoid_: Capability Conformance, scan completed, user satisfaction alone

## Product Proof

**Ground Truth Manifest**:
The sealed Evaluation-only record of hidden defects, safe controls, expected coverage, acceptable proof, and adjudicated outcomes that is inaccessible to the product under evaluation.
_Avoid_: Scan input, repository guidance, Codex Security output

**Corpus Lane**:
A versioned class of Benchmark Subjects serving deterministic micro-fixtures, realistically seeded defects, historical vulnerable/fixed pairs, or clean negative controls.
_Avoid_: Random repository collection, Evaluation Arm, one demo project

**Development Corpus**:
The visible Benchmark partition used for implementation, prompt, Analyzer, and Policy development without contributing release-holdout proof.
_Avoid_: Qualification Corpus, Release Holdout, training claim

**Qualification Corpus**:
The Benchmark partition hidden during an Evaluation Run and used for milestone evidence, then retired from that role when its Ground Truth is exposed for tuning.
_Avoid_: Development Corpus, Release Holdout, permanent secret set

**Release Holdout**:
The access-controlled Benchmark partition never used for product tuning and reserved for pre-registered RC-to-stable effectiveness proof until exposure requires rotation.
_Avoid_: Qualification Corpus, private demo, reusable failed exam

**Evaluation Arm**:
A frozen product, model, Analyzer, Policy, Profile, budget, and tool configuration run against the same Benchmark case for comparative evidence.
_Avoid_: Individual Analyzer Run, cherry-picked result, product version alone

**Matched-budget Comparison**:
The Evaluation view comparing Arms under equivalent cost or execution budgets alongside their native-profile results.
_Avoid_: Equal wall-clock assumption, native-profile comparison alone, cheapest run

**Validated Recall**:
The proportion of Ground Truth defects correctly surfaced as validated Security Findings, reported both for Critical/High defects and with frozen severity weights.
_Avoid_: Candidate count, raw scanner recall, number of Findings

**Validated Precision**:
The proportion of reported validated Security Findings confirmed by independent Ground Truth adjudication.
_Avoid_: Model confidence, candidate precision, reviewer acceptance alone

**Unsafe Satisfaction Rate**:
The proportion of Assessments returning `SATISFIED` despite a hidden Policy-blocking Ground Truth defect.
_Avoid_: False-negative count alone, failed scan rate, Unsafe Approval Rate

**Coverage Honesty Rate**:
The proportion of incomplete or unsupported Benchmark cases for which the product avoids false satisfaction and accurately records missing coverage or indeterminacy.
_Avoid_: Coverage percentage, successful Analyzer rate, recall

**Product Utility**:
The comparative reduction in validated security risk and human decision effort relative to elapsed time, execution cost, remediation success, and unnecessary rework.
_Avoid_: User satisfaction alone, Finding count, token use alone

**Benchmark Profile**:
The pre-run frozen repetitions, randomness, budgets, scoring, convergence, and failure treatment used to evaluate one set of Evaluation Arms.
_Avoid_: Assessment Profile, post-run tuning, best-run selection

**Finding Matching Contract**:
The pre-run rules mapping one reported Finding to at most one Ground Truth defect using weakness, control or sink, path, impact, and Subject rather than exact line number or post-hoc judgment.
_Avoid_: Finding Fingerprint, fuzzy deduplication, partial-credit intuition

**Adjudication Record**:
The durable blinded judgments, Evidence, identities, disagreement, and tie-break outcome establishing whether a reported Finding matches Ground Truth.
_Avoid_: Model vote, Finding status, reviewer chat

**Benchmark Sufficiency**:
The predeclared minimum support and uncertainty bounds required in each severity, weakness, mode, and ecosystem stratum before an Evaluation can yield a passing conclusion.
_Avoid_: Aggregate case count, average score alone, Benchmark completeness claim

**Moving Provider**:
A model or backend whose exact deployment cannot be pinned and whose qualification Evidence therefore expires and must be refreshed for each release claim.
_Avoid_: Provider Composition, unavailable Provider, compatible version range

**Bridge Run**:
A controlled Evaluation that runs representative identical Arms across two Benchmark major versions to characterize comparability without pretending their scores are identical measures.
_Avoid_: Benchmark migration, score conversion, ordinary regression run

**Evaluation Budget**:
The frozen wall time, model, Analyzer, compute, storage, network, and human-adjudication limits charged to one Evaluation Arm as part of its measured result.
_Avoid_: Assessment Budget, unreported cost, billing total alone

**Benchmark Leakage**:
Any path by which an Evaluation Arm receives hidden Ground Truth, seed identity, expected Finding, or benchmark-specific hints unavailable in normal product use.
_Avoid_: Public security guidance, legitimate Subject context, discovered Evidence

**Capability Conformance Test Kit**:
The reusable deterministic contract suite for product commands, state machines, authorization, Policy, Evidence, recovery, storage, artifacts, Providers, and packed Harness behavior.
_Avoid_: Benchmark Corpus, unit tests alone, manual checklist

**Adversarial Repository Fixture**:
A hostile Subject designed to test whether repository-controlled content can inject instructions, escape paths, forge Evidence, weaken Policy, exhaust resources, or corrupt remediation and delivery behavior.
_Avoid_: Vulnerability seed, ordinary negative control, penetration test target

**Evaluation Run Bundle**:
The immutable artifact binding Corpus and Ground Truth versions, Evaluation Arm configuration, inputs, raw results, matching, adjudication, metrics, cost, and failures for one reproducible experiment.
_Avoid_: Final score, screenshot, Assessment Bundle

**Dogfood Assessment**:
A real Assessment of DSH-owned code used for operational feedback and discovery whose confirmed Findings may block release but whose unknown Ground Truth cannot establish Security Effectiveness.
_Avoid_: Release Holdout, demonstration, ordinary customer scan

**Release Constitution**:
The versioned, pre-registered hard safety floors, statistical thresholds, regression rules, evidence requirements, and promotion constraints governing one product release line.
_Avoid_: Release checklist, Benchmark Profile, post-run judgment

**Hard Safety Floor**:
A non-negotiable Release condition covering complete Conformance, action and disclosure containment, Evidence integrity, Critical Unsafe Satisfaction, and Benchmark Leakage independently of aggregate Effectiveness.
_Avoid_: Statistical Release Threshold, aspirational target, average score

**Statistical Release Threshold**:
A Development- and Qualification-calibrated Effectiveness or Utility requirement frozen before Release Holdout access.
_Avoid_: Hard Safety Floor, post-Holdout target, one-run score

**Retired Holdout**:
A former Qualification or Release partition whose Ground Truth or performance has influenced product changes and therefore can no longer establish future release generalization.
_Avoid_: Development Corpus deletion, failed Case, active Holdout

**Non-inferiority Margin**:
The pre-registered maximum permitted regression against the previous stable release for each mandatory safety and Effectiveness stratum.
_Avoid_: Aggregate improvement, tolerance chosen after results, confidence interval

**Security Support Matrix**:
The versioned product statement of operating systems, ecosystems, Harness versions, Assessment Modes, Profiles, Providers, and Analyzer limitations backed by release Evidence.
_Avoid_: Package compatibility range, README feature list, best effort

**Support Claim**:
A public security capability statement bound to an exact Support Matrix, Policy, Benchmark, Corpus, Provider, measured Effectiveness, cost, uncertainty, and known limitations.
_Avoid_: Security guarantee, marketing slogan, scan result

**Security Telemetry**:
Explicitly opted-in aggregate operational measurements that exclude source, paths, Findings, Evidence, credentials, and Ground Truth.
_Avoid_: Evaluation Run Bundle, scan upload, default analytics

**Security Scorecard**:
The audience-safe published View of release Evaluation methods, versions, Corpus statistics, metrics, uncertainty, budgets, limitations, and failures without exposing active Holdout answers or Sensitive Evidence.
_Avoid_: Evaluation Run Bundle, passing badge, Ground Truth export

**Security Principal**:
The identity of a human, agent session, or governed service derived from a trusted Host channel; identity alone grants no action.
_Avoid_: Caller-supplied username, model persona, Security Authority

**Security Authority**:
The exact actions, Repository scope, disclosure scope, constraints, and expiry granted to a Security Principal by the Host.
_Avoid_: Role label alone, self-declared permission, Decision Authority

**Security Authority Resolver**:
The fail-closed Host boundary that maps an authenticated Workbench operator, exact Harness session, or Kernel-issued invocation context to a Security Principal and Security Authority.
_Avoid_: Request-body authorization, repository configuration, model judgment

**Repository Registry**:
The Host-owned mapping from stable Repository IDs to canonical roots and their Policy, Evidence, Egress, Profile, and platform bindings.
_Avoid_: Filesystem discovery, caller path, package manifest

**Repository Registration**:
A separately authorized administrative change that adds or revises one Repository Registry entry and its security bindings.
_Avoid_: Assessment start, opening a folder, Subject snapshot

**Assessment Command**:
A typed, authorized, idempotent state-changing request executed only through the Security Service against an expected revision.
_Avoid_: Assessment Store write, generic execute, Analyzer result

**Assessment Query**:
A typed, authorized, bounded read projection produced by the Security Service with disclosure and pagination controls.
_Avoid_: Raw Store access, SQL, unrestricted Evidence dump

**Resume Contract**:
The rule that resume retains the frozen Subject, Policy, Coverage Plan, Provider Composition, and Assessment Budget while creating new Attempts only for incomplete eligible work.
_Avoid_: New Assessment, configuration migration, silent retry

**Cancellation Request**:
The durable intent to stop an Assessment that immediately closes admission but does not itself establish CANCELED.
_Avoid_: Process signal alone, CANCELED state, timeout

**Cancellation Quiescence**:
The durable proof that every assessment-owned role, Analyzer, and process has stopped and can no longer publish results, required before CANCELED commits.
_Avoid_: Best-effort kill, elapsed grace period, no visible process

**Risk Decision Window**:
The explicit pre-Seal BLOCKED condition in which an authorized human or Control Plane Decision Authority may decide a defined Finding risk before final Policy Evaluation.
_Avoid_: Editing a Seal, model approval, indefinite waiver

**Seal Publication**:
The boundary that atomically binds verified immutable artifacts to the committed Seal, Verdict, Bundle Manifest, and Submission identity.
_Avoid_: Export rendering, file copy, state flag alone

**Official Security Export**:
An authorized artifact generated from a SEALED Assessment under a named Export Profile and bound to its canonical Bundle.
_Avoid_: Workbench screenshot, Diagnostic View, raw Evidence directory

**Diagnostic View**:
A bounded, authorized, explicitly non-authoritative Workbench projection of a BLOCKED or CANCELED Assessment for investigation or recovery.
_Avoid_: Official Security Export, Assessment Bundle, Submission

**Analyzer Registration**:
An effect-scoped contribution of a validated Analyzer descriptor and factory through the Security Service, removed with its owning Cordis Fiber.
_Avoid_: Dynamic code loading, direct registry mutation, per-run script path

**Assessment Aggregate**:
The narrow transactional consistency boundary owning one Assessment's lifecycle, plan, Attempts, Findings, Coverage, Risk Decisions, Verdict, Seal, and authoritative references.
_Avoid_: Whole product database, Repository Registry, Evidence payload directory

**Revision Journal**:
The append-only, versioned record of each committed externally observable Assessment mutation, transactionally paired with its projection update.
_Avoid_: Process log, complete Event Sourcing promise, mutable audit table

**Current Projection**:
The query-optimized present view of an aggregate updated in the same transaction as its Revision Journal entry.
_Avoid_: Independent source of truth, cached UI state, Analyzer working memory

**Durable Work Item**:
A transactionally published outbox instruction for one bounded asynchronous operation that a fenced Runner may claim.
_Avoid_: In-memory callback, Analyzer result, user task list

**Idempotency Record**:
The durable binding among Principal and authority context, operation, target, idempotency key, canonical request digest, and original committed outcome.
_Avoid_: Request cache, aggregate revision, content digest alone

**Idempotency Conflict**:
The fail-closed result when an existing idempotency key is reused with a different effective request digest or scope.
_Avoid_: Stale Revision, duplicate successful retry, generic invalid input

**Transition Matrix**:
The exhaustive Kernel-owned table of legal source state, command, guards, target state, journal fact, and invariants for Assessment lifecycle changes.
_Avoid_: Workflow suggestion, UI stepper, scattered Service conditionals

**Result Admission**:
The fenced, idempotent Kernel decision that accepts one terminal Attempt result into the Assessment Aggregate at most once.
_Avoid_: Analyzer execution, Evidence staging, role-agent message

**Evidence Staging**:
The bounded private area and writer through which an untrusted producer submits candidate Evidence for validation and protection before publication.
_Avoid_: Evidence Store, final Evidence identity, repository output folder

**Evidence Publication**:
The atomic Service operation that validates and protects staged bytes, establishes their Digest Envelope, and makes an immutable Evidence object eligible for authoritative reference.
_Avoid_: Export, staging write, database row without an object

**Digest Envelope**:
The versioned identity of hashed content that records algorithm, media type, byte length, and deterministic canonicalization rules.
_Avoid_: Bare hexadecimal string, filesystem timestamp, Finding Fingerprint

**Migration Lease**:
The exclusive Store authority required to execute one verified forward-only database schema migration while normal admission is closed.
_Avoid_: Assessment Execution Lease, startup lock file, downgrade permission

**Recovery Reconciliation**:
The startup process that restores storage consistency and records interrupted work without executing semantic Assessment work or silently resuming it.
_Avoid_: Resume, Analyzer retry, database editing

**Query Cursor**:
An opaque pagination capability bound to normalized filters, disclosure authority, Repository scope, stable ordering, page ceiling, and a consistency watermark.
_Avoid_: Row offset, reusable access token, unrestricted continuation string

**Public Security Error**:
The stable redacted error envelope exposed by every product surface, carrying a code, safe message, retryability, correlation ID, and relevant revision without sensitive diagnostics.
_Avoid_: Raw exception, stack trace, internal log event

**Analyzer Identity**:
The immutable tuple of namespaced Analyzer ID, semantic implementation version, Descriptor schema version, and integrity-bound package or build digest.
_Avoid_: Display name, npm package alone, installation path

**Analyzer Descriptor**:
The deeply frozen JSON-safe declaration of one Analyzer's identity, supported Coverage and Evidence, execution class, resources, egress, and compatibility claims.
_Avoid_: Analyzer instance, configuration secret, runtime capability

**Capability Vocabulary**:
The versioned core taxonomy and namespaced extension rules used to express Analyzer support and requirements without granting execution authority.
_Avoid_: Free-form feature tags, Capability Handle, Policy obligation

**Eligibility Decision**:
The immutable Kernel result stating whether and why one exact Analyzer execution may satisfy specified mandatory Coverage under the frozen Assessment contract.
_Avoid_: Analyzer claim, Qualification Record alone, final Verdict

**Analyzer Factory**:
The registered executable provider that creates and disposes one Analyzer instance for one durable Attempt after composition admission.
_Avoid_: Analyzer Descriptor, singleton scanner, command string

**Analyzer Input**:
The immutable versioned value describing one Attempt's Subject material, target, Requirement, permitted Evidence context, Policy fragment, deadline, and budget without Host authority.
_Avoid_: Cordis context, workspace path, Assessment Store

**Analyzer Contribution**:
The one versioned terminal result proposed by an Analyzer, containing Coverage Claims, Candidate Findings, Evidence references, diagnostics, resource use, and completion disposition for Kernel admission.
_Avoid_: Security Verdict, direct state mutation, Runner Event

**Runner Event**:
A bounded non-authoritative progress or diagnostic observation emitted during an Attempt whose loss cannot alter Assessment semantics.
_Avoid_: Revision Journal entry, Analyzer Contribution, process stdout stream

**Cancellation Fence**:
The durable boundary that closes Result Admission for a canceled Attempt and invalidates every later result or capability use carrying its former generation.
_Avoid_: AbortSignal alone, CANCELED Assessment state, process exit

**Budget Reservation**:
The Kernel-owned maximum resource allocation deducted from the frozen Assessment Budget before one Attempt may begin and settled after all child work ends.
_Avoid_: Usage estimate, provider bill, unbounded timeout

**Concurrency Envelope**:
The frozen hierarchical limits and fair-queue constraints governing simultaneous work across Host, Repository, Assessment, Provider, Analyzer, and execution class.
_Avoid_: Assessment Budget, process count alone, Analyzer preference

**In-process Extension**:
Host-approved executable plugin code loaded in the Harness process and therefore part of the Host trust boundary rather than isolated by the Analyzer SPI.
_Avoid_: Pure Analyzer, Untrusted Analyzer, sandboxed script

**Untrusted Analyzer**:
Analyzer code not admitted to the Host process and permitted to run only through a separately qualified isolation backend with enforceable capability boundaries.
_Avoid_: Unqualified in-process plugin, Advisory Finding, hostile Subject

**Capability Handle**:
An opaque non-transferable Attempt-scoped object granting one bounded operation under fixed authority, budget, deadline, and fencing.
_Avoid_: Provider Capability, Cordis service, reusable credential

**Egress Broker**:
The qualified capability mediating external model or provider requests under frozen destinations, credentials, Source Slices, Data Egress limits, quotas, and audit.
_Avoid_: Ambient network, browser tool, Analyzer-owned HTTP client

**Analyzer Qualification Record**:
The Host-trusted, evidence-bound, scoped, and expiring statement that one exact Analyzer build satisfies specified Conformance, isolation, and Effectiveness requirements.
_Avoid_: Analyzer Descriptor, registration success, marketing certification

**Analyzer Parse Cache**:
A disposable non-authoritative content-addressed optimization for deterministic intermediate parsing, bound to exact semantic inputs and incapable of satisfying Coverage by itself.
_Avoid_: Reused Analyzer Contribution, Evidence Store, Verdict cache

**Security Role Catalog**:
The versioned closed set of governed Role identities available to the read-only Assessment Engine, excluding approval and Risk Acceptance authority.
_Avoid_: User persona list, arbitrary Subagent prompt, organization directory

**Role Definition**:
The immutable product asset binding a Role identity to its Prompt, model requirements, Tool Manifest, schemas, budget ceiling, independence class, and compatibility.
_Avoid_: Role Attempt, chat persona, repository instruction

**Role Admission**:
The Kernel decision selecting an exact qualified Role Definition and Provider into the frozen Coverage Plan under Policy and budget.
_Avoid_: Caller role request, agent self-delegation, session creation

**Prompt Compiler**:
The versioned component that encodes trusted Role rules, typed task data, Tool Manifest, and delimited untrusted content into an auditable model invocation.
_Avoid_: String concatenation, repository prompt, model response parser

**Context Grant**:
The immutable purpose-specific set of Subject slices, Evidence projections, task constraints, and disclosure categories authorized for one Role Attempt.
_Avoid_: Whole repository access, parent conversation, Security Authority

**Source Slice Request**:
A structured Role request for additional bounded Subject content that the Service independently checks against purpose, containment, sensitivity, Egress, and budget.
_Avoid_: File read path, ambient repository browser, Egress permission

**Role Attempt**:
One durable execution of an exact Role Definition through a fresh isolated Subagent session with frozen Provider, Prompt, context, tools, budget, and lineage.
_Avoid_: Role Definition, parent conversation, Analyzer Attempt

**Role Transcript**:
The protected Execution Evidence of model messages and governed tool interactions from one Role Attempt, never an authoritative Finding or ordinary chat log.
_Avoid_: Role Contribution, conversation history, public report

**Role Tool Manifest**:
The immutable least-privilege list and schemas of Attempt-scoped capabilities available to one Role Definition.
_Avoid_: Harness tool registry, Capability Vocabulary, model-selected tools

**Follow-up Request**:
A structured non-authoritative Role proposal for additional governed analysis that only the Kernel may admit as a durable child Attempt.
_Avoid_: Direct Subagent spawn, Work Item, user instruction

**Role Exchange**:
The governed transfer of immutable Contributions, Evidence projections, requests, or Challenge Packages between Role phases without direct mutable agent communication.
_Avoid_: Group chat, shared memory, hidden model context

**Independent Pass**:
A Role Attempt intentionally blinded from peer outputs until its initial contribution freezes, with separately recorded context, randomness, Provider, and model lineage.
_Avoid_: Duplicate response, Challenge phase, product Evaluation repetition

**Challenge Package**:
The bounded immutable set of claims, Evidence references, conflicts, and questions supplied to a Challenge Analyst after initial contributions freeze.
_Avoid_: Editable Finding, full transcript dump, majority ballot

**Evidence Convergence**:
The deterministic reconciliation of candidates and challenges under Validation Contracts, Evidence eligibility, independence, identity, and Coverage rules rather than agent votes.
_Avoid_: Consensus chat, confidence average, Policy Evaluation

**Role Contribution**:
The bounded versioned terminal proposal from one Role Attempt containing hypotheses, Candidate Findings, Coverage Observations, Evidence context, uncertainty, challenges, requests, and completion status.
_Avoid_: Security Verdict, Role Transcript, Analyzer Contribution

**Format Repair Invocation**:
The single optional predeclared and budgeted syntax-only model call used to transform malformed Role output into its required schema without adding semantic claims.
_Avoid_: Semantic retry, heuristic parsing, new Role Attempt

**Model Invocation Record**:
The protected lineage record binding one model call to Provider, deployment, Role and Prompt versions, tool and context digests, parameters, usage, response digest, and parent Attempt.
_Avoid_: Provider Composition alone, Role Transcript, billing receipt

**Deterministic-only Profile**:
A separately named qualified Assessment Profile whose Coverage Plan intentionally contains no governed Role Agent obligation and makes no model-assisted coverage claim.
_Avoid_: Standard without a model, degraded Deep, Analyzer disguised as an Agent

**Candidate Admission**:
The Service boundary that validates a proposed Candidate's schema, provenance, Subject Anchors, security claim, Evidence references, and bounds before it enters validation.
_Avoid_: Validation Outcome, Finding creation, heuristic parsing

**Candidate Cluster**:
A non-destructive grouping of potentially equivalent admitted Candidates that preserves every identity, claim, Evidence source, contradiction, and lineage.
_Avoid_: Automatically merged Finding, fuzzy deduplication, deleted duplicate

**Finding Revision**:
An immutable append-only version of one Assessment-local Finding recording an Evidence-backed correction or refinement and its superseded predecessor.
_Avoid_: Aggregate revision, edited SEALED Finding, new cross-Assessment Finding

**Finding Supersession**:
The explicit relation selecting a newer Finding Revision as current while retaining the complete prior revision chain.
_Avoid_: Deletion, Finding Resolution, Candidate rejection

**Weakness Classification**:
The versioned namespaced Primary and optional Secondary weakness identities attached to a Candidate or Finding, including an explicit UNKNOWN value.
_Avoid_: Scanner label, free-text category, Technical Severity

**Source Anchor**:
The stable bounded reference to exact Subject content using canonical relative path, content digest, byte span, and optional language symbol.
_Avoid_: Live workspace line number, absolute Host path, copied source file

**Evidence Type Registry**:
The versioned closed core and namespaced extension catalog of Evidence kinds, schemas, validation, and protection rules recognized by the product.
_Avoid_: File extension list, Evidence Store directory, arbitrary Analyzer output

**Evidence Eligibility Decision**:
The immutable Kernel judgment that one exact Evidence object is or is not eligible for one Security Claim under one Contract and lineage context.
_Avoid_: Evidence existence, producer confidence, global trust badge

**Validation Contract Resolution**:
The frozen Kernel selection of the exact weakness-specific Validation Contract from Policy, Mode, ecosystem, execution boundary, and qualified capabilities.
_Avoid_: Validator preference, post-result rule choice, generic threshold

**Validation Outcome**:
The versioned evidence-backed result classifying one Candidate as VALIDATED, REJECTED, or UNRESOLVED under an exact Validation Contract.
_Avoid_: Model confidence, Finding Resolution, Security Verdict

**Counter-Evidence**:
Eligible Evidence that proves a Validation Contract's rejection condition rather than merely failing to prove the Candidate.
_Avoid_: Missing exploit, Reviewer opinion, timeout

**Independent Validation Lineage**:
The provenance graph demonstrating that validation satisfies a Contract's restrictions on shared Candidate, model, Prompt, Provider, tool, and Evidence ancestry.
_Avoid_: Different Attempt ID alone, self-reflection, majority vote

**Attack Path Graph**:
The typed Evidence graph of entry, attacker capabilities, preconditions, trust boundaries, controls, bypasses, sinks, and impact with explicit unknown edges.
_Avoid_: Narrative exploit story, universal validation prerequisite, production attack

**Severity Method**:
The versioned deterministic calculation mapping Evidence-backed impact and exploitability dimensions to Technical Severity while retaining unknown inputs.
_Avoid_: Scanner score, Policy Significance, model probability

**Evidence Confidence Rubric**:
The versioned deterministic grading of proof completeness, qualification, reproducibility, independence, binding, freshness, controls, and Proof Gaps.
_Avoid_: Technical Severity, model confidence percentage, vote count

**Candidate Overflow**:
The recorded condition that an admitted Candidate quota was reached, creating a visible Coverage Gap instead of silently truncating discovery.
_Avoid_: Deduplication, low-priority Finding, ordinary pagination

**Evidence Link**:
The immutable purpose-specific binding from one Evidence digest to a Security Claim, Subject, Contract, Eligibility Decision, producer lineage, and consumer.
_Avoid_: Blob copy, transitive trust, generic attachment

**Security Claim**:
One precise falsifiable assertion about a Subject's security property, defect, reachability, impact, or control that Evidence may support or refute.
_Avoid_: Finding title, model opinion, Policy obligation

**Declarative Security Policy**:
A schema-versioned non-executable document of typed security requirements, selectors, obligations, exceptions, authorities, and composition operators compiled without model interpretation.
_Avoid_: TypeScript rule, natural-language prompt, repository instruction

**Policy Layer**:
One provenance-preserving Baseline, Host or Organization, or Repository strengthening input with exact identity, digest, authority, scope, and version.
_Avoid_: Flattened effective Policy, configuration precedence, runtime override

**Policy AST**:
The canonical typed representation produced from valid composed Policy Layers and consumed by deterministic planning and evaluation.
_Avoid_: Raw Policy document, executable syntax tree, Coverage Plan

**Policy Lattice**:
The versioned rule-specific ordering and composition semantics proving that a lower Policy Layer only strengthens inherited security requirements.
_Avoid_: Last-write-wins merge, role hierarchy, Severity scale

**Policy Compilation Record**:
The immutable binding of Policy Compiler version, all explicit input identities and digests, canonical AST and Coverage Plan digests, diagnostics, and rejected constructs.
_Avoid_: Build log, Policy AST alone, Evaluation Trace

**Inventory Completeness**:
The evidence-backed determination that a Subject Inventory covers the components, ecosystems, dependencies, configuration, entry points, boundaries, and exclusions required by a selected Mode and Profile.
_Avoid_: File count, successful walk, model summary

**Inventory Gap**:
A typed relevant region or fact that Subject Inventory could not safely identify, read, classify, or support and which must affect Coverage honestly.
_Avoid_: Explicit supported exclusion, Coverage Gap, empty directory

**Coverage Obligation**:
A stable typed completion contract binding a Security Requirement and Subject scope to mandatory Evidence, independence, provider conditions, dependencies, and resolution rules.
_Avoid_: Analyzer task, file percentage, Role suggestion

**Coverage Dependency Graph**:
The immutable acyclic graph of Coverage Obligations and governed barriers defining prerequisite Evidence, execution, parallelism, and completion semantics.
_Avoid_: Agent plan, mutable task list, process tree

**Plan Amendment**:
An append-only Evidence-triggered strengthening or expansion of a frozen Coverage Plan that preserves prior obligations and records a new digest and budget impact.
_Avoid_: Plan edit, obligation deletion, Resume configuration change

**Coverage Resolution**:
The Kernel-owned terminal classification of one Coverage Obligation as SATISFIED, NOT_APPLICABLE, or GAP after validating Claims, Evidence, eligibility, and completion rules.
_Avoid_: Coverage Claim, progress percentage, Analyzer exit code

**Not Applicable Proof**:
Eligible Inventory, selector, and Negative Evidence demonstrating that one exact Coverage Obligation's precondition is absent from the frozen Subject.
_Avoid_: Empty result, unsupported Analyzer, user waiver

**Coverage Aggregation**:
The deterministic parent-child rule that retains every obligation result and requires all mandatory descendants without weighted compensation.
_Avoid_: Average percentage, task count, Verdict calculation

**Advisory Work**:
Optional qualified analysis that may enrich Evidence or discover Findings but cannot satisfy or compensate for a mandatory Coverage Obligation.
_Avoid_: Mandatory Analyzer, Risk Acceptance, unqualified output

**Evaluation Instant**:
The single Host-provided recorded time input against which final Policy Evaluation determines every relevant freshness and expiry condition.
_Avoid_: Ambient system time, Assessment creation time, Submission validation time

**Verdict Candidate**:
The pure Policy Evaluator output proposing SATISFIED, FAILED, or INDETERMINATE with its complete trace before Seal Readiness and atomic publication.
_Avoid_: SEALED Security Verdict, agent recommendation, Mission decision

**Evaluation Trace**:
The immutable rule-by-rule explanation binding Policy inputs, Coverage, Findings, Risk Decisions, method versions, and Evaluation Instant to a Verdict Candidate.
_Avoid_: Model reasoning, application log, report narrative

**Seal Readiness Check**:
The independent deterministic Kernel validation that all lifecycle, Coverage, authority, integrity, quiescence, Evidence, Verdict, Bundle, and Submission invariants hold before sealing.
_Avoid_: Workbench confirmation, Policy Evaluation alone, artifact upload

**Packed Conformance**:
Release-bearing black-box verification performed against the exact npm artifact installed into a fresh supported Harness profile through public entry points.
_Avoid_: Source-import test, local workspace alias, manual demo

**Reference Test Host**:
The isolated real Harness and Cordis composition used to exercise the packed plugin with explicit temporary authorities and production lifecycle semantics.
_Avoid_: Mock runtime, developer profile, modified Harness Core

**Test Forensic Reader**:
A separate read-only test utility that inspects persisted invariants without entering the product process or manufacturing authoritative state.
_Avoid_: Store mutation helper, test Principal, production diagnostic API

**Reference Fake**:
A versioned deterministic implementation of an official Provider or capability contract used to produce controlled Conformance outcomes without claiming Effectiveness.
_Avoid_: Runtime bypass, benchmark product Arm, arbitrary mock

**State-machine Conformance**:
Generated comparison of public Service behavior against the pure Transition Matrix model across valid and invalid command sequences.
_Avoid_: Happy-path test, workflow screenshot, implementation-specific unit test

**Crash Checkpoint**:
A named non-authorizing test interception around a durable boundary where the complete Host can be hard-terminated for restart proof.
_Avoid_: Caught exception, production feature flag, ordinary log marker

**Multi-process Race Suite**:
The black-box scenarios running multiple real Hosts against one isolated authority root to prove CAS, idempotency, leases, fencing, migration, cancellation, and sealing.
_Avoid_: Thread-only test, sequential retry, load benchmark

**Platform Adversarial Fixture**:
A versioned hostile filesystem Subject and expected outcome specialized for Windows, Linux, or macOS semantics.
_Avoid_: Generic vulnerable repository, Effectiveness Case, one-platform smoke test

**Canonical Golden Vector**:
A reviewed exact-byte and digest fixture proving deterministic canonical encoding and reader semantics for a versioned security artifact.
_Avoid_: Auto-updated snapshot, visual report snapshot, approximate JSON equality

**Surface Parity Suite**:
One transport-independent scenario set run through Service, model tools, Typert Remote, and Control Plane Provider to prove shared domain semantics and surface-specific controls.
_Avoid_: Duplicate hand-written tests, UI-only scenario, internal method test

**Workbench E2E**:
Real-browser verification of the packed Workbench and Host across lifecycle, authority, accessibility, redaction, recovery, and user workflows.
_Avoid_: Component snapshot, manual screenshot, Service integration test

**Lifecycle Conformance**:
Proof that dormant, activation, disposal, dependency loss, HMR, reactivation, and uninstall obey Cordis ownership and quiescence contracts without leaked capabilities.
_Avoid_: Startup smoke test, process kill, package removal alone

**Benchmark Arm Isolation**:
The rule that every Evaluation Arm and repetition receives fresh Stores, caches, sessions, Provider state, credentials, and temporary resources around the same immutable Subject.
_Avoid_: Shared model conversation, warm product cache, different benchmark input

**Ground Truth Air Gap**:
The enforced separation preventing scanning Runners from accessing expected defects, matching rules, seed metadata, or Arm labels before sealed output exists.
_Avoid_: Hidden repository folder, prompt instruction not to look, post-hoc redaction

**Metrics Engine**:
The pure versioned implementation calculating predeclared Effectiveness, Utility, uncertainty, and comparison measures from immutable Evaluation evidence.
_Avoid_: Report template formula, spreadsheet calculation, model-written score

**Conformance Mutant Suite**:
The controlled test-only security defects that black-box tests must detect, proving critical invariant checks are effective rather than merely present.
_Avoid_: Fuzz input, published feature flag, random source mutation

**Resource Proof**:
The platform- and Profile-scoped measurement of limits, consumption, leakage, cancellation, and recovery against predeclared thresholds and pressure fixtures.
_Avoid_: Average duration, provider bill, informal profiling

**Release Evidence Manifest**:
The machine-readable digest-bound index connecting one exact candidate artifact to every required proof result, Support Matrix claim, limitation, and exception.
_Avoid_: CI badge, README checklist, latest test run

**Diagnostic Rerun**:
A repetition used only to investigate an existing deterministic failure and incapable of replacing or erasing its release impact.
_Avoid_: Flake retry, new qualified run, stochastic Evaluation repetition

**Security Invocation**:
An opaque non-serializable capability minted by the Security Authority Resolver from a trusted caller channel and required for an authority-bearing Service operation.
_Avoid_: Request Principal field, browser token, reusable permission DTO

**Kernel Decision**:
The pure Security Assessment Kernel result containing canonical state change, Journal Facts, work intents, evaluation output, or invariant rejection without I/O.
_Avoid_: Command Receipt, Store transaction, Agent judgment

**Journal Fact**:
A canonical immutable domain fact emitted by a Kernel Decision for append to the Revision Journal within the authoritative transaction.
_Avoid_: Runner Event, process log, mutable projection row

**Engine Wake**:
The package-private notification that durable Work Items exist and the Assessment Engine may run them toward a stable point under current leases.
_Avoid_: Public command, silent Resume, in-memory-only task

**Persistence Module**:
The package-private deep Module owning SQLite transactions, Journal, projections, idempotency, Outbox, leases, migrations, CAS, and recovery queries.
_Avoid_: Public Store Interface, entity Repository collection, raw connection

**Evidence Persistence Module**:
The package-private deep Module owning Evidence staging, validation, protection, atomic publication, reading, retention, quarantine, and garbage collection.
_Avoid_: Analyzer output directory, SQLite blob table, public Evidence Store

**External Provider Seam**:
A justified location whose Interface admits multiple qualified production or test Adapters such as Analyzers, Key Providers, or Egress Brokers.
_Avoid_: Interface for every class, Store mocking port, package export alone

**Module Dependency Rule**:
The one-way requirement that domain values and Kernel remain independent of I/O and Harness while implementations and Adapters depend inward on their Interfaces.
_Avoid_: Global service locator, circular import, Adapter imported by Kernel

**Runtime Entry**:
An independently activated Cordis package export that registers Fiber-owned production behavior only when its bundle row is enabled.
_Avoid_: Contract Entry, package installation, ordinary module import

**Contract Entry**:
A side-effect-free package export containing schemas, types, SPI helpers, generated contracts, or Conformance utilities without runtime activation.
_Avoid_: Cordis Provider, auto-starting module, test bypass

**Package Export Map**:
The reviewed mapping of package subpaths to root Service, Consumers, Client, invariant, contracts, Analyzer SPI, Conformance, Typert, and Remote entries.
_Avoid_: Cordis bundle rows, source folder layout, multiple npm products

**Side-effect-free Import**:
The guarantee that loading a Contract Entry performs no registration, I/O, configuration access, timer, process, network, or global mutation.
_Avoid_: Dormant Cordis activation, lazy database open, import-time singleton

**Public DTO**:
A versioned runtime-validated JSON-safe request, Receipt, Snapshot, View, cursor, event, or error crossing the Security Service Interface.
_Avoid_: Aggregate class, SQLite row, capability handle

**Security Result**:
The discriminated public operation envelope containing either one versioned value or one stable redacted Public Security Error.
_Avoid_: Raw exception, nullable result, transport-specific failure

**Command Receipt**:
The immutable successful mutation result binding operation, target identity, committed revision, idempotency identity, accepted state, Work identity, and correlation.
_Avoid_: Assessment Snapshot, mutable aggregate, async completion promise

**Assessment Snapshot**:
The immutable bounded versioned query projection of one Assessment at a committed revision under a caller's disclosure authority.
_Avoid_: Aggregate object, browser cache, Assessment Bundle

**Repository Administration**:
The separately authorized explicit registration, revision, disabling, and bounded querying of Host-owned Repository Registry entries without hard deletion.
_Avoid_: Assessment start, raw Registry edit, workspace discovery

**Runtime Health**:
The bounded authorized Snapshot of READY, READ_ONLY_SAFE, QUIESCING, or STOPPED state and the redacted checks governing Service admission.
_Avoid_: Process liveness, monitoring badge, Assessment state

**Transport Adapter**:
The thin Module that derives channel authority, validates framing, propagates cancellation, calls the Security Service, and maps its result without domain Policy.
_Avoid_: Second state machine, Store client, Policy evaluator

**Invariant Entry**:
The optional dormant Cordis Runtime Entry that verifies Harness and plugin composition and contributes only to Runtime Health without repairing or patching the Host.
_Avoid_: Assessment Engine, migration tool, Harness fork

**Conformance Module**:
The side-effect-free Contract Entry providing public Provider and Analyzer suites, Fixture builders, Reference Fakes, and assertions without security bypasses.
_Avoid_: Production test mode, second Kernel, Store mutation library

**Service Operation Catalog**:
The fixed reviewed set of explicit v0.1 Security Service commands, queries, waits, artifact operations, and local Analyzer registration without generic execution.
_Avoid_: Store CRUD, dynamic method, transport route list

**Invocation Options**:
The process-local cancellation and bounded deadline controls passed separately from a Security Invocation and semantic Request.
_Avoid_: Permission options, Request DTO fields, Assessment Budget

**Analyzer Registration Disposer**:
The synchronous cleanup function returned after valid local Analyzer registration and owned by the contributing Cordis Fiber.
_Avoid_: Remote deregistration command, Analyzer Factory disposer, plugin uninstall script

**Security Catalog**:
The authority-filtered Snapshot of effective Modes, Profiles, ecosystems, qualified Provider and Analyzer support, limitations, and Support Matrix references.
_Avoid_: Internal Registry, marketing feature list, Runtime Health

**Repository Revision**:
The monotonically increasing immutable version of one Repository Registry entry and its Host-owned security bindings.
_Avoid_: Git revision, Assessment revision, mutable config file

**Start Assessment Request**:
The minimal Request naming Repository, Subject kind, Mode and Profile, Target Selector, optional stronger controls, and idempotency without supplying authority or composition.
_Avoid_: Assessment Aggregate, repository path, Provider selection

**Target Selector**:
The versioned discriminated Repository, Change, or Targeted value that canonically bounds the Subject scope represented by an Assessment Mode.
_Avoid_: Free-form prompt, filesystem glob, Coverage Plan

**Repository Target**:
The Target Selector variant covering the admitted Repository Subject under Repository-mode inventory and Policy rules.
_Avoid_: Repository Registry entry, arbitrary root, Targeted Target

**Change Target**:
The Target Selector variant binding exact base and head or an immutable Change identity and its impact-cone contract.
_Avoid_: Branch name, raw diff text, live pull request

**Targeted Target**:
The Target Selector variant binding explicit canonical components, packages, or Subject-relative paths under Policy scope limits.
_Avoid_: Repository-wide claim, free-form target, absolute path

**Subject Freeze**:
The stable-read materialization, manifesting, integrity verification, and atomic publication that must succeed before an Assessment is created.
_Avoid_: Assessment start Receipt, live workspace read, partial staging

**Assessment List Item**:
The low-sensitivity bounded summary of one Assessment returned in a watermarked paginated list without Evidence or aggregate internals.
_Avoid_: Assessment Snapshot, Finding Summary, list cursor

**Revision Wait Result**:
The bounded signal reporting whether an Assessment revision changed, its current revision and state, terminality, and need to refetch a Snapshot.
_Avoid_: Event stream, Journal Fact, progress log

**Finding Summary**:
The redacted list projection of Finding identity, revision, validation, classification, severity, significance, sensitivity, and Assessment reference.
_Avoid_: Finding Detail View, report paragraph, Candidate Finding

**Finding Detail View**:
The authority-filtered revision-bound projection of one Finding's lineage, validation, severity, confidence, Coverage, risk, Evidence Link metadata, and attack-path summary.
_Avoid_: Mutable Finding, raw Evidence, Markdown report

**Evidence View**:
The purpose- and Profile-bound authorized representation of one Evidence object as bounded content, metadata, controlled read capability, or redacted denial.
_Avoid_: Evidence Store path, Evidence Link, unrestricted blob

**Risk Decision**:
An immutable authorized acceptance or denial action over one exact Finding and Assessment contract with rationale, controls, expiry, and decision-maker lineage.
_Avoid_: Risk Acceptance alone, Agent recommendation, Finding edit

**Bundle Manifest View**:
The disclosure-filtered projection of canonical Bundle record identities, digests, sizes, classifications, omissions, schema, and Seal reference.
_Avoid_: Canonical Assessment Bundle bytes, filesystem directory, export report

**Delivery Destination**:
A Host-registered authorized export target identified by stable ID and bounded destination policy without exposing credentials or arbitrary paths to callers.
_Avoid_: User-provided absolute path, Evidence Store, browser download URL

**Export Request**:
The authorized mutation selecting a SEALED Assessment, Export Profile, registered Delivery Destination, idempotency identity, and permitted bounded options.
_Avoid_: Direct file write, Bundle query, external Tracking payload

**Contract Version**:
The explicit major version selecting public operation and DTO semantics, validation, defaults, authority, and failure behavior.
_Avoid_: Package version, Bundle schema alone, Analyzer version

**Compatibility Reader**:
The fail-closed implementation that validates and interprets a supported historical Bundle or Submission schema without rewriting its sealed bytes.
_Avoid_: In-place migration, generic JSON parser, current writer

**Mutation Envelope**:
The common Contract Version and idempotency identity on every mutation plus expected revision for an existing Aggregate or Registry entry.
_Avoid_: Security Invocation, transport headers, arbitrary metadata

**Workbench Launcher**:
The additive `sidebar.footer.action` contribution that opens the Security Workbench overlay without replacing any Harness shell owner.
_Avoid_: Root route replacement, model tool, Host menu patch

**Workbench Route State**:
The low-sensitivity opaque View identifiers and layout state permitted in navigation history while protected domain context remains in memory and is reauthorized.
_Avoid_: Evidence content, repository path, download capability

**Assessment Wizard**:
The Workbench flow constructing a valid Start Assessment Request exclusively from registered Repository, Catalog, Profile, Mode, Target, and stronger-control choices.
_Avoid_: Free-form agent prompt, path picker, Provider editor

**Start Preflight**:
The Service-derived preview binding effective Subject target, Policy, Profile, Provider Composition, Egress, Evidence Protection, budget, limitations, and one proposal digest before start confirmation.
_Avoid_: Editable Assessment config, marketing estimate, created Assessment

**Phase Graph View**:
The revision-bound Workbench projection of durable phase dependencies, Attempts, Coverage, milestones, budget, blockers, and terminal state without raw logs.
_Avoid_: Agent plan, process list, progress animation

**Role Card**:
The non-authoritative Workbench summary of one governed Role Attempt's identity, lineage, state, Provider, budget, milestones, and admitted output counts.
_Avoid_: Chat answer, Role Contribution, approval badge

**Role Detail View**:
The immutable authorized presentation of a Role Contribution, requests, challenges, lineage, and separately disclosed Transcript without editing or prompt injection.
_Avoid_: Live agent chat, mutable Contribution, parent conversation

**Deep Independence View**:
The staged presentation that keeps peer Contributions unavailable to independent execution until initial passes freeze, then shows challenge and convergence lineage distinctly.
_Avoid_: Shared live answers, merged consensus bubble, hidden execution

**Available Action**:
One authority- and revision-specific operation projected by the Security Service as currently admissible for an Assessment Snapshot.
_Avoid_: Client-inferred button, permission grant, queued Work Item

**Blocked Recovery View**:
The Workbench explanation of stable blockers, affected obligations, Attempts, retained Evidence, recovery conditions, and allowed actions without completion bypasses.
_Avoid_: Generic error dialog, force-complete control, diagnostic log dump

**Finding Triage View**:
The multidimensional Workbench projection separating Policy Significance, Severity, Validation, Confidence, weakness, sensitivity, Coverage, and record kind.
_Avoid_: Single risk score, scanner output list, editable validation

**Evidence Disclosure View**:
The metadata-first Workbench presentation that requires a new purpose-specific authorization before receiving bounded sensitive Evidence content.
_Avoid_: Evidence Store browser, automatic source preload, durable decryption

**Risk Decision Form**:
The governed Workbench input for an immutable authorized decision containing rationale, controls and expiry against an exact Finding and revision.
_Avoid_: Finding editor, acceptance checkbox, decision-maker identity field

**Dual Authority Attestation**:
The pending Critical break-glass decision requiring two matching attestations from distinct independently authenticated qualified Authorities before effect.
_Avoid_: Double click, administrator impersonation, one shared session

**Export Preview**:
The Service-derived Workbench summary of an Export Profile's included categories, redactions, format, registered destination, expiry, and warnings before delivery.
_Avoid_: Client-rendered artifact, arbitrary save path, Bundle Manifest View

**Reconnect Recovery**:
The Client behavior that re-derives authority and refetches Service state by opaque ID and revision, using original idempotency only for an uncertain mutation.
_Avoid_: Browser-state continuation, automatic new Assessment, hidden retry

**Browser Persistence Policy**:
The explicit rule allowing only versioned low-sensitivity UI preferences and opaque recent IDs while excluding protected Assessment payloads from browser storage and history.
_Avoid_: Offline Evidence cache, persisted Security Invocation, full Snapshot storage

**Host CSP Inheritance**:
The requirement that Workbench resources, requests, downloads, and remote content remain within Harness web security and origin policy without independent weakening.
_Avoid_: Plugin-owned permissive CSP, remote analytics, inline bypass

**Accessible Workbench**:
The keyboard-operable, focus-correct, semantically labeled, non-color-dependent, responsive English and Simplified Chinese Security UI.
_Avoid_: Screenshot-only proof, translated machine identifiers, inaccessible overlay
