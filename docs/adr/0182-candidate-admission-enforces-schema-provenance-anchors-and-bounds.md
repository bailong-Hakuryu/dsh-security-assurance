---
status: accepted
---

# Candidate Admission enforces schema provenance anchors and bounds

Before a proposal enters the Finding pipeline, Candidate Admission validates its schema version, producer and Attempt lineage, Subject identity, Source Anchors, weakness hypothesis, affected asset or control, security claim, Evidence references, and per-field and aggregate size limits. Normalization may canonicalize representation but cannot invent missing facts or repair semantic claims. Invalid, unauthenticated, out-of-Subject, oversized, or stale proposals remain protected diagnostics and never participate in deduplication, validation, Coverage, or reporting as Candidates.

For Role Contributions, the package-private pure admission operation now
reparses the exact Context Grant, Contribution, and durable Contribution
Admission Link; verifies their Assessment, Subject, Role, Attempt generation and
fence, invocation, resource-use, count, revision, and digest bindings; and then
admits the Candidate batch atomically. Every Source Anchor must match one
caller-supplied, raw-byte-reverified frozen-Subject slice and remain within its
byte length. Every Candidate Evidence reference must name a caller-confirmed
durable Evidence object. Duplicate anchors, ambiguous weakness identities,
duplicate durable Evidence identities, drifted source material, stale lineage,
and schema or aggregate-bound violations fail closed with fixed-code protected
diagnostics.

Schema v6 persists each caller-identified admission attempt inside the Role
Attempt aggregate boundary. A successful attempt commits the entire batch and
all Candidate rows with one Assessment revision; a failed semantic admission
commits only a digest-bound diagnostic containing the fixed code and, when it
was safely parsed, the Candidate ID. The request digest binds the exact source
material without storing its bytes, and the diagnostic stores neither source
nor claim text. Exact replay returns the existing success or rejection without
advancing revision. Reusing an attempt identity for different input, admitting
after cancellation or Attempt settlement, or observing a stale revision fails
closed. A new attempt may retry a previously rejected Contribution after its
missing durable inputs become available. Persistence still creates no
Validation Outcome, Finding, Coverage authority, cluster, Evidence merge, or
ADR 0197 Evidence Link.
