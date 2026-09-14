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
diagnostics. Rejections are not yet persisted; the caller must retain those
diagnostics until the durable admission slice lands.
