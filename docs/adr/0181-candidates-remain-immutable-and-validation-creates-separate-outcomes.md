---
status: accepted
---

# Candidates remain immutable and Validation creates separate outcomes

A Candidate Finding is an immutable, source-attributed proposal and never changes identity or content to become a Security Finding. Validation creates a separate versioned Validation Outcome linked to that candidate and either establishes a new Assessment-local Finding, records a Rejected Candidate, or preserves an Unresolved Candidate with its Proof Gaps. Original proposals, contradictory candidates, and every validation lineage remain independently inspectable after the outcome and in the canonical Bundle.

The package-private Role Candidate Admission seam implements the first half of
this separation for governed Role Contributions. It emits one deeply frozen,
digest-bound admission record per Candidate and binds the complete Candidate
content independently from its producer lineage. The record contains no
Validation Outcome or Finding identity, and the operation grants no authority
to validate, cluster, merge Evidence, resolve Coverage, or report a Finding.
Durable admission storage and the later Validation Outcome integration remain
separate follow-on work.
