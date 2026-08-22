---
status: accepted
---

# Security Assessments bind an immutable Subject

Security Assessment is the durable aggregate over Analyzer Runs, Findings, Coverage, Evidence, and Verdict, and it binds an immutable Assessment Subject at creation. Revisions and change sets use exact identities and digests; a dirty worktree must be sealed as a snapshot rather than read as mutable live state during evaluation.

