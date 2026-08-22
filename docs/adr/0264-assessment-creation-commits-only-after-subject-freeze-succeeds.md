---
status: accepted
---

# Assessment creation commits only after Subject Freeze succeeds

`startAssessment` first resolves Repository bindings and performs a bounded stable read that materializes and integrity-checks the complete immutable Subject Snapshot and manifest in private staging. Only after atomic Subject Freeze succeeds may one transaction create the Assessment Aggregate, initial Revision Journal entry, Coverage-planning Work Item, idempotency record, and Command Receipt referencing that exact snapshot. Failure, cancellation, instability, or resource exhaustion before Freeze leaves no Assessment identity that could masquerade as resumable work; recoverable staging is non-authoritative.
