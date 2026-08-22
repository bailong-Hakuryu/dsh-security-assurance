---
status: accepted
---

# Revisions advance once per externally observable transaction

Each transaction that changes an externally observable Assessment projection advances its monotonically increasing revision exactly once, regardless of the number of rows changed. State transitions, accepted results, Findings, Coverage, Risk Decisions, and named progress milestones are observable mutations; lease heartbeats, log chunks, staging writes, and internal maintenance are not. Revision therefore represents committed domain change rather than database write volume and remains suitable for optimistic concurrency and Workbench long polling.
