---
status: accepted
---

# Commands return Receipts and queries return immutable Snapshots

A successful state-changing command returns a versioned immutable Command Receipt containing operation, target identity, committed revision, idempotency identity, accepted state, relevant Work identity, and correlation data rather than an aggregate or mutable object. Queries return bounded versioned immutable Assessment Snapshots or audience-specific Views keyed by identity and revision. Callers continue through explicit IDs, expected revisions, wait cursors, and new operations, never through retained object references or transaction handles.
