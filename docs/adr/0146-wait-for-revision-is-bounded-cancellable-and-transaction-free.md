---
status: accepted
---

# Wait for revision is bounded cancellable and transaction-free

`waitForRevision` returns immediately when the Assessment revision exceeds `afterRevision` or the Assessment is terminal. Otherwise it waits for at most thirty seconds under per-Principal concurrency and rate limits, accepts cancellation, and returns `changed: false` with the current revision on timeout; clients may then safely repeat from that revision. The wait holds no SQLite transaction, write lock, Execution Lease, or privileged Store object and does not itself change observable state.
