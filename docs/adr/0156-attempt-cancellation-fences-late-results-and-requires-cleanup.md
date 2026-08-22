---
status: accepted
---

# Attempt cancellation fences late results and requires cleanup

Attempt cancellation first closes result admission with a durable Cancellation Fence and signals the Attempt-scoped `AbortSignal`. After a bounded cooperative grace period, the qualified execution backend terminates the applicable process tree, broker operation, or child work and waits for disposal evidence; any result carrying the canceled or stale fence is rejected. If cleanup or quiescence cannot be proved, the Assessment becomes BLOCKED rather than claiming that cancellation completed safely.
