---
status: accepted
---

# Analyzer instances are Attempt-scoped and disposable

The registered Analyzer Factory creates a fresh instance for one durable Attempt under its frozen runtime context and returns a deterministic asynchronous disposer. Instances do not share mutable state across Assessments or Attempts, and every process, stream, timer, temporary object, broker call, and child task they obtain is owned by that Attempt scope. Terminal completion, interruption, cancellation, and startup recovery all require disposal or a durable record that quiescence could not be proved.
