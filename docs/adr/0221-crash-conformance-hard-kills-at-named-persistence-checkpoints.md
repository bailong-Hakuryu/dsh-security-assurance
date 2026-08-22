---
status: accepted
---

# Crash Conformance hard-kills at named persistence checkpoints

The test build exposes non-authorizing named Crash Checkpoints around each durable transaction, Outbox claim, Evidence publication, result admission, lease change, cancellation boundary, migration, Bundle staging, and Seal Publication step. Crash Conformance hard-terminates the complete Host at each checkpoint, restarts the packed plugin against the same isolated authority root, and verifies journals, projections, artifacts, fencing, orphan handling, and explicit BLOCKED recovery. Throwing and catching an in-process exception is insufficient crash proof.
