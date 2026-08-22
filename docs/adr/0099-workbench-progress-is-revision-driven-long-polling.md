---
status: accepted
---

# Workbench progress is revision-driven long polling

The first Workbench observes progress through a bounded, cancellable Typert operation equivalent to `waitForRevision(assessmentId, afterRevision, timeout, signal)`. A changed revision causes the Client to fetch a new immutable snapshot, while timeout or reconnect safely repeats from the last observed revision; v0.1 does not add a plugin-specific SSE or WebSocket protocol.

