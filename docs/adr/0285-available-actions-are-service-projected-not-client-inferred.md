---
status: accepted
---

# Available actions are Service-projected not Client-inferred

Every Assessment Snapshot contains an authority-filtered `availableActions` projection derived by the Security Service from current state, revision, Security Invocation, Policy, blockers, and active decision windows. The Workbench renders only those actions and still submits their exact expected revision and idempotency identity; absence disables and explains rather than guessing from a local state table. A stale displayed action may fail safely and trigger refetch but never receives client-side override or optimistic mutation.
