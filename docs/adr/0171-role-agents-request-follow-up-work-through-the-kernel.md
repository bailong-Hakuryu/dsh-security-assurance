---
status: accepted
---

# Role Agents request follow-up work through the Kernel

A Role Agent cannot directly spawn another agent, Analyzer, process, or recursive conversation. It may emit a structured Follow-up Request naming the unresolved obligation, required role or capability, Evidence basis, and bounded reason. The Kernel validates that request against the frozen phase graph, Policy, independence rules, recursion depth, Concurrency Envelope, and remaining budget before creating a new durable child Attempt, rejecting or retaining the request as diagnostic when it is not admissible.
