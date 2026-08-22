---
status: accepted
---

# State transitions are exhaustive and declarative

The Assessment Kernel defines one exhaustive Transition Matrix containing every permitted source state, command, target state, guard, emitted journal fact, and required invariant. Security Service methods invoke that Kernel instead of implementing independent transition logic, and any unlisted or guard-failing transition returns a stable `INVALID_STATE` or more specific conflict without mutation. Model-based and table-driven conformance tests cover every permitted edge and representative rejection path, including crash, cancellation, resume, Risk Decision, and Seal boundaries.
