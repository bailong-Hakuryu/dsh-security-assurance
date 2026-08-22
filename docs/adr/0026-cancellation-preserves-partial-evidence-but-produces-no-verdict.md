---
status: accepted
---

# Cancellation preserves partial Evidence but produces no Verdict

Cancellation stops new dispatch, revokes execution grants, fences or quiesces in-flight Analyzers, and retains partial Evidence plus the cancellation reason. The terminal Assessment is `CANCELED` and has no Security Verdict; a Control Plane Requirement canceled in this way is an operational failure that the Kernel evaluates as indeterminate assurance.

