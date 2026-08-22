---
status: accepted
---

# Security authority is derived from the real caller channel

Every Security Service command and query obtains its Security Principal and exact Security Authority from a trusted host channel through the Security Authority Resolver. Agent authority is bound to the exact Harness session, Workbench authority is bound to the authenticated Host Operator, and Control Plane authority is bound to a Kernel-issued invocation context. Request payloads may carry correlation data but can never declare or enlarge identity, permissions, repository scope, or expiry; an unavailable or ambiguous authority resolution fails closed.
