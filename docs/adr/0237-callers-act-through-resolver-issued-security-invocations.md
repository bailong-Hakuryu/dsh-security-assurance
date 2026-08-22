---
status: accepted
---

# Callers act through Resolver-issued Security Invocations

Every authority-bearing Service operation receives an opaque non-serializable Security Invocation minted only by the Security Authority Resolver from a trusted real channel. Package-owned model tools bind the exact Harness session, Workbench Remote binds the authenticated Host Operator, and the Control Plane Adapter binds a Kernel-issued context; another trusted Host Adapter must register an equivalent resolver path. Request DTOs, browser payloads, repository data, and ordinary plugin code cannot construct, deserialize, copy, or enlarge an Invocation by declaring a Principal or permission.
