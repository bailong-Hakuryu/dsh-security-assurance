---
status: accepted
---

# Security Service is sole mutation boundary

Every Assessment, Remediation, Delivery, Risk Acceptance, and integration state change passes through the explicit Security Service contract and its authorization, revision, idempotency, and Evidence checks. Workbench components, model tools, Typert Remote adapters, Control Plane adapters, Analyzers, and Security Role Agents may submit commands or Evidence contributions but cannot write the Assessment Store, Evidence journal, or authoritative aggregate directly.

