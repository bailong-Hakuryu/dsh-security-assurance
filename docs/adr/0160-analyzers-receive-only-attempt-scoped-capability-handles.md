---
status: accepted
---

# Analyzers receive only Attempt-scoped Capability Handles

The Analyzer runtime receives the minimum execution-class-specific handles needed for its admitted task, such as bounded `SubjectReader`, `EvidenceWriter`, `ProcessRunner`, `ModelInvoker`, clock, and diagnostic sink capabilities. It receives neither the raw Cordis context nor direct `ctx.fs`, `ctx.subprocess`, Store, network, credential, or Security Service access. Each opaque handle is bound to Attempt identity, authority, budget, deadline, and fencing token, rejects use after settlement, and cannot be serialized or transferred into another Attempt.
