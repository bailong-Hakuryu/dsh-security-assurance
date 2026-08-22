---
status: accepted
---

# Provider Composition is frozen into the Assessment Seal

The Assessment Seal binds the Provider package and digest, implementation, capability descriptor, schemas, backend adapter, analyzers, rule sets, models, prompts, and execution lineage alongside Subject and Security Policy. A change to any bound component requires a new Security Assessment rather than silently resuming an old one with different semantics.

