---
status: accepted
---

# Analyzer Descriptors are frozen validated pure data

An Analyzer registers a deeply frozen, JSON-safe, schema-validated Descriptor before Assessment admission opens. The Descriptor contains only declarative identity, support, Coverage, Evidence, execution, resource, egress, and compatibility claims; it contains no closures, credentials, Host paths, mutable objects, live service handles, or Subject-dependent code. Runtime construction remains in the separately registered Analyzer Factory, and the admitted Descriptor cannot change during an Assessment.
