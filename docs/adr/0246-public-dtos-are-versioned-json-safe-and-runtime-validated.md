---
status: accepted
---

# Public DTOs are versioned, JSON-safe, and runtime-validated

Every public request, Receipt, Snapshot, View, event, cursor, error, Analyzer descriptor, and contribution has an explicit schema version, branded opaque identities, bounded fields, canonical optional-value semantics, and runtime validation at each Interface. DTOs contain only JSON-safe primitives, arrays, and records and never expose `Date`, `Map`, `Set`, `BigInt`, class instances, raw `Error`, SQLite rows, Host paths, file handles, capability objects, or mutable aggregate references. TypeScript declarations are generated or checked from the same semantic schemas rather than acting as the only validation.
