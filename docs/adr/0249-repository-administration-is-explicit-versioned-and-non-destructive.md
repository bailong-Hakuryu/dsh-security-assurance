---
status: accepted
---

# Repository Administration is explicit, versioned, and non-destructive

The Service exposes separately authorized `registerRepository`, `updateRepository`, and `disableRepository` commands plus bounded repository queries. Registration resolves and records canonical identity and security bindings; update appends a new Registry revision that affects only future Assessments; disable prevents new starts while retaining history and existing frozen contracts. Start never registers a path implicitly, and v0.1 exposes no hard-delete or raw Registry mutation operation that can destroy audit lineage.
