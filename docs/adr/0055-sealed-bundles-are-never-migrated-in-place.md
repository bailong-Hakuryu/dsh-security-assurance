---
status: accepted
---

# Sealed Bundles are never migrated in place

Every Canonical Assessment Bundle record carries an explicit schema version and sealed Bundles remain byte-stable. A compatible reader may derive a provenance-bound Normalized Bundle View, but unknown or incompatible schemas fail closed and migration never rewrites original Evidence or Verdict.

