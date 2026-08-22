---
status: accepted
---

# Service health is explicit and safe mode remains queryable

The Security Service exposes a bounded authorized Runtime Health Snapshot with `READY`, `READ_ONLY_SAFE`, `QUIESCING`, or `STOPPED` state, exact dependency and compatibility checks, admission status, and redacted remediation diagnostics. Missing mandatory keys or Providers, schema or integrity problems, migration failure, and incompatible runtime composition enter `READ_ONLY_SAFE` when bounded metadata can still be trusted; mutating operations fail closed while authorized diagnosis and export of already valid sealed records remain available where their keys and integrity permit.
