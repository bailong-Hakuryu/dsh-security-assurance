---
status: accepted
---

# Browser persistence excludes sensitive Assessment payloads

The Workbench does not persist source, Evidence content, Findings, attack paths, transcripts, Risk Decision rationale, credentials, export capabilities or locations, Repository paths, Security Invocations, or full Assessment Snapshots in localStorage, sessionStorage, IndexedDB, Service Worker caches, URLs, or browser logs. It may retain versioned low-sensitivity UI preferences and recent opaque IDs under an explicit cleanup and logout policy. Sensitive in-memory values are discarded on close, authority loss, completion of submission, or expiry.
