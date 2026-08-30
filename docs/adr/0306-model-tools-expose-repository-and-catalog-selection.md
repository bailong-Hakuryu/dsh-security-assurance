---
status: accepted
---

# Model tools expose Repository and Catalog selection

The model-facing Consumer adds two read-only tools before the six Assessment
operations: `security_repositories` returns bounded authority-visible path-free
Repository choices, and `security_catalog` returns the effective modes,
profiles, target and Subject kinds, stronger controls, ecosystems, and
platforms for an optional selected Repository.

These tools mint only `repository:read` authority from the exact live Harness
session and return closed canonical JSON projections. They never expose a root,
root identity digest, credential, Security Invocation, Registry handle,
Evidence, provider secret, or repository administration operation. Their
purpose is to let an ordinary user or model construct a valid
`security_assessment_start` request without querying SQLite or copying a
generated Repository ID from deployment configuration.
