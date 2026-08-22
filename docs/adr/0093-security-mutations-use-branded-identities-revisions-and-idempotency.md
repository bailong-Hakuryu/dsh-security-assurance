---
status: accepted
---

# Security mutations use branded identities revisions and idempotency

Public domain identities are opaque branded values. Every state-changing Security Service command carries an idempotency key and, when targeting an existing aggregate, its expected committed revision; duplicate submissions return the original committed outcome and stale revisions fail without mutation. Content digests remain integrity facts and never replace aggregate identity.

