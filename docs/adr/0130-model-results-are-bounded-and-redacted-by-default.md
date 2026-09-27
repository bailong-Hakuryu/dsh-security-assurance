---
status: accepted
---

# Model results are bounded and redacted by default

Model tools return only a bounded receipt, revision, state, coverage summary, sealed Verdict when available, and redacted Finding summaries by default. Sensitive Evidence, full attack paths, credentials, protected source slices, and export locations require separate disclosure authority and are returned through controlled views or handles rather than being inserted directly into model conversation history. Pagination, size limits, and redaction remain Service-enforced regardless of model request text.

Amended by ADR 0325: a Finding summary may also carry an allowlisted repository-relative location (path and JSON pointer); anchor digests and file content remain excluded.
