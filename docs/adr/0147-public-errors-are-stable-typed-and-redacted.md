---
status: accepted
---

# Public errors are stable typed and redacted

Every public surface maps failures to a versioned Public Security Error containing a stable code, safe message, retryability, correlation ID, and current revision when relevant. The first contract distinguishes denied or masked access, not found, invalid input, invalid state, stale revision, idempotency conflict, integrity failure, Provider unavailable, unsupported schema, resource or rate limit, and internal failure. Paths, Evidence, secrets, provider payloads, stack traces, and existence of unauthorized resources remain only in access-controlled diagnostics and never leak through the public envelope.
