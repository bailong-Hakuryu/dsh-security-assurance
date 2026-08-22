---
status: accepted
---

# Idempotency binds authority operation target and request

Every mutation stores an Idempotency Record scoped to the resolved Security Principal and authority context, operation, Repository or aggregate target, idempotency key, and canonical request digest. Repeating the same effective request returns the original committed result and revision without executing it again; reusing that key with a different digest fails as `IDEMPOTENCY_CONFLICT` without mutation. Records remain protected for at least the operation's effective audit and replay horizon rather than expiring while a legitimate retry may still arrive.
