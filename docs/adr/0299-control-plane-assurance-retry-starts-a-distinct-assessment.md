---
status: accepted
---

# Control Plane Assurance Retry starts a distinct Assessment

The optional Adapter treats a successor Control Plane Provider Invocation as a
new Security Assessment request. Its idempotency identity includes the new
Control Plane Invocation ID, so a prior blocked, canceled, or failed Assessment
is never resumed, reused, or rewritten for Assurance Retry. The new Assessment
uses the same frozen Mission Attempt Subject selection and independently
reaches its own terminal state. Adapter `recover()` remains reserved for
reconciling the same durably begun Provider Invocation after host restart.
Only external `blocked` and `canceled` outcomes are eligible for this successor;
`failed` is terminal for the frozen Provider configuration.

An unchanged repository may produce the same content-addressed Subject digest.
Subject Freeze can reuse that private publication only after revalidating its
canonical Manifest, root digest, exact materialized file set, and every file
digest. Platform-specific rename collision errors, including Windows
`EPERM`/`EACCES`, are treated only as a prompt to perform that verification;
missing, unreadable, or corrupted publications still fail closed.
