---
status: accepted
---

# Export expiry uses two-phase exact-target reaping

The fixed Export Profile expiry is enforced by the Security Service even when
no Client is connected. At expiry the Service first persists owner-bound
`EXPIRED` status with access denied, `PURGE_PENDING`, and a tombstone binding
the exact artifact identity, digest, policy expiry, deletion authority, and
reason. It then removes only the single artifact file derived from the validated
Export ID, without recursive deletion, globbing, or a caller-provided path, and
finally persists `PURGED` with completion time. A crash or deletion error between
those phases leaves download denied and is reconciled by the lifecycle worker at
startup and on its bounded retry interval. The durable Export record and
tombstone remain; expiry never pretends the governed artifact did not exist.
