---
status: accepted
---

# SQLite migrations are monotonic verified and fail closed

Database schema changes are numbered, forward-only migrations performed under an exclusive Migration Lease after a protected backup and pre-migration integrity check. Each step validates its expected source version, runs transactionally where SQLite permits, records its result, and performs post-migration integrity and invariant checks before normal admission opens. Failure or an unknown newer schema places the Service in read-only safe mode; rollback restores a verified backup rather than executing an in-place downgrade over authoritative data.
