---
status: accepted
---

# Commands publish durable work transactionally

When an Assessment Command requires asynchronous execution, one SQLite transaction commits its authorized outcome, the new aggregate revision, and every required Durable Work Item in the Service-owned outbox. A Runner performs work only after claiming such an item under the current Execution Lease and fencing token; it never relies on an in-memory callback created after commit. A crash before commit creates neither state nor work, and a crash after commit leaves durable work available for explicit recovery and reconciliation.
