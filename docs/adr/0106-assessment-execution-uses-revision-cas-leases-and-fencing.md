---
status: accepted
---

# Assessment execution uses revision CAS leases and fencing

The Store uses SQLite WAL for concurrent readers, aggregate revision comparison for every mutation, and one expiring Assessment Execution Lease carrying a monotonically increasing fencing token for Runner writes. Several product processes may inspect the same authority root, but only the current fenced lease holder may advance an Assessment; lease expiry never authorizes silent Analyzer replay.

