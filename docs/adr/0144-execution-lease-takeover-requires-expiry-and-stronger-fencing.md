---
status: accepted
---

# Execution Lease takeover requires expiry and stronger fencing

An Assessment Execution Lease records its holder, database-observed expiry, renewal state, and monotonically increasing fencing token. Renewal and takeover use transactional comparison against the current lease; a contender may take ownership only after verified expiry and must commit a strictly greater token. Every Runner result and work mutation presents that token, so the Store permanently rejects a delayed former holder even if its process remains alive or its local clock disagrees.
