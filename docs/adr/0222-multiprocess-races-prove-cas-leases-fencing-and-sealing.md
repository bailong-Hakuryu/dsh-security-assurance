---
status: accepted
---

# Multiprocess races prove CAS, leases, fencing, and sealing

The Multi-process Race Suite runs at least two independently started packed Hosts against one isolated Security authority root and deliberately races start idempotency, stale revisions, Work Item claims, lease renewal and takeover, duplicate and delayed results, Resume, cancellation, HMR recovery, schema migration, artifact publication, and sealing. Assertions require exactly the contract-permitted committed outcomes, monotonically fenced ownership, no duplicate semantic result, and no split Seal; thread-only simulations do not satisfy this proof.
