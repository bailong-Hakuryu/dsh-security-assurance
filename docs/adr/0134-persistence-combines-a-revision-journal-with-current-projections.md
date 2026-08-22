---
status: accepted
---

# Persistence combines a Revision Journal with current projections

Every committed Assessment mutation appends an immutable, versioned Revision Journal entry and transactionally updates the corresponding Current Projection in SQLite. The journal provides provenance, audit, and recovery checks, while projections provide bounded reads; neither may disagree after commit. The product does not claim full event sourcing or require arbitrary future database reconstruction solely from historical events, and migration never rewrites an already committed journal entry.
