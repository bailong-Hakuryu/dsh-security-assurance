---
status: accepted
---

# SQLite Persistence is a package-private deep Module

One package-private Persistence Module owns SQLite connection lifecycle, transactions, Revision Journal and Current Projections, idempotency, Outbox and Work Items, leases and fencing, migrations, retention metadata, CAS, and recovery queries. Aggregate-specific SQL repositories, raw rows, connection handles, Unit of Work objects, and fault injection controls never cross the external Service Interface. Release tests use the real SQLite implementation through public operations, while internal tests and the read-only Test Forensic Reader observe its seam without making it public.
