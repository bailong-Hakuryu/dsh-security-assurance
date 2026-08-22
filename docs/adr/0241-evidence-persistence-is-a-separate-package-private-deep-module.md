---
status: accepted
---

# Evidence Persistence is a separate package-private deep Module

Evidence Persistence is a package-private Module distinct from relational aggregate persistence because it hides streaming staging, byte and schema limits, digesting, classification, redaction, encryption, atomic publication, protected reading, retention, quarantine, and garbage collection behind a small internal Interface. SQLite stores identities, Digests, links, and publication facts but not producer-owned paths or uncontrolled payload handling. Only the Security Service and Assessment Engine may coordinate references to this Module, and Evidence producers receive bounded writers rather than the Module itself.
