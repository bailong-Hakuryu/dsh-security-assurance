---
status: accepted
---

# Weakness Classification is versioned namespaced and explicit about Unknowns

Each Candidate and validated Finding carries a versioned Weakness Classification with one Primary Weakness and optional Secondary Weaknesses drawn from a qualified core taxonomy or collision-resistant extension namespace. Scanner labels and free text are preserved only as source observations and cannot silently become canonical classifications. `UNKNOWN` is an explicit value that prevents selection of an unjustifiably permissive Validation Contract and leaves the relevant contract or Coverage obligation unresolved unless Policy defines a qualified conservative path.
