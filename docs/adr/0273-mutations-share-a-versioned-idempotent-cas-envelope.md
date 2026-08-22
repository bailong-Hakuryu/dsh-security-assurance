---
status: accepted
---

# Mutations share a versioned idempotent CAS envelope

Every mutating public Request includes a supported Contract Version and idempotency key, and every mutation of an existing Aggregate or Registry entry additionally includes its exact expected revision. Operation-specific schemas embed this common Mutation Envelope without permitting arbitrary metadata or caller authority. The Service canonicalizes the complete effective request for idempotency, performs one revision comparison, and returns the original Receipt for a true replay or a stable typed conflict without partial mutation.
