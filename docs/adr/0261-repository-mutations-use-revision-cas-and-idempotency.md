---
status: accepted
---

# Repository mutations use revision CAS and idempotency

`registerRepository` requires a Mutation Envelope with an idempotency key and derives a new stable Repository ID; replay of an equal request returns the original Receipt. `updateRepository` and `disableRepository` additionally require the exact Repository ID and expected Repository Revision and reject stale or mismatched changes without mutation. Every update appends a new immutable registry revision used only by future Assessments, while existing Assessments retain their frozen repository bindings.
