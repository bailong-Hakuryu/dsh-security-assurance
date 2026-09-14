---
status: accepted
---

# Malformed Role output allows at most one governed format repair

The Service preserves the protected raw response and first applies strict deterministic parsing and schema validation without heuristic extraction. A Role Definition may predeclare one separately recorded and budgeted Format Repair Invocation that receives only the original response, target schema, and syntax-only instructions; its result is accepted only when semantic claims and Evidence references are traceable to the original and it introduces no new fact or conclusion. If parsing or that check still fails, the Role Attempt fails explicitly and no partial contribution is admitted.

The predeclaration is durable authority, not a late retry decision: it commits atomically with the exact Role Attempt generation and cannot be added or replaced after execution begins. The Store admits at most one text-free repair result only after the original and repair Model Invocation Evidence links are both durable, requires any resulting Role Contribution to match that record, and rejects Evidence extension after Contribution admission. Exact replay may recover across process restart; conflicts fail closed.
