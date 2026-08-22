---
status: accepted
---

# Cancellation commits only after proven quiescence

Cancellation first persists a Cancellation Request, closes admission for new role, analyzer, and process work, signals every active unit to terminate, and waits for their durable completion or termination records. The Service commits CANCELED only after Cancellation Quiescence proves that no assessment-owned work can still publish results or mutate state. If quiescence cannot be proved, the Assessment becomes BLOCKED with the unresolved work recorded rather than presenting a false cancellation.
