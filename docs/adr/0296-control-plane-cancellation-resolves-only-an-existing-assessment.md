---
status: accepted
---

# Control Plane cancellation resolves only an existing Assessment

The optional Control Plane Provider treats explicit Mission cancellation as a
separate operation from Provider-call abort or plugin disposal. It derives the
same stable start identity as `assess()` and uses a package-private,
authority-checked lookup to resolve only an existing idempotency record. The
lookup is independent of mutable Repository bindings and never calls
`startAssessment` while canceling. No record means no external Assessment was
started. A non-terminal Assessment is canceled through the public
revision-bound and idempotent `cancelAssessment` operation and re-read as
`CANCELED` before the Adapter returns its external identity. A sealed or already
canceled Assessment is reported as already terminal. Lookup, cancellation,
verification, or timeout failure cannot be converted into successful Mission
cancellation.
