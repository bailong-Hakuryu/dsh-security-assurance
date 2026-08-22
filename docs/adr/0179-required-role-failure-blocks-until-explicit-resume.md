---
status: accepted
---

# Required Role failure blocks until explicit Resume

Failure, malformed output, Provider loss, cancellation, timeout, or budget interruption of a Role Attempt required by the Coverage Plan leaves the Assessment BLOCKED and retains every successful independent contribution unchanged. The Engine does not silently retry, substitute a model, lower independence, or discard the failed lineage. Authorized Resume creates new Attempts only for incomplete eligible graph nodes under the frozen contract; if no path remains, Coverage Reconciliation may seal only `INDETERMINATE`.
