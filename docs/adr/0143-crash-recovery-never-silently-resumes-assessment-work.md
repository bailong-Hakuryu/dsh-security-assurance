---
status: accepted
---

# Crash recovery never silently resumes Assessment work

Startup Recovery Reconciliation may verify storage, repair reproducible projections or indices, reconcile published and staged objects, expire leases, and durably mark abandoned Attempts as interrupted. It does not invoke Analyzers, consume remaining budget, change Findings, evaluate Policy, or advance an Assessment as if work had completed. Any Assessment requiring semantic work remains or becomes BLOCKED with explicit recovery diagnostics and can proceed only through an authorized resume under its frozen contract.
