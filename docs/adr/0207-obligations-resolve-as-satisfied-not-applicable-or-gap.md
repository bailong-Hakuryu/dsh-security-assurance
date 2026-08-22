---
status: accepted
---

# Obligations resolve as SATISFIED, NOT_APPLICABLE, or GAP

A Coverage Obligation is `PENDING` while eligible work or reconciliation remains and must resolve before sealing as exactly `SATISFIED`, `NOT_APPLICABLE`, or `GAP`. `SATISFIED` proves its completion contract, `NOT_APPLICABLE` proves its selector is absent, and `GAP` records a typed missing, failed, unsupported, overflowed, expired, unsafe, or budget-exhausted condition. Percent completion, process success, or absence of Findings is not a resolution state, and no Seal may contain a `PENDING` obligation.
