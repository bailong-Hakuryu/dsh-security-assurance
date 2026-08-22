---
status: accepted
---

# Resume and Cancel require revision, idempotency, and reason

`resumeAssessment` and `cancelAssessment` require the exact Assessment ID, expected revision, idempotency key, and a bounded structured operator reason in addition to the trusted Security Invocation. Resume contains no Subject, Policy, Provider, Analyzer, plan, budget, or state override and may only create eligible new Attempts under the frozen contract. Cancel contains no force-complete, skip-cleanup, delete-Evidence, or Verdict field and returns a Receipt for the durable Cancellation Request rather than prematurely claiming CANCELED.
