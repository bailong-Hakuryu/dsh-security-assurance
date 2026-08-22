---
status: accepted
---

# Policy Evaluation uses one recorded instant

One Host-provided Evaluation Instant is committed as an explicit input before final Policy Evaluation. Evidence freshness, advisory snapshot validity, Provider qualification, Risk Acceptance, compensating controls, and other expiry rules are all evaluated relative to that same instant rather than whichever local clock a rule happens to read. The evaluator has no ambient time access, and later Submission validation uses its own recorded validation instant without rewriting the historical Assessment decision.
