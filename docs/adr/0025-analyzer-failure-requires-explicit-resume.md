---
status: accepted
---

# Analyzer failure requires explicit Resume

Every Analyzer Attempt is durable and budget-charged, and failure moves the Assessment to `BLOCKED` without overwriting its record or silently retrying. Explicit Resume may create a new Attempt only with the same frozen Subject, Policy, and Provider Composition; composition change requires a new Assessment.

