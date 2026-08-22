---
status: accepted
---

# Conformance Mutants must be killed before release

The Conformance Mutant Suite builds controlled test-only variants that remove or invert critical authorization, revision, idempotency, fencing, Evidence eligibility, path containment, egress, budget, cancellation, Coverage, Verdict, Seal, Risk Acceptance, redaction, and artifact-integrity checks. The applicable black-box suite must fail for every mandatory mutant and record the killing test; a surviving mutant is a proof gap that blocks release. Mutants never enter a published artifact or weaken production paths through a runtime switch.
