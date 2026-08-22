---
status: accepted
---

# The Policy Evaluator is pure and emits a complete trace

The deterministic Policy Evaluator consumes only frozen canonical Subject, Policy AST, Coverage Resolutions, Findings, Evidence Eligibility Decisions, Risk Decisions, Evaluation Instant, and declared method versions. It produces a Verdict Candidate plus a complete rule-by-rule Evaluation Trace and diagnostics, but performs no Store write, artifact publication, Provider call, model invocation, clock read, or state transition. Re-evaluating equal canonical inputs under the same evaluator version must produce byte-equivalent semantic output.
