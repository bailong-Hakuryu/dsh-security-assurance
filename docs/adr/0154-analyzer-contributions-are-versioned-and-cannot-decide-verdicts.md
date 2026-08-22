---
status: accepted
---

# Analyzer Contributions are versioned and cannot decide Verdicts

An Analyzer terminates with one size-bounded, schema-versioned `AnalyzerContribution` containing Coverage Claims, Candidate Findings, published Evidence references, diagnostics, measured resource use, and an explicit completion disposition. The Service validates the complete contribution before Result Admission, and the Kernel independently reconciles its claims with Policy and the Coverage Plan. Contributions cannot contain or trigger an Assessment state transition, Risk Acceptance, final Severity override, Security Verdict, Seal, Submission, Store mutation, or arbitrary follow-up execution.
