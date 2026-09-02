---
status: accepted
---

# Gitleaks reports are normalized without secret material

The Host, CI job, or operator executes Gitleaks outside the Pure Analyzer boundary and freezes its built-in v8 JSON report as `gitleaks-report.json` with the Assessment Subject. The package-owned normalizer and an independent Validation Contract may read the exact protected report bytes, but every contributed Evidence record, Candidate, Finding, Seal, query projection, and export retains only the rule identity, affected Subject-relative path, bounded location, frozen report binding, and deterministic product identity. Secret values, matched text, source lines, secret hashes, author identity, email, commit message, and other arbitrary scanner prose are never projected from the report.

An empty, structurally valid frozen report may prove complete Coverage for `security/secret-leak-audit`. Every report entry becomes one Candidate anchored to its exact JSON Pointer and is independently re-derived from the frozen report before it can become a validated HIGH, blocking Finding. Missing, malformed, truncated, over-budget, contradictory, or fabricated reports and Coverage fail closed to an indeterminate Verdict. The qualification claims only faithful normalization of a frozen Gitleaks v8 JSON report; scan freshness, Gitleaks configuration, repository-history breadth, allowlists, and detector effectiveness remain explicit Host responsibilities.
