---
status: accepted
---

# Authoritative Contributions are not reused across Assessments in v0.1

The first release does not satisfy Coverage, recreate Findings, or support a Verdict by reusing an Analyzer Contribution from another Assessment, even when Subject content appears identical. Deterministic parsers may use a non-authoritative content-addressed Analyzer Parse Cache bound to exact implementation, schema, Policy-relevant inputs, platform, and Provider conditions, but every gate-bearing Attempt executes and admits a new contribution with fresh lineage and budget accounting. Cache loss or rejection changes performance only, never semantics.
