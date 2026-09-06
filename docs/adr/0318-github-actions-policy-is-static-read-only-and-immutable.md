---
status: accepted
---

# GitHub Actions Policy Is Static, Read-Only, and Immutable

The `security/github-actions-supply-chain` Policy evaluates only digest-verified
`.github/workflows/*.yml` and `.yaml` files selected from the frozen Subject. A
package-owned PURE Analyzer parses YAML 1.2 without aliases or merge keys,
requires an explicit read-only or empty top-level token boundary, rejects any
job-level widening, and requires external Actions and reusable workflows to use
a full commit SHA and container Actions to use a SHA-256 image digest.

The independent Validation Contract re-runs the complete parse and compares the
entire Contribution before Candidate or Coverage Evidence can affect the
Verdict. Malformed or unsupported YAML is `INDETERMINATE`; a verified empty or
safe workflow set is `SATISFIED`; verified violations are blocking Findings.
The Policy does not execute workflows, resolve refs, contact GitHub, decide
whether write authority is justified, or retain arbitrary workflow values in
published Evidence. Workflows that legitimately need write authority require a
different reviewed Policy rather than an exception hidden inside this one.
