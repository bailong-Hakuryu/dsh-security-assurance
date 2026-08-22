---
status: accepted
---

# Findings require explicit Validation state

Discovery creates Candidate Findings that become validated Security Findings, Rejected Candidates with retained counter-Evidence, or Unresolved Candidates. Only an eligible Evidence Contract may validate a Finding; model-generated candidates require an independent validation lineage, while a deterministic Analyzer may self-validate only when its frozen contract explicitly proves the relevant defect.

