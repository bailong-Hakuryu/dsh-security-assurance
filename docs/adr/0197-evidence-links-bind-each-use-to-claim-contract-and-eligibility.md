---
status: accepted
---

# Evidence Links bind each use to Claim, Contract, and Eligibility

Every authoritative use of an Evidence object creates an immutable Evidence Link binding its exact digest to a Security Claim, purpose, Subject, Validation or other Evidence Contract, Eligibility Decision, producer lineage, and consuming record. One immutable blob may support several claims without byte duplication, but each link is evaluated independently and eligibility or conclusions never propagate transitively through another Finding. The canonical Bundle can therefore answer which Evidence supports each statement and under which rule.
