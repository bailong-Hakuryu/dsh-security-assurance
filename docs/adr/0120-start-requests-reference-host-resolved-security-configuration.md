---
status: accepted
---

# Start requests reference Host-resolved security configuration

An assessment start request contains only a Repository ID, Subject type, Mode or Profile, selected targets, and an optional request for stronger controls. The Security Service resolves the canonical root, effective Policy, Evidence and egress rules, Provider Composition, Assessment Budget, and immutable Subject snapshot from Host-owned configuration. A caller may narrow scope only where Policy permits or request stronger treatment, but cannot supply paths, replace providers, weaken controls, or override the resolved contract.
