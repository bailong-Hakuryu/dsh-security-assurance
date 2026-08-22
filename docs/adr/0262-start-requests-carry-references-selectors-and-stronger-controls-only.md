---
status: accepted
---

# Start requests carry references, selectors, and stronger controls only

`startAssessment` accepts a Contract Version, Repository ID, Subject kind, Assessment Mode and Profile, mode-specific Target Selector, optional request for predeclared stronger controls, and idempotency key. The caller cannot supply a filesystem root, Security Policy document, Provider Composition, Analyzer list, Evidence key, egress destination, execution command, budget increase beyond authorized profiles, or initial Assessment state. The Service resolves every effective semantic input from Host-owned versioned configuration and records the resolution before Subject Freeze.
