---
status: accepted
---

# Patch generation and application use separate authority

Remediation generates an immutable Patch Artifact in private staging, bound to one Remediation Case, exact source Subject, changed paths, and content digest without modifying the target. Standalone application requires host-derived Remediation Authority for that exact digest and compatible workspace; Control Plane application remains owned by a Developer Role holding the Repository Write Lease, and stale subjects or altered patches are rejected.

