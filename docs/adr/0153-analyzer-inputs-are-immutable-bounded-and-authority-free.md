---
status: accepted
---

# Analyzer inputs are immutable bounded and authority-free

`AnalyzerInput` is a versioned immutable value containing the Attempt and Analyzer identities, Subject Manifest or approved Source Slices, exact target and Requirement, allowed prior Evidence references, the relevant Policy fragment, deadlines, and frozen budget limits. It contains no original workspace path, Assessment Store, Security Service, Cordis context, credentials, or ambient Host authority. Executable access is supplied separately through execution-class-specific Capability Handles whose presence never changes the frozen semantic input.
