---
status: accepted
---

# Contract imports are side-effect-free and runtime entries start dormant

Importing `./contracts`, `./analyzer`, `./conformance`, generated types, or any type-only root export performs no registration, file access, database connection, process launch, timer, network request, configuration read, or global mutation. Runtime entries likewise act only when Cordis activates their configured bundle rows and dispose all effects with their Fibers; package installation or dormant presence changes no Host behavior. Tests explicitly import every export under a clean process to prove this property.
