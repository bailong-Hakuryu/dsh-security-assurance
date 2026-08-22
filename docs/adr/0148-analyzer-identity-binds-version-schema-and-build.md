---
status: accepted
---

# Analyzer identity binds version schema and build

Every Analyzer has a stable namespaced `analyzerId`, a semantic implementation version, an Analyzer Descriptor schema version, and an integrity-bound package or build digest. That tuple is the Analyzer Identity frozen into registration, Provider Composition, Attempts, Evidence lineage, Qualification, and Seals. Reusing the same identity and version for different executable content fails registration, while a display name, npm package name, or mutable installation path is never sufficient identity.
