---
status: accepted
---

# Role tools are fixed least-privilege manifests

Each Role Definition freezes a minimal Role Tool Manifest whose operations are implemented as Attempt-scoped Capability Handles. Tools may read approved Subject material, query bounded Evidence projections, request Source Slices or governed validation, and stage a Role Contribution, but they never expose generic shell, Web, repository write, arbitrary network, raw Cordis context, generic Security Service, Risk Acceptance, or Store access. Every call is schema-validated, authority-checked, budgeted, fenced, and durably attributed to the Role Attempt.
