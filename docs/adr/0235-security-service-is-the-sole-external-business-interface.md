---
status: accepted
---

# Security Service is the sole external business Interface

`ctx.securityAssurance` is the product's sole external business Interface and sole path for authoritative commands, queries, registrations, waiting, and disclosure. The Security Assessment Kernel, Assessment Engine, SQLite Persistence, Evidence Persistence, scheduler, registries, and transaction machinery remain package-private Modules and are not exported for callers to orchestrate. Workbench, tools, Control Plane, third-party integrations, and tests receive leverage through the same Service Interface rather than learning internal state or ordering.
