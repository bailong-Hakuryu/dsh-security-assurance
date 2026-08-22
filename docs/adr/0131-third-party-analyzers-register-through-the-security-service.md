---
status: accepted
---

# Third-party analyzers register through the Security Service

Third-party plugins contribute analyzers only through `ctx.securityAssurance.registerAnalyzer(descriptor, factory)`. Registration is owned by the contributor's Cordis Fiber and is removed by its disposer; an Assessment freezes the exact registered Analyzer identity, version, descriptor, capabilities, and factory-backed provider handle it selected. Duplicate identity and version pairs, invalid descriptors or result schemas, and incomplete or contradictory capability declarations fail loudly during registration rather than degrading at execution time.
