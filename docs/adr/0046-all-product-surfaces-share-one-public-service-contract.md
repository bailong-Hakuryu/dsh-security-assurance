---
status: accepted
---

# All product surfaces share one public Service contract

The first runnable release exposes the Harness plugin, public service contract, Assessment operations, and local Security Workbench. CLI, TypeScript SDK, batch, and CI surfaces follow through the same service and Assessment Engine rather than introducing parallel state; the Workbench reads projections and invokes public commands instead of editing Stores.

