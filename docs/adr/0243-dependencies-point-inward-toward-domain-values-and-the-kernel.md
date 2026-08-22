---
status: accepted
---

# Dependencies point inward toward domain values and the Kernel

Side-effect-free domain values and schemas sit at the innermost dependency level, and the pure Kernel depends only on them. Persistence and execution implementations depend inward on domain and Kernel contracts; the Security Service composes those implementations; Harness root, model tools, Typert Remote, Control Plane, Client, invariant, and conformance Adapters depend on the public Service contracts. Domain and Kernel never import Cordis, Harness, SQLite, Node filesystem or subprocess, browser code, or an Adapter, and no global `ctx` is used as an internal service locator.
