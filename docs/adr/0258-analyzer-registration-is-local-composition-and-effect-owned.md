---
status: accepted
---

# Analyzer registration is local composition and effect-owned

`registerAnalyzer(descriptor, factory)` exists only on the in-process Cordis Service for Host-approved plugin composition and is absent from Typert Remote, browser, model tools, and Control Plane payloads. It synchronously validates identity, schema, declared capabilities, duplicate registration, and factory shape and returns an Analyzer Registration Disposer tied by the contributor to its Cordis Fiber. Backend liveness and verdict eligibility remain runtime planning decisions, while invalid structural registration throws a composition error and never degrades silently.
