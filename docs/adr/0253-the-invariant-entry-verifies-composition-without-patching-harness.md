---
status: accepted
---

# The invariant entry verifies composition without patching Harness

The optional `./invariant` Cordis entry verifies the exact Harness version, required Service Definitions, bundle dependencies, generated contract compatibility, public capability identity, and declared runtime composition and reports its result into Service health. It neither starts a second Assessment Engine nor mutates Assessment state, repairs configuration, patches Harness, monkey-patches `agent-loop`, registers substitute Providers, or weakens admission when a check fails. Its effects are Fiber-owned and dormant unless explicitly activated.
