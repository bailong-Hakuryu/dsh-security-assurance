---
status: accepted
---

# v0.1 gate-bearing local Analyzers use bounded Harness capabilities

Pure Analyzers receive only immutable bounded data and narrow capability objects. Constrained Process Analyzers use `ctx.fs`, `ctx.subprocess`, and `ctx.sandbox` with structured argv, canonical read-only Subject paths, scrubbed environment, explicit deadlines and output ceilings, and awaited process-tree cleanup, and they do not execute Subject code or lifecycle scripts. Work requiring enforceable network isolation or execution of untrusted Subject code needs an additional qualified backend; without it the contribution is Advisory or leaves required Coverage indeterminate.

