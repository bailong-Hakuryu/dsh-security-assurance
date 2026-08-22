---
status: accepted
---

# Assessment Engine is package-private and hides phase orchestration

The Assessment Engine is one package-private deep Module whose narrow Interface permits startup recovery, wake after committed Work Items, bounded execution toward a stable point, and quiescence. It owns dispatch, scheduling, Runner lifecycle, phase dependencies, Provider and Role calls, cancellation propagation, budget settlement, and durable interruption without exposing per-phase methods or a second command surface. The Security Service commits authoritative intent; an Engine Wake consumes that intent but cannot bypass the Kernel or Store transaction rules.
