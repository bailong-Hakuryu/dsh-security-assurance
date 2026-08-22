---
status: accepted
---

# Provider unavailability is distinct from an invalid contribution

Disabled or unselected Providers do not affect startup, and an unavailable `when-available` Provider remains a diagnostic rather than a registered promise. A required or structurally invalid contribution causes safe read-only startup, while loss of a Provider already frozen into an Assessment blocks that Assessment and never triggers silent substitution.

