---
status: accepted
---

# Workbench uses package-owned Typert remotes

The package publishes generated strict `./typert` and `./remote` contracts, and its Client entry mounts that contribution through `ctx.remote.$mount()`. Workbench actions therefore reach explicit Security Service operations without modifying Harness's central API, inventing an ad hoc REST mirror, or granting the browser access to SQLite or Evidence paths.

