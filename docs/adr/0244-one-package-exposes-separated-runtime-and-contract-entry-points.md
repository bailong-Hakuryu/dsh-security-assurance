---
status: accepted
---

# One package exposes separated runtime and contract entry points

The `dsh-security-assurance` export map provides the root Service and Engine Provider at `.`, Cordis Consumers at `./tools`, `./control-plane-provider`, and `./client`, composition checks at `./invariant`, side-effect-free libraries at `./contracts`, `./analyzer`, and `./conformance`, and generated Workbench contracts at `./typert` and `./remote`. One `cordis.patch.yml` installs independently activatable dormant Host and Client rows. These exports remain one product and npm unit until a real independently deployed Adapter justifies a package split.
