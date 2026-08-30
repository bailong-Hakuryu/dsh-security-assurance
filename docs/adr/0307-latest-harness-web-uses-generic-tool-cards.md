# ADR 0307: Latest Harness Web Uses Generic Tool Cards

Status: Accepted

## Context

The earlier Workbench client was implemented against the external client-runtime
preset published with Harness `0.1.1-rc.2`. Harness `0.1.2-alpha.1` no longer
publishes that preset and discovers plugin bundles through `dsh.bundle` instead.
Publishing a client entry whose required runtime cannot be installed would make
the plugin package unusable for new users.

Harness already renders registered tools through its generic Web tool cards.
Security Assurance exposes eight bounded model tools, including repository and
catalog discovery, so a user can perform the supported workflow without a
package-owned browser surface.

## Decision

The `0.1.0-rc.2` package does not export or advertise the legacy client entry.
Its bundle activates the root Service, invariant, Host Repository Provider,
eight model tools, and optional Control Plane Provider. Web users interact with
those tools through the Harness generic UI. The authenticated Workbench Remote
remains disabled unless a deployment supplies a real Host authority resolver.

The old client source and its historical tests remain in the repository as
migration material, but they are outside the candidate build, package, and
current-Harness release gate.

## Consequences

- A fresh Harness `0.1.2-alpha.1` profile can install and activate the package
  without an unavailable client-runtime dependency.
- Direct Web use is functional but uses generic tool cards rather than the
  richer legacy Workbench experience.
- A future native client must target the then-current Harness client extension
  surface and receive its own compatibility ADR and browser acceptance gate.
