# ADR 0321: Local Workbench Authority Matches the Model Tools

Status: Accepted

## Context

The Workbench Remote resolves every call's opaque authority context through a
Host-supplied `WorkbenchAuthorityContextResolverV1` (ADR 0275), and the
direct-use bundle keeps it disabled because a plain Harness Web deployment
supplies no resolver. The same user can already assess repositories through
the eight model tools in chat, so a direct-use Workbench can reuse that trust
without widening it.

Every supported Harness Web version, `0.1.2-alpha.1` through `0.1.5-rc.3`,
routes all `/api` traffic — including Remote calls — through the
`connection` service's Host/Origin fence and login-token cookie, and no
configuration disables that authentication. The same versions share the
client module system of ADR 0322 and declare the `sidebar.footer.action` and
`shell.overlay` list slots the Workbench client (ADR 0276) mounts into.

ADR 0307 excluded that client because it targeted a client-runtime preset
Harness no longer publishes.

## Decision

The package adds a `dsh-security-assurance/workbench-local` entry. It creates
an in-memory authority, mounts a `securityAssuranceWorkbenchSession` Remote
that issues opaque contexts to the authenticated browser, and mounts the
existing Workbench Remote with that authority as its resolver.

Issued contexts are random, expire after eight hours by default, are bounded
per process, and are revoked when the plugin unloads. They resolve to the
principal `harness-web:local-operator` with exactly the reach of the model
tools: `health:read`, `repository:read`, `assessment:read`,
`assessment:start`, `assessment:resume`, `assessment:cancel`,
`export:request`, and `export:read`. Risk Decisions, break-glass, Evidence
disclosure, Export download, Assurance Submission reads, and Repository
administration remain grants that only a deployment resolver can make. The
issuing Remote reads no identity or permission from the wire.

The direct-use bundle enables `workbench-local` and keeps the
deployment-supplied `workbench-remote` disabled. A composition enables
exactly one of the two, because both provide the `securityAssuranceWorkbench`
Remote.

The `./client` bundle carries the Workbench beside the tool cards,
superseding ADR 0307's exclusion. It starts as a child plugin only once the
page's Remote transport exists, so the cards never depend on it. From a
closed Workbench, the sidebar launcher asks the session Remote for a context
and opens the Assessment selector; the page sends no identity or permission.
When the Host exports no local authority, the gateway reports the method as
unavailable and the overlay keeps its Host-integration guidance; any other
failure, or a context without a valid identity, fails closed and retains
nothing. Harness relays Remote results without decoding them in the browser,
so the Controller itself rejects every Evidence binding change. The bundle
requires only the page's platform modules and bundles its strict Remote
codecs. Its styles use only theme tokens present in every supported version.

## Consequences

- Service-projected available actions (ADR 0285) omit actions the local
  operator cannot take, and the Service rejects them with `UNAUTHORIZED` if a
  caller submits one anyway.
- Anyone who can pass Harness Web authentication for this Host can act as the
  local operator; the grant is intentionally no broader than the chat tools
  that user already has.
- The packed profile smoke proves over the real `/api` transport that an
  unauthenticated request receives no context and an authenticated one reads
  the current workspace with exactly the local permissions.
- The release-grade packed browser E2E drives this local Workbench
  (ADR 0324).
- The client bundle grows to about 630 kB unminified, mostly the strict Remote
  codecs and their validator.
