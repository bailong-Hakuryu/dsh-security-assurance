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
configuration disables that authentication.

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

The deployment-supplied `workbench-remote` entry is unchanged. A composition
enables exactly one of the two entries, because both provide the
`securityAssuranceWorkbench` Remote.

## Consequences

- Service-projected available actions (ADR 0285) omit actions the local
  operator cannot take, and the Service rejects them with `UNAUTHORIZED` if a
  caller submits one anyway.
- The direct-use bundle enables the entry only together with a Workbench
  client that passes browser acceptance on the current Harness client module
  system (ADR 0320).
- Anyone who can pass Harness Web authentication for this Host can act as the
  local operator; the grant is intentionally no broader than the chat tools
  that user already has.
