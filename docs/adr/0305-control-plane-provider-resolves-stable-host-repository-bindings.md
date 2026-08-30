---
status: accepted
---

# Control Plane Provider resolves stable Host Repository bindings

The optional Control Plane Provider accepts exactly one Host-owned repository
identity in its frozen configuration: either the existing public `repositoryId`
or a stable `repositoryBindingId`. A binding ID is resolved at operation time
through the optional `securityAssuranceHostRepositories` Service. The Adapter
accepts only an enabled immutable binding and carries the resulting Repository
ID into the existing same-canonical-root assertion before any Assessment starts.

This removes the deployment-time handshake in which an operator first booted
Security Assurance, extracted a generated Repository UUID, and pasted it into
Engineering Control Plane configuration. It does not expose a root path or mint
authority: the Host Repository Provider remains the only component that owns
registration configuration, the Security Registry remains authoritative, and a
missing, disabled, malformed, or unloaded binding fails closed as
`invalid_provider_configuration`.
