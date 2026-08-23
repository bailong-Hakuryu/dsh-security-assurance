---
status: accepted
---

# Host Repository Provider is a trusted composition Adapter

Packed Host profiles register deployment-owned Repository roots through the
optional Host Repository Provider rather than exporting Security Invocation
minting or writing the Registry directly. The Provider invokes the root
Security Service with package-owned Host authority and exposes only immutable
`bindingId` to Repository ID results; disposal removes the composition Service
but preserves authoritative Registry history.
