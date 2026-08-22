---
status: accepted
---

# Repository admin DTOs bind Host-resolved security configuration

Repository Administration requests provide a Host-resolvable root input and explicit Policy, Profile, Evidence Protection, Data Egress, platform, and allowed Delivery Destination bindings, subject to administrative Security Invocation. The Service canonicalizes and validates the root and named bindings before committing a Registry revision and never accepts repository lifecycle scripts, shell fragments, credentials, raw Provider objects, arbitrary analyzers, or repository-authored authority. Queries return redacted identities and effective binding summaries rather than Host secrets or unrestricted paths.
