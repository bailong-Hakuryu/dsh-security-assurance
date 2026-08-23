---
status: accepted
---

# Control Plane integration is an optional by-value Adapter

DSH Security Assurance remains an independently installable root Service. Its
optional `control-plane-provider` Cordis entry injects the Security Service and
Engineering Control Plane Service, then registers the exact
`dsh/security-assurance` Provider descriptor through the Control Plane's public
Assurance Provider contract. Neither root entry imports the other product.

Host Policy binds a selected Provider to one already registered Security
Repository using the bounded public `repositoryId` carried in the frozen
Provider request. The Adapter receives no repository path or credential. It
uses a package-private authority-checked operation to present that Registry
entry to the Kernel-issued process-local Repository Binding Assertion. A
Repository ID without a successful same-canonical-root assertion is not valid
binding and starts no Assessment. The Adapter then issues a package-owned
`control-plane` Security Invocation and starts a Workspace
Snapshot Assessment, waits by durable revision, and obtains the verified sealed
Security Submission through the Security Service.

The Adapter translates domain artifacts into the provider-neutral eligibility
profile and embeds the complete canonical Security Submission plus its source
digest as Evidence by value. It does not share either product's SQLite file,
writable Evidence directory, transaction, Kernel, or live Provider handle. A
missing or invalid binding, unavailable Service operation, blocked Assessment,
or cancellation returns an external failure and therefore cannot silently
satisfy a Mission requirement. Security Verdict remains a Provider claim; only
the Control Plane derives the Mission Assurance Result and Quality Gate.
