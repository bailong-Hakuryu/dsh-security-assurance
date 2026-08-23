---
status: accepted
---

# Control Plane Repository binding precedes Assessment start

The optional Adapter may start a Security Assessment only after the root
Security Service resolves its configured Repository ID and the Kernel-issued
process-local assertion confirms that canonical root is the Control Plane
Mission Repository. The Service invokes the assertion internally and never
returns its private root to the Adapter. Missing assertion support is a
recoverable external block; a canonical-root mismatch is a terminal external
failure for the frozen Provider configuration and creates no Assessment.
