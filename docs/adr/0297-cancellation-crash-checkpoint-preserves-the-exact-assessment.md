---
status: accepted
---

# Cancellation Crash Checkpoint preserves the exact Assessment

Dual-plugin conformance installs a package-private, non-authorizing named Crash
Checkpoint on one Security Service instance. The checkpoints observe that the
Control Plane Assessment has started and may interrupt after Security durably
commits `CANCELED` but before the Adapter returns its Provider outcome. They are
absent from the package export map, runtime configuration, public Service
interface, and persistence. After both plugin instances restart, a new explicit
Mission cancellation must resolve the stable start identity, report the same
Assessment ID as already canceled, and allow Control Plane to record its own
terminal proof. This deterministic in-process fault test does not replace the
separate packed multi-process hard-kill Crash Conformance requirement.
