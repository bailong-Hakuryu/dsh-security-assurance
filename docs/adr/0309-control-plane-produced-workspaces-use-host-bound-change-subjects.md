---
status: accepted
---

# Control Plane produced workspaces use Host-bound Change Subjects

The Control Plane Provider starts `CHANGE`, not `REPOSITORY`, after a Mission's
Developer and Implementation Evidence complete. Its source is the Host-only
`workspace_change` Subject: canonical branch, baseline HEAD, Workspace
Fingerprint, and Produced Change Fingerprint copied from the Kernel-issued
Assurance Execution Context. Its Change target binds the same baseline and two
fingerprints with the default Policy impact cone.

Subject Freeze independently resolves the registered Repository, verifies the
process-local Repository Binding Assertion, and atomically captures the full
resulting workspace. It recomputes the Control Plane V1 status fingerprint and
the byte-exact produced-change fingerprint from the raw tracked patch plus all
admitted untracked file digests. Branch, HEAD, selection, deletion set, status,
patch, untracked enumeration, and file bytes must remain stable across the
capture. Any mismatch or drift fails closed before an Assessment exists.

The optional Control Plane peer cannot become a static dependency of the
standalone Security Assurance service. The verifier therefore carries a local
implementation of the versioned public algorithms, while cross-package
conformance tests require identical outputs. An algorithm change requires a
new version on both sides.

`workspace_change` is intentionally absent from the Catalog, model tools, and
Workbench start wizard. Models retain the backward-compatible exact-commit
`change` contract and cannot invent Host identity claims. Existing exact
base/head Change Assessments remain supported unchanged.
