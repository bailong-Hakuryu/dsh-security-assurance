---
status: accepted
---

# Release Proof Indexes Compose Qualification Inputs

External release automation must not manually copy indexed proof objects into a
Release Evidence Manifest request. The packaged
`dsh-security-assurance-release-assemble` command accepts the strict
qualification envelope plus one `releaseProofIndexPath`, re-reads the index,
its release-file binding, and every referenced Release Proof Record, and emits
the exact input consumed by `dsh-security-assurance-release-qualify`.

Assembly verifies the binding's raw JSON digest, requires the draft and index
to resolve to the same binding file, requires the binding, index, and the
candidate/qualified/proposed-promotion identities to name one candidate, and
recomputes every indexed record digest and projection. Resolved record paths
must be unique. Indexed and independently supplied proof kinds must not
overlap. The merged proofs are ordered by the Release Evidence Manifest
taxonomy and written atomically to a previously absent file with the binding
path rebased relative to that output.

The adapter copies proof status and identity without reinterpretation. It does
not upgrade failed or inconclusive evidence, manufacture missing proof, run
qualification, or tag, upload, sign, release, or publish a package. The
existing qualification command remains the only external release module that
evaluates the Release Constitution and Manifest verification, and it still
independently re-reads the bound source, candidate, and lock bytes.
