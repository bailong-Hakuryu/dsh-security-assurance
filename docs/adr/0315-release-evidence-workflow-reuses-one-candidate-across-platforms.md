---
status: accepted
---

# Release Evidence Workflow Reuses One Candidate Across Platforms

The manually triggered Release Candidate Evidence workflow requires the full
40-character Control Plane commit SHA, packs Security Assurance and that exact
companion once, binds the Security candidate to the clean source revision and
dependency lock, and uploads those files as one immutable workflow artifact.
Linux, macOS, and Windows jobs must
download that artifact and supply its retained tarballs to the packed-profile
runner. They may not repack a platform-local candidate before emitting their
strict `ReleaseProofRecordV1`.

The collection job starts only after every platform job succeeds. It downloads
all three records and the original candidate bundle, installs the collection
CLI from the packed Security Assurance candidate, and produces the
deterministically ordered proof index. GitHub's artifact transport digest is a
useful transfer check, but the product boundary remains the candidate digest in
the release-file binding, the proof emitter's retained-byte check, and the
collector's independent record validation.

This workflow records evidence only. It does not complete the Release
Constitution portfolio, run qualification, create a tag, upload a GitHub
Release, or publish to npm. Those remain separate, explicitly authorized steps.
