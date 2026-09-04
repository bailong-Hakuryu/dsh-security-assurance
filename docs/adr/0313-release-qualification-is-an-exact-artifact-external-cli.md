---
status: accepted
---

# Release qualification is an exact-artifact external CLI

Stable promotion is decided outside the runtime `SecurityAssuranceService`. The packaged `dsh-security-assurance-release-bind` command first turns an explicit source-repository, candidate-artifact, and dependency-lock descriptor into a deterministic versioned binding file. It requires a clean tracked source tree, records the exact Git revision, computes raw-byte SHA-256 envelopes, rebases paths relative to the binding file, and records no ambient timestamp. The side-effect-free `dsh-security-assurance/release-file-bindings` Contract Entry exposes both strict schemas to external automation. This step records file facts but cannot manufacture test, security, effectiveness, or utility proof.

The packaged `dsh-security-assurance-release-qualify` command consumes a strict Release Evidence Manifest request plus a reference to that binding file. Before evaluating promotion, it independently rereads every bound file, verifies that the repository `HEAD` equals both recorded source revisions, checks tracked-tree cleanliness before and after byte verification, requires the candidate tarball bytes to equal the binding and the candidate, qualified, and proposed-promotion evidence digests, and requires every declared lock file to equal both the binding and manifest digest. It then calls the existing pure Release Constitution and Release Evidence Manifest boundary and atomically publishes a manifest, public scorecard, and compact qualification verdict into a previously absent output directory.

Qualification exit code `0` is reserved for a `VERIFIED` manifest whose Release Constitution decision is `PROMOTE`. A valid but blocked or incomplete portfolio remains auditable and exits `2`; malformed, unavailable, dirty, or digest-mismatched input exits `1` without publishing a portfolio. Binding failures also exit `1` without a binding file. Neither command tags, uploads, signs, or publishes a package, and therefore neither can bypass the separate human-controlled release action.
