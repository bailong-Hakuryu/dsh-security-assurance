---
status: accepted
---

# Stable Promotion Handoff Proves Package Equivalence

Qualification authorizes only the exact release-candidate artifact named by
its verified portfolio. Before a human-controlled release action can publish a
stable package, the packaged `dsh-security-assurance-release-handoff` command
must bind that portfolio to both the retained candidate tarball and the
proposed stable tarball. It strictly parses and cross-checks the Manifest,
public Scorecard reference, and qualification verdict, requires
`PROMOTE`/`VERIFIED`, and requires the retained candidate's raw bytes to equal
all three qualified artifact identities.

The comparison opens both bounded gzip tarballs without executing package
code. Their entry paths, types, modes, and inventory must be identical. The
package name is immutable, the candidate must be a prerelease, and the stable
version must be the same major/minor/patch without a prerelease suffix.
`package.json` may change only its `version` field. Other text files may change
only through exact replacement of the full candidate version token with the
stable version. `README.md` and `CHANGELOG.md` are the only package entries
whose release-documentation bytes may otherwise change; binary drift, added
files, executable-mode drift, links, unsupported tar entries, or any other
content change fails closed.

Success atomically emits a deterministic, versioned handoff receipt binding
the raw qualification files and both tarballs. It reuses the qualification
evaluation time instead of adding an ambient timestamp, enumerates every
version or release-documentation change, and says `authorization: NOT_GRANTED`.
The receipt does not tag, sign, upload, create a GitHub Release, publish to npm,
or grant release authority. Detached signatures and the final release action
remain separately reviewed, human-controlled steps.
