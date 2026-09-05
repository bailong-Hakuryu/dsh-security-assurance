# v0.1 Release Candidate Checklist

## Candidate

- Package: `dsh-security-assurance`
- Candidate version: `0.1.0-rc.11`
- Qualified Harness target: `0.1.2-alpha.1`
- Node.js: `^22.19.0 || >=24.0.0`
- License: MIT

This file records the boundary between the locally delivered acceptance
candidate and stable `0.1.0`. Passing automated tests alone is not a stable
security-effectiveness claim.

## Automated candidate gates

Run the complete local gate with:

```sh
pnpm release:check
```

It covers linting, type checking, the full current-Harness deterministic test
suite, a clean build, npm pack inspection, and a fresh Harness `0.1.2-alpha.1` Web
profile that installs both packed bundles, composes their active rows, boots a
clean Git repository, completes browser-token authentication, and serves the
Web page. Public CI repeats this packed-installation gate on Ubuntu, macOS, and
Windows. Legacy `0.1.1-rc.2` consumer and browser scenarios remain available as
non-release compatibility checks. The exact delivered tarball and source
revision are recorded in the external delivery manifest.

For final artifact verification, the packed scripts accept absolute artifact
paths through `DSH_SECURITY_PACKED_ARTIFACT` and
`DSH_CONTROL_PLANE_PACKED_ARTIFACT`. This makes the latest-Harness profile
smoke exercise the exact files whose SHA-256 digests are delivered.

## Exact-artifact qualification

First describe only the real source checkout, packed candidate, and lock files:

```json
{
  "schemaVersion": 1,
  "sourceRepositoryPath": ".",
  "candidateArtifact": {
    "path": "./artifacts/dsh-security-assurance.tgz",
    "mediaType": "application/gzip"
  },
  "dependencyLockFiles": [
    {
      "lockKind": "PNPM_LOCK",
      "path": "./pnpm-lock.yaml",
      "mediaType": "application/yaml"
    }
  ]
}
```

Generate a deterministic, versioned binding file from those exact bytes and a
clean tracked source tree:

```sh
pnpm release:bind -- --input ./release-files.json --output ./release-file-bindings.json
```

The binding contains the verified Git `HEAD` and raw-byte SHA-256 envelopes.
It contains no timestamp and is byte-identical for identical inputs placed in
the same directory. Use those facts when the external release automation
assembles the Release Constitution request, public Scorecard, and complete
proof portfolio. The binder does not manufacture or upgrade any proof result.

## Exact-artifact proof records

Retain the candidate tarball and pass its absolute path to each packed check.
When `DSH_RELEASE_PROOF_OUTPUT` names a previously absent JSON file, a passing
profile smoke writes a platform-specific `ReleaseProofRecordV1` after its Web
probe and cleanup complete. The runner installs a private snapshot of the
supplied tarball, hashes that tested snapshot, and refuses to emit proof if the
retained source changes before record commit:

```powershell
$env:DSH_SECURITY_PACKED_ARTIFACT = (Resolve-Path .\artifacts\dsh-security-assurance.tgz)
$env:DSH_CONTROL_PLANE_PACKED_ARTIFACT = (Resolve-Path .\artifacts\dsh-engineering-control-plane.tgz)
$env:DSH_RELEASE_PROOF_OUTPUT = "$PWD\evidence\windows-platform.json"
pnpm pack:profile-smoke
```

The real-browser runner uses the same Security candidate variable and output
variable. It selects the actual package manifest from the tarball. For the
current candidate, ADR 0307 excludes `./client`, so the run verifies the current
Harness Web shell but records `WORKBENCH` as `INCONCLUSIVE`. It must never turn
generic Web availability into passed Workbench evidence.

```powershell
$env:DSH_RELEASE_PROOF_OUTPUT = "$PWD\evidence\workbench.json"
pnpm pack:browser-e2e
```

Collect any completed records against the binding with a strict input file:

```json
{
  "schemaVersion": 1,
  "releaseFileBindingsPath": "./release-file-bindings.json",
  "proofFiles": [
    "./evidence/windows-platform.json",
    "./evidence/workbench.json"
  ]
}
```

```sh
pnpm release:collect -- --input ./release-proof-input.json --output ./release-proof-index.json
```

Collection rejects malformed records, duplicate paths, record IDs or proof
kinds, and every candidate digest mismatch. It hashes the raw proof-record
bytes and orders records by the Manifest proof taxonomy, so
`records[].proof` can be composed without reinterpretation into the complete
Release Evidence Manifest request. Missing records remain missing, and failed
or inconclusive records keep their original status.

For repeatable cross-platform collection, manually run the repository's
**Release Candidate Evidence** workflow and provide the exact 40-character
Control Plane commit SHA to pack. Its preparation job packs both plugins once and
creates the binding. Linux, macOS, and Windows jobs download those same
tarballs, emit one platform record each, and the final job installs
`dsh-security-assurance-release-collect` from the packed candidate before
producing the downloadable `release-evidence-index` artifact. The workflow
does not run qualification, tag, create a GitHub Release, or publish to npm.

After the independently produced Release Constitution, Scorecard, and remaining
proof references are ready, describe the qualification draft with the normal
qualification fields plus the collected index:

```json
{
  "schemaVersion": 1,
  "releaseProofIndexPath": "./release-proof-index.json",
  "releaseFileBindingsPath": "./release-file-bindings.json",
  "releaseEvidence": "<ReleaseEvidenceManifestRequestV1 with non-indexed proofs>"
}
```

Proof kinds already present in the index must be omitted from the draft's
`releaseEvidence.proofs`. Assemble the strict qualification input, then run the
existing qualification command:

```sh
pnpm release:assemble -- --input ./release-qualification-draft.json --output ./release-qualification-input.json
```

```sh
pnpm release:qualify -- --input ./release-qualification-input.json --output ./release-qualification
```

The strict qualification envelope has this outer shape. The binding path is
resolved relative to the qualification input; paths inside the binding are
resolved relative to the binding file itself:

```json
{
  "schemaVersion": 1,
  "releaseFileBindingsPath": "./release-file-bindings.json",
  "releaseEvidence": "<ReleaseEvidenceManifestRequestV1>"
}
```

The source revision, candidate digests, and lock digests inside
`releaseEvidence` must equal the binding. Qualification independently rereads
every file, requires the Git `HEAD` to match both inputs, rejects tracked
working-tree drift, and checks the source again after byte verification. It
atomically creates `release-evidence-manifest.json`,
`public-security-scorecard.json`, and `release-qualification-verdict.json` in a
previously absent output directory.

Exit `0` means both `manifestVerification: VERIFIED` and
`releaseDecision: PROMOTE`. Exit `2` preserves a valid blocked or inconclusive
portfolio for review. Exit `1` means input, source, byte binding, or output
validation failed and no portfolio is emitted. This command does not tag,
upload, sign, or publish anything. The side-effect-free
`dsh-security-assurance/release-file-bindings` exposes the binding schemas and
`dsh-security-assurance/release-proof` exposes strict record, collection-input,
and index schemas. `dsh-security-assurance/release-qualification` exposes the
strict assembly and qualification-input schemas for external release
automation. Assembly re-verifies the binding bytes and every indexed record,
preserves failed and inconclusive status, and neither qualifies nor promotes.

## Acceptance gates before stable promotion

- Verify the delivered tarball digest and install it without workspace links.
- Exercise the intended repository and generic Web tool-card flows under the
  deployment policy that will be used in production.
- Record Windows, Linux, and macOS packed-installation evidence before claiming
  stable cross-platform support.
- Complete the Release Constitution evidence set, support matrix, holdout,
  effectiveness, utility, dogfood, and self-security review required by the
  accepted ADRs.
- Confirm zero unresolved Critical or High self-security findings and document
  any accepted Medium risk with explicit scope and expiry.
- Confirm package ownership, npm authentication/2FA, GitHub destination, and
  final release notes.

## Promotion rule

After every gate passes, promote the exact qualified code to `0.1.0` by changing
only version, signature, and release metadata. Any behavior or configuration
change creates a new release candidate and reruns qualification. Tagging,
GitHub upload, and npm publication happen only after acceptance.
