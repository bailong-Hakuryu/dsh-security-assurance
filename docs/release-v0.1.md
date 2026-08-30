# v0.1 Release Candidate Checklist

## Candidate

- Package: `dsh-security-assurance`
- Candidate version: `0.1.0-rc.4`
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

It covers type checking, the full current-Harness deterministic test suite, a
clean build, npm pack inspection, and a fresh Harness `0.1.2-alpha.1` Web
profile that installs both packed bundles, composes their active rows, boots a
clean Git repository, completes browser-token authentication, and serves the
Web page. Legacy `0.1.1-rc.2` consumer and browser scenarios remain available
as non-release compatibility checks. The exact delivered tarball and source
revision are recorded in the external delivery manifest.

For final artifact verification, the packed scripts accept absolute artifact
paths through `DSH_SECURITY_PACKED_ARTIFACT` and
`DSH_CONTROL_PLANE_PACKED_ARTIFACT`. This makes the latest-Harness profile
smoke exercise the exact files whose SHA-256 digests are delivered.

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
