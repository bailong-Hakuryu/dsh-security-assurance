# ADR 0253 Compliance Report

## Decision

ADR 0253 requires an optional `./invariant` Cordis companion that verifies the
deployed Harness composition and contributes the result to Security Assurance
Runtime Health. The companion must remain dormant unless explicitly enabled,
must not repair or patch the runtime, and must own all effects through Cordis
Fiber lifecycle.

## Implementation

`src/invariant.ts` is a package-owned companion registered through
`@deepseek-ai/dsh-invariants`. It is a module plugin with `name`, `inject`, and
`apply`; it does not register another public Cordis Service.

Activation has two layers:

1. The outer companion requires the Harness `invariants` registry.
2. The registered child installer requires the `securityAssurance` Service,
   evaluates the composition, publishes one immutable Health contribution, and
   registers automatic revocation on its child Fiber.

`src/internal/harness-verification.ts` defines the versioned package-private
protocol shared by the root Service and companion. Contributions require an
opaque authority and an owner token. A stale Fiber cannot revoke a newer
contribution, and received checks are copied and frozen before retention.

The public observation seam is only `SecurityAssuranceService.getHealth()`.
There is no public invariant Service, manual `dispose()` method, or verification
accessor.

## Required Checks

The companion publishes exactly six required checks:

| Check | Evidence |
| --- | --- |
| `composition.harness-version` | The invariant registry and Typert registry package versions exactly equal `TARGET_HARNESS_VERSION` (original ADR 0253 baseline; ADR 0310 later replaces this with one coherent release from the closed `SUPPORTED_HARNESS_VERSIONS` set). |
| `composition.required-service-definitions` | `securityAssurance`, `invariants`, `loader`, and `typert` expose their required runtime operations. |
| `composition.bundle-dependencies` | Cordis, Loader, invariant registry, Typert registry, and Zod package manifests resolve at runtime. |
| `composition.generated-contract` | The registered `dsh-security-assurance#host` Typert model contains every public Security Assurance method, and each method exists on the live Service. |
| `composition.capability-identity` | Package, face, package key, Service key, and exported Service identity match the generated host contract. |
| `composition.declared-runtime` | Enabled Loader entries exist for both `dsh-security-assurance` and `dsh-security-assurance/invariant`. |

Every check has status `PASS`, `FAIL`, or `NOT_EVALUATED`. Overall verification
is `PASS` only when every required check is `PASS`; both `FAIL` and
`NOT_EVALUATED` therefore produce overall `FAIL`.

## Runtime Admission

When the companion is absent, Health reports `PENDING_INVARIANT` and no
composition checks. When it is active:

- `PASS` permits normal mutation admission, subject to the existing persistence,
  Node, and lifecycle gates.
- `FAIL` moves an active Service to `READ_ONLY_SAFE` and rejects mutation
  commands with `UNAVAILABLE` while queries remain available.
- Disposing the real companion Fiber revokes its checks and restores
  `PENDING_INVARIANT` without disposing the root Service.

Diagnostics are bounded and redact credentials, API keys, provider tokens,
bearer tokens, JWTs, URLs, IP-independent paths, and long hexadecimal secrets
before entering public Health.

## Bundle Declaration

`cordis.patch.yml` declares both the root Service and the invariant companion as
disabled entries. Deployment owners enable them deliberately; package install
alone has no runtime side effects.

The package exports `./invariant`, includes its JavaScript and declaration files
in the publication allowlist, and declares the Harness Loader, invariant
registry, and Typert registry peer contracts used by verification.

## Verification Coverage

`tests/invariant.spec.ts` verifies behavior through public seams:

- dormant `PENDING_INVARIANT` behavior;
- all six checks passing under a valid declared composition;
- fail-closed handling of a required `NOT_EVALUATED` check;
- real mutation rejection in `READ_ONLY_SAFE`;
- automatic revocation through real `Fiber.dispose()`;
- generated-method and capability-identity mismatch detection;
- missing enabled Loader entry detection; and
- public diagnostic redaction.

Build generation also verifies that `lib/invariant.js` and its declarations are
produced and that the companion is not emitted as a Typert business Service.

## Compliance Status

ADR 0253 is fully implemented. The implementation is dormant, read-only,
fail-closed while active, Fiber-owned, Health-observable, and aligned with the
Harness invariant registry and generated-contract seams.
