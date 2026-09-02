# Invariant Entry Usage Guide

## Purpose

`dsh-security-assurance/invariant` is an optional, dormant Harness companion.
When enabled, it validates the deployed Security Assurance composition and
publishes the result through the root Service's Runtime Health snapshot. It does
not start Assessments, mutate Security Assurance state, repair configuration,
or patch Harness.

## Activation

The normal Harness composition uses the disabled rows supplied by
`cordis.patch.yml`:

```yml
- id: dsh-security-assurance
  name: dsh-security-assurance
  disabled: false
- id: dsh-security-assurance-invariant
  name: dsh-security-assurance/invariant
  disabled: false
```

The Harness invariant registry, Loader, and Typert registry must already be part
of the Host composition. The root Service remains usable without the companion;
in that case Health reports `PENDING_INVARIANT`.

For a programmatic integration test, load the companion as a module plugin:

```ts
import { Context } from '@deepseek-ai/cordis'
import { InvariantRegistry } from '@deepseek-ai/dsh-invariants'
import SecurityAssuranceService from 'dsh-security-assurance'
import * as securityAssuranceInvariant from 'dsh-security-assurance/invariant'

const ctx = new Context()
await ctx.plugin(InvariantRegistry)
await ctx.plugin(SecurityAssuranceService, { dshHome: '/var/lib/dsh' })
await ctx.plugin(securityAssuranceInvariant)
```

Loader and Typert must expose the real deployment entries and generated host
package record for verification to pass.

## Reading Results

Health is the only public verification API:

```ts
const result = await ctx.securityAssurance.getHealth(trustedInvocation, {
  schemaVersion: 1,
})

if (result.ok) {
  console.log(result.value.compatibility.harnessVerification)
  for (const check of result.value.checks) {
    if (check.id.startsWith('composition.')) {
      console.log(check.id, check.status, check.message)
    }
  }
}
```

`harnessVerification` has three states:

- `PENDING_INVARIANT`: the optional companion is not active.
- `PASS`: all six required composition checks passed.
- `FAIL`: at least one required check failed or could not be evaluated.

An active `FAIL` places the Service in `READ_ONLY_SAFE`: queries remain
available, while mutation commands return a retryable `UNAVAILABLE` result.

## Checks

The companion emits exactly these required checks:

1. `composition.harness-version`
2. `composition.required-service-definitions`
3. `composition.bundle-dependencies`
4. `composition.generated-contract`
5. `composition.capability-identity`
6. `composition.declared-runtime`

`NOT_EVALUATED` is diagnostic detail, not a bypass. Because every composition
check is required, it causes the overall result to be `FAIL`.

## Troubleshooting

### Required Service Definitions fail

Confirm the active Context provides:

- `securityAssurance` with its Health API;
- `invariants.register()`;
- `loader.entries()`; and
- `typert.getPackage()`.

The companion intentionally does not require unrelated `logger` or `http`
Services.

### Generated contract or capability identity fails

Regenerate and register the host Typert contribution for
`dsh-security-assurance#host`. The main model must use Service key
`securityAssurance`, export name `SecurityAssuranceService`, and contain every
public Service method.

### Declared runtime fails

Inspect Loader entries and confirm both exact identities are enabled:

- `dsh-security-assurance` -> `dsh-security-assurance`
- `dsh-security-assurance-invariant` -> `dsh-security-assurance/invariant`

A disabled, renamed, or absent row is a failure.

### Harness version fails

The installed `@deepseek-ai/dsh-invariants` and
`@deepseek-ai/dsh-typert-registry` versions must be identical and belong to
the closed `SUPPORTED_HARNESS_VERSIONS` set. A mixed supported-version runtime
or any unverified version fails closed; see ADR 0310.

### Companion unloads

No manual cleanup API exists. Disposing its Cordis Fiber automatically removes
the composition checks and returns Health to `PENDING_INVARIANT`. This is the
expected lifecycle behavior.

## Operational Guidance

- Enable the companion in integration, staging, and production compositions
  where drift must block mutations.
- Alert on `harnessVerification: FAIL` and review the individual redacted check
  messages.
- Fix the declared composition or package versions; do not bypass admission or
  add runtime repair logic.
- Keep the companion dormant only when the deployment deliberately accepts an
  unverified composition.

See [ADR 0253 Compliance Report](./adr-0253-compliance-report.md) for the
requirement-to-implementation mapping.
