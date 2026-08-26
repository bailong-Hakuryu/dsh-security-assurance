# ADR 0250 Compliance Report

## Decision scope

ADR 0250 constrains Security Assurance configuration to Host-owned references and bounded operational choices. Configuration must not carry API tokens, encryption key material, repository credentials, production secrets, or caller-selected bypasses.

This report covers the configuration surfaces implemented in v0.1 today:

- Security Assurance root plugin configuration;
- Host Repository bootstrap configuration;
- Engineering Control Plane Assurance Provider activation configuration;
- dormant runtime-entry selection in `cordis.patch.yml`.

Broker, external Credential Provider, and Evidence Key Provider configuration fields are not currently exposed. They are therefore outside this implementation claim and must preserve the same reference-only boundary when introduced.

## Requirement mapping

| Requirement | Public implementation seam | Verification |
| --- | --- | --- |
| Root plugin accepts only declared non-secret configuration | Cordis activation of `SecurityAssuranceService` accepts only optional `dshHome` through a strict runtime schema | Unknown `apiToken` activation fails with one generic, value-free composition error |
| Repository bootstrap contains bindings, not credentials | `SecurityAssuranceHostRepositoryProvider` uses strict nested registration and binding schemas | Secret-bearing registration fails before Registry mutation; public Repository list remains empty |
| Provider activation contains public identifiers only | Engineering Control Plane canonicalizes bounded Provider configuration | Sensitive keys, known credential prefixes, compact JOSE/JWT values, and AWS access-key identifiers are rejected |
| Failure diagnostics do not disclose secret values | Configuration failures name only the invalid semantic field or use a generic activation error | Tests assert that supplied credential values are absent from thrown errors |
| Runtime entries remain explicitly enabled and dormant by default | `cordis.patch.yml` contributes disabled rows | Existing dormant-entry and packed side-effect tests |
| Legal public references remain usable | Provider `repositoryId` configuration remains accepted, detached, frozen, and canonical | Existing Effective Policy test |

## Genuine implementation gaps fixed

### Security root configuration was compile-time-only

The exported TypeScript `Config` interface allowed only `dshHome`, but the root Service did not validate configuration at runtime. JavaScript, YAML-derived, or otherwise untyped callers could supply `apiToken` or any other unknown field and the plugin would silently activate.

The root Service now validates configuration with a strict runtime schema before resolving paths or opening persistence. Invalid configuration fails activation with `Security Assurance configuration is invalid`, without reflecting keys or values.

### Control Plane Provider values missed credential-shaped formats

Assurance Provider activation already rejected sensitive configuration keys and several token prefixes, but accepted compact JOSE/JWT values and AWS access-key identifiers when placed under a benign-looking key.

Provider configuration validation now rejects both forms while preserving public identifier configuration such as a registered `repositoryId`.

## Verification

- Security Assurance ADR 0250 suite: 2 passing tests.
- Security Assurance full suite: 21 files, 245 passing tests.
- Security Assurance typecheck and build: passing.
- Security Assurance package dry run: 47 files.
- Packed consumer smoke: all package, lifecycle, Provider, gate, publication, and restart checks passing.
- Engineering Control Plane Effective Policy suite: 8 passing tests.
- Engineering Control Plane full suite: 27 files, 130 passing tests.
- Engineering Control Plane typecheck, lint, and build: passing.

## Assessment

ADR 0250 is complete for the configuration surfaces currently exposed by v0.1. Future broker, key-provider, Provider, Analyzer, diagnostic, or operational-default configuration must be added as strict reference-only fields and must not widen this conclusion to raw capabilities or secret material.
