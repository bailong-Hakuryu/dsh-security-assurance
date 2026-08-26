# ADR 0252 Compliance Report

## Decision

ADR 0252 requires every transport Adapter to derive trusted channel authority, validate transport framing, propagate cancellation, invoke one Security Service operation, and translate the resulting DTO or `SecurityResult`. Domain Policy, Store mutation, Coverage or Verdict calculation, retries, redaction, and durable state machines belong to the Security Service.

## Requirement mapping

| Requirement | Implementation seam | Verification |
| --- | --- | --- |
| Trusted channel authority | Model tools derive a live Harness-session Invocation; Workbench resolves an opaque Host authority context; the Control Plane Provider derives its fixed Provider authority during Cordis composition | Existing tool, Workbench Remote, and Control Plane Provider suites reject missing or mismatched channel authority |
| Transport framing | Tools parse operation schemas and project bounded model DTOs; Workbench handlers accept generated Typert contracts; Provider validates its exact `repositoryId` configuration | Existing adapter suites cover malformed requests and invalid Provider configuration |
| Cancellation propagation | Tool and Workbench handlers pass the caller signal; Provider maps `ProviderInvocationOptions.signal` into the Service call | Existing cancellation tests plus the packed integration smoke exercise the published surfaces |
| One Service operation per Adapter entry | Each tool and Workbench handler delegates once to its corresponding public operation; each Provider `assess`, `recover`, and `cancel` entry delegates once to the package-private Service-owned Control Plane operation | ADR 0252 source-boundary test requires exactly three Provider delegations and forbids direct calls to the seven lower-level assessment operations |
| No Adapter domain dependencies | Shipped Adapters may import only their documented authority, framing, freezing, canonical translation, or Service-operation helpers | ADR 0252 import-allowlist test covers model tools, Workbench Remote, Host Repository Provider, and Control Plane Provider |
| Service owns orchestration and decisions | Security Service now owns Provider idempotency keys, Repository binding verification, assessment start/wait/recovery, cancellation reconciliation, outcome normalization, and Coverage calculation | The existing real two-plugin Provider suite remains green after moving the seam |
| Adapter translation only | Provider seals the Control Plane submission from the normalized Service outcome without inspecting Security verdict or coverage resolutions | ADR 0252 test forbids verdict/coverage derivation and retry loops in the Provider source |

## Genuine implementation gap fixed

### Control Plane Provider contained a second domain state machine

The Provider previously called seven lower-level Security operations directly, generated command idempotency keys, verified Repository bindings, waited and resumed Assessments in a loop, retried cancellation reconciliation four times, and calculated the claimed outcome and Coverage projection. This meant a domain fix in the Service would not automatically fix the Control Plane Adapter.

The orchestration now lives behind one package-private operation owned and installed by `SecurityAssuranceService`. `assess`, `recover`, and `cancel` each validate Provider framing, make one Service call, and translate the normalized result into the Control Plane contract. The optional Control Plane runtime remains outside the root Service dependency graph.

## Scope notes

The Host Repository Provider may iterate bounded Host configuration during startup because one configured registration is one transport request; it does not inspect or mutate the Security Store and retains only path-free binding DTOs. Workbench evidence guards verify that a Service DTO matches the narrower transport profile; they do not alter Service redaction or disclose additional data.

## Verification

- ADR 0252 dedicated suite: 2 passing tests.
- Real two-plugin Control Plane Provider suite: 9 passing tests.
- Security Assurance full suite: 23 files, 253 passing tests.
- Engineering Control Plane full suite: 28 files, 131 passing tests.
- Both plugin typechecks and builds: passing; Control Plane lint: passing.
- Security package dry run: 47 files.
- Packed consumer smoke: imports, lifecycle, model tools, Workbench, Provider integration, gates, unload, and restart all passing.

## Assessment

ADR 0252 is complete for every shipped v0.1 transport Adapter. The audit found and removed one real architectural violation rather than only adding verification: the Control Plane Provider no longer owns Security assessment behavior, so Service-side fixes now govern every surface.
