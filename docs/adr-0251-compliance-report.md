# ADR 0251 Compliance Report

## Decision

ADR 0251 requires an authorized, bounded Runtime Health Snapshot with explicit `READY`, `READ_ONLY_SAFE`, `QUIESCING`, and `STOPPED` states. Safe Mode must keep trustworthy diagnosis and already verified sealed records queryable while every new mutation fails closed.

## Requirement mapping

| Requirement | Public implementation seam | Verification |
| --- | --- | --- |
| Authorized bounded health | `getHealth` requires `health:read`, validates a versioned empty request, returns a frozen `SecurityResult<RuntimeHealthSnapshot>` | Missing authority returns redacted `UNAUTHORIZED`; existing health tests cover malformed requests, cancellation, deadlines, immutability, and unexpected-error redaction |
| Explicit lifecycle | Service-owned lifecycle drives `READY`, `QUIESCING`, and `STOPPED`; failed startup admission derives `READ_ONLY_SAFE` | Public Cordis teardown tests observe `QUIESCING` while owned Analyzer disposal drains and `STOPPED` after disposal |
| Exact admission | Startup-captured Node compatibility and private-store availability govern mutation admission | Supported runtime/store reports `READY`; foreign store and unsupported Node report `READ_ONLY_SAFE` with named checks |
| Safe Mode fails mutations closed | All eight commands share one runtime mutation-admission predicate; startup recovery uses the same predicate | Unsupported-Node test submits valid requests to every command and receives retryable `UNAVAILABLE`; Registry remains unchanged |
| Trustworthy diagnosis remains available | Store-independent `getCatalog` remains available without Repository or preflight selection | Foreign-store test reads the bounded global Catalog while Store-backed Repository operations reject |
| Quiescing admits reads only | The private Store remains readable while owned effects drain; commands reject as soon as lifecycle leaves `ACTIVE` | Repository list succeeds during the Analyzer disposal barrier while disable rejects |
| Verified sealed records remain queryable | Sealed Submission and Export Preview reads remain enabled when persistence and artifact integrity pass, even if Node composition is incompatible | Restart test creates a sealed Assessment, restarts under Node 23, reads Submission and Export Preview, and rejects a new Export Request |
| Diagnostics are redacted | Health checks expose stable IDs, bounded messages, versions, and admission only | Foreign database test proves the DSH home, database filename, and foreign table name are absent |

## Genuine implementation gaps fixed

### Teardown was reported as Safe Mode

A retained public Service reference returned `READ_ONLY_SAFE` after Cordis disposal and continued to claim query admission. The Service now owns an explicit lifecycle: mutations close at `QUIESCING`, bounded Store reads remain available while owned effects drain, and every admission class closes at `STOPPED`.

### Health admission and command admission disagreed

An unsupported Node version changed the health snapshot to `READ_ONLY_SAFE`, but command implementations only checked Store availability and disposal. Commands could therefore still mutate while health claimed they were closed. Runtime compatibility is now captured at Service construction and shared by startup recovery and all eight command entrypoints.

### Safe Mode disabled too much diagnosis

The global Security Catalog was rejected whenever the private Store was unavailable even though it does not require Repository state. It now remains available for bounded diagnosis; Repository-bound Catalog and Store queries still fail closed.

The health snapshot also tied sealed-record reads to mutation admission. It now reports sealed exports available whenever the active Service has a validated Store, allowing integrity-verified reads on an incompatible runtime while continuing to block new Export Requests.

## Current scope

The v0.1 Service currently has mandatory SQLite and Node compatibility checks plus a dormant Harness composition check. It does not yet expose mandatory external key-provider or broker configuration. Any future mandatory key or Provider must contribute a named redacted health check and enter the same mutation-admission decision before this compliance claim is extended to it.

## Verification

- ADR 0251 dedicated suite: 6 passing tests.
- Security health suites: 12 passing tests.
- Security Assurance full suite: 22 files, 251 passing tests.
- Typecheck and build: passing.
- Package dry run: 47 files.
- Packed consumer smoke: package imports, lifecycle, Provider integration, gates, publication, unload, and restart all passing.

## Assessment

ADR 0251 is complete for the v0.1 runtime dependencies and public Service operations currently implemented. The implementation now distinguishes lifecycle shutdown from Safe Mode, enforces the advertised mutation boundary, retains only trustworthy reads, and keeps diagnostics bounded and redacted.
