# ADR 0310: Harness Compatibility Window Is an Explicit Verified Set

Status: Accepted

## Context

The plugin was first qualified against one exact Harness release candidate
(ADR 0117) and later re-targeted to Harness `0.1.2-alpha.1` (ADR 0307), with
the composition invariant failing closed on any other resolved Harness
runtime version. Harness has since published `0.1.2-alpha.2` through
`0.1.2-alpha.5`, so the three most recent verifiable tags no longer include
the qualification target.

A single exact pin cannot express verified support for several Harness
versions, while an open semver range would claim compatibility with future
versions that have never been built or probed. Support claims must stay
backed by evidence, and a newly published Harness tag must surface as a
verification signal without anyone editing a workflow first.

## Decision

The compatibility window is a closed, explicit set:
`SUPPORTED_HARNESS_VERSIONS` in `src/contracts.ts`, led by the primary
qualification target `TARGET_HARNESS_VERSION`. The composition invariant
admits exactly one coherent release from this set, rejects a runtime assembled
from different supported package versions, and keeps failing closed on
anything else; peer dependency ranges spell out the same versions as an exact
disjunction.

A scheduled Harness Compatibility workflow, owned by this repository on
behalf of both plugins, lists the official Harness tags daily and feeds the
union of the three most recent tags and the declared supported set into an
auditable matrix JSON. Each lane records the peeled release-tree commit and
checks out that immutable SHA rather than trusting a tag to remain unmoved.
Product-code changes also trigger the matrix. The primary target runs on
Ubuntu, macOS, and Windows;
every other version runs on Ubuntu; every lane runs on Node 22 and 24 and
executes both the dual-plugin joint E2E (Mission, Developer workspace
change, CHANGE Assessment, sealed submission, Quality Gate propagation) and
a packed dual-tarball fresh-profile installation with a live Web probe.

A newly published tag therefore enters verification automatically and fails
closed there until a reviewed change admits it into the supported set. A
manual workflow dispatch accepts one Harness ref for debugging and runs it
across the full primary lane set. Discovery never skips missing versions
silently: an unreachable remote, fewer than three verifiable tags, or a
declared version missing upstream all fail the workflow.

Where Harness patch releases drift a public shape — `0.1.2-alpha.4` replaced
the `Session.events` getter with `snapshotEvents()` — the plugin reads
through a capability-tolerant seam that accepts each verified shape and
fails closed on anything else, never through version sniffing at runtime.

## Consequences

- Every supported-version claim is backed by a passing matrix lane on each
  supported Node major, and the README badge reflects the scheduled state.
- A new upstream Harness tag produces an automatic red-or-green signal; the
  fix for red is a deliberate supported-set extension after local
  verification, never a silent skip.
- Adding a Harness version means updating `SUPPORTED_HARNESS_VERSIONS`, the
  peer dependency disjunctions, and the README support matrix together, kept
  consistent by `tests/harness-compat-matrix.spec.ts`.
- The primary qualification target stays `0.1.2-alpha.1`; re-targeting is a
  separate decision with its own release-gate consequences.
