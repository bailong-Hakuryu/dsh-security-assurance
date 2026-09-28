# ADR 0329: Generated Codecs Span the Supported Harness Protocols

Status: Accepted; supplements ADRs 0324 and 0327.

The release candidate is built on Harness 0.1.2-alpha.1, whose generated
strict codecs expose a `schema`. Harness 0.1.7 requires `create()` instead.
Its loader rejected that candidate and withdrew the Remote definitions,
although the compatibility matrix passed after rebuilding with each Host's
own generator. Source compatibility did not establish artifact compatibility.

At generation time, embed a small compatibility adapter in both published
Host and Remote contributions. An eager schema gains a factory returning
that parser; a factory-only codec gains a memoized schema getter. New
generators retain lazy materialization. The generated type symbols, parsers,
lookup descriptors, authorization and result validation remain unchanged.
Missing strict codecs or unusable parsers throw; no SRC fallback is enabled.
The client bundle includes the same adapted Remote contribution.

This keeps the primary build target and the closed supported version set.
Switching only the release build to 0.1.7 would reverse the incompatibility
for older Hosts. Text replacement of individual generated schema expressions
would couple the adapter to generator formatting; adapting the exported
descriptors preserves the generator's validators directly.

The public-artifact regression tests exercise both access paths and reject
invalid request and result values. The matrix runs them with each generator.
Release browser acceptance must also run the exact retained candidate on
0.1.5-rc.3 and 0.1.7-rc.2, with separate proof indexes because each run has
the same `WORKBENCH` proof kind. A rebuild per Host cannot substitute for
this same-artifact check.
