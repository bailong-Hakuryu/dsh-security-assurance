# ADR 0327: Admit Harness 0.1.7

Status: Accepted; amends ADR 0322

## Context

npm `next` for DeepSeek Harness is `0.1.7-rc.2`. The daily compatibility
matrix ran `0.1.7-alpha.2`, `0.1.7-rc.1`, and `0.1.7-rc.2` as unverified
recent tags, and all of them failed while building the Control Plane, before
either plugin ran. Four changes in 0.1.7 were responsible:

1. The shared `plugin` message source kind is gone. `MessageSourceMap` is
   still merge-extensible, and each producer now declares its own kind.
   Session-format v4 rewrites released third-party `plugin` sources to
   `plugin:<name>`.
2. Harness vendors schemastery `3.18.4`, whose `Schemastery` interface has a
   third type parameter. Both plugins also depend on npm schemastery, locked
   at `3.18.1`. Both copies declare `global namespace Schemastery`, so the
   two interfaces merge and schema types stop resolving.
3. Cordis moves to `4.0.4`, with loader `1.0.5` and include `1.0.9`, outside
   the exact Cordis peers pinned when `0.1.5-rc.3` was admitted.
4. The primitives module renamed its icons (`IconDataOutline16` became
   `IconDataOutlineRegular`). It is still in the client module table, so the
   bundle loads, but the Workbench launcher resolved `undefined` and its
   `sidebar.footer.action` entry crashed (React error #130). Only a real
   browser on npm Harness 0.1.7-rc.2 showed this; the profile smoke only
   checks that Web answers.

## Decision

- Admit `0.1.7-alpha.2`, `0.1.7-rc.1`, and `0.1.7-rc.2`, which ship one
  vendor graph, into `SUPPORTED_HARNESS_VERSIONS` and both plugins' exact DSH
  peer disjunctions. Add Cordis `4.0.4`, loader `1.0.5`, and include `1.0.9`
  to the exact Cordis peers. `0.1.6-*` and `0.1.7-alpha.1` ship intermediate
  graphs; they stay outside the closed set and fail closed.
- `/security` and `/mission` declare their own source kinds,
  `dsh-security-assurance` and `dsh-engineering-control-plane`, with
  `form: 'instructions'`. Every supported Harness renders an unknown
  non-user kind as an injected-context row labelled by the kind, which matches
  the earlier `plugin` label. Neither plugin reads these messages back.
- The Workbench draws its own launcher, close, and empty-state icons and
  requests no export from `@deepseek-ai/dsh-client-ui-primitives`. ADR 0322's
  shared client surface still holds for the module table, slots, and loader,
  but not for a platform module's export names.
- Both plugins type-check against the host Harness's schemastery
  declarations through a `paths` entry. The runtime dependency on npm
  schemastery is unchanged; Harness 0.1.5-rc.3 already runs these plugins with
  a schema object from a different schemastery copy.

## Consequences

- One source tree compiles and passes the full suites on `0.1.2-alpha.1` and
  `0.1.7-rc.2`. The matrix now runs the three admitted tags as supported
  lanes.
- Sessions written before this change keep their `plugin` source until
  Harness 0.1.7 migrates them to `plugin:<name>`, so one conversation can
  show both labels.
- A Harness that ships yet another schemastery major would need its own
  declarations; the `paths` entry always follows whichever Harness checkout
  the plugin is built against.
