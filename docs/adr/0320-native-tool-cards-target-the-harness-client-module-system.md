# ADR 0320: Native Tool Cards Target the Harness Client Module System

Status: Accepted

## Context

ADR 0307 retired the legacy Workbench client and left Web users with Harness's
generic tool rows: a generic title, the raw tool name, raw JSON arguments, and
a raw JSON result. It required that any future native client target the
then-current Harness client extension surface and carry its own compatibility
ADR and browser acceptance gate.

Every supported Harness version, `0.1.2-alpha.1` through `0.1.5-rc.3`, shares
one client extension surface:

- the Host serves a package's built `./client` export when an enabled Loader
  row names the package exactly and its manifest declares `dsh.client` with
  `platform: "web"`;
- the served file is a lazy-CJS factory registered through
  `window.__ModuleLoader__.load({ id, factory })`, whose `require` resolves only
  the page's module table (including React);
- the keyed `tool.call.toolview` slot renders one view per wire tool name with
  the same owner properties and the same running/settled tool-call blocks.

Harness publishes no bundling preset for packages outside its repository.

## Decision

The package ships a browser-only `./client` bundle that registers one
Security card per model tool in `tool.call.toolview`. Its tsdown entry
reproduces the loader factory artifact directly and keeps React and every
`@deepseek-ai/*` specifier external, so the package adds no runtime
dependency and ships no copy of React.

Each card is a pure function of the tool-call block: a one-line title and
summary with state, verdict, and severity chips, expandable into detail fields
and the raw input/output. Cards read nothing beyond the blocks the conversation
already holds, call no Service, hold no authority, and render text only through
React text nodes. Styles use only Harness theme tokens present in every
supported version and honor reduced motion. Strings ship in Chinese and English
(ADR 0294); canonical identifiers are never translated.

The client is not the Workbench. Release tooling selects the Workbench browser
flow only from an explicit package-private marker, so shipping `./client` alone
never claims `WORKBENCH_CLIENT_SHIPPED`.

## Consequences

- Direct Web users see purpose-built Security cards instead of raw JSON rows,
  in live sessions and in replayed history.
- The packed profile smoke asserts that the Web boot graph lists the package's
  client and serves it as a loader factory artifact, on each Harness version
  the compatibility matrix exercises.
- A Harness change to the client module system, the toolview slot, or the
  tool-call block shape requires a compatibility review before admission.
- Non-Web surfaces keep the generic presentation; tool results and the model
  contract are unchanged.
