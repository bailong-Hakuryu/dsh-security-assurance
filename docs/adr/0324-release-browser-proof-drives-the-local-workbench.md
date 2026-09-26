# ADR 0324: The Release Browser Proof Drives the Local Workbench

Status: Accepted

## Context

The packed browser E2E produces the release `WORKBENCH` proof. It was written
for the retired Workbench client: a test-only reference package, declared in
the pre-`0.1.2` client manifest format, exposed a window bridge that opened the
Workbench under full and denied authority contexts from a deployment
resolver. Current Harness versions cannot load that package, so the scenario
could not run, and the proof stayed `INCONCLUSIVE` even after the candidate
shipped a Workbench again (ADR 0321). The Workbench flow was selected by a
package-private manifest marker that no candidate declared.

## Decision

The runner reads the packed manifest and the packed bundle patch. It drives the
Workbench flow only when the tarball exports `./client`, packs `lib/client.js`,
and enables the `dsh-security-assurance/workbench-local` row; otherwise it
verifies only the Harness Web shell and records `WORKBENCH_CLIENT_SHIPPED` as
`INCONCLUSIVE`.

The Workbench flow installs a fresh Harness from npm
(`DSH_BROWSER_HARNESS_VERSION`, default the npm `latest` in the verified set;
any other value must be in the verified set) and operates the page only
through real controls, with no test package, bridge, or authority context in
the browser:

- the launcher opens a dialog that takes focus, contains Tab, and returns focus
  on Escape;
- Runtime Health, the Repository list, the Catalog wizard, and Start Preflight
  run through the local context;
- a Risk Decision Window blocks one Assessment: the Service projects only
  cancellation, Evidence links stay inert before the seal, and the operator
  cancels it;
- a second Assessment seals: Evidence metadata opens, disclosure is refused,
  the Export is delivered to its registered destination, and no download is
  offered;
- a reload lists both Assessments again; losing the network fails closed and
  reopening recovers once the Host is reachable;
- an unauthenticated `/api` caller receives no context, a Chinese page offers
  the same Workbench, and no issued context, Host path, or script body reaches
  history, storage, the DOM, or the console.

The assertion identifiers are unchanged, so the proof contract and release
qualification are unchanged.

## Consequences

- `WORKBENCH` can pass for a candidate that ships the local Workbench, and it
  proves only the local operator's reach. Risk Decisions, disclosure, and
  download under a deployment resolver remain covered by Service and Remote
  tests, not by the browser proof.
- The runner needs network access to install Harness from npm and a local
  Chrome or Edge.
- A fresh npm install of an older verified Harness can fail on its own
  floating ranges: `0.1.2-rc.1` declares `@deepseek-ai/cordis: ^4.0.2`, which
  now resolves the 0.1.7-era Cordis, and its Host exits before listening. The
  runner reports the Host's output instead of timing out; the default version
  pins Cordis and is unaffected.
- On a failure the runner prints the Workbench dialog text, which never
  contains a context or a Host path.
