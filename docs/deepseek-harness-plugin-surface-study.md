# DeepSeek Harness plugin surface study

Status: factual implementation input; not an ADR

This note records the local `deepseek-harness-master` facts that constrain the
DSH Security Assurance plugin. The Harness checkout was inspected read-only and
remains outside this product's implementation boundary.

## Inspected baseline

- Harness source: `D:\Deepseek\deepseek-harness-master`
- Harness package version observed: `0.1.1-rc.2`
- Required Node range observed: `^22.19 || >=24`
- Primary references: repository `AGENTS.md`, `docs/architecture.zh.md`,
  `docs/defensive-patterns.zh.md`, the Cordis primer/tutorial/service docs,
  plugin development docs, capability-seam guidance, package/tool cookbooks,
  testing policy, and the concrete subagent, workflow, filesystem, subprocess,
  sandbox, Web Client, Typert, and Web server packages.

## 1. Plugin boundary

Harness has no privileged product kernel that a third-party feature must patch.
Every runtime contribution is a Cordis plugin mounted into a configuration tree.
Security Assurance must therefore remain an external plugin bundle and must not
modify `agent-loop` or any file under the Harness checkout.

A distributable plugin uses an npm package with `dsh.bundle.patch` pointing to a
`cordis.patch.yml`. One package may expose several Cordis entry points, and its
patch may insert each entry separately. This matches the existing Control Plane
shape and does not require premature publication as several npm packages.

Configuration layers are applied after the base profile and can be overridden by
the user's profile/home/command-line overlays. A security-sensitive bundle can
therefore install dormant rows and require the deployment owner to enable them
with complete policy and repository configuration.

## 2. Capability seam

Harness models a replaceable capability as three roles:

1. Service Definition owns the public API and request/result vocabulary.
2. Service Provider implements that API.
3. Consumer exposes the capability to a model, command, UI, or another service.

Roles may share one npm package until they need independent publication or
replacement. The subagent and workflow families prove both shapes. Service
dependencies are declared with Cordis `inject`; ordering in YAML is not an
activation guarantee. If a required Service disappears, dependent fibers are
disposed and reactivate only when the Service returns.

For Security Assurance, the natural authoritative Host Service key is a unique
singular key such as `securityAssurance`. It should own Assessment operations and
the Engine lifecycle. Analyzer implementations form a versioned registry behind
that Service rather than separate Cordis Services per scan.

## 3. Registration and teardown

Registrations are reversible effects. `ctx.effect()`, `ctx.on()`, Service
registration, tool registration, Web routes, Remote mounts, and Client slot
contributions all have fiber-owned teardown. Security Assurance must prove that
unloading its rows removes every tool, route, contribution, listener, registry
entry, and live process, and that asynchronous teardown reaches quiescence.

Public run handles follow an explicit ownership boundary. Existing subagent and
workflow contracts establish the useful pattern: acceptance publishes a stable
identity; the holder owns cancellation/disposal; terminal domain failures settle
as typed results; only failures outside the contract reject; `dispose()` is
idempotent and waits for real resource shutdown.

## 4. Model-facing control surface

Tools are Consumer plugins registered through `ctx.tools.register(defineTool())`.
Their arguments are schema-validated before execution. Tool execution receives
an immutable execution identity and a required `AbortSignal`; canonical JSON
output is separated from model rendering. Security tools should call the public
Security Assurance Service and must never operate directly on SQLite or Evidence
files.

The minimal standalone operations already accepted by the product map cleanly to
bounded tools: start, status, resume, cancel, and export. Remediation, risk
acceptance, delivery, and tracking require distinct tools or commands because
their authority and side effects differ from read-only Assessment.

## 5. Subject and analyzer execution world

Harness exposes one filesystem execution world through `ctx.fs` and its paired
process world through `ctx.subprocess`:

- `ctx.fs` provides stable opaque file identities, canonical process paths,
  containment checks, no-follow final-component inspection, bounded byte reads,
  stable directory listing, and optional atomic mutation primitives.
- `ctx.subprocess` accepts fully specified argv without shell interpretation,
  scrubs sensitive and `DSH_*` environment variables, bounds collected output,
  owns process-tree termination, and waits for complete exit during disposal.
- `ctx.sandbox` can wrap process argv with a per-call filesystem policy and fails
  closed if requested confinement is unavailable.

The shipped sandbox vocabulary governs filesystem access only. It does not prove
network denial, syscall confinement, or credential isolation. Consequently, a
gate-bearing analyzer that needs stronger egress or isolation guarantees requires
a Security-owned execution backend/adapter whose capability descriptor states
what it can enforce. A backend unable to meet the frozen Execution Context may
produce only Advisory Findings, as already required by ADR 0017.

The immutable Subject and private Evidence Store are different worlds. Subject
reads should use the execution-world seam and explicit containment. Plugin-owned
SQLite, sealed bundles, encryption metadata, and staging belong below a resolved
DSH home path and must not be routed through model-facing filesystem tools.

## 6. Durable Engine

Harness session logs are authoritative for model-visible, same-session facts;
they are not a cross-session Assessment database. `ctx.jobs` is a generic live
task capability and is not a durable Assessment authority. The Security
Assessment Engine therefore needs its accepted plugin-owned SQLite journal plus
Evidence Store and a process-local Runner that recovers non-terminal Assessments
at startup.

The Engine should publish immutable snapshots/receipts from committed revisions.
Optional session events may project an Assessment launched from a chat into that
chat, but such events are views and replay aids, never the canonical workflow
state or verdict authority.

## 7. Workbench without Harness changes

The Web profile supports independently built Client plugins. A package declaring
`dsh.client` and exporting `./client` is discovered from the actual Loader tree,
served as its own browser bundle, and governed by a Client-side Cordis fiber.
This allows Security Assurance to ship a Workbench in the same installable bundle
without editing the Harness Web application.

Client UI composition is slot-only. The root and primary columns are single-owner
slots and must not be replaced. Additive entry points include `shell.overlay` and
`sidebar.footer.action`; a security launcher can occupy the latter and open a
Workbench overlay through the former. Unloading the Client plugin removes both.

Browser business code does not receive Host `ctx` and must not read plugin files.
The current Host/Client RPC seam is Typert Remote:

- the Host Service marks explicit methods and publishes generated strict
  descriptors/codecs through `./typert` and `./remote` exports;
- the Client plugin mounts its own generated Remote contribution through
  `ctx.remote.$mount()`;
- Workbench components call that Remote contract and render snapshots;
- no direct Store mutation or second UI state machine is introduced.

The old central API map is not the extension seam. Typert contribution mounting
lets this external plugin add its own namespace without changing Harness API
source. If Typert generation cannot be made self-contained for the tree-out
package, the fallback is a plugin-owned loopback HTTP route registered through
`ctx.webServer`; that fallback would need its own strict schema, cancellation,
origin/authentication, and packed-profile proof and should not be selected merely
for convenience.

## 8. Control Plane integration

Control Plane and Security Assurance remain separate Stores and Services. Their
integration crosses only versioned capability values:

- Control Plane freezes an Assurance Provider capability and issues an Assurance
  Execution Context.
- Security Assurance starts or resolves an Assessment through its public Service.
- only a sealed, digest-bound Assurance Submission is returned.
- Control Plane validates and imports the Submission by value; it never opens the
  Security database or treats the Security Verdict as Mission approval.

The provider adapter may live as a separate entry point in the Security package,
because it consumes both public contracts but does not own either kernel.

## 9. Packaging consequence

The smallest honest first package can remain one npm bundle with independent
entry points:

- package root: Security Assurance Service and Engine provider;
- `./tools`: model-facing Assessment Consumer;
- `./control-plane-provider`: optional Control Plane Provider adapter;
- `./client`: browser Workbench plugin;
- `./invariant`: startup/runtime contract checks;
- generated `./typert` and `./remote` artifacts when Workbench RPC is enabled;
- one `cordis.patch.yml` installing dormant Host rows and an optional Client row.

This is one plugin product and one installation unit. The internal modules remain
deep and separately testable; publication is split only after a real independent
provider or consumer requires it.

## 10. Required proof layers

Harness policy requires more than unit coverage for a product-visible plugin.
Security Assurance must include:

- per-file behavior and branch tests, including registry HMR disposal;
- deterministic Kernel, Policy, Evidence, seal, recovery, and authorization tests;
- a real Loader composition test using published entry points;
- packed/tarball installation smoke tests against the exact Harness release;
- real filesystem/subprocess/sandbox tests and hostile repository fixtures;
- crash/restart and SQLite migration fixtures;
- model-visible transcript or assembled snapshot tests for every non-trivial tool
  surface;
- Client component, Remote, HMR, and browser journey tests for the Workbench;
- capability-conformance and independent effectiveness suites defined by the
  product proof ADRs.

E2E assertions must inspect the external world and sealed records. An agent or
Analyzer claiming that a test passed is never itself proof that it passed.

## Open product decisions

The Harness facts above settle the extension mechanism. Remaining decisions are
product choices: the public package/Service names, exact entry-point contract,
Workbench placement, Analyzer execution backend policy, initial built-in Analyzer
set, startup/recovery behavior, and the boundary between always-installed dormant
rows and separately activated optional surfaces. These belong in ADRs before any
scaffolding begins.
