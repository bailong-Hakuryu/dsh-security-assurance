# ADR 0326: Model Repository Choices Name Their Host Bindings

Status: Accepted

## Context

The direct-use composition registers the launch directory as the Host
binding `current-workspace` with the display name "Current workspace"
(`cordis.patch.yml`). Registrations are durable, so every launch from another
directory adds another ENABLED Repository with the same display name
(SECURITY-REVIEW F-15(c)). `security_repositories` returned only path-free
fields, so the entries were indistinguishable.

In a real run, launched from the third of three directories,
`security_repositories` returned three "Current workspace" entries. The model
picked the first one, assessed a different directory, and then reported that
assessment as covering the workspace it had been asked about. The Control
Plane gate was unaffected because it resolves `repositoryBindingId` through
the Host Repository Provider.

## Decision

The Host Repository Provider gains `bindings()`, which lists every configured
binding after registration settles. It is path-free, like `resolve`.

`security_repositories` adds `hostBindingIds` to each Repository that a
current Host binding resolved to, for example
`hostBindingIds: ["current-workspace"]`. Repositories left by earlier launches
carry no `hostBindingIds`. A binding identity is operator configuration, not
repository data, and roots still never reach the model.

A missing, failed, or disposing provider yields no marks. The tool never
guesses one, and the listing itself is unchanged.

The tool description and the `/security` prompt tell the model that the
Repository whose `hostBindingIds` includes `current-workspace` is the launch
workspace, and that display names alone do not identify a Repository.

## Consequences

- A standalone `/security` run picks the same Repository the Control Plane
  gate binds, even after launches from other directories.
- Stale registrations stay listed and ENABLED. Retiring them remains an
  operator action (F-15(c) is narrowed, not closed).
- One extra in-process provider read per listing; no Service call is added.
