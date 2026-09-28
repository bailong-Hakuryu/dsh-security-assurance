# ADR 0328: Every Repository Surface Names the Launch Workspace

Status: Accepted; extends ADR 0326

## Context

The direct-use composition registers each launch directory as a Repository
named "Current workspace". Registrations are durable, so a user who has run
Harness from three project directories has three ENABLED entries with the
same name (SECURITY-REVIEW F-15(c)). ADR 0326 told the model which one the
Host bound at launch, but people saw the same ambiguity:

- the `security_repositories` tool card listed each entry only by display
  name, so three rows read "Current workspace";
- the Workbench repository list showed display names and Repository IDs, with
  nothing marking the launch directory.

Retiring the earlier registrations was rejected. Disabling is terminal in the
Security Service, so a user who returns to an earlier project could no longer
assess it, and two Hosts sharing one `DSH_HOME` from different directories
would disable each other's Repository. The earlier entries are projects the
user worked on, not stale data.

## Decision

- The Workbench Remote returns `WorkbenchRepositoryListV1`, whose entries
  carry the same path-free `hostBindingIds` as the model tool. The Service's
  `RepositoryListSnapshotV1` contract is unchanged; the marks come from the
  Host Repository Provider through `internal/host-binding-marks.ts`, which the
  model tool now shares.
- The Workbench repository list puts the launch workspace first and badges it
  "当前启动目录 / Launch workspace".
- The `security_repositories` card puts the launch workspace first, labels
  every entry "name · short Repository ID", and adds the same marker to the
  launch workspace's row.

## Consequences

- Model, card, and Workbench identify the same Repository as the launch
  workspace, and same-named entries can be told apart on every surface.
- Earlier registrations stay ENABLED and assessable. F-15(c) is mitigated by
  naming, not closed by retirement.
- A deployment that configures other binding IDs sees them in
  `hostBindingIds`; only `current-workspace` gets the badge and the ordering.
