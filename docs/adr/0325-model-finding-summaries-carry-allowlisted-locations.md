# ADR 0325: Model Finding Summaries Carry Allowlisted Locations

Status: Accepted; amends ADR 0130

## Context

ADR 0130 keeps model tools to redacted Finding summaries, and ADR 0268 keeps
Source Anchors in the authorized Finding Detail View. The summaries therefore
contain no repository-controlled text at all. In a real run the model reached
the right conclusion only by reading `package.json` itself and marking the
link as its own inference, while the Workbench showed the anchor
(`package.json`, `/scripts/postinstall`) to the same user.

A Source Anchor's path and JSON pointer come from the repository, so passing
them to the model reopens a channel for repository-controlled text.

## Decision

`security_assessment_findings` reads each listed Finding's Detail View
through the same `assessment:read` authority and adds a `location` —
`{ path, pointer }` — only when both are plain:

- the path is repository-relative, with at most eight `/`-separated segments,
  each 1–64 characters from `[A-Za-z0-9._-]` and never `.` or `..`;
- the locator is a JSON pointer that is empty or starts with `/`, with at most
  eight segments under the same rule, so escaped (`~0`, `~1`) segments are
  excluded too.

Anything else is omitted rather than escaped. The anchor's file digest, the
file's content, and every other Detail View field stay out of the model
result, and a Finding whose detail cannot be read simply has no location. The
tool description and output schema tell the model to treat the location as
repository data, not instructions. The Service's summary and detail
contracts (ADR 0268) are unchanged; only the model-tool projection widens.

## Consequences

- The model can state exactly where a Finding is instead of inferring it, and
  the findings card shows the same `path#pointer`.
- The only repository text a model tool now carries is a short run of
  identifier-like characters with no spaces, markup, or control characters.
  A plain token such as `ignore_previous` can still pass; that residual risk
  is accepted as bounded by the 64-character segment limit and the
  eight-segment cap.
- A findings page costs one extra Detail View read per listed Finding.
