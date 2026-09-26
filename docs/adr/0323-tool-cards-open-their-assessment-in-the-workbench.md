# ADR 0323: Tool Cards Open Their Assessment in the Workbench

Status: Accepted

## Context

A `/security` conversation shows each Security tool call as a card
(ADR 0322), and the Workbench (ADR 0321) shows the full Assessment: progress,
Findings, Evidence metadata, and the Bundle. The two surfaces were
disconnected, so an operator who saw a status or findings card had to open the
Workbench from the sidebar and find the same Assessment in its list.

Cards are pure functions of the tool-call block and must stay that way: a
replayed or streamed block, or one produced by a model following untrusted
repository text, must never let a card reach a Service or an authority
context.

## Decision

A card whose call concerns exactly one Assessment names it: the start,
status, findings, resume, cancel, and export tools take the identity from the
settled result or, while running, from the call arguments. A failed call, a
discovery tool, or any value that is not a canonical Assessment identity names
nothing.

The client bundle creates one Workbench bridge per page. The cards receive
only its availability snapshot and an `open` request through their slot
registration; the Workbench attaches an opener once it is installed and
detaches it on disposal. While no Workbench is attached — for example before
the Remote transport exists — cards offer no action and `open` does nothing.

When the Workbench is available, a card that names an Assessment shows an
open action in its row and in its expanded actions. Opening shows the
overlay, requests a fresh local context exactly as the launcher does, and
loads that Assessment. The Service decides whether this operator may read it,
and a failure fails closed on that Assessment.

An opened Assessment is not a dead end: its detail view leads back to the
Assessment list under the same context, whether it was reached from a card or
from the list.

## Consequences

- A card still calls no Service and holds no context; the bridge rejects any
  identity that is not canonical before the Workbench sees it.
- An identity a model supplies can open only an Assessment the local operator
  could already read from the Workbench list.
- A Host that exports no local authority keeps the Workbench's
  Host-integration guidance, as the launcher does.
- Cards render unchanged on a Host without the Remote transport.
