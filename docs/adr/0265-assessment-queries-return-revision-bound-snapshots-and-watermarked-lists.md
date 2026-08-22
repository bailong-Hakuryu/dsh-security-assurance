---
status: accepted
---

# Assessment queries return revision-bound Snapshots and watermarked lists

`getAssessment` returns one immutable authority-filtered Assessment Snapshot bound to its committed revision, state, frozen contract identities, bounded progress and Coverage summary, Verdict when sealed, blocker summary, and available actions. `listAssessments` returns only redacted Assessment List Items through a stable keyset cursor and first-page consistency watermark. Neither operation exposes aggregate internals, event journals, Work Items, private paths, raw Provider diagnostics, or mutable objects.
