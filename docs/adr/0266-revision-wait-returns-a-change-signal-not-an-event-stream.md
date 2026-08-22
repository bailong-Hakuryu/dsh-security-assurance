---
status: accepted
---

# Revision wait returns a change signal not an event stream

`waitForAssessmentRevision` accepts Assessment ID, `afterRevision`, and bounded wait options and returns a Revision Wait Result containing `changed`, current revision, current lifecycle state, terminal indicator, and whether the caller should fetch a fresh Snapshot. It does not return Journal Facts, patches, Evidence, Finding payloads, progress logs, or a transport-specific subscription. Timeout and reconnect remain idempotent, and disclosure changes require a new authorized Snapshot query rather than trusting previously observed payloads.
