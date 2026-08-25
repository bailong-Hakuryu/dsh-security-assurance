---
status: accepted
---

# Export Delivery recovery is Service-owned and bounded

`requestExport` durably commits its owner-bound `PENDING` record before artifact
I/O. The Security Service then performs the first idempotent attempt and owns a
lifecycle-bound worker that scans unfinished records at startup, wakes for new
work, and retries transient artifact or source-read failures after fixed
backoff. Delivery stops after five recorded attempts; an existing artifact with
different canonical bytes fails immediately as an integrity conflict. Status
exposes only bounded attempt count, timestamps, retry time, and safe failure
category, never a path or raw exception. The Workbench may refresh this Service
truth but owns no retry policy or delivery timer. Service teardown aborts the
worker wait and joins its current attempt before closing persistence.
