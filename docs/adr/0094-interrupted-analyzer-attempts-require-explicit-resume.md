---
status: accepted
---

# Interrupted Analyzer attempts require explicit resume

Startup recovery may deterministically complete or roll back an unfinished database transaction, but it never silently re-executes an Analyzer Attempt. An Attempt that began without a durable terminal outcome is retained as interrupted, its Assessment becomes `BLOCKED`, and an authorized explicit resume creates a new budgeted Attempt with its own provenance.

