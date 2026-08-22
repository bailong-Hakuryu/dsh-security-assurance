---
status: accepted
---

# Seal, Verdict, Bundle, and Submission commit atomically

Before an Assessment can become SEALED, the Service completes canonicalization, digests, integrity checks, and atomic publication of immutable artifacts from private staging. One database transaction then commits the Seal, Verdict, canonical Bundle Manifest, and Submission identity against those exact artifact digests and the final revision. If any artifact or record is missing, inconsistent, or cannot be committed, no SEALED state exists; recoverable orphaned staging or unpublished records are never authoritative.
