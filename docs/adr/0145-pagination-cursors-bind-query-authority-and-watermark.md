---
status: accepted
---

# Pagination cursors bind query authority and watermark

Bounded collection queries use opaque keyset cursors rather than caller-controlled offsets. A cursor binds the normalized query and filters, resolved disclosure authority and Repository scope, stable ordering keys, page-size ceiling, and the first page's consistency watermark; changing any binding invalidates it instead of broadening the result. Queries neither return unbounded pages nor reveal counts, gaps, or identifiers outside the caller's authorized view.
