---
status: accepted
---

# Analyzers read only content-addressed Subject Snapshots

Every admitted Subject is materialized in plugin-private storage and bound by a canonical manifest of paths, byte digests, modes, links, exclusions, and root digest. Materialization may use copying, reflinks, or archive extraction but never an ordinary hard link whose bytes can change with the source workspace; all Analyzers read the resulting read-only snapshot rather than the original tree.

