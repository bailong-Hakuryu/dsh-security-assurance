---
status: accepted
---

# Security private state lives under DSH home

The Service keeps its SQLite database, content-addressed Evidence, Subject Snapshots, private staging, canonical Bundles, and temporary artifacts below the resolved `$DSH_HOME/security-assurance/` authority root. It never creates product state in the target repository; copying a derived export elsewhere is a separate authorized Delivery operation with an explicit destination.

