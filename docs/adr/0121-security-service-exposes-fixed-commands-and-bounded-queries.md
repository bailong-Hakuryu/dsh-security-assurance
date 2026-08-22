---
status: accepted
---

# Security Service exposes fixed commands and bounded queries

The public Security Service exposes an explicit typed surface for repository and assessment listing, start, get, revision wait, resume, cancel, bounded Finding and Evidence views, risk decision, sealed Bundle and Submission lookup, and authorized export. It exposes no Assessment Store CRUD, generic execute method, generic query language, raw SQL, or caller-selected mutation primitive. Every Assessment Command and Assessment Query performs authority, scope, state, revision, and disclosure checks inside the Service boundary.
