---
status: accepted
---

# Prompt compilation separates trusted rules from untrusted data

A versioned Prompt Compiler constructs each Role invocation from immutable trusted system rules, a typed task envelope, an explicit Role Tool Manifest, and structurally delimited untrusted Subject and Evidence data. It never interpolates repository text as instruction or treats `AGENTS.md`, comments, documentation, filenames, generated content, tool-like markup, or model-directed requests as authority. The compiler records component versions and the final Prompt digest so the exact instruction boundary is auditable without exposing protected payloads in ordinary views.
