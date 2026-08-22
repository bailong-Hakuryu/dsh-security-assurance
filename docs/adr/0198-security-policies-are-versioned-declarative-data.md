---
status: accepted
---

# Security Policies are versioned declarative data

Every Security Policy is a schema-versioned declarative document compiled into a canonical Policy AST. The language contains typed requirements, selectors, thresholds, obligations, exceptions, authority rules, and composition operators but no executable JavaScript or TypeScript, dynamic imports, templates with Host access, arbitrary commands, or natural-language clauses whose meaning requires a model. Unknown schema versions or constructs fail compilation rather than being ignored or guessed.
