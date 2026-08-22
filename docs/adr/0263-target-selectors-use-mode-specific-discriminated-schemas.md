---
status: accepted
---

# Target Selectors use Mode-specific discriminated schemas

Target selection is a closed versioned discriminated union: Repository Target covers the admitted repository Subject, Change Target binds exact base and head or an immutable Change identity plus impact-cone rules, and Targeted Target binds explicit canonical components, packages, or relative paths under Policy limits. Free-form target prose, branch names without resolution, raw diff text, globs that escape the root, and Agent-interpreted selectors are invalid. Each selector's canonical form and digest enter Subject and Coverage identity.
