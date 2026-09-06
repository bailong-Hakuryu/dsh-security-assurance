---
status: accepted
---

# pnpm lockfile integrity is proved from frozen root metadata

The bundled `security/pnpm-lockfile-integrity` Policy evaluates only the root `package.json` and `pnpm-lock.yaml` captured in an immutable Subject. It accepts pnpm lockfile v9 when `packageManager` names one exact pnpm version, the root importer exactly matches the manifest dependency specifiers, and every package resolution carries a valid SRI digest; parsing, aliases, unsupported versions, or incompatible package managers fail closed. This deliberately chooses reproducible offline metadata over running pnpm or consulting a mutable Registry, and limits v1 to the root importer rather than making unsupported workspace-wide claims.
