---
status: accepted
---

# npm publish surface is a manifest contract

The bundled `security/npm-publish-surface` Policy evaluates only the exact frozen root `package.json` and proves that a public package identity, access declaration, explicit files allowlist, and all declared exports, main, types, and bin targets are mutually consistent. Version 1 intentionally remains a PURE offline manifest contract: it does not execute `npm pack`, enumerate the filesystem, consult the Registry, or claim package provenance or dependency safety; those claims require separately bound release artifacts.
