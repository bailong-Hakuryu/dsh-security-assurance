---
status: accepted
---

# Tests have no security semantic bypass

Production code exposes no `testMode`, magic Principal, integrity skip, plaintext shortcut, direct Store mutation, automatic Risk Acceptance, or hidden transition that weakens a security invariant. Deterministic test dependencies enter through the same authenticated registration and Provider seams used in normal operation. Assertions requiring internal verification use a separate read-only Test Forensic Reader outside the product process and cannot manufacture a state that public commands could not lawfully commit.
