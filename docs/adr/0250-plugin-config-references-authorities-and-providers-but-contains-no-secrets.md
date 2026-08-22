---
status: accepted
---

# Plugin config references authorities and Providers but contains no secrets

Security Assurance configuration may select the authority root, Host Policy and Profile identities, enabled runtime entries, Repository Registry bootstrap policy, Provider and Analyzer IDs, qualified broker and key-provider references, concurrency and bounded operational defaults, and diagnostics behavior. It never embeds API tokens, encryption key material, repository credentials, production secrets, or a caller-selected bypass; such material is resolved through the Evidence Key Provider or Credential and Egress Broker under authority. Repository `.env` and Subject configuration are untrusted data and never supply plugin secrets.
