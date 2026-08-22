---
status: accepted
---

# Sensitive Evidence requires an explicit Key Provider

Sensitive Evidence encryption uses a host-configured Evidence Key Provider, and plaintext key material is never generated into or retained by the Security database. When the frozen Evidence Protection Policy requires encryption and the Provider is absent, invalid, or cannot unwrap required keys, the Service enters read-only safe mode: metadata may remain inspectable, but new Assessments and mutations are rejected and protected payloads remain unavailable.

