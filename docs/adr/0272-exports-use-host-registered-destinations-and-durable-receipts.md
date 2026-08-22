---
status: accepted
---

# Exports use Host-registered destinations and durable Receipts

`requestExport` accepts a SEALED Assessment ID, named Export Profile, Host-registered Delivery Destination ID, Contract Version, idempotency key, and any destination-specific bounded non-secret options allowed by that registration. It never accepts an arbitrary absolute path, URL, credential, shell command, or browser-selected Store location and returns a Command Receipt for durable Delivery work. `getExport` returns status, artifact identity, digest, profile, redacted destination summary, expiry and authorized access action; browser download uses a short-lived one-use Host capability rather than a path.
