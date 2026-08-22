---
status: accepted
---

# Sensitive Evidence is protected and secrets are never retained

The Security Evidence Store uses a plugin-owned least-privilege directory, content addressing, integrity digests, and an Evidence Protection Policy whose versioned Key Provider encrypts Sensitive Evidence. If a required key is unavailable, only permitted redacted records may persist and raw sensitive content is blocked; original secret values are never retained, only their type, location, irreversible fingerprint, and minimum context.

