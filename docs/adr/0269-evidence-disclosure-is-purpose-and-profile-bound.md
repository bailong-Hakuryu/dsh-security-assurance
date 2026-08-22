---
status: accepted
---

# Evidence disclosure is purpose- and Profile-bound

`getEvidenceView` requires exact Evidence identity, consuming Assessment or Finding context, declared viewing purpose, and a named authorized Evidence View Profile. The Service re-evaluates Security Invocation disclosure scope, Evidence classification, key availability, retention, redaction, Egress, and byte limits and returns either bounded safe content, structured metadata, a Host-controlled one-use read capability, or a redacted denial. It never returns the Evidence Store path, encryption material, unrestricted source, or a capability reusable outside its invocation and expiry.
