---
status: accepted
---

# Evidence enters through staged verified publication

Analyzers and role agents receive only a Service-owned bounded Evidence Staging writer and never a final Evidence path or Store handle. The Service streams and enforces byte, count, media, classification, schema, digest, protection, and applicable redaction constraints before atomically publishing the immutable object; an Assessment transaction may reference only an already published identity and digest. Incomplete or failed staging objects are quarantined for bounded recovery or garbage collection and are never authoritative Evidence.
