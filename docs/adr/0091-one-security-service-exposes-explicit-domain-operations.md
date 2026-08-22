---
status: accepted
---

# One Security Service exposes explicit domain operations

`ctx.securityAssurance` is the single public Service and exposes explicit, strongly typed Assessment, Remediation, and Delivery commands and queries. The three deep modules remain separately implemented behind that contract; neither a generic `execute(action, payload)` interface nor several competing Cordis mutation Services are permitted.

