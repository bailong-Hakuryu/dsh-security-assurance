---
status: accepted
---

# Seams exist only where multiple Adapters justify them

The design creates a seam only where behavior genuinely varies and at least production plus test or multiple production Adapters exist: Analyzer and Provider contributions, Evidence Key Provider, governed Egress Broker, Host Clock, and externally owned integration contracts. SQLite, ordinary filesystem mechanics, scheduler internals, canonicalization, and Kernel rules remain implementations or internal seams rather than public ports invented for mocking. A new external seam requires an ADR identifying its distinct Adapters and the complexity it hides.
