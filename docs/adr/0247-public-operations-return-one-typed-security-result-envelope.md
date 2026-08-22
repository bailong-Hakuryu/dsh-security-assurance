---
status: accepted
---

# Public operations return one typed Security Result envelope

Every public Service operation resolves to a discriminated `SecurityResult<T>` carrying either its versioned value or one Public Security Error; expected domain, authorization, concurrency, integrity, availability, limit, and cancellation failures do not cross the Interface as raw exceptions. Unexpected implementation failures are caught at the Service seam, correlated, protected in diagnostics, and represented as redacted `INTERNAL` results. Adapters map this same envelope to tools and transports without redefining retryability or failure semantics.
