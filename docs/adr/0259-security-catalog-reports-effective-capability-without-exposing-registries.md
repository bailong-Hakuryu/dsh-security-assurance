---
status: accepted
---

# Security Catalog reports effective capability without exposing Registries

`getCatalog` returns a versioned authority-filtered Security Catalog of Assessment Modes and Profiles, supported ecosystems and platforms, configured Provider and Analyzer eligibility summaries, required dependencies, limitations, and Security Support Matrix references effective for the caller's visible repositories. It does not expose factories, credentials, backend configuration, raw Registry entries, protected probe diagnostics, internal paths, or unavailable resources outside authority. Catalog claims are derived from current qualified composition and may not exceed the published Support Matrix.
