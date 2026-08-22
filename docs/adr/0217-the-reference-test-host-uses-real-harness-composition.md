---
status: accepted
---

# The Reference Test Host uses real Harness composition

The Reference Test Host composes the packed plugin through actual Harness and Cordis loading, Service injection, tools, Typert Remote, Client slots, and lifecycle semantics rather than a simplified replacement runtime. Each test receives explicit isolated Repository Registry entries, Subject workspace, `$DSH_HOME`, database, Evidence keys, Provider registry, clock, ports, and process ownership below a temporary authority root. Shared developer state, credentials, caches, and production configuration never participate.
