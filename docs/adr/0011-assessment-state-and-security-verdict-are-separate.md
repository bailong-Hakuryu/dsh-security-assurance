---
status: accepted
---

# Assessment State and Security Verdict are separate

Security Assessments move through `CREATED`, `RUNNING`, resumable `BLOCKED`, terminal `SEALED`, or terminal `CANCELED` operational states. Only a sealed Assessment carries a Security Verdict, preserving the distinction between work that may resume and a completed evaluation whose Evidence is insufficient.

