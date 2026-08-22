---
status: accepted
---

# Security Service is one deep Module with explicit operations

The Security Service presents a small set of explicit typed repository, Assessment, risk-decision, artifact, export, health, and Analyzer-registration operations. Behind that Interface it resolves authority, validates DTOs and revisions, enforces idempotency and lifecycle, executes Kernel Decisions, controls transactions and Evidence, applies redaction and pagination, and maps failures. It exposes neither generic `execute` or `query`, entity CRUD, transaction objects, phase controls, nor one shallow public class per use case.
