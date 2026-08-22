---
status: accepted
---

# Workbench is a Service Client not an authority

The Security Workbench renders immutable Security Service Snapshots and submits only catalogued Commands under a Host-derived Security Invocation. It owns transient presentation state but no Assessment lifecycle, Coverage, Finding, Evidence, Risk Decision, Verdict, export, authorization, or retry semantics and never edits a Store or canonical artifact. Refresh, another Client, and headless operation therefore observe the same Service truth, and deleting the Workbench removes no security behavior from the Host product.
