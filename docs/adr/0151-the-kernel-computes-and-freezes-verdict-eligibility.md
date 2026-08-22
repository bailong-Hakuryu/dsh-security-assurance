---
status: accepted
---

# The Kernel computes and freezes Verdict Eligibility

An Analyzer cannot declare itself Verdict-eligible. During Coverage Plan construction, the Assessment Kernel computes an immutable Eligibility Decision from the validated Descriptor, exact Analyzer Qualification Record, Provider identity, live Backend Probe, effective Policy, execution boundary, Evidence and Coverage contracts, Data Egress contract, and current runtime conditions. The decision and reasons are frozen into the plan; an ineligible contribution may remain Advisory but cannot satisfy a mandatory obligation or support an Assurance Submission.
