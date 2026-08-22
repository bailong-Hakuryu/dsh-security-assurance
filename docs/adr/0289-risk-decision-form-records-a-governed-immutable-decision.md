---
status: accepted
---

# Risk Decision form records a governed immutable decision

The Risk Decision form presents the immutable Finding and current revision, applicable Policy ceiling, derived Decision Authority, required rationale, compensating controls, expiry limits, prior attestations, and the exact consequence without offering Finding edits. Submission calls `recordRiskDecision` with a fresh idempotency identity and then discards local sensitive input and refetches the Assessment Snapshot. The UI never claims acceptance from optimistic state, model recommendation, a checkbox, or a caller-entered decision-maker identity.
