---
status: accepted
---

# Assessment Aggregate has a narrow consistency boundary

The Assessment Aggregate owns its lifecycle, frozen plan, Attempts, Findings, Coverage, Risk Decisions, Verdict, Seal, and immutable references needed to enforce their joint invariants. Repository Registry entries, content-addressed Evidence payloads, Remediation Cases, and Delivery records remain separate consistency boundaries referenced by stable identity and digest. A Finding or Attempt is not independently mutable outside the Assessment Aggregate, while unrelated repositories and delivery workflows do not enlarge the Assessment transaction.
