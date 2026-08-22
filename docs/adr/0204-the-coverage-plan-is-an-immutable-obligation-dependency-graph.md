---
status: accepted
---

# The Coverage Plan is an immutable Obligation dependency graph

The compiled Coverage Plan is a versioned immutable directed acyclic graph whose nodes are Coverage Obligations or governed phase barriers and whose edges encode prerequisite Evidence, execution, and reconciliation dependencies. It fixes admissible parallelism and completion semantics without becoming an Agent-authored task list or a mutable workflow script. Cycles, orphaned mandatory nodes, missing completion contracts, or unsatisfied Provider eligibility invalidate the plan before Assessment execution begins.
