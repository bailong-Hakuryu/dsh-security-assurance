---
status: accepted
---

# Execution may repeat but result admission is at most once

The product does not claim exactly-once Analyzer execution across process failure: a physical invocation may occur more than once after an interrupted claim. Each invocation is bound to a durable Attempt ID, Work Item, Provider identity, lease generation, and fencing token, and the Assessment Kernel admits its terminal result at most once through an idempotent compare-and-swap commit. Stale, duplicate, or conflicting submissions are recorded or rejected but can never add duplicate Findings, Coverage, Evidence references, or progress.
