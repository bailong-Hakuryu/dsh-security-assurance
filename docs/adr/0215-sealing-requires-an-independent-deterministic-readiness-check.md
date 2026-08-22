---
status: accepted
---

# Sealing requires an independent deterministic Readiness Check

After Policy Evaluation and before Seal Publication, an independent Kernel Seal Readiness Check verifies that the phase graph and every obligation are terminal, no work, lease, handle, Risk Decision Window, or unpublished Evidence remains active, all revisions and integrity chains agree, the Verdict Candidate matches its trace, and the canonical Bundle and Submission inputs can be generated. Failure records exact invariant violations and leaves or moves the Assessment `BLOCKED`; neither an operator click nor evaluator success can bypass readiness before the atomic Seal transaction.
