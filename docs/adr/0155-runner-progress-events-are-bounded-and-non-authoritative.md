---
status: accepted
---

# Runner progress events are bounded and non-authoritative

An Analyzer may emit only schema-validated, rate- and size-limited Runner Events through its Attempt runtime. Events provide diagnostics and progress but cannot create Findings, satisfy Coverage, spend unrecorded budget, or mutate authoritative state; losing them must not change the Assessment outcome. Only predeclared named milestones may update the public progress projection and aggregate revision, while the terminal Analyzer Contribution remains the sole semantic result submitted for admission.
