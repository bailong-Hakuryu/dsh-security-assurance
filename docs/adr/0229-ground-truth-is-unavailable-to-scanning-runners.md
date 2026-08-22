---
status: accepted
---

# Ground Truth is unavailable to scanning Runners

Benchmark scanning Runners receive an opaque Case identity and immutable Subject but do not mount, fetch, infer from filenames, or otherwise access Ground Truth, expected Findings, seed metadata, matching rules, or Arm labels. Only after an Arm produces its immutable sealed result does a separately authorized evaluator join that output with the Ground Truth Manifest. Canary markers and access audits test the air gap, and any detected leakage invalidates the complete Evaluation Run rather than merely removing contaminated Findings.
