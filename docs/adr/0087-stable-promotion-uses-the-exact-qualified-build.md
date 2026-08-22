---
status: accepted
---

# Stable promotion uses the exact qualified build

The build promoted from RC to stable is byte-equivalent in behavior, with only version, signature, and release metadata allowed to change. Any code, configuration default, rule, prompt, Analyzer, or schema behavior change creates a new RC and reruns the applicable Release Constitution rather than relying on human judgment that the edit was small.
