---
status: accepted
---

# Exact-commit Change mode admits full resulting-tree Evidence

An exact-commit Change Assessment binds the resolved base commit, resolved head commit, raw diff digest, and complete frozen head tree. A qualified Analyzer may satisfy Change Coverage by evaluating its complete relevant input set across that resulting tree because the full tree is a safe superset of the Policy impact cone.

This choice can report a Policy violation that already existed outside the changed files. That conservative result is preferable to inferring safety from diff lines alone. An Analyzer that narrows its input below the complete relevant set must instead establish an Evidence-backed impact cone; otherwise its Coverage remains incomplete.

This decision applies only to exact committed base-to-head pairs. Produced-but-uncommitted workspace changes require a separately versioned identity and Host binding contract before they can enter Change mode.
