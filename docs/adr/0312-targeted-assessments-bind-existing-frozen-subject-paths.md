---
status: accepted
---

# Targeted Assessments bind existing frozen Subject paths

A `TARGETED` Assessment does not weaken Subject immutability. The Service freezes and digest-binds the complete admitted `git_revision` or `workspace_snapshot`, including the canonical Target selector. Each requested relative path must identify an exact frozen Subject entry or a directory prefix containing at least one frozen entry. A missing path is an invalid request and is rejected before an Assessment is created.

The first qualified `TARGETED` composition is `security/node-package-lifecycle`. Its bundled PURE Analyzer receives only verified `package.json` slices whose paths equal a selected file or descend from a selected directory. An existing Target with no analyzable package manifest cannot prove the policy obligation and therefore seals `INDETERMINATE` with an `UNSUPPORTED_SUBJECT` Coverage gap; it never produces a vacuous `SATISFIED` Verdict.

The npm audit and Gitleaks report policies remain unsupported in `TARGETED` mode until the Service can independently prove that each externally produced report covers exactly the selected Target. Extending the built-in Analyzer from repository and change scope to this bounded target scope changes its public qualification claim, so its Analyzer version advances to `1.1.0` and its qualification identity advances to `dsh/qualification/builtin-node-package-lifecycle/v2`.
