---
status: accepted
---

# A proven blocking violation takes precedence over incomplete Coverage

If at least one validated, unaccepted Finding deterministically has blocking Policy Significance, the Security Verdict is `FAILED` even when other obligations contain Coverage Gaps, because sufficient eligible Evidence already proves that Policy is not satisfied. The Seal and every View must still disclose all gaps and state that `FAILED` does not imply exhaustive analysis. When no blocking violation is proved, any material mandatory gap yields `INDETERMINATE`; only complete mandatory Coverage with no blocking Finding yields `SATISFIED`.
