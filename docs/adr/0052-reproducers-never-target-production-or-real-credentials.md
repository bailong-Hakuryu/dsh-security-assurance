---
status: accepted
---

# Reproducers never target production or real credentials

Validation and Fix Verification run Safe Reproducers only in isolated snapshots or approved sandboxes with synthetic data, bounded resources, denied external network by default, and no production target, real credential, persistent destruction, or escape behavior. Tests outside that boundary are not executed and produce an explicit Proof Gap rather than an automatic rejection.

