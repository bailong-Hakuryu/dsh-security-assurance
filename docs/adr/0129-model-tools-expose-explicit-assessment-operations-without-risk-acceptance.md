---
status: accepted
---

# Model tools expose explicit Assessment operations without Risk Acceptance

The model-facing Consumer consists of separate tools named `security_assessment_start`, `security_assessment_status`, `security_assessment_findings`, `security_assessment_resume`, `security_assessment_cancel`, and `security_assessment_export`. Each tool delegates one bounded operation to the Security Service under session-derived authority and has an operation-specific schema; there is no generic security command tool and no model tool for Risk Acceptance or repository administration.
