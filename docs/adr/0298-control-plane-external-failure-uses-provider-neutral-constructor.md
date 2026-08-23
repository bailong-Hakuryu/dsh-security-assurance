---
status: accepted
---

# Control Plane external failure uses the provider-neutral constructor

The optional Control Plane Adapter returns the Control Plane package's strict
`ExternalAssessmentFailureV1` value whenever no sealed Security Submission can
be supplied. It must use the public provider-neutral constructor rather than a
type assertion, attach only the bounded `reason` and `code`, and disclose no
Security path, credential, stack, Finding, or private Assessment payload. The
Control Plane owns durable Invocation settlement, Assurance Assessment, Result,
and Gate interpretation. Security Assurance does not fabricate a Submission or
claim a Mission outcome when its Assessment is blocked, canceled, or failed.
