---
status: accepted
---

# Assurance integration exchanges sealed submissions

DSH Security Assurance and DSH Engineering Control Plane own separate stores and never share database tables or writable paths. Security Assurance exports an immutable digest-bound Assurance Submission; the Control Plane validates it and imports the Evidence snapshot required for its own durable Assurance Result.

