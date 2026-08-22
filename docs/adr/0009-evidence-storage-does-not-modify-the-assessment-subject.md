---
status: accepted
---

# Evidence storage does not modify the Assessment Subject

Canonical Security Assessment records and Evidence live in the plugin-owned Security Evidence Store, not in the evaluated repository. Writing an Evidence copy into the Assessment Subject requires an explicit export action, preventing assessment activity from mutating its own target or trusting target-controlled canonical records.

