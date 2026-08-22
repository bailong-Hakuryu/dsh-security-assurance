---
status: accepted
---

# Contract majors govern semantic compatibility

Public DTO and operation contracts carry an explicit major version. Within one major, additions are optional or otherwise backward compatible under each schema's declared unknown-field behavior and cannot change existing field meaning, authority, defaults, or failure semantics; a breaking change introduces a new major and an explicit Adapter or rejection path. Compatibility Readers for SEALED Assessment Bundles and Assurance Submissions remain available for the complete supported retention and integration horizon, which is longer than ordinary live request compatibility, and sealed bytes are never rewritten.
