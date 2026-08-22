---
status: accepted
---

# Assessment subjects come from a Host-owned Repository Registry

An Assessment may target only a Repository ID already present in the Host-owned Repository Registry. The registry binds that ID to a canonical root and its Policy, Evidence, Egress, Assessment Profile, and platform constraints; repository-controlled files cannot alter those bindings. Repository Registration is a separately authorized administrative operation, and ordinary start requests cannot submit an arbitrary filesystem path or implicitly register a repository.
