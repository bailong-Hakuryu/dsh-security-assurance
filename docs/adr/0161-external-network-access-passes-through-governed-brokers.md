---
status: accepted
---

# External network access passes through governed brokers

Gate-bearing Analyzer execution has no ambient `fetch`, socket, inherited proxy, or repository-configured network path. An external model or service is reached only through a qualified Egress Broker such as `ModelInvoker` or `ExternalProviderClient`, bound to frozen destinations, Provider identity, credentials, Source Slices, Data Egress Contract, request and byte quotas, timeout, and audit records. If the selected backend cannot enforce the required network boundary, that execution is Advisory or leaves mandatory Coverage unsatisfied rather than receiving silent permission.
