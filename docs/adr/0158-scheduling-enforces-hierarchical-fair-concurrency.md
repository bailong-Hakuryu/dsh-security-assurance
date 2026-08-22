---
status: accepted
---

# Scheduling enforces hierarchical fair concurrency

The Service-owned scheduler is the only admission path for Assessment, Provider, Analyzer, Role, process, and broker work. It enforces a frozen Concurrency Envelope across Host, Repository, Assessment, Provider, Analyzer identity, and execution class, using bounded fair queues so one large or failing Assessment cannot starve others. Analyzer code cannot bypass those limits by spawning unregistered child work; such behavior is a contract violation and disqualifies gate-bearing execution.
