---
status: accepted
---

# Benchmark Arms and repetitions are state-isolated

Every Evaluation Arm and stochastic repetition receives a fresh Security Store, Evidence root, Subject materialization, cache namespace, Harness session, Provider state, credentials, and temporary environment while reading the same immutable benchmark Subject and predeclared inputs. No Analyzer Parse Cache, prior Finding, transcript, adjudication, model conversation, or telemetry may cross an Arm boundary. Any unavoidable shared external Provider condition is recorded and balanced rather than hidden as independent execution.
