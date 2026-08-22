---
status: accepted
---

# Gate-bearing assessment requires bounded execution

Provider work runs through an Assurance Execution Context with read-only access to the immutable Subject, private staging writes, and policy-mediated process and network actions. Control Plane mode uses its Action Gate and standalone mode enforces an equivalent Security-owned policy; backends whose identity, execution, coverage, or Evidence cannot be bounded contribute only Advisory Findings.

