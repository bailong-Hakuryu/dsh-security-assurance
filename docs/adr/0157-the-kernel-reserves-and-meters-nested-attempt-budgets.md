---
status: accepted
---

# The Kernel reserves and meters nested Attempt budgets

Before an Attempt starts, the Kernel atomically reserves its maximum permitted share from the frozen Assessment Budget. Service-owned Capability Handles meter or enforce wall time, model calls and tokens, process count, output and Evidence bytes, storage, and other supported resource dimensions; every child process, agent, or broker request is charged to its parent Attempt and cannot create a new budget authority. Unused reservation is released only after settlement, while overrun terminates or blocks the Attempt and remains part of the measured result.
