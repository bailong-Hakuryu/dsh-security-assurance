---
status: accepted
---

# Assessment progress is a revision-bound phase and Coverage View

Assessment Detail renders a revision-bound Phase Graph View of durable nodes, dependencies, Attempt states, Coverage Resolutions or pending obligations, named milestones, budget consumption, blockers, and terminal status from Assessment Snapshots. It never streams raw internal logs, estimates completion from animation, or treats a process heartbeat as domain progress. Revision wait only signals refetch, and every displayed fact is labeled with the Snapshot revision from which it came.
