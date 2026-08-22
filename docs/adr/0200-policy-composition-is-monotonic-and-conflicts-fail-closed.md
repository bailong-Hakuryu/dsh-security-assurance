---
status: accepted
---

# Policy composition is monotonic and conflicts fail closed

Policy layers compose through an explicit versioned Policy Lattice in which lower-trust layers may add obligations, narrow exemptions, strengthen Evidence and independence, lower risk tolerance, or reduce granted capability, but cannot weaken an inherited rule. The compiler proves each change monotonic for its rule kind and records the relation. Contradictory, incomparable, cyclic, or unsupported combinations fail closed with diagnostics and cannot be resolved by last-write-wins, Analyzer preference, Role Agent interpretation, or caller choice.
