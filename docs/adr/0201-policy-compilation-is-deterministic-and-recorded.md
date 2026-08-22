---
status: accepted
---

# Policy compilation is deterministic and recorded

The Policy Compiler is a side-effect-free deterministic transformation over exact Policy Layers, frozen Subject Inventory, Assessment Mode and Profile, platform facts, Provider eligibility, and other explicit inputs. It performs no network access, model call, filesystem discovery, or ambient-time lookup and produces the same canonical Policy AST, diagnostics, Coverage Plan, and digests for equal inputs. A Policy Compilation Record binds compiler version, every input digest, output digest, warning and rejected construct for the Assessment Seal.
