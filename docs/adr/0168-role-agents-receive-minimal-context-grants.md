---
status: accepted
---

# Role Agents receive minimal Context Grants

The Assessment Engine gives each Role Attempt a purpose-specific Context Grant containing only approved inventory, Source Slices, Evidence projections, task constraints, and disclosure categories needed for that role. A Role Agent may request additional material only through a structured Source Slice Request stating purpose and target; the Service rechecks Subject containment, sensitivity, secret redaction, Data Egress, token and byte budget, and Role need before granting it. Agents never receive an ambient repository browser, original workspace root, or full parent conversation.
