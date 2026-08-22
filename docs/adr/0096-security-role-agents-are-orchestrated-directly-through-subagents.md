---
status: accepted
---

# Security Role Agents are orchestrated directly through Subagents

The Assessment Engine invokes `ctx.subagents` directly with frozen Role prompts, tool restrictions, output schemas, Provider selection, and budgets, and durably records every admitted and settled Role contribution. Harness Workflow scripts are not the Assessment authority because their current lifecycle is non-durable, and Security Assurance neither modifies nor embeds `agent-loop`.

