---
status: accepted
---

# Each Role Attempt uses a fresh isolated Subagent session

Every durable Role Attempt creates a fresh `ctx.subagents` session bound to its exact Assessment, role, Provider, model, Prompt, Context Grant, Tool Manifest, budget, and attempt lineage. It inherits neither the host conversation nor hidden state from previous or parallel Role sessions; prior results are visible only when the Engine deliberately packages an authorized immutable input. The Role Transcript and model payloads are protected Execution Evidence with explicit retention and disclosure rules, not an informal continuation of chat history.
