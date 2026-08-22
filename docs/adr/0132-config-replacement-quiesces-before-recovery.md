---
status: accepted
---

# Config replacement quiesces before recovery

On Security Service configuration replacement or HMR, the old Service first closes command admission, quiesces owned execution, records every interruption durably, and only then unloads its registrations and resources. The replacement Service performs normal durable recovery, but existing Assessments retain their frozen configuration and remain BLOCKED until an explicit resume can prove compatible providers and runtime conditions. Replacement never silently migrates, reinterprets, or auto-resumes an Assessment under new semantics.
