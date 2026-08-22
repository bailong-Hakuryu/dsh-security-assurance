---
status: accepted
---

# Assessment start publishes a durable receipt

`startAssessment` returns an Assessment Receipt immediately after the durable creation transaction commits. Cancellation before that boundary produces no identity; after publication, the Assessment Engine owns continued execution and the initiating signal no longer cancels it. Later lifecycle changes require explicit status, resume, or cancel operations rather than ownership of a live process handle or Harness Job.

