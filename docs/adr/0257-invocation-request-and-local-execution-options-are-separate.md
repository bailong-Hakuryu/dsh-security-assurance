---
status: accepted
---

# Invocation, Request, and local execution options are separate

Authority-bearing runtime operations have an Interface equivalent to `operation(invocation, request, options?)`: the opaque Security Invocation carries trusted channel authority, the versioned Request is a JSON-safe semantic DTO, and Invocation Options contain only process-local cancellation and a bounded caller deadline. Principal, permissions, Host paths, capability objects, transport headers, and authority hints never enter the Request; an Adapter derives the Invocation and maps its own cancellation primitive without serializing either local capability.
