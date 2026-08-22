---
status: accepted
---

# Public operations are async Results except local Analyzer registration

Every runtime command, query, wait, and export operation returns `Promise<SecurityResult<T>>`, giving local Service callers and transport Adapters one asynchronous outcome contract. They do not mix callbacks, event emitters, raw streams, synchronous domain exceptions, or fire-and-forget mutation. `registerAnalyzer` is the sole exception because it is a synchronous Host composition SPI whose successful return establishes an effect-scoped registration and whose invalid contribution fails activation loudly rather than becoming a remote business result.
