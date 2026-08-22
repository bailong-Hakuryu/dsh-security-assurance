---
status: accepted
---

# The conformance Module tests public contracts without bypasses

The side-effect-free `./conformance` Module publishes versioned Provider and Analyzer contract suites, adversarial and lifecycle Fixture builders, deterministic Reference Fakes, canonical result assertions, and adapters for running those tests through a supplied public Service composition. It does not export Store writers, authority minting, integrity skips, secret fixtures, production mutation helpers, or a second Kernel. Third-party contributors can therefore prove their declared Interface before registration while remaining subject to Host Qualification and the same packed release tests.
