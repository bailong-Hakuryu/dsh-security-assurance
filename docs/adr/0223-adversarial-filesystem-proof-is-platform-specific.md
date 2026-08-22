---
status: accepted
---

# Adversarial filesystem proof is platform-specific

Release Conformance runs qualified Platform Adversarial Fixtures covering links and escape attempts, case folding and collisions, Unicode normalization, reserved and special names, long paths, permissions, unstable reads, generated and oversized files, submodules, malicious archives, and platform-specific objects such as relevant NTFS behavior. Windows, Linux, and macOS runs preserve their distinct expected Evidence and Coverage outcomes instead of assuming one platform's filesystem semantics prove another's.
