---
status: accepted
---

# Source Anchors bind Subject content and stable spans

A Source Anchor binds the exact Subject and child Subject when applicable, canonical relative path, content digest, byte span, and optional language symbol or syntax identity. Human-facing line and column numbers are derived from those frozen bytes and never serve as identity by themselves. An anchor outside the Subject, against mismatched content, or without a representable bounded location fails admission rather than resolving against the caller's live workspace.
