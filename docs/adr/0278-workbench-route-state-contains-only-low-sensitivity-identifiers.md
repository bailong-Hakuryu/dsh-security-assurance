---
status: accepted
---

# Workbench route state contains only low-sensitivity identifiers

Workbench navigation and browser history may contain only low-sensitivity opaque View identifiers and non-sensitive layout state. Evidence content, Source Anchors, repository paths, search terms derived from protected source, Finding details, Risk rationale, transcripts, export destinations, download capabilities, credentials, and authorization context remain in bounded in-memory state and are re-fetched under current authority. Copying or restoring a URL therefore never grants disclosure or reconstructs sensitive payloads.
