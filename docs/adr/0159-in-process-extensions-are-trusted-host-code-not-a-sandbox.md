---
status: accepted
---

# In-process extensions are trusted Host code not a sandbox

An Analyzer plugin loaded into the Harness process is a Host-approved In-process Extension with the ambient authority of executable JavaScript, even when it cooperates with the Security SPI. Registration, descriptors, and Capability Handles govern correct integration but do not sandbox malicious in-process code. Code the Host does not trust at that level must execute through a separately qualified isolation backend as an Untrusted Analyzer, and the product never advertises SPI compliance itself as a security boundary.
