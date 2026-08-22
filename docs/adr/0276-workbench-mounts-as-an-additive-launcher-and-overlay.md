---
status: accepted
---

# Workbench mounts as an additive launcher and overlay

The optional Client Runtime Entry contributes a Security Workbench Launcher to Harness `sidebar.footer.action` and renders the complete interface through `shell.overlay`. It neither replaces nor patches the root shell, sidebar, conversation, details owner, router, or agent-loop and remains absent in headless or Client-disabled compositions. Mount, close, HMR, and disposal are Fiber-owned, restore focus correctly, and remove every slot contribution without leaving Host UI state.
