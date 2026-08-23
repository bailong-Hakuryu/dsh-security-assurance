---
status: accepted
---

# Package-private protocol Symbols have versioned process identities

Root and Adapter entries are independent JavaScript bundles, so package-private
same-process protocol keys use versioned `Symbol.for` identities that remain
equal across those bundles. The keys expose no authority by themselves and are
absent from public exports; incompatible protocol revisions must use a new key,
while trusted in-process Harness plugins remain inside the Host security model.
