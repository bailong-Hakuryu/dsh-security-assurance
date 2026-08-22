---
status: accepted
---

# Digests use versioned deterministic envelopes

Every content or record digest is represented by a versioned Digest Envelope that names the algorithm, media type, byte length, and canonicalization identifier. Binary content is hashed over exact bytes, while structured records use a specified deterministic encoding whose field ordering, number representation, Unicode handling, and absent-value rules do not depend on runtime or locale. A future algorithm or encoding change creates a new envelope version and never reinterprets an existing digest.
