---
status: accepted
---

# Canonical security artifacts have reviewed Golden Vectors

Canonical encoding, Digest Envelopes, manifests, Evidence Links, Evaluation Traces, Seals, Assessment Bundles, Assurance Submissions, and audience exports have versioned Canonical Golden Vectors that assert exact bytes, digests, and semantic reader output across supported platforms. Test runners never update expected vectors automatically. Any intentional change requires schema compatibility analysis, an ADR or equivalent reviewed reason, explicit vector regeneration, and proof that readers still fail closed on unsupported versions.
