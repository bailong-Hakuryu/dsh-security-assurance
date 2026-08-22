---
status: accepted
---

# Bundle Manifest is a View and Submission is self-contained

`getBundleManifest` returns a disclosure-filtered Bundle Manifest View with canonical schema, record identities, digests, sizes, classifications, omissions, and Seal reference but never private filesystem locations or unchecked bytes. `getAssuranceSubmission` returns the complete immutable versioned digest-bound Submission DTO needed for an authorized consumer to validate and import by value without querying the Security Store. Neither operation regenerates authority from Markdown or serves anything for an unsealed Assessment.
