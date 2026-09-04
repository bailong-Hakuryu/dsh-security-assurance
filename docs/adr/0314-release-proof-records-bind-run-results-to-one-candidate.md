---
status: accepted
---

# Release Proof Records Bind Run Results to One Candidate

Packed release checks may emit one strict `ReleaseProofRecordV1` only after
their assertions and lifecycle cleanup finish. Each record names its producer,
environment, exact raw-byte candidate digest, proof kind, assertion outcomes,
and completion time. Its reported status is derived from those assertions; a
producer cannot claim a platform or Workbench result outside its allowed proof
kind.

When release automation supplies a retained candidate, the runner installs a
private snapshot and the record hashes that tested snapshot. Before committing
the record, the emitter re-reads the retained candidate and fails closed unless
its digest still matches the tested snapshot. A browser-produced Workbench
record must explicitly include the `WORKBENCH_CLIENT_SHIPPED` assertion.

The external `dsh-security-assurance-release-collect` command validates a
release-file binding and every supplied proof record, rejects candidate digest,
record-id, path, or proof-kind ambiguity, hashes each record's raw JSON bytes,
and atomically writes a deterministic index ordered by the Release Evidence
Manifest proof taxonomy. Each indexed `proof` is directly usable as a
`ReleaseEvidenceProofV1`, but collection does not upgrade a failed or
inconclusive status and does not manufacture missing evidence.

The current candidate deliberately ships no legacy Workbench client under ADR
0307. Its real-browser run may therefore prove current Web host compatibility
while recording the `WORKBENCH` proof as `INCONCLUSIVE`; only a future packed
candidate that actually restores a supported `./client` entry may produce a
passed Workbench record.
