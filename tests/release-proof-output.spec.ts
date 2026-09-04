import { createHash } from 'node:crypto'
import { existsSync } from 'node:fs'
import { mkdtemp, readFile, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'

import { writeReleaseProofRecord } from '../src/release-proof-output.js'
import { releaseProofRecordV1Schema } from '../src/release-proof.js'

describe('release proof output', () => {
  it('atomically writes a schema-valid proof bound to exact candidate bytes', async () => {
    const root = await mkdtemp(join(tmpdir(), 'dsh-release-proof-output-'))
    const artifactPath = join(root, 'candidate.tgz')
    const outputPath = join(root, 'proofs', 'linux-platform.json')
    const artifactBytes = Buffer.from('candidate-release-proof-bytes\n', 'utf8')
    await writeFile(artifactPath, artifactBytes)

    const record = await writeReleaseProofRecord({
      outputPath,
      candidateArtifactPath: artifactPath,
      candidateArtifactMediaType: 'application/gzip',
      proofRecordId: 'proof/packed-profile/linux/0.1.0-rc.10',
      proofKind: 'LINUX_PLATFORM',
      producer: 'PACKED_HARNESS_PROFILE_SMOKE',
      producerVersion: '0.1.0-rc.10',
      completedAtEpochMs: 1_788_516_000_000,
      environment: {
        platform: 'LINUX',
        architecture: 'x64',
        nodeVersion: '24.19.0',
        harnessVersion: '0.1.2-alpha.1',
      },
      assertions: [{ assertionId: 'HARNESS_WEB_RESPONDED', status: 'PASSED' }],
    })

    expect(releaseProofRecordV1Schema.parse(JSON.parse(
      await readFile(outputPath, 'utf8'),
    ))).toEqual(record)
    expect(record.candidateArtifactDigest).toEqual({
      schemaVersion: 1,
      algorithm: 'sha256',
      mediaType: 'application/gzip',
      byteLength: artifactBytes.byteLength,
      canonicalization: 'raw-bytes',
      value: createHash('sha256').update(artifactBytes).digest('hex'),
    })
  })

  it('never replaces an existing proof output', async () => {
    const root = await mkdtemp(join(tmpdir(), 'dsh-release-proof-existing-'))
    const artifactPath = join(root, 'candidate.tgz')
    const outputPath = join(root, 'proof.json')
    await writeFile(artifactPath, 'candidate\n', 'utf8')
    await writeFile(outputPath, 'existing-proof\n', 'utf8')

    await expect(writeReleaseProofRecord({
      outputPath,
      candidateArtifactPath: artifactPath,
      candidateArtifactMediaType: 'application/gzip',
      proofRecordId: 'proof/packed-profile/linux/existing',
      proofKind: 'LINUX_PLATFORM',
      producer: 'PACKED_HARNESS_PROFILE_SMOKE',
      producerVersion: '0.1.0-rc.10',
      completedAtEpochMs: 1_788_516_000_000,
      environment: {
        platform: 'LINUX',
        architecture: 'x64',
        nodeVersion: '24.19.0',
        harnessVersion: '0.1.2-alpha.1',
      },
      assertions: [{ assertionId: 'HARNESS_WEB_RESPONDED', status: 'PASSED' }],
    })).rejects.toMatchObject({ code: 'OUTPUT_ALREADY_EXISTS' })
    expect(await readFile(outputPath, 'utf8')).toBe('existing-proof\n')
  })

  it('fails closed when the retained candidate drifts from the tested snapshot', async () => {
    const root = await mkdtemp(join(tmpdir(), 'dsh-release-proof-drift-'))
    const retainedArtifactPath = join(root, 'candidate.tgz')
    const testedSnapshotPath = join(root, 'tested-candidate.tgz')
    const outputPath = join(root, 'proof.json')
    await writeFile(retainedArtifactPath, 'tested-candidate-bytes\n', 'utf8')
    await writeFile(testedSnapshotPath, 'tested-candidate-bytes\n', 'utf8')
    await writeFile(retainedArtifactPath, 'changed-after-test\n', 'utf8')

    await expect(writeReleaseProofRecord({
      outputPath,
      candidateArtifactPath: testedSnapshotPath,
      retainedCandidateArtifactPath: retainedArtifactPath,
      candidateArtifactMediaType: 'application/gzip',
      proofRecordId: 'proof/packed-profile/linux/drift',
      proofKind: 'LINUX_PLATFORM',
      producer: 'PACKED_HARNESS_PROFILE_SMOKE',
      producerVersion: '0.1.0-rc.10',
      completedAtEpochMs: 1_788_516_000_000,
      environment: {
        platform: 'LINUX',
        architecture: 'x64',
        nodeVersion: '24.19.0',
        harnessVersion: '0.1.2-alpha.1',
      },
      assertions: [{ assertionId: 'HARNESS_WEB_RESPONDED', status: 'PASSED' }],
    })).rejects.toMatchObject({ code: 'CANDIDATE_SNAPSHOT_MISMATCH' })
    expect(existsSync(outputPath)).toBe(false)
  })
})
