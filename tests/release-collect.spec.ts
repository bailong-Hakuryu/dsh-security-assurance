import { execFile } from 'node:child_process'
import { createHash } from 'node:crypto'
import { existsSync } from 'node:fs'
import { mkdtemp, readFile, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { promisify } from 'node:util'
import { describe, expect, it } from 'vitest'

import type { DigestEnvelopeV1 } from '../src/digest-envelope.js'
import { releaseProofIndexV1Schema } from '../src/release-proof.js'

const execute = promisify(execFile)
const cliPath = fileURLToPath(new URL('../src/release-collect.ts', import.meta.url))

function rawDigest(bytes: Buffer, mediaType: string): DigestEnvelopeV1 {
  return {
    schemaVersion: 1,
    algorithm: 'sha256',
    mediaType,
    byteLength: bytes.byteLength,
    canonicalization: 'raw-bytes',
    value: createHash('sha256').update(bytes).digest('hex'),
  }
}

function proofRecord(
  proofKind: 'WINDOWS_PLATFORM' | 'WORKBENCH',
  candidateArtifactDigest: DigestEnvelopeV1,
) {
  const workbench = proofKind === 'WORKBENCH'
  return {
    schemaVersion: 1,
    engineId: 'security/release-proof-record/v1',
    proofRecordId: workbench
      ? 'proof/packed-browser/windows/0.1.0-rc.10'
      : 'proof/packed-profile/windows/0.1.0-rc.10',
    proofKind,
    producer: workbench ? 'PACKED_BROWSER_E2E' : 'PACKED_HARNESS_PROFILE_SMOKE',
    producerVersion: '0.1.0-rc.10',
    reportedStatus: workbench ? 'INCONCLUSIVE' : 'PASSED',
    candidateArtifactDigest,
    completedAtEpochMs: workbench ? 1_788_516_100_000 : 1_788_516_000_000,
    environment: {
      platform: 'WINDOWS',
      architecture: 'x64',
      nodeVersion: '24.19.0',
      harnessVersion: '0.1.2-rc.1',
    },
    assertions: workbench
      ? [{ assertionId: 'WORKBENCH_CLIENT_SHIPPED', status: 'INCONCLUSIVE' }]
      : [{ assertionId: 'HARNESS_WEB_RESPONDED', status: 'PASSED' }],
  }
}

async function fixture() {
  const root = await mkdtemp(join(tmpdir(), 'dsh-release-collect-'))
  const candidateBytes = Buffer.from('exact-packed-candidate-bytes\n', 'utf8')
  const candidateDigest = rawDigest(candidateBytes, 'application/gzip')
  const lockDigest = rawDigest(Buffer.from('lockfileVersion: 9.0\n'), 'application/yaml')
  await writeFile(join(root, 'candidate.tgz'), candidateBytes)
  const binding = {
    schemaVersion: 1,
    engineId: 'security/release-file-bindings/v1',
    sourceRepositoryPath: 'repository',
    sourceRevision: 'a'.repeat(40),
    candidateArtifact: {
      path: 'candidate.tgz',
      mediaType: 'application/gzip',
      digest: candidateDigest,
    },
    dependencyLockFiles: [{
      lockKind: 'PNPM_LOCK',
      path: 'repository/pnpm-lock.yaml',
      mediaType: 'application/yaml',
      digest: lockDigest,
    }],
  }
  await writeFile(join(root, 'release-file-bindings.json'), `${JSON.stringify(binding, null, 2)}\n`)
  const profileRecord = proofRecord('WINDOWS_PLATFORM', candidateDigest)
  const workbenchRecord = proofRecord('WORKBENCH', candidateDigest)
  const profileBytes = Buffer.from(`${JSON.stringify(profileRecord, null, 2)}\n`)
  const workbenchBytes = Buffer.from(`${JSON.stringify(workbenchRecord, null, 2)}\n`)
  await writeFile(join(root, 'windows-platform.json'), profileBytes)
  await writeFile(join(root, 'workbench.json'), workbenchBytes)
  return { root, binding, candidateDigest, profileRecord, workbenchRecord, profileBytes, workbenchBytes }
}

async function writeInput(root: string, proofFiles: string[], name = 'collect-input.json') {
  const inputPath = join(root, name)
  await writeFile(inputPath, `${JSON.stringify({
    schemaVersion: 1,
    releaseFileBindingsPath: 'release-file-bindings.json',
    proofFiles,
  }, null, 2)}\n`)
  return inputPath
}

async function runCli(inputPath: string, outputPath: string) {
  return execute(process.execPath, [
    '--experimental-strip-types',
    cliPath,
    '--',
    '--input', inputPath,
    '--output', outputPath,
  ], { windowsHide: true })
}

describe('release proof collection CLI', () => {
  it('builds a deterministic manifest-ready index from exact-artifact proof records', async () => {
    const fixtureValue = await fixture()
    const inputPath = await writeInput(fixtureValue.root, ['workbench.json', 'windows-platform.json'])
    const reversedInputPath = await writeInput(
      fixtureValue.root,
      ['windows-platform.json', 'workbench.json'],
      'collect-input-reversed.json',
    )
    const outputPath = join(fixtureValue.root, 'proof-index.json')
    const reversedOutputPath = join(fixtureValue.root, 'proof-index-reversed.json')

    const { stdout, stderr } = await runCli(inputPath, outputPath)
    await runCli(reversedInputPath, reversedOutputPath)

    expect(stdout).toBe('')
    expect(stderr).toBe('')
    const output = releaseProofIndexV1Schema.parse(JSON.parse(await readFile(outputPath, 'utf8')))
    const reversedOutput = releaseProofIndexV1Schema.parse(
      JSON.parse(await readFile(reversedOutputPath, 'utf8')),
    )
    expect(reversedOutput).toEqual(output)
    expect(output.candidateArtifactDigest).toEqual(fixtureValue.candidateDigest)
    expect(output.records.map(record => record.proof.proofKind)).toEqual([
      'WINDOWS_PLATFORM',
      'WORKBENCH',
    ])
    expect(output.records.map(record => record.proof)).toEqual([
      {
        proofKind: 'WINDOWS_PLATFORM',
        evidenceId: fixtureValue.profileRecord.proofRecordId,
        evidenceDigest: rawDigest(fixtureValue.profileBytes, 'application/json'),
        reportedStatus: 'PASSED',
        candidateArtifactDigest: fixtureValue.candidateDigest,
        completedAtEpochMs: fixtureValue.profileRecord.completedAtEpochMs,
      },
      {
        proofKind: 'WORKBENCH',
        evidenceId: fixtureValue.workbenchRecord.proofRecordId,
        evidenceDigest: rawDigest(fixtureValue.workbenchBytes, 'application/json'),
        reportedStatus: 'INCONCLUSIVE',
        candidateArtifactDigest: fixtureValue.candidateDigest,
        completedAtEpochMs: fixtureValue.workbenchRecord.completedAtEpochMs,
      },
    ])
  })

  it('fails closed without output when a proof names another candidate', async () => {
    const fixtureValue = await fixture()
    const workbenchPath = join(fixtureValue.root, 'workbench.json')
    await writeFile(workbenchPath, `${JSON.stringify(proofRecord(
      'WORKBENCH',
      { ...fixtureValue.candidateDigest, value: 'f'.repeat(64) },
    ), null, 2)}\n`)
    const inputPath = await writeInput(fixtureValue.root, ['workbench.json'])
    const outputPath = join(fixtureValue.root, 'proof-index.json')

    await expect(runCli(inputPath, outputPath)).rejects.toMatchObject({
      code: 1,
      stderr: expect.stringContaining('CANDIDATE_DIGEST_MISMATCH'),
    })
    expect(existsSync(outputPath)).toBe(false)
  })

  it('fails closed without output when two records claim the same proof kind', async () => {
    const fixtureValue = await fixture()
    await writeFile(
      join(fixtureValue.root, 'windows-platform-copy.json'),
      `${JSON.stringify({
        ...fixtureValue.profileRecord,
        proofRecordId: 'proof/packed-profile/windows/copy',
      }, null, 2)}\n`,
    )
    const inputPath = await writeInput(
      fixtureValue.root,
      ['windows-platform.json', 'windows-platform-copy.json'],
    )
    const outputPath = join(fixtureValue.root, 'proof-index.json')

    await expect(runCli(inputPath, outputPath)).rejects.toMatchObject({
      code: 1,
      stderr: expect.stringContaining('DUPLICATE_PROOF_KIND'),
    })
    expect(existsSync(outputPath)).toBe(false)
  })
})
