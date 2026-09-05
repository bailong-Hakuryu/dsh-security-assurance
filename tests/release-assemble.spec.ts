import { execFile } from 'node:child_process'
import { createHash } from 'node:crypto'
import { existsSync } from 'node:fs'
import { mkdir, mkdtemp, readFile, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { dirname, join, relative } from 'node:path'
import { fileURLToPath } from 'node:url'
import { promisify } from 'node:util'
import { describe, expect, it } from 'vitest'

import type { DigestEnvelopeV1 } from '../src/digest-envelope.js'
import { releaseQualificationInputV1Schema } from '../src/release-qualification.js'
import { releaseQualificationFixture } from './support/release-qualification-fixture.js'

const execute = promisify(execFile)
const cliPath = fileURLToPath(new URL('../src/release-assemble.ts', import.meta.url))
const qualifyCliPath = fileURLToPath(new URL('../src/release-qualify.ts', import.meta.url))

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

function portableRelative(from: string, to: string): string {
  const path = relative(dirname(from), to)
  return (path.length === 0 ? '.' : path).replaceAll('\\', '/')
}

async function git(repository: string, ...args: string[]) {
  return execute('git', ['-c', `safe.directory=${repository}`, '-C', repository, ...args], {
    windowsHide: true,
  })
}

async function fixture() {
  const root = await mkdtemp(join(tmpdir(), 'dsh-release-assemble-'))
  const inputs = join(root, 'inputs')
  const evidence = join(root, 'evidence')
  const repository = join(root, 'repository')
  const outputDirectory = join(root, 'qualification')
  await Promise.all([mkdir(inputs), mkdir(evidence), mkdir(repository), mkdir(outputDirectory)])

  const candidateBytes = Buffer.from('exact-candidate\n')
  const lockBytes = Buffer.from('lockfileVersion: 9.0\n')
  const candidatePath = join(evidence, 'candidate.tgz')
  const lockPath = join(repository, 'pnpm-lock.yaml')
  await Promise.all([
    writeFile(candidatePath, candidateBytes),
    writeFile(lockPath, lockBytes),
    writeFile(join(repository, 'package.json'), '{"name":"release-assembly-fixture"}\n'),
  ])
  await git(repository, 'init')
  await git(repository, 'config', 'user.name', 'Release Assembly Fixture')
  await git(repository, 'config', 'user.email', 'release-assembly@example.invalid')
  await git(repository, 'add', 'package.json', 'pnpm-lock.yaml')
  await git(repository, 'commit', '-m', 'fixture')
  const sourceRevision = (await git(repository, 'rev-parse', 'HEAD')).stdout.trim()

  const candidateDigest = rawDigest(candidateBytes, 'application/gzip')
  const lockDigest = rawDigest(lockBytes, 'application/yaml')
  const releaseEvidence = releaseQualificationFixture({
    sourceRevision,
    candidateArtifactDigest: candidateDigest,
    lockDigest,
  })
  const fixtureProof = releaseEvidence.proofs.find(
    proof => proof.proofKind === 'WINDOWS_PLATFORM',
  )
  if (fixtureProof === undefined) throw new Error('Fixture lacks Windows proof')
  const proofRecordPath = join(evidence, 'windows-platform.json')
  const proofRecordBytes = Buffer.from(`${JSON.stringify({
    schemaVersion: 1,
    engineId: 'security/release-proof-record/v1',
    proofRecordId: fixtureProof.evidenceId,
    proofKind: fixtureProof.proofKind,
    producer: 'PACKED_HARNESS_PROFILE_SMOKE',
    producerVersion: '0.1.0-rc.11',
    reportedStatus: fixtureProof.reportedStatus,
    candidateArtifactDigest: candidateDigest,
    completedAtEpochMs: fixtureProof.completedAtEpochMs,
    environment: {
      platform: 'WINDOWS',
      architecture: 'x64',
      nodeVersion: '24.19.0',
      harnessVersion: '0.1.3-alpha.1',
    },
    assertions: [{ assertionId: 'HARNESS_WEB_RESPONDED', status: 'PASSED' }],
  }, null, 2)}\n`)
  await writeFile(proofRecordPath, proofRecordBytes)
  const indexedProof = {
    ...fixtureProof,
    evidenceDigest: rawDigest(proofRecordBytes, 'application/json'),
  }
  const windowsPlatformProof = releaseEvidence.releaseEvaluation.candidate.platformProofs.find(
    proof => proof.platform === 'WINDOWS',
  )
  if (windowsPlatformProof === undefined) throw new Error('Fixture lacks Windows platform evidence')
  windowsPlatformProof.evidenceId = indexedProof.evidenceId
  windowsPlatformProof.evidenceDigest = indexedProof.evidenceDigest
  releaseEvidence.proofs = releaseEvidence.proofs.filter(
    proof => proof.proofKind !== 'WINDOWS_PLATFORM',
  )

  const bindingsPath = join(evidence, 'release-file-bindings.json')
  const bindingsBytes = Buffer.from(`${JSON.stringify({
    schemaVersion: 1,
    engineId: 'security/release-file-bindings/v1',
    sourceRepositoryPath: portableRelative(bindingsPath, repository),
    sourceRevision,
    candidateArtifact: {
      path: portableRelative(bindingsPath, candidatePath),
      mediaType: 'application/gzip',
      digest: candidateDigest,
    },
    dependencyLockFiles: [{
      lockKind: 'PNPM_LOCK',
      path: portableRelative(bindingsPath, lockPath),
      mediaType: 'application/yaml',
      digest: lockDigest,
    }],
  }, null, 2)}\n`)
  await writeFile(bindingsPath, bindingsBytes)

  const proofIndexPath = join(evidence, 'release-proof-index.json')
  await writeFile(proofIndexPath, `${JSON.stringify({
    schemaVersion: 1,
    engineId: 'security/release-proof-index/v1',
    releaseFileBindingsPath: 'release-file-bindings.json',
    releaseFileBindingsDigest: rawDigest(bindingsBytes, 'application/json'),
    candidateArtifactDigest: candidateDigest,
    records: [{
      recordPath: 'windows-platform.json',
      producer: 'PACKED_HARNESS_PROFILE_SMOKE',
      producerVersion: '0.1.0-rc.11',
      environment: {
        platform: 'WINDOWS',
        architecture: 'x64',
        nodeVersion: '24.19.0',
        harnessVersion: '0.1.3-alpha.1',
      },
      proof: indexedProof,
    }],
  }, null, 2)}\n`)

  const inputPath = join(inputs, 'release-assembly-input.json')
  const outputPath = join(outputDirectory, 'release-qualification-input.json')
  await writeFile(inputPath, `${JSON.stringify({
    schemaVersion: 1,
    releaseProofIndexPath: portableRelative(inputPath, proofIndexPath),
    releaseFileBindingsPath: portableRelative(inputPath, bindingsPath),
    releaseEvidence,
  }, null, 2)}\n`)
  return {
    bindingsPath,
    indexedProof,
    inputPath,
    outputPath,
    proofIndexPath,
    proofRecordPath,
  }
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

async function runQualification(inputPath: string, outputPath: string) {
  return execute(process.execPath, [
    '--experimental-strip-types',
    qualifyCliPath,
    '--',
    '--input', inputPath,
    '--output', outputPath,
  ], { windowsHide: true })
}

describe('release qualification assembly CLI', () => {
  it('merges indexed proofs into a qualification input without reinterpretation', async () => {
    const { bindingsPath, indexedProof, inputPath, outputPath } = await fixture()

    const { stdout, stderr } = await runCli(inputPath, outputPath)

    expect(stdout).toBe('')
    expect(stderr).toBe('')
    const output = releaseQualificationInputV1Schema.parse(
      JSON.parse(await readFile(outputPath, 'utf8')),
    )
    expect(output.releaseFileBindingsPath).toBe(portableRelative(outputPath, bindingsPath))
    expect(output.releaseEvidence.proofs.find(
      proof => proof.proofKind === 'WINDOWS_PLATFORM',
    )).toEqual(indexedProof)
  })

  it('fails closed without output when an indexed proof record changes after collection', async () => {
    const { inputPath, outputPath, proofRecordPath } = await fixture()
    await writeFile(proofRecordPath, '{"tampered":true}\n')

    await expect(runCli(inputPath, outputPath)).rejects.toMatchObject({
      code: 1,
      stderr: expect.stringContaining('PROOF_RECORD_DIGEST_MISMATCH'),
    })
    expect(existsSync(outputPath)).toBe(false)
  })

  it('fails closed when the qualification draft names another candidate', async () => {
    const { bindingsPath, inputPath, outputPath, proofIndexPath, proofRecordPath } = await fixture()
    const bindings = JSON.parse(await readFile(bindingsPath, 'utf8')) as {
      candidateArtifact: { digest: DigestEnvelopeV1 }
    }
    const alternateDigest = { ...bindings.candidateArtifact.digest, value: 'f'.repeat(64) }
    bindings.candidateArtifact.digest = alternateDigest
    const bindingsBytes = Buffer.from(`${JSON.stringify(bindings, null, 2)}\n`)
    await writeFile(bindingsPath, bindingsBytes)

    const proofRecord = JSON.parse(await readFile(proofRecordPath, 'utf8')) as {
      candidateArtifactDigest: DigestEnvelopeV1
    }
    proofRecord.candidateArtifactDigest = alternateDigest
    const proofRecordBytes = Buffer.from(`${JSON.stringify(proofRecord, null, 2)}\n`)
    await writeFile(proofRecordPath, proofRecordBytes)

    const proofIndex = JSON.parse(await readFile(proofIndexPath, 'utf8')) as {
      releaseFileBindingsDigest: DigestEnvelopeV1
      candidateArtifactDigest: DigestEnvelopeV1
      records: Array<{
        proof: {
          evidenceDigest: DigestEnvelopeV1
          candidateArtifactDigest: DigestEnvelopeV1
        }
      }>
    }
    proofIndex.releaseFileBindingsDigest = rawDigest(bindingsBytes, 'application/json')
    proofIndex.candidateArtifactDigest = alternateDigest
    proofIndex.records[0]!.proof.evidenceDigest = rawDigest(proofRecordBytes, 'application/json')
    proofIndex.records[0]!.proof.candidateArtifactDigest = alternateDigest
    await writeFile(proofIndexPath, `${JSON.stringify(proofIndex, null, 2)}\n`)

    await expect(runCli(inputPath, outputPath)).rejects.toMatchObject({
      code: 1,
      stderr: expect.stringContaining('CANDIDATE_DIGEST_MISMATCH'),
    })
    expect(existsSync(outputPath)).toBe(false)
  })

  it('rejects distinct index paths that resolve to the same proof record', async () => {
    const { inputPath, outputPath, proofIndexPath } = await fixture()
    const proofIndex = JSON.parse(await readFile(proofIndexPath, 'utf8')) as {
      records: Array<{
        recordPath: string
        proof: { proofKind: string; evidenceId: string }
      }>
    }
    const aliasedRecord = structuredClone(proofIndex.records[0]!)
    aliasedRecord.recordPath = `./${aliasedRecord.recordPath}`
    aliasedRecord.proof.proofKind = 'WORKBENCH'
    aliasedRecord.proof.evidenceId = 'proof/aliased-workbench'
    proofIndex.records.push(aliasedRecord)
    await writeFile(proofIndexPath, `${JSON.stringify(proofIndex, null, 2)}\n`)

    await expect(runCli(inputPath, outputPath)).rejects.toMatchObject({
      code: 1,
      stderr: expect.stringContaining('DUPLICATE_PROOF_PATH'),
    })
    expect(existsSync(outputPath)).toBe(false)
  })

  it('hands the assembled exact-artifact portfolio to the existing qualification seam', async () => {
    const { inputPath, outputPath } = await fixture()
    await runCli(inputPath, outputPath)

    const { stdout, stderr } = await runQualification(
      outputPath,
      join(dirname(outputPath), 'qualification-output'),
    )

    expect(stderr).toBe('')
    expect(JSON.parse(stdout)).toMatchObject({
      qualification: 'PROMOTE',
      manifestVerification: 'VERIFIED',
      releaseDecision: 'PROMOTE',
    })
  })

  it('preserves an indexed inconclusive status in the qualification input', async () => {
    const { inputPath, outputPath, proofIndexPath, proofRecordPath } = await fixture()
    const proofRecord = JSON.parse(await readFile(proofRecordPath, 'utf8')) as {
      reportedStatus: string
      assertions: Array<{ status: string }>
    }
    proofRecord.reportedStatus = 'INCONCLUSIVE'
    proofRecord.assertions[0]!.status = 'INCONCLUSIVE'
    const proofRecordBytes = Buffer.from(`${JSON.stringify(proofRecord, null, 2)}\n`)
    await writeFile(proofRecordPath, proofRecordBytes)

    const proofIndex = JSON.parse(await readFile(proofIndexPath, 'utf8')) as {
      records: Array<{
        proof: { evidenceDigest: DigestEnvelopeV1; reportedStatus: string }
      }>
    }
    proofIndex.records[0]!.proof.evidenceDigest = rawDigest(proofRecordBytes, 'application/json')
    proofIndex.records[0]!.proof.reportedStatus = 'INCONCLUSIVE'
    await writeFile(proofIndexPath, `${JSON.stringify(proofIndex, null, 2)}\n`)

    await runCli(inputPath, outputPath)

    const output = releaseQualificationInputV1Schema.parse(
      JSON.parse(await readFile(outputPath, 'utf8')),
    )
    expect(output.releaseEvidence.proofs.find(
      proof => proof.proofKind === 'WINDOWS_PLATFORM',
    )?.reportedStatus).toBe('INCONCLUSIVE')
  })
})
