import { execFile } from 'node:child_process'
import { createHash } from 'node:crypto'
import { existsSync } from 'node:fs'
import { mkdir, mkdtemp, readFile, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { promisify } from 'node:util'
import { describe, expect, it } from 'vitest'

import type { DigestEnvelopeV1 } from '../src/digest-envelope.js'
import { releaseEvidenceManifestV1Schema } from '../src/evaluation.js'
import { releaseQualificationFixture } from './support/release-qualification-fixture.js'

const execute = promisify(execFile)
const cliPath = fileURLToPath(new URL('../src/release-qualify.ts', import.meta.url))
const bindCliPath = fileURLToPath(new URL('../src/release-bind.ts', import.meta.url))

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

async function git(repository: string, ...args: string[]) {
  return execute('git', ['-c', `safe.directory=${repository}`, '-C', repository, ...args], {
    windowsHide: true,
  })
}

async function fixture() {
  const root = await mkdtemp(join(tmpdir(), 'dsh-release-qualify-'))
  const repository = join(root, 'repository')
  await mkdir(repository)
  const lockBytes = Buffer.from('lockfileVersion: 9.0\n', 'utf8')
  const artifactBytes = Buffer.from('exact-packed-candidate-bytes\n', 'utf8')
  await writeFile(join(repository, 'package.json'), '{"name":"release-fixture"}\n', 'utf8')
  await writeFile(join(repository, 'pnpm-lock.yaml'), lockBytes)
  await writeFile(join(root, 'candidate.tgz'), artifactBytes)
  await git(repository, 'init')
  await git(repository, 'config', 'user.name', 'Release Fixture')
  await git(repository, 'config', 'user.email', 'release-fixture@example.invalid')
  await git(repository, 'add', 'package.json', 'pnpm-lock.yaml')
  await git(repository, 'commit', '-m', 'fixture')
  const { stdout } = await git(repository, 'rev-parse', 'HEAD')
  const sourceRevision = stdout.trim()
  const releaseEvidence = releaseQualificationFixture({
    sourceRevision,
    candidateArtifactDigest: rawDigest(artifactBytes, 'application/gzip'),
    lockDigest: rawDigest(lockBytes, 'application/yaml'),
  })
  const bindingInputPath = join(root, 'release-files.json')
  const bindingPath = join(root, 'release-file-bindings.json')
  await writeFile(bindingInputPath, `${JSON.stringify({
    schemaVersion: 1,
    sourceRepositoryPath: 'repository',
    candidateArtifact: { path: 'candidate.tgz', mediaType: 'application/gzip' },
    dependencyLockFiles: [{
      lockKind: 'PNPM_LOCK',
      path: 'repository/pnpm-lock.yaml',
      mediaType: 'application/yaml',
    }],
  }, null, 2)}\n`, 'utf8')
  await execute(process.execPath, [
    '--experimental-strip-types',
    bindCliPath,
    '--',
    '--input',
    bindingInputPath,
    '--output',
    bindingPath,
  ], { windowsHide: true })
  const inputPath = join(root, 'qualification-input.json')
  const outputPath = join(root, 'qualification-output')
  await writeFile(inputPath, `${JSON.stringify({
    schemaVersion: 1,
    releaseFileBindingsPath: 'release-file-bindings.json',
    releaseEvidence,
  }, null, 2)}\n`, 'utf8')
  return { root, repository, inputPath, outputPath, bindingPath }
}

async function runCli(inputPath: string, outputPath: string) {
  return execute(process.execPath, [
    '--experimental-strip-types',
    cliPath,
    '--',
    '--input',
    inputPath,
    '--output',
    outputPath,
  ], { windowsHide: true })
}

describe('release qualification CLI', () => {
  it('qualifies one exact artifact, source revision, lock set, and evidence portfolio', async () => {
    const { inputPath, outputPath } = await fixture()

    const { stdout, stderr } = await runCli(inputPath, outputPath)

    expect(stderr).toBe('')
    expect(JSON.parse(stdout)).toMatchObject({
      qualification: 'PROMOTE',
      releaseDecision: 'PROMOTE',
      manifestVerification: 'VERIFIED',
    })
    const manifest = releaseEvidenceManifestV1Schema.parse(JSON.parse(
      await readFile(join(outputPath, 'release-evidence-manifest.json'), 'utf8'),
    ))
    expect(manifest.sourceRevision).toHaveLength(40)
    expect(manifest.verification.decision).toBe('VERIFIED')
    expect(JSON.parse(
      await readFile(join(outputPath, 'release-qualification-verdict.json'), 'utf8'),
    )).toEqual(JSON.parse(stdout))
    expect(JSON.parse(
      await readFile(join(outputPath, 'public-security-scorecard.json'), 'utf8'),
    )).toEqual(manifest.publicScorecard)
  })

  it('fails closed before emitting a portfolio when candidate bytes drift', async () => {
    const { root, inputPath, outputPath } = await fixture()
    await writeFile(join(root, 'candidate.tgz'), 'tampered-candidate-bytes\n', 'utf8')

    await expect(runCli(inputPath, outputPath)).rejects.toMatchObject({
      code: 1,
      stderr: expect.stringContaining('ARTIFACT_DIGEST_MISMATCH'),
    })
    expect(existsSync(outputPath)).toBe(false)
  })

  it('rejects lock drift even when the new source revision is supplied', async () => {
    const { repository, inputPath, outputPath, bindingPath } = await fixture()
    await writeFile(join(repository, 'pnpm-lock.yaml'), 'lockfileVersion: 9.1\n', 'utf8')
    await git(repository, 'add', 'pnpm-lock.yaml')
    await git(repository, 'commit', '-m', 'drift lock')
    const { stdout } = await git(repository, 'rev-parse', 'HEAD')
    const input = JSON.parse(await readFile(inputPath, 'utf8')) as {
      releaseEvidence: { sourceRevision: string }
    }
    input.releaseEvidence.sourceRevision = stdout.trim()
    await writeFile(inputPath, `${JSON.stringify(input, null, 2)}\n`, 'utf8')
    const binding = JSON.parse(await readFile(bindingPath, 'utf8')) as {
      sourceRevision: string
    }
    binding.sourceRevision = stdout.trim()
    await writeFile(bindingPath, `${JSON.stringify(binding, null, 2)}\n`, 'utf8')

    await expect(runCli(inputPath, outputPath)).rejects.toMatchObject({
      code: 1,
      stderr: expect.stringContaining('LOCK_DIGEST_MISMATCH'),
    })
    expect(existsSync(outputPath)).toBe(false)
  })

  it('emits an auditable inconclusive portfolio without claiming promotion', async () => {
    const { inputPath, outputPath } = await fixture()
    const input = JSON.parse(await readFile(inputPath, 'utf8')) as {
      releaseEvidence: { proofs: Array<{ proofKind: string }> }
    }
    input.releaseEvidence.proofs = input.releaseEvidence.proofs.filter(
      proof => proof.proofKind !== 'WORKBENCH',
    )
    await writeFile(inputPath, `${JSON.stringify(input, null, 2)}\n`, 'utf8')

    await expect(runCli(inputPath, outputPath)).rejects.toMatchObject({
      code: 2,
      stdout: expect.stringContaining('"qualification": "INCONCLUSIVE"'),
    })
    const verdict = JSON.parse(
      await readFile(join(outputPath, 'release-qualification-verdict.json'), 'utf8'),
    ) as { qualification: string; releaseDecision: string; manifestVerification: string }
    expect(verdict).toEqual(expect.objectContaining({
      qualification: 'INCONCLUSIVE',
      releaseDecision: 'PROMOTE',
      manifestVerification: 'INCONCLUSIVE',
    }))
  })
})
