import { execFile } from 'node:child_process'
import { createHash } from 'node:crypto'
import { existsSync } from 'node:fs'
import { mkdir, mkdtemp, readFile, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { promisify } from 'node:util'
import { describe, expect, it } from 'vitest'

const execute = promisify(execFile)
const cliPath = fileURLToPath(new URL('../src/release-bind.ts', import.meta.url))

async function git(repository: string, ...args: string[]) {
  return execute('git', ['-c', `safe.directory=${repository}`, '-C', repository, ...args], {
    windowsHide: true,
  })
}

async function fixture() {
  const root = await mkdtemp(join(tmpdir(), 'dsh-release-bind-'))
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
  const inputPath = join(root, 'release-files.json')
  const outputPath = join(root, 'release-file-bindings.json')
  await writeFile(inputPath, `${JSON.stringify({
    schemaVersion: 1,
    sourceRepositoryPath: 'repository',
    candidateArtifact: { path: 'candidate.tgz', mediaType: 'application/gzip' },
    dependencyLockFiles: [{
      lockKind: 'PNPM_LOCK',
      path: 'repository/pnpm-lock.yaml',
      mediaType: 'application/yaml',
    }],
  }, null, 2)}\n`, 'utf8')
  return { root, repository, inputPath, outputPath, lockBytes, artifactBytes }
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

describe('release file binding CLI', () => {
  it('writes deterministic raw-byte bindings for a clean source revision', async () => {
    const { repository, inputPath, outputPath, lockBytes, artifactBytes } = await fixture()
    const secondOutputPath = join(outputPath, '..', 'release-file-bindings-copy.json')
    const { stdout, stderr } = await runCli(inputPath, outputPath)
    await runCli(inputPath, secondOutputPath)

    expect(stderr).toBe('')
    expect(stdout).toBe('')
    expect(await readFile(secondOutputPath, 'utf8')).toBe(await readFile(outputPath, 'utf8'))
    const { stdout: revision } = await git(repository, 'rev-parse', 'HEAD')
    expect(JSON.parse(await readFile(outputPath, 'utf8'))).toEqual({
      schemaVersion: 1,
      engineId: 'security/release-file-bindings/v1',
      sourceRepositoryPath: 'repository',
      sourceRevision: revision.trim(),
      candidateArtifact: {
        path: 'candidate.tgz',
        mediaType: 'application/gzip',
        digest: {
          schemaVersion: 1,
          algorithm: 'sha256',
          mediaType: 'application/gzip',
          byteLength: artifactBytes.byteLength,
          canonicalization: 'raw-bytes',
          value: createHash('sha256').update(artifactBytes).digest('hex'),
        },
      },
      dependencyLockFiles: [{
        lockKind: 'PNPM_LOCK',
        path: 'repository/pnpm-lock.yaml',
        mediaType: 'application/yaml',
        digest: {
          schemaVersion: 1,
          algorithm: 'sha256',
          mediaType: 'application/yaml',
          byteLength: lockBytes.byteLength,
          canonicalization: 'raw-bytes',
          value: createHash('sha256').update(lockBytes).digest('hex'),
        },
      }],
    })
  })

  it('fails closed without an output when tracked source bytes are dirty', async () => {
    const { repository, inputPath, outputPath } = await fixture()
    await writeFile(join(repository, 'package.json'), '{"name":"dirty"}\n', 'utf8')

    await expect(runCli(inputPath, outputPath)).rejects.toMatchObject({
      code: 1,
      stderr: expect.stringContaining('SOURCE_NOT_CLEAN'),
    })
    expect(existsSync(outputPath)).toBe(false)
  })
})
