import { execFile } from 'node:child_process'
import { createHash } from 'node:crypto'
import { existsSync } from 'node:fs'
import { mkdir, mkdtemp, readFile, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { promisify } from 'node:util'
import { gzipSync } from 'node:zlib'
import { describe, expect, it } from 'vitest'

import { SECURITY_ASSURANCE_PRODUCT_VERSION } from '../src/contracts.js'
import type { DigestEnvelopeV1 } from '../src/digest-envelope.js'
import { releasePromotionHandoffV1Schema } from '../src/release-promotion.js'
import { releaseQualificationFixture } from './support/release-qualification-fixture.js'

const execute = promisify(execFile)
const bindCliPath = fileURLToPath(new URL('../src/release-bind.ts', import.meta.url))
const qualifyCliPath = fileURLToPath(new URL('../src/release-qualify.ts', import.meta.url))
const handoffCliPath = fileURLToPath(new URL('../src/release-handoff.ts', import.meta.url))
const candidateVersion = SECURITY_ASSURANCE_PRODUCT_VERSION
const stableVersion = '0.1.0'

type PackageFile = {
  readonly path: string
  readonly contents: string | Buffer
  readonly mode?: number
}

function writeTarString(header: Buffer, offset: number, length: number, value: string): void {
  const bytes = Buffer.from(value, 'utf8')
  if (bytes.byteLength > length) throw new Error(`Tar value is too long: ${value}`)
  bytes.copy(header, offset)
}

function writeTarOctal(header: Buffer, offset: number, length: number, value: number): void {
  writeTarString(header, offset, length, `${value.toString(8).padStart(length - 1, '0')}\0`)
}

function tarHeader(path: string, size: number, mode: number): Buffer {
  const header = Buffer.alloc(512)
  writeTarString(header, 0, 100, path)
  writeTarOctal(header, 100, 8, mode)
  writeTarOctal(header, 108, 8, 0)
  writeTarOctal(header, 116, 8, 0)
  writeTarOctal(header, 124, 12, size)
  writeTarOctal(header, 136, 12, 0)
  header.fill(0x20, 148, 156)
  header[156] = '0'.charCodeAt(0)
  writeTarString(header, 257, 6, 'ustar\0')
  writeTarString(header, 263, 2, '00')
  const checksum = header.reduce((sum, byte) => sum + byte, 0)
  writeTarString(header, 148, 8, `${checksum.toString(8).padStart(6, '0')}\0 `)
  return header
}

function packageArchive(files: readonly PackageFile[]): Buffer {
  const chunks: Buffer[] = []
  for (const file of [...files].sort((left, right) => left.path.localeCompare(right.path))) {
    const contents = Buffer.isBuffer(file.contents) ? file.contents : Buffer.from(file.contents)
    chunks.push(tarHeader(`package/${file.path}`, contents.byteLength, file.mode ?? 0o644))
    chunks.push(contents)
    const padding = (512 - (contents.byteLength % 512)) % 512
    if (padding > 0) chunks.push(Buffer.alloc(padding))
  }
  chunks.push(Buffer.alloc(1_024))
  return gzipSync(Buffer.concat(chunks), { level: 9 })
}

function manifest(version: string): string {
  return `${JSON.stringify({
    name: 'dsh-security-assurance',
    version,
    type: 'module',
    main: 'lib/index.js',
    bin: { security: 'lib/index.js' },
  }, null, 2)}\n`
}

function candidateFiles(): PackageFile[] {
  return [
    { path: 'package.json', contents: manifest(candidateVersion) },
    { path: 'lib/index.js', contents: `export const VERSION = '${candidateVersion}'\nexport const safe = true\n` },
    { path: 'README.md', contents: `# Security Assurance ${candidateVersion}\n` },
    { path: 'CHANGELOG.md', contents: `## ${candidateVersion}\n\n- Candidate.\n` },
    { path: 'LICENSE', contents: 'MIT\n' },
  ]
}

function stableFiles(): PackageFile[] {
  return [
    { path: 'package.json', contents: manifest(stableVersion) },
    { path: 'lib/index.js', contents: `export const VERSION = '${stableVersion}'\nexport const safe = true\n` },
    { path: 'README.md', contents: '# Security Assurance stable\n' },
    { path: 'CHANGELOG.md', contents: '## 0.1.0\n\n- Stable promotion.\n' },
    { path: 'LICENSE', contents: 'MIT\n' },
  ]
}

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

async function runTypeScriptCli(path: string, ...args: string[]) {
  return execute(process.execPath, [
    '--experimental-strip-types',
    path,
    '--',
    ...args,
  ], { windowsHide: true })
}

async function npmPackageArchive(files: readonly PackageFile[]): Promise<Buffer> {
  const root = await mkdtemp(join(tmpdir(), 'dsh-release-handoff-npm-pack-'))
  const packageRoot = join(root, 'package-source')
  const outputRoot = join(root, 'packed')
  await Promise.all([
    mkdir(join(packageRoot, 'lib'), { recursive: true }),
    mkdir(outputRoot),
  ])
  await Promise.all(files.map(file => writeFile(
    join(packageRoot, file.path),
    file.contents,
    file.mode === undefined ? undefined : { mode: file.mode },
  )))
  const npmCommand = process.platform === 'win32'
    ? process.execPath
    : 'npm'
  const npmPrefix = process.platform === 'win32'
    ? [join(dirname(process.execPath), 'node_modules', 'npm', 'bin', 'npm-cli.js')]
    : []
  const packed = await execute(npmCommand, [
    ...npmPrefix,
    '--cache', join(root, 'npm-cache'),
    'pack',
    '--json',
    '--ignore-scripts',
    '--pack-destination', outputRoot,
  ], { cwd: packageRoot, windowsHide: true })
  const report = JSON.parse(packed.stdout) as Array<{ filename?: string }>
  const filename = report[0]?.filename
  if (filename === undefined) throw new Error('npm pack did not return a filename')
  return readFile(join(outputRoot, filename))
}

async function fixture(options: {
  readonly promotable?: boolean
  readonly candidateBytes?: Buffer
  readonly proposedBytes?: Buffer
} = {}) {
  const root = await mkdtemp(join(tmpdir(), 'dsh-release-handoff-'))
  const repository = join(root, 'repository')
  const qualificationOutput = join(root, 'qualification')
  await mkdir(repository)
  const lockBytes = Buffer.from('lockfileVersion: 9.0\n')
  const candidateBytes = options.candidateBytes ?? packageArchive(candidateFiles())
  const proposedBytes = options.proposedBytes ?? packageArchive(stableFiles())
  const candidatePath = join(root, 'candidate.tgz')
  const proposedPath = join(root, 'stable.tgz')
  await Promise.all([
    writeFile(join(repository, 'package.json'), '{"name":"release-handoff-fixture"}\n'),
    writeFile(join(repository, 'pnpm-lock.yaml'), lockBytes),
    writeFile(candidatePath, candidateBytes),
    writeFile(proposedPath, proposedBytes),
  ])
  await git(repository, 'init')
  await git(repository, 'config', 'user.name', 'Release Handoff Fixture')
  await git(repository, 'config', 'user.email', 'release-handoff@example.invalid')
  await git(repository, 'add', 'package.json', 'pnpm-lock.yaml')
  await git(repository, 'commit', '-m', 'fixture')
  const sourceRevision = (await git(repository, 'rev-parse', 'HEAD')).stdout.trim()
  const releaseEvidence = releaseQualificationFixture({
    sourceRevision,
    candidateArtifactDigest: rawDigest(candidateBytes, 'application/gzip'),
    lockDigest: rawDigest(lockBytes, 'application/yaml'),
  })
  if (options.promotable === false) {
    releaseEvidence.proofs = releaseEvidence.proofs.filter(
      proof => proof.proofKind !== 'WORKBENCH',
    )
  }
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
  }, null, 2)}\n`)
  await runTypeScriptCli(
    bindCliPath,
    '--input', bindingInputPath,
    '--output', bindingPath,
  )
  const qualificationInputPath = join(root, 'qualification-input.json')
  await writeFile(qualificationInputPath, `${JSON.stringify({
    schemaVersion: 1,
    releaseFileBindingsPath: 'release-file-bindings.json',
    releaseEvidence,
  }, null, 2)}\n`)
  if (options.promotable === false) {
    await expect(runTypeScriptCli(
      qualifyCliPath,
      '--input', qualificationInputPath,
      '--output', qualificationOutput,
    )).rejects.toMatchObject({ code: 2 })
  } else {
    await runTypeScriptCli(
      qualifyCliPath,
      '--input', qualificationInputPath,
      '--output', qualificationOutput,
    )
  }
  const handoffInputPath = join(root, 'handoff-input.json')
  const receiptPath = join(root, 'promotion-handoff.json')
  await writeFile(handoffInputPath, `${JSON.stringify({
    schemaVersion: 1,
    qualificationOutputPath: 'qualification',
    qualifiedCandidateArtifact: { path: 'candidate.tgz', mediaType: 'application/gzip' },
    proposedStableArtifact: { path: 'stable.tgz', mediaType: 'application/gzip' },
    expectedStableVersion: stableVersion,
  }, null, 2)}\n`)
  return {
    root,
    qualificationOutput,
    candidatePath,
    proposedPath,
    handoffInputPath,
    receiptPath,
  }
}

async function runHandoff(inputPath: string, outputPath: string) {
  return runTypeScriptCli(
    handoffCliPath,
    '--input', inputPath,
    '--output', outputPath,
  )
}

describe('release promotion handoff CLI', () => {
  it('proves RC-to-stable behavior equivalence without granting release authority', async () => {
    const { handoffInputPath, receiptPath } = await fixture()

    const { stdout, stderr } = await runHandoff(handoffInputPath, receiptPath)

    expect(stderr).toBe('')
    const receipt = releasePromotionHandoffV1Schema.parse(JSON.parse(stdout))
    expect(JSON.parse(await readFile(receiptPath, 'utf8'))).toEqual(receipt)
    expect(receipt).toMatchObject({
      packageName: 'dsh-security-assurance',
      candidateVersion,
      stableVersion,
      comparedEntryCount: 5,
      equivalence: 'EXACT_VERSION_TOKEN_REPLACEMENT_V1',
      verification: 'BEHAVIOR_EQUIVALENT',
      authorization: 'NOT_GRANTED',
      versionChangedEntryPaths: ['package/lib/index.js', 'package/package.json'],
      releaseMetadataChangedEntryPaths: ['package/CHANGELOG.md', 'package/README.md'],
    })
  })

  it('accepts npm-produced tarballs rather than only synthetic archive fixtures', async () => {
    const [candidateBytes, proposedBytes] = await Promise.all([
      npmPackageArchive(candidateFiles()),
      npmPackageArchive(stableFiles()),
    ])
    const { handoffInputPath, receiptPath } = await fixture({
      candidateBytes,
      proposedBytes,
    })

    const { stdout } = await runHandoff(handoffInputPath, receiptPath)

    expect(releasePromotionHandoffV1Schema.parse(JSON.parse(stdout))).toMatchObject({
      verification: 'BEHAVIOR_EQUIVALENT',
      authorization: 'NOT_GRANTED',
    })
  }, 30_000)

  it('rejects runtime behavior drift in the proposed stable package', async () => {
    const fixtureState = await fixture()
    const driftedFiles = stableFiles().map(file => file.path === 'lib/index.js'
      ? { ...file, contents: `export const VERSION = '${stableVersion}'\nexport const safe = false\n` }
      : file)
    await writeFile(fixtureState.proposedPath, packageArchive(driftedFiles))

    await expect(runHandoff(
      fixtureState.handoffInputPath,
      fixtureState.receiptPath,
    )).rejects.toMatchObject({
      code: 1,
      stderr: expect.stringContaining('ARTIFACT_BEHAVIOR_MISMATCH'),
    })
    expect(existsSync(fixtureState.receiptPath)).toBe(false)
  })

  it('rejects an added package entry even when existing behavior is unchanged', async () => {
    const fixtureState = await fixture()
    await writeFile(fixtureState.proposedPath, packageArchive([
      ...stableFiles(),
      { path: 'lib/extra.js', contents: 'export const extra = true\n' },
    ]))

    await expect(runHandoff(
      fixtureState.handoffInputPath,
      fixtureState.receiptPath,
    )).rejects.toMatchObject({
      code: 1,
      stderr: expect.stringContaining('PACKAGE_INVENTORY_MISMATCH'),
    })
    expect(existsSync(fixtureState.receiptPath)).toBe(false)
  })

  it('rejects a candidate artifact that differs from the qualified bytes', async () => {
    const fixtureState = await fixture()
    await writeFile(fixtureState.candidatePath, packageArchive([
      ...candidateFiles(),
      { path: 'unexpected.txt', contents: 'drift\n' },
    ]))

    await expect(runHandoff(
      fixtureState.handoffInputPath,
      fixtureState.receiptPath,
    )).rejects.toMatchObject({
      code: 1,
      stderr: expect.stringContaining('QUALIFIED_ARTIFACT_DIGEST_MISMATCH'),
    })
    expect(existsSync(fixtureState.receiptPath)).toBe(false)
  })

  it('rejects a valid but inconclusive qualification portfolio', async () => {
    const { handoffInputPath, receiptPath } = await fixture({ promotable: false })

    await expect(runHandoff(handoffInputPath, receiptPath)).rejects.toMatchObject({
      code: 1,
      stderr: expect.stringContaining('QUALIFICATION_NOT_PROMOTABLE'),
    })
    expect(existsSync(receiptPath)).toBe(false)
  })

  it('rejects tampering between qualification and promotion handoff', async () => {
    const fixtureState = await fixture()
    const verdictPath = join(
      fixtureState.qualificationOutput,
      'release-qualification-verdict.json',
    )
    const verdict = JSON.parse(await readFile(verdictPath, 'utf8')) as { manifestId: string }
    verdict.manifestId = 'another-manifest'
    await writeFile(verdictPath, `${JSON.stringify(verdict, null, 2)}\n`)

    await expect(runHandoff(
      fixtureState.handoffInputPath,
      fixtureState.receiptPath,
    )).rejects.toMatchObject({
      code: 1,
      stderr: expect.stringContaining('QUALIFICATION_PORTFOLIO_MISMATCH'),
    })
    expect(existsSync(fixtureState.receiptPath)).toBe(false)
  })
})
