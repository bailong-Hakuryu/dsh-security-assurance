#!/usr/bin/env node

import { createHash } from 'node:crypto'
import { lstat, link, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { basename, dirname, resolve } from 'node:path'
import { gunzipSync } from 'node:zlib'

import type { DigestEnvelopeV1 } from './digest-envelope.ts'
import { isDirectCliInvocation } from './internal/cli-entry.ts'
import {
  releaseEvidenceScorecardReferenceV1Schema,
  releaseEvidenceManifestV1Schema,
  type ReleaseEvidenceManifestV1,
} from './evaluation.ts'
import {
  ReleaseFileBoundaryError,
  releaseFileFailure,
  sameDigest,
} from './internal/release-file-verification.ts'
import {
  releaseQualificationVerdictV1Schema,
  type ReleaseQualificationVerdictV1,
} from './release-qualification.ts'
import {
  RELEASE_PROMOTION_HANDOFF_ENGINE_ID,
  releasePromotionHandoffInputV1Schema,
  releasePromotionHandoffV1Schema,
  type ReleasePromotionHandoffInputV1,
  type ReleasePromotionHandoffV1,
} from './release-promotion.ts'

const maximumJsonBytes = 50 * 1024 * 1024
const maximumArchiveBytes = 50 * 1024 * 1024
const maximumExpandedArchiveBytes = 200 * 1024 * 1024
const maximumArchiveEntries = 10_000
const tarBlockBytes = 512
const releaseMetadataPaths = new Set([
  'package/CHANGELOG.md',
  'package/README.md',
])

type ReleaseHandoffIo = {
  readonly stdout: { write(value: string): unknown }
  readonly stderr: { write(value: string): unknown }
}

type CliArguments = {
  readonly inputPath: string
  readonly outputPath: string
}

type QualificationPortfolio = {
  readonly manifest: ReleaseEvidenceManifestV1
  readonly publicScorecard: ReleaseEvidenceManifestV1['publicScorecard']
  readonly verdict: ReleaseQualificationVerdictV1
  readonly digests: ReleasePromotionHandoffV1['qualificationPortfolioDigests']
}

type ArchiveEntry = {
  readonly path: string
  readonly kind: 'FILE' | 'DIRECTORY'
  readonly mode: number
  readonly bytes: Buffer
}

function invalid(code: string, message: string): never {
  return releaseFileFailure(code, message)
}

function serialized(value: unknown): string {
  return `${JSON.stringify(value, null, 2)}\n`
}

function parseArguments(args: readonly string[]): CliArguments {
  const normalizedArgs = args[0] === '--' ? args.slice(1) : args
  const values = new Map<string, string>()
  for (let index = 0; index < normalizedArgs.length; index += 2) {
    const flag = normalizedArgs[index]
    const value = normalizedArgs[index + 1]
    if (
      (flag !== '--input' && flag !== '--output')
      || value === undefined
      || value.length === 0
      || values.has(flag)
    ) {
      return invalid(
        'INVALID_ARGUMENTS',
        'Usage: dsh-security-assurance-release-handoff --input <handoff.json> --output <receipt.json>',
      )
    }
    values.set(flag, value)
  }
  const inputPath = values.get('--input')
  const outputPath = values.get('--output')
  if (normalizedArgs.length !== 4 || inputPath === undefined || outputPath === undefined) {
    return invalid(
      'INVALID_ARGUMENTS',
      'Usage: dsh-security-assurance-release-handoff --input <handoff.json> --output <receipt.json>',
    )
  }
  return { inputPath: resolve(inputPath), outputPath: resolve(outputPath) }
}

async function readBoundFile(
  path: string,
  maximumBytes: number,
  code: string,
  message: string,
): Promise<Buffer> {
  try {
    const before = await lstat(path)
    if (!before.isFile() || before.isSymbolicLink() || before.size > maximumBytes) {
      return invalid(code, message)
    }
    const bytes = await readFile(path)
    const after = await lstat(path)
    if (
      !after.isFile()
      || after.isSymbolicLink()
      || after.size !== before.size
      || bytes.byteLength !== before.size
      || after.mtimeMs !== before.mtimeMs
    ) {
      return invalid(code, message)
    }
    return bytes
  } catch (error) {
    if (error instanceof ReleaseFileBoundaryError) throw error
    return invalid(code, message)
  }
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

function parseJson(bytes: Buffer, code: string, message: string): unknown {
  try {
    return JSON.parse(bytes.toString('utf8'))
  } catch {
    return invalid(code, message)
  }
}

async function parseInput(inputPath: string): Promise<ReleasePromotionHandoffInputV1> {
  const bytes = await readBoundFile(
    inputPath,
    maximumJsonBytes,
    'INVALID_INPUT',
    'Release promotion handoff input is invalid.',
  )
  const parsed = releasePromotionHandoffInputV1Schema.safeParse(parseJson(
    bytes,
    'INVALID_INPUT',
    'Release promotion handoff input is invalid.',
  ))
  if (!parsed.success) {
    return invalid('INVALID_INPUT', 'Release promotion handoff input is invalid.')
  }
  return parsed.data
}

async function readQualificationPortfolio(path: string): Promise<QualificationPortfolio> {
  const readPortfolioFile = (name: string) => readBoundFile(
    resolve(path, name),
    maximumJsonBytes,
    'INVALID_QUALIFICATION_PORTFOLIO',
    'Release qualification portfolio is invalid.',
  )
  const [manifestBytes, scorecardBytes, verdictBytes] = await Promise.all([
    readPortfolioFile('release-evidence-manifest.json'),
    readPortfolioFile('public-security-scorecard.json'),
    readPortfolioFile('release-qualification-verdict.json'),
  ])
  const manifestResult = releaseEvidenceManifestV1Schema.safeParse(parseJson(
    manifestBytes,
    'INVALID_QUALIFICATION_PORTFOLIO',
    'Release qualification portfolio is invalid.',
  ))
  const scorecardResult = releaseEvidenceScorecardReferenceV1Schema.safeParse(parseJson(
    scorecardBytes,
    'INVALID_QUALIFICATION_PORTFOLIO',
    'Release qualification portfolio is invalid.',
  ))
  const verdictResult = releaseQualificationVerdictV1Schema.safeParse(parseJson(
    verdictBytes,
    'INVALID_QUALIFICATION_PORTFOLIO',
    'Release qualification portfolio is invalid.',
  ))
  if (!manifestResult.success || !scorecardResult.success || !verdictResult.success) {
    return invalid('INVALID_QUALIFICATION_PORTFOLIO', 'Release qualification portfolio is invalid.')
  }
  const manifest = manifestResult.data
  const publicScorecard = scorecardResult.data
  const verdict = verdictResult.data
  if (
    JSON.stringify(publicScorecard) !== JSON.stringify(manifest.publicScorecard)
    || verdict.evaluatedAtEpochMs !== manifest.assembledAtEpochMs
    || verdict.sourceRevision !== manifest.sourceRevision
    || verdict.manifestId !== manifest.manifestId
    || verdict.releaseCandidateId !== manifest.releaseCandidateId
    || !sameDigest(verdict.candidateArtifactDigest, manifest.candidateArtifactDigest)
    || verdict.releaseDecision !== manifest.releaseConstitution.decision
    || verdict.manifestVerification !== manifest.verification.decision
  ) {
    return invalid(
      'QUALIFICATION_PORTFOLIO_MISMATCH',
      'Release qualification files do not describe one result.',
    )
  }
  if (
    verdict.qualification !== 'PROMOTE'
    || verdict.releaseDecision !== 'PROMOTE'
    || verdict.manifestVerification !== 'VERIFIED'
  ) {
    return invalid(
      'QUALIFICATION_NOT_PROMOTABLE',
      'Release qualification did not authorize a promotion candidate.',
    )
  }
  return {
    manifest,
    publicScorecard,
    verdict,
    digests: {
      manifest: rawDigest(manifestBytes, 'application/json'),
      publicScorecard: rawDigest(scorecardBytes, 'application/json'),
      verdict: rawDigest(verdictBytes, 'application/json'),
    },
  }
}

function isZeroBlock(bytes: Buffer, offset: number): boolean {
  for (let index = offset; index < offset + tarBlockBytes; index += 1) {
    if (bytes[index] !== 0) return false
  }
  return true
}

function tarString(bytes: Buffer, offset: number, length: number): string {
  const field = bytes.subarray(offset, offset + length)
  const end = field.indexOf(0)
  return field.subarray(0, end === -1 ? field.length : end).toString('utf8')
}

function tarOctal(bytes: Buffer, offset: number, length: number): number {
  const field = bytes.subarray(offset, offset + length)
  if ((field[0] ?? 0) >= 0x80) {
    return invalid('INVALID_PACKAGE_ARCHIVE', 'Package archive uses an unsupported number encoding.')
  }
  const value = field.toString('ascii').replaceAll('\0', '').trim()
  if (!/^[0-7]*$/u.test(value)) {
    return invalid('INVALID_PACKAGE_ARCHIVE', 'Package archive has an invalid numeric field.')
  }
  return value.length === 0 ? 0 : Number.parseInt(value, 8)
}

function assertTarChecksum(bytes: Buffer, offset: number): void {
  const expected = tarOctal(bytes, offset + 148, 8)
  let actual = 0
  for (let index = 0; index < tarBlockBytes; index += 1) {
    actual += index >= 148 && index < 156 ? 0x20 : bytes[offset + index]!
  }
  if (actual !== expected) {
    return invalid('INVALID_PACKAGE_ARCHIVE', 'Package archive header checksum is invalid.')
  }
}

function parsePax(bytes: Buffer): Map<string, string> {
  const values = new Map<string, string>()
  let offset = 0
  while (offset < bytes.byteLength) {
    const separator = bytes.indexOf(0x20, offset)
    if (separator === -1) {
      return invalid('INVALID_PACKAGE_ARCHIVE', 'Package archive has invalid PAX metadata.')
    }
    const lengthText = bytes.subarray(offset, separator).toString('ascii')
    if (!/^\d+$/u.test(lengthText)) {
      return invalid('INVALID_PACKAGE_ARCHIVE', 'Package archive has invalid PAX metadata.')
    }
    const recordLength = Number.parseInt(lengthText, 10)
    const recordEnd = offset + recordLength
    if (recordLength <= separator - offset + 2 || recordEnd > bytes.byteLength) {
      return invalid('INVALID_PACKAGE_ARCHIVE', 'Package archive has invalid PAX metadata.')
    }
    const record = bytes.subarray(separator + 1, recordEnd)
    if (record.at(-1) !== 0x0a) {
      return invalid('INVALID_PACKAGE_ARCHIVE', 'Package archive has invalid PAX metadata.')
    }
    const assignment = record.subarray(0, -1).toString('utf8')
    const equals = assignment.indexOf('=')
    if (equals <= 0) {
      return invalid('INVALID_PACKAGE_ARCHIVE', 'Package archive has invalid PAX metadata.')
    }
    values.set(assignment.slice(0, equals), assignment.slice(equals + 1))
    offset = recordEnd
  }
  return values
}

function normalizedPackagePath(path: string): string {
  if (
    path.length === 0
    || path.length > 4_096
    || path.includes('\\')
    || path.startsWith('/')
    || !path.startsWith('package/')
    || path.split('/').some(segment => segment.length === 0 || segment === '.' || segment === '..')
  ) {
    return invalid('INVALID_PACKAGE_ARCHIVE', 'Package archive contains an invalid entry path.')
  }
  return path
}

function parsePackageArchive(compressedBytes: Buffer): readonly ArchiveEntry[] {
  let bytes: Buffer
  try {
    bytes = gunzipSync(compressedBytes, { maxOutputLength: maximumExpandedArchiveBytes })
  } catch {
    return invalid('INVALID_PACKAGE_ARCHIVE', 'Package archive is not a bounded gzip tarball.')
  }
  const entries = new Map<string, ArchiveEntry>()
  let offset = 0
  let localPax = new Map<string, string>()
  let globalPax = new Map<string, string>()
  let longName: string | undefined
  while (offset + tarBlockBytes <= bytes.byteLength) {
    if (isZeroBlock(bytes, offset)) {
      for (let index = offset; index < bytes.byteLength; index += 1) {
        if (bytes[index] !== 0) {
          return invalid('INVALID_PACKAGE_ARCHIVE', 'Package archive has trailing data.')
        }
      }
      return [...entries.values()].sort((left, right) => left.path.localeCompare(right.path))
    }
    assertTarChecksum(bytes, offset)
    const size = tarOctal(bytes, offset + 124, 12)
    const mode = tarOctal(bytes, offset + 100, 8) & 0o7777
    const typeFlag = String.fromCharCode(bytes[offset + 156] ?? 0)
    const bodyOffset = offset + tarBlockBytes
    const bodyEnd = bodyOffset + size
    const nextOffset = bodyOffset + Math.ceil(size / tarBlockBytes) * tarBlockBytes
    if (!Number.isSafeInteger(size) || bodyEnd > bytes.byteLength || nextOffset > bytes.byteLength) {
      return invalid('INVALID_PACKAGE_ARCHIVE', 'Package archive entry exceeds its boundary.')
    }
    const body = bytes.subarray(bodyOffset, bodyEnd)
    if (typeFlag === 'x' || typeFlag === 'g') {
      const pax = parsePax(body)
      if (typeFlag === 'x') localPax = pax
      else globalPax = new Map([...globalPax, ...pax])
      offset = nextOffset
      continue
    }
    if (typeFlag === 'L') {
      longName = tarString(body, 0, body.byteLength)
      offset = nextOffset
      continue
    }
    if (typeFlag !== '\0' && typeFlag !== '0' && typeFlag !== '5') {
      return invalid('INVALID_PACKAGE_ARCHIVE', 'Package archive contains an unsupported entry type.')
    }
    const name = tarString(bytes, offset, 100)
    const prefix = tarString(bytes, offset + 345, 155)
    const standardPath = prefix.length === 0 ? name : `${prefix}/${name}`
    const path = normalizedPackagePath(localPax.get('path') ?? globalPax.get('path') ?? longName ?? standardPath)
    const kind = typeFlag === '5' ? 'DIRECTORY' as const : 'FILE' as const
    if (entries.has(path) || entries.size >= maximumArchiveEntries || (kind === 'DIRECTORY' && size !== 0)) {
      return invalid('INVALID_PACKAGE_ARCHIVE', 'Package archive contains invalid duplicate or directory entries.')
    }
    entries.set(path, { path, kind, mode, bytes: Buffer.from(body) })
    localPax = new Map()
    longName = undefined
    offset = nextOffset
  }
  return invalid('INVALID_PACKAGE_ARCHIVE', 'Package archive is truncated.')
}

function utf8(bytes: Buffer): string | undefined {
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes)
  } catch {
    return undefined
  }
}

function jsonObject(bytes: Buffer): Record<string, unknown> {
  const text = utf8(bytes)
  if (text === undefined) {
    return invalid('INVALID_PACKAGE_MANIFEST', 'Package manifest is not valid UTF-8 JSON.')
  }
  let decoded: unknown
  try {
    decoded = JSON.parse(text)
  } catch {
    return invalid('INVALID_PACKAGE_MANIFEST', 'Package manifest is not valid UTF-8 JSON.')
  }
  if (decoded === null || Array.isArray(decoded) || typeof decoded !== 'object') {
    return invalid('INVALID_PACKAGE_MANIFEST', 'Package manifest is not a JSON object.')
  }
  return decoded as Record<string, unknown>
}

function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value)
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`
  const record = value as Record<string, unknown>
  return `{${Object.keys(record).sort().map(key => (
    `${JSON.stringify(key)}:${canonicalJson(record[key])}`
  )).join(',')}}`
}

function sameEntryShape(left: ArchiveEntry, right: ArchiveEntry): boolean {
  return left.path === right.path && left.kind === right.kind && left.mode === right.mode
}

function comparePackageArchives(
  candidateEntries: readonly ArchiveEntry[],
  stableEntries: readonly ArchiveEntry[],
  qualificationVersion: string,
  expectedStableVersion: string,
): {
  readonly packageName: string
  readonly candidateVersion: string
  readonly versionChangedEntryPaths: readonly string[]
  readonly releaseMetadataChangedEntryPaths: readonly string[]
} {
  if (
    candidateEntries.length !== stableEntries.length
    || candidateEntries.some((entry, index) => !sameEntryShape(entry, stableEntries[index]!))
  ) {
    return invalid('PACKAGE_INVENTORY_MISMATCH', 'Proposed stable package changes the archive inventory.')
  }
  const candidateManifestEntry = candidateEntries.find(entry => entry.path === 'package/package.json')
  const stableManifestEntry = stableEntries.find(entry => entry.path === 'package/package.json')
  if (
    candidateManifestEntry?.kind !== 'FILE'
    || stableManifestEntry?.kind !== 'FILE'
  ) {
    return invalid('INVALID_PACKAGE_MANIFEST', 'Package archive lacks package/package.json.')
  }
  const candidateManifest = jsonObject(candidateManifestEntry.bytes)
  const stableManifest = jsonObject(stableManifestEntry.bytes)
  const packageName = candidateManifest.name
  const candidateVersion = candidateManifest.version
  if (
    typeof packageName !== 'string'
    || packageName.length === 0
    || packageName !== stableManifest.name
    || typeof candidateVersion !== 'string'
    || candidateVersion !== qualificationVersion
    || stableManifest.version !== expectedStableVersion
    || candidateVersion.split('-', 1)[0] !== expectedStableVersion
    || !new RegExp(
      '^(?:0|[1-9]\\d*)\\.(?:0|[1-9]\\d*)\\.(?:0|[1-9]\\d*)-[0-9A-Za-z-]+(?:\\.[0-9A-Za-z-]+)*(?:\\+[0-9A-Za-z-]+(?:\\.[0-9A-Za-z-]+)*)?$',
      'u',
    ).test(candidateVersion)
  ) {
    return invalid('INVALID_VERSION_TRANSITION', 'Package versions do not describe one RC-to-stable transition.')
  }
  if (
    canonicalJson({ ...candidateManifest, version: expectedStableVersion })
    !== canonicalJson(stableManifest)
  ) {
    return invalid('PACKAGE_MANIFEST_DRIFT', 'Proposed stable package changes manifest fields other than version.')
  }

  const versionChangedEntryPaths = ['package/package.json']
  const releaseMetadataChangedEntryPaths: string[] = []
  for (let index = 0; index < candidateEntries.length; index += 1) {
    const candidate = candidateEntries[index]!
    const stable = stableEntries[index]!
    if (candidate.path === 'package/package.json' || candidate.bytes.equals(stable.bytes)) continue
    if (releaseMetadataPaths.has(candidate.path)) {
      releaseMetadataChangedEntryPaths.push(candidate.path)
      continue
    }
    if (candidate.kind !== 'FILE') {
      return invalid('ARTIFACT_BEHAVIOR_MISMATCH', 'Proposed stable package changes package behavior.')
    }
    const candidateText = utf8(candidate.bytes)
    const stableText = utf8(stable.bytes)
    if (candidateText === undefined || stableText === undefined) {
      return invalid('ARTIFACT_BEHAVIOR_MISMATCH', 'Proposed stable package changes binary content.')
    }
    const promotedText = candidateText.replaceAll(candidateVersion, expectedStableVersion)
    if (promotedText === candidateText || promotedText !== stableText) {
      return invalid('ARTIFACT_BEHAVIOR_MISMATCH', 'Proposed stable package changes more than its version token.')
    }
    versionChangedEntryPaths.push(candidate.path)
  }
  versionChangedEntryPaths.sort()
  releaseMetadataChangedEntryPaths.sort()
  return {
    packageName,
    candidateVersion,
    versionChangedEntryPaths,
    releaseMetadataChangedEntryPaths,
  }
}

async function assertOutputAbsent(outputPath: string): Promise<void> {
  try {
    await lstat(outputPath)
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return
    return invalid('OUTPUT_UNAVAILABLE', 'Release promotion handoff output cannot be prepared.')
  }
  return invalid('OUTPUT_ALREADY_EXISTS', 'Release promotion handoff output already exists.')
}

async function writeReceipt(outputPath: string, receipt: ReleasePromotionHandoffV1): Promise<void> {
  const parent = dirname(outputPath)
  await mkdir(parent, { recursive: true })
  const staging = await mkdtemp(resolve(parent, `.${basename(outputPath)}-`))
  const stagedFile = resolve(staging, basename(outputPath))
  try {
    await writeFile(stagedFile, serialized(receipt), {
      encoding: 'utf8',
      flag: 'wx',
      mode: 0o600,
    })
    await link(stagedFile, outputPath)
  } catch {
    return invalid('OUTPUT_WRITE_FAILED', 'Release promotion handoff receipt could not be committed.')
  } finally {
    await rm(staging, { recursive: true, force: true }).catch(() => undefined)
  }
}

async function verifyHandoff(
  inputPath: string,
  input: ReleasePromotionHandoffInputV1,
): Promise<ReleasePromotionHandoffV1> {
  const inputDirectory = dirname(inputPath)
  const qualification = await readQualificationPortfolio(
    resolve(inputDirectory, input.qualificationOutputPath),
  )
  const candidatePath = resolve(inputDirectory, input.qualifiedCandidateArtifact.path)
  const proposedPath = resolve(inputDirectory, input.proposedStableArtifact.path)
  if (candidatePath === proposedPath) {
    return invalid('ARTIFACT_PATH_COLLISION', 'Qualified and proposed artifacts must be distinct files.')
  }
  const [candidateBytes, proposedBytes] = await Promise.all([
    readBoundFile(
      candidatePath,
      maximumArchiveBytes,
      'INVALID_QUALIFIED_ARTIFACT',
      'Qualified candidate artifact is invalid.',
    ),
    readBoundFile(
      proposedPath,
      maximumArchiveBytes,
      'INVALID_PROPOSED_ARTIFACT',
      'Proposed stable artifact is invalid.',
    ),
  ])
  const candidateDigest = rawDigest(candidateBytes, input.qualifiedCandidateArtifact.mediaType)
  if (
    !sameDigest(candidateDigest, qualification.manifest.candidateArtifactDigest)
    || !sameDigest(candidateDigest, qualification.manifest.qualifiedArtifactDigest)
    || !sameDigest(candidateDigest, qualification.manifest.proposedPromotionArtifactDigest)
  ) {
    return invalid('QUALIFIED_ARTIFACT_DIGEST_MISMATCH', 'Qualified artifact does not match its portfolio.')
  }
  const candidateEntries = parsePackageArchive(candidateBytes)
  const comparison = comparePackageArchives(
    candidateEntries,
    parsePackageArchive(proposedBytes),
    qualification.publicScorecard.releaseVersion,
    input.expectedStableVersion,
  )
  return releasePromotionHandoffV1Schema.parse({
    schemaVersion: 1,
    engineId: RELEASE_PROMOTION_HANDOFF_ENGINE_ID,
    evaluatedAtEpochMs: qualification.verdict.evaluatedAtEpochMs,
    sourceRevision: qualification.verdict.sourceRevision,
    manifestId: qualification.verdict.manifestId,
    releaseCandidateId: qualification.verdict.releaseCandidateId,
    packageName: comparison.packageName,
    candidateVersion: comparison.candidateVersion,
    stableVersion: input.expectedStableVersion,
    qualificationPortfolioDigests: qualification.digests,
    qualifiedCandidateArtifactDigest: candidateDigest,
    proposedStableArtifactDigest: rawDigest(
      proposedBytes,
      input.proposedStableArtifact.mediaType,
    ),
    comparedEntryCount: candidateEntries.length,
    versionChangedEntryPaths: comparison.versionChangedEntryPaths,
    releaseMetadataChangedEntryPaths: comparison.releaseMetadataChangedEntryPaths,
    equivalence: 'EXACT_VERSION_TOKEN_REPLACEMENT_V1',
    verification: 'BEHAVIOR_EQUIVALENT',
    authorization: 'NOT_GRANTED',
  })
}

async function runReleaseHandoffCli(
  args: readonly string[],
  io: ReleaseHandoffIo = process,
): Promise<number> {
  try {
    const parsedArguments = parseArguments(args)
    await assertOutputAbsent(parsedArguments.outputPath)
    const input = await parseInput(parsedArguments.inputPath)
    const receipt = await verifyHandoff(parsedArguments.inputPath, input)
    await writeReceipt(parsedArguments.outputPath, receipt)
    io.stdout.write(serialized(receipt))
    return 0
  } catch (error) {
    const failure = error instanceof ReleaseFileBoundaryError
      ? error
      : new ReleaseFileBoundaryError(
          'RELEASE_PROMOTION_HANDOFF_FAILED',
          'Release promotion handoff verification failed closed.',
        )
    io.stderr.write(serialized({ code: failure.code, message: failure.message }))
    return 1
  }
}

const invokedPath = process.argv[1]
if (isDirectCliInvocation(import.meta.url, invokedPath)) {
  process.exitCode = await runReleaseHandoffCli(process.argv.slice(2))
}
