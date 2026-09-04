#!/usr/bin/env node

import { createHash } from 'node:crypto'
import { link, lstat, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { basename, dirname, relative, resolve } from 'node:path'
import { pathToFileURL } from 'node:url'

import type { DigestEnvelopeV1 } from './digest-envelope.ts'
import {
  ReleaseFileBoundaryError,
  releaseFileFailure,
  sameDigest,
} from './internal/release-file-verification.ts'
import { releaseFileBindingsV1Schema } from './release-file-bindings.ts'
import {
  RELEASE_EVIDENCE_PROOF_KINDS,
  RELEASE_PROOF_INDEX_ENGINE_ID,
  releaseProofCollectionInputV1Schema,
  releaseProofIndexV1Schema,
  releaseProofRecordV1Schema,
  type ReleaseProofCollectionInputV1,
  type ReleaseProofIndexV1,
  type ReleaseProofRecordV1,
} from './release-proof.ts'

const maximumJsonBytes = 1024 * 1024

type ReleaseCollectionIo = {
  readonly stderr: { write(value: string): unknown }
}

type CliArguments = {
  readonly inputPath: string
  readonly outputPath: string
}

type JsonFile = {
  readonly bytes: Buffer
  readonly decoded: unknown
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
      return releaseFileFailure(
        'INVALID_ARGUMENTS',
        'Usage: dsh-security-assurance-release-collect --input <proofs.json> --output <index.json>',
      )
    }
    values.set(flag, value)
  }
  const inputPath = values.get('--input')
  const outputPath = values.get('--output')
  if (normalizedArgs.length !== 4 || inputPath === undefined || outputPath === undefined) {
    return releaseFileFailure(
      'INVALID_ARGUMENTS',
      'Usage: dsh-security-assurance-release-collect --input <proofs.json> --output <index.json>',
    )
  }
  return { inputPath: resolve(inputPath), outputPath: resolve(outputPath) }
}

async function readJsonFile(path: string, code: string, message: string): Promise<JsonFile> {
  try {
    const fileStat = await lstat(path)
    if (!fileStat.isFile() || fileStat.size > maximumJsonBytes) {
      return releaseFileFailure(code, message)
    }
    const bytes = await readFile(path)
    if (bytes.byteLength > maximumJsonBytes) return releaseFileFailure(code, message)
    return { bytes, decoded: JSON.parse(bytes.toString('utf8')) }
  } catch (error) {
    if (error instanceof ReleaseFileBoundaryError) throw error
    return releaseFileFailure(code, message)
  }
}

async function parseInput(inputPath: string): Promise<ReleaseProofCollectionInputV1> {
  const input = await readJsonFile(
    inputPath,
    'INVALID_INPUT',
    'Release proof collection input is invalid.',
  )
  const parsed = releaseProofCollectionInputV1Schema.safeParse(input.decoded)
  if (!parsed.success) {
    return releaseFileFailure('INVALID_INPUT', 'Release proof collection input is invalid.')
  }
  return parsed.data
}

function rawJsonDigest(bytes: Buffer): DigestEnvelopeV1 {
  return {
    schemaVersion: 1,
    algorithm: 'sha256',
    mediaType: 'application/json',
    byteLength: bytes.byteLength,
    canonicalization: 'raw-bytes',
    value: createHash('sha256').update(bytes).digest('hex'),
  }
}

async function assertOutputAbsent(outputPath: string): Promise<void> {
  try {
    await lstat(outputPath)
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return
    return releaseFileFailure('OUTPUT_UNAVAILABLE', 'Release proof index cannot be prepared.')
  }
  return releaseFileFailure('OUTPUT_ALREADY_EXISTS', 'Release proof index already exists.')
}

function outputRelativePath(outputPath: string, targetPath: string): string {
  const rebased = relative(dirname(outputPath), targetPath)
  return (rebased.length === 0 ? '.' : rebased).replaceAll('\\', '/')
}

async function assembleIndex(
  inputPath: string,
  outputPath: string,
  input: ReleaseProofCollectionInputV1,
): Promise<ReleaseProofIndexV1> {
  const inputDirectory = dirname(inputPath)
  const bindingsPath = resolve(inputDirectory, input.releaseFileBindingsPath)
  const bindingsFile = await readJsonFile(
    bindingsPath,
    'INVALID_BINDINGS',
    'Release file bindings are invalid.',
  )
  const parsedBindings = releaseFileBindingsV1Schema.safeParse(bindingsFile.decoded)
  if (!parsedBindings.success) {
    return releaseFileFailure('INVALID_BINDINGS', 'Release file bindings are invalid.')
  }

  const proofPaths = input.proofFiles.map(path => resolve(inputDirectory, path))
  if (new Set(proofPaths).size !== proofPaths.length) {
    return releaseFileFailure('DUPLICATE_PROOF_PATH', 'Release Proof Record paths must be unique.')
  }
  const records = await Promise.all(proofPaths.map(async path => {
    const file = await readJsonFile(
      path,
      'INVALID_PROOF_RECORD',
      'A Release Proof Record is invalid.',
    )
    const parsed = releaseProofRecordV1Schema.safeParse(file.decoded)
    if (!parsed.success) {
      return releaseFileFailure('INVALID_PROOF_RECORD', 'A Release Proof Record is invalid.')
    }
    return { path, bytes: file.bytes, value: parsed.data }
  }))

  const proofKinds = records.map(record => record.value.proofKind)
  if (new Set(proofKinds).size !== proofKinds.length) {
    return releaseFileFailure('DUPLICATE_PROOF_KIND', 'Release Proof Record kinds must be unique.')
  }
  const proofRecordIds = records.map(record => record.value.proofRecordId)
  if (new Set(proofRecordIds).size !== proofRecordIds.length) {
    return releaseFileFailure('DUPLICATE_PROOF_RECORD_ID', 'Release Proof Record ids must be unique.')
  }
  if (records.some(record => !sameDigest(
    record.value.candidateArtifactDigest,
    parsedBindings.data.candidateArtifact.digest,
  ))) {
    return releaseFileFailure(
      'CANDIDATE_DIGEST_MISMATCH',
      'A Release Proof Record names a different candidate artifact.',
    )
  }

  records.sort((left, right) => (
    RELEASE_EVIDENCE_PROOF_KINDS.indexOf(left.value.proofKind)
    - RELEASE_EVIDENCE_PROOF_KINDS.indexOf(right.value.proofKind)
  ))
  return releaseProofIndexV1Schema.parse({
    schemaVersion: 1,
    engineId: RELEASE_PROOF_INDEX_ENGINE_ID,
    releaseFileBindingsPath: outputRelativePath(outputPath, bindingsPath),
    releaseFileBindingsDigest: rawJsonDigest(bindingsFile.bytes),
    candidateArtifactDigest: parsedBindings.data.candidateArtifact.digest,
    records: records.map(record => ({
      recordPath: outputRelativePath(outputPath, record.path),
      producer: record.value.producer,
      producerVersion: record.value.producerVersion,
      environment: record.value.environment,
      proof: projectManifestProof(record.value, record.bytes),
    })),
  })
}

function projectManifestProof(record: ReleaseProofRecordV1, bytes: Buffer) {
  return {
    proofKind: record.proofKind,
    evidenceId: record.proofRecordId,
    evidenceDigest: rawJsonDigest(bytes),
    reportedStatus: record.reportedStatus,
    candidateArtifactDigest: record.candidateArtifactDigest,
    completedAtEpochMs: record.completedAtEpochMs,
  }
}

function serialized(value: unknown): string {
  return `${JSON.stringify(value, null, 2)}\n`
}

async function writeIndex(outputPath: string, index: ReleaseProofIndexV1): Promise<void> {
  const parent = dirname(outputPath)
  await mkdir(parent, { recursive: true })
  const staging = await mkdtemp(resolve(parent, `.${basename(outputPath)}-`))
  const stagedFile = resolve(staging, basename(outputPath))
  try {
    await writeFile(stagedFile, serialized(index), {
      encoding: 'utf8',
      flag: 'wx',
      mode: 0o600,
    })
    await link(stagedFile, outputPath)
  } catch {
    return releaseFileFailure('OUTPUT_WRITE_FAILED', 'Release proof index could not be committed.')
  } finally {
    await rm(staging, { recursive: true, force: true }).catch(() => undefined)
  }
}

async function runReleaseCollectionCli(
  args: readonly string[],
  io: ReleaseCollectionIo = process,
): Promise<number> {
  try {
    const parsedArguments = parseArguments(args)
    await assertOutputAbsent(parsedArguments.outputPath)
    const input = await parseInput(parsedArguments.inputPath)
    const index = await assembleIndex(parsedArguments.inputPath, parsedArguments.outputPath, input)
    await writeIndex(parsedArguments.outputPath, index)
    return 0
  } catch (error) {
    const failure = error instanceof ReleaseFileBoundaryError
      ? error
      : new ReleaseFileBoundaryError(
          'RELEASE_PROOF_COLLECTION_FAILED',
          'Release proof collection failed closed.',
        )
    io.stderr.write(serialized({ code: failure.code, message: failure.message }))
    return 1
  }
}

const invokedPath = process.argv[1]
if (invokedPath !== undefined && pathToFileURL(resolve(invokedPath)).href === import.meta.url) {
  process.exitCode = await runReleaseCollectionCli(process.argv.slice(2))
}
