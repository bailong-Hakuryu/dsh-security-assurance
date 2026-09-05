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
  releaseProofIndexV1Schema,
  releaseProofRecordV1Schema,
  RELEASE_EVIDENCE_PROOF_KINDS,
} from './release-proof.ts'
import {
  releaseQualificationAssemblyInputV1Schema,
  releaseQualificationInputV1Schema,
  type ReleaseQualificationAssemblyInputV1,
  type ReleaseQualificationInputV1,
} from './release-qualification.ts'

const maximumJsonBytes = 50 * 1024 * 1024

type ReleaseAssemblyIo = {
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
        'Usage: dsh-security-assurance-release-assemble --input <draft.json> --output <qualification.json>',
      )
    }
    values.set(flag, value)
  }
  const inputPath = values.get('--input')
  const outputPath = values.get('--output')
  if (normalizedArgs.length !== 4 || inputPath === undefined || outputPath === undefined) {
    return releaseFileFailure(
      'INVALID_ARGUMENTS',
      'Usage: dsh-security-assurance-release-assemble --input <draft.json> --output <qualification.json>',
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

function outputRelativePath(outputPath: string, targetPath: string): string {
  const rebased = relative(dirname(outputPath), targetPath)
  return (rebased.length === 0 ? '.' : rebased).replaceAll('\\', '/')
}

async function assertOutputAbsent(outputPath: string): Promise<void> {
  try {
    await lstat(outputPath)
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return
    return releaseFileFailure('OUTPUT_UNAVAILABLE', 'Release qualification input cannot be prepared.')
  }
  return releaseFileFailure('OUTPUT_ALREADY_EXISTS', 'Release qualification input already exists.')
}

async function assembleQualificationInput(
  inputPath: string,
  outputPath: string,
  input: ReleaseQualificationAssemblyInputV1,
): Promise<ReleaseQualificationInputV1> {
  const inputDirectory = dirname(inputPath)
  const indexPath = resolve(inputDirectory, input.releaseProofIndexPath)
  const indexFile = await readJsonFile(
    indexPath,
    'INVALID_PROOF_INDEX',
    'Release Proof Index is invalid.',
  )
  const parsedIndex = releaseProofIndexV1Schema.safeParse(indexFile.decoded)
  if (!parsedIndex.success) {
    return releaseFileFailure('INVALID_PROOF_INDEX', 'Release Proof Index is invalid.')
  }
  const index = parsedIndex.data
  const indexedRecordPaths = index.records.map(record => (
    resolve(dirname(indexPath), record.recordPath)
  ))
  if (new Set(indexedRecordPaths).size !== indexedRecordPaths.length) {
    return releaseFileFailure(
      'DUPLICATE_PROOF_PATH',
      'Indexed Release Proof Record paths must resolve uniquely.',
    )
  }
  await Promise.all(index.records.map(async (record, recordIndex) => {
    const recordFile = await readJsonFile(
      indexedRecordPaths[recordIndex]!,
      'INVALID_PROOF_RECORD',
      'An indexed Release Proof Record is invalid.',
    )
    if (!sameDigest(rawJsonDigest(recordFile.bytes), record.proof.evidenceDigest)) {
      return releaseFileFailure(
        'PROOF_RECORD_DIGEST_MISMATCH',
        'An indexed Release Proof Record changed after collection.',
      )
    }
    const parsedRecord = releaseProofRecordV1Schema.safeParse(recordFile.decoded)
    if (!parsedRecord.success) {
      return releaseFileFailure(
        'INVALID_PROOF_RECORD',
        'An indexed Release Proof Record is invalid.',
      )
    }
    const value = parsedRecord.data
    const projectedRecord = {
      producer: value.producer,
      producerVersion: value.producerVersion,
      environment: value.environment,
      proof: {
        proofKind: value.proofKind,
        evidenceId: value.proofRecordId,
        evidenceDigest: rawJsonDigest(recordFile.bytes),
        reportedStatus: value.reportedStatus,
        candidateArtifactDigest: value.candidateArtifactDigest,
        completedAtEpochMs: value.completedAtEpochMs,
      },
    }
    const indexedRecord = {
      producer: record.producer,
      producerVersion: record.producerVersion,
      environment: record.environment,
      proof: record.proof,
    }
    if (JSON.stringify(projectedRecord) !== JSON.stringify(indexedRecord)) {
      return releaseFileFailure(
        'PROOF_INDEX_RECORD_MISMATCH',
        'Release Proof Index metadata does not match its record.',
      )
    }
  }))
  const draftBindingsPath = resolve(inputDirectory, input.releaseFileBindingsPath)
  const indexedBindingsPath = resolve(dirname(indexPath), index.releaseFileBindingsPath)
  if (draftBindingsPath !== indexedBindingsPath) {
    return releaseFileFailure(
      'BINDINGS_PATH_MISMATCH',
      'Release qualification draft and Proof Index name different bindings.',
    )
  }
  const bindingsFile = await readJsonFile(
    indexedBindingsPath,
    'INVALID_BINDINGS',
    'Release file bindings are invalid.',
  )
  const parsedBindings = releaseFileBindingsV1Schema.safeParse(bindingsFile.decoded)
  if (
    !parsedBindings.success
    || !sameDigest(rawJsonDigest(bindingsFile.bytes), index.releaseFileBindingsDigest)
    || !sameDigest(parsedBindings.data.candidateArtifact.digest, index.candidateArtifactDigest)
  ) {
    return releaseFileFailure('INVALID_BINDINGS', 'Release file bindings are invalid.')
  }
  const candidate = input.releaseEvidence.releaseEvaluation.candidate
  if ([
    candidate.candidateArtifactDigest,
    candidate.qualifiedArtifactDigest,
    candidate.proposedPromotionArtifactDigest,
  ].some(digest => !sameDigest(digest, index.candidateArtifactDigest))) {
    return releaseFileFailure(
      'CANDIDATE_DIGEST_MISMATCH',
      'Release qualification draft and Proof Index name different candidate artifacts.',
    )
  }

  const proofs = [
    ...input.releaseEvidence.proofs,
    ...index.records.map(record => record.proof),
  ]
  const proofKinds = proofs.map(proof => proof.proofKind)
  if (new Set(proofKinds).size !== proofKinds.length) {
    return releaseFileFailure(
      'DUPLICATE_PROOF_KIND',
      'Release qualification draft and Proof Index contain the same proof kind.',
    )
  }
  proofs.sort((left, right) => (
    RELEASE_EVIDENCE_PROOF_KINDS.indexOf(left.proofKind)
    - RELEASE_EVIDENCE_PROOF_KINDS.indexOf(right.proofKind)
  ))
  const { releaseProofIndexPath: _releaseProofIndexPath, ...draft } = input
  return releaseQualificationInputV1Schema.parse({
    ...draft,
    releaseFileBindingsPath: outputRelativePath(outputPath, indexedBindingsPath),
    releaseEvidence: { ...draft.releaseEvidence, proofs },
  })
}

function serialized(value: unknown): string {
  return `${JSON.stringify(value, null, 2)}\n`
}

async function writeQualificationInput(
  outputPath: string,
  input: ReleaseQualificationInputV1,
): Promise<void> {
  const parent = dirname(outputPath)
  await mkdir(parent, { recursive: true })
  const staging = await mkdtemp(resolve(parent, `.${basename(outputPath)}-`))
  const stagedFile = resolve(staging, basename(outputPath))
  try {
    await writeFile(stagedFile, serialized(input), {
      encoding: 'utf8',
      flag: 'wx',
      mode: 0o600,
    })
    await link(stagedFile, outputPath)
  } catch {
    return releaseFileFailure(
      'OUTPUT_WRITE_FAILED',
      'Release qualification input could not be committed.',
    )
  } finally {
    await rm(staging, { recursive: true, force: true }).catch(() => undefined)
  }
}

async function runReleaseAssemblyCli(
  args: readonly string[],
  io: ReleaseAssemblyIo = process,
): Promise<number> {
  try {
    const parsedArguments = parseArguments(args)
    await assertOutputAbsent(parsedArguments.outputPath)
    const inputFile = await readJsonFile(
      parsedArguments.inputPath,
      'INVALID_INPUT',
      'Release qualification assembly input is invalid.',
    )
    const parsedInput = releaseQualificationAssemblyInputV1Schema.safeParse(inputFile.decoded)
    if (!parsedInput.success) {
      return releaseFileFailure('INVALID_INPUT', 'Release qualification assembly input is invalid.')
    }
    const assembled = await assembleQualificationInput(
      parsedArguments.inputPath,
      parsedArguments.outputPath,
      parsedInput.data,
    )
    await writeQualificationInput(parsedArguments.outputPath, assembled)
    return 0
  } catch (error) {
    const failure = error instanceof ReleaseFileBoundaryError
      ? error
      : new ReleaseFileBoundaryError(
          'RELEASE_QUALIFICATION_ASSEMBLY_FAILED',
          'Release qualification input assembly failed closed.',
        )
    io.stderr.write(serialized({ code: failure.code, message: failure.message }))
    return 1
  }
}

const invokedPath = process.argv[1]
if (invokedPath !== undefined && pathToFileURL(resolve(invokedPath)).href === import.meta.url) {
  process.exitCode = await runReleaseAssemblyCli(process.argv.slice(2))
}
