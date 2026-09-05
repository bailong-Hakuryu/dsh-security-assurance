#!/usr/bin/env node

import {
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  rename,
  rm,
  stat,
  writeFile,
} from 'node:fs/promises'
import { basename, dirname, resolve } from 'node:path'
import { pathToFileURL } from 'node:url'
import { z } from 'zod'

import { digestEnvelopeV1Schema } from './digest-envelope.ts'
import {
  assembleReleaseEvidenceManifestV1,
  type ReleaseEvidenceManifestV1,
} from './evaluation.ts'
import {
  ReleaseFileBoundaryError,
  digestRawFile,
  inspectCleanSourceRevision,
  releaseFileFailure,
  sameDigest,
} from './internal/release-file-verification.ts'
import {
  releaseFileBindingsV1Schema,
  type ReleaseFileBindingsV1,
} from './release-file-bindings.ts'
import {
  releaseQualificationInputV1Schema,
  type ReleaseQualificationInputV1,
} from './release-qualification.ts'

const RELEASE_QUALIFICATION_CLI_ENGINE_ID = 'security/release-qualification-cli/v1' as const

const maximumInputBytes = 50 * 1024 * 1024
const releaseQualificationVerdictV1Schema = z.strictObject({
  schemaVersion: z.literal(1),
  engineId: z.literal(RELEASE_QUALIFICATION_CLI_ENGINE_ID),
  evaluatedAtEpochMs: z.number().int().nonnegative(),
  sourceRevision: z.string().regex(/^(?:[0-9a-f]{40}|[0-9a-f]{64})$/),
  manifestId: z.string().min(1).max(128),
  releaseCandidateId: z.string().min(1).max(128),
  candidateArtifactDigest: digestEnvelopeV1Schema,
  releaseDecision: z.enum(['PROMOTE', 'BLOCKED', 'INCONCLUSIVE']),
  manifestVerification: z.enum(['VERIFIED', 'BLOCKED', 'INCONCLUSIVE']),
  qualification: z.enum(['PROMOTE', 'BLOCKED', 'INCONCLUSIVE']),
})

type ReleaseQualificationVerdictV1 = z.infer<
  typeof releaseQualificationVerdictV1Schema
>

type ReleaseQualificationIo = {
  readonly stdout: { write(value: string): unknown }
  readonly stderr: { write(value: string): unknown }
}

type CliArguments = {
  readonly inputPath: string
  readonly outputPath: string
}

function invalid(code: string, message: string): never {
  return releaseFileFailure(code, message)
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
        'Usage: dsh-security-assurance-release-qualify --input <evidence.json> --output <directory>',
      )
    }
    values.set(flag, value)
  }
  const inputPath = values.get('--input')
  const outputPath = values.get('--output')
  if (normalizedArgs.length !== 4 || inputPath === undefined || outputPath === undefined) {
    return invalid(
      'INVALID_ARGUMENTS',
      'Usage: dsh-security-assurance-release-qualify --input <evidence.json> --output <directory>',
    )
  }
  return { inputPath: resolve(inputPath), outputPath: resolve(outputPath) }
}

async function parseInput(inputPath: string): Promise<ReleaseQualificationInputV1> {
  let bytes: string
  try {
    const inputStat = await stat(inputPath)
    if (!inputStat.isFile() || inputStat.size > maximumInputBytes) {
      return invalid('INVALID_INPUT', 'Release qualification input is invalid.')
    }
    bytes = await readFile(inputPath, 'utf8')
  } catch {
    return invalid('INVALID_INPUT', 'Release qualification input is invalid.')
  }
  let decoded: unknown
  try {
    decoded = JSON.parse(bytes)
  } catch {
    return invalid('INVALID_INPUT', 'Release qualification input is invalid.')
  }
  const parsed = releaseQualificationInputV1Schema.safeParse(decoded)
  if (!parsed.success) {
    return invalid('INVALID_INPUT', 'Release qualification input is invalid.')
  }
  return parsed.data
}

async function parseBindings(bindingPath: string): Promise<ReleaseFileBindingsV1> {
  let bytes: string
  try {
    const bindingStat = await stat(bindingPath)
    if (!bindingStat.isFile() || bindingStat.size > maximumInputBytes) {
      return invalid('INVALID_FILE_BINDINGS', 'Release file bindings are invalid.')
    }
    bytes = await readFile(bindingPath, 'utf8')
  } catch {
    return invalid('INVALID_FILE_BINDINGS', 'Release file bindings are invalid.')
  }
  let decoded: unknown
  try {
    decoded = JSON.parse(bytes)
  } catch {
    return invalid('INVALID_FILE_BINDINGS', 'Release file bindings are invalid.')
  }
  const parsed = releaseFileBindingsV1Schema.safeParse(decoded)
  if (!parsed.success) {
    return invalid('INVALID_FILE_BINDINGS', 'Release file bindings are invalid.')
  }
  return parsed.data
}

async function assertOutputAbsent(outputPath: string): Promise<void> {
  try {
    await lstat(outputPath)
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return
    return invalid('OUTPUT_UNAVAILABLE', 'Release qualification output cannot be prepared.')
  }
  return invalid('OUTPUT_ALREADY_EXISTS', 'Release qualification output already exists.')
}

async function assertSource(
  bindingDirectory: string,
  bindings: ReleaseFileBindingsV1,
  sourceRevision: string,
): Promise<void> {
  const head = await inspectCleanSourceRevision(
    resolve(bindingDirectory, bindings.sourceRepositoryPath),
  )
  if (head !== bindings.sourceRevision || head !== sourceRevision) {
    return invalid('SOURCE_REVISION_MISMATCH', 'The source revision does not match release evidence.')
  }
}

async function assertArtifactBinding(
  bindingDirectory: string,
  bindings: ReleaseFileBindingsV1,
  expected: ReleaseQualificationInputV1['releaseEvidence']['releaseEvaluation']['candidate'],
): Promise<void> {
  for (const digest of [
    expected.candidateArtifactDigest,
    expected.qualifiedArtifactDigest,
    expected.proposedPromotionArtifactDigest,
  ]) {
    if (digest.canonicalization !== 'raw-bytes') {
      return invalid('ARTIFACT_BINDING_INVALID', 'Candidate artifact evidence is not raw-byte bound.')
    }
  }
  const actual = await digestRawFile(
    resolve(bindingDirectory, bindings.candidateArtifact.path),
    bindings.candidateArtifact.mediaType,
  )
  if (
    !sameDigest(actual, bindings.candidateArtifact.digest)
    || !sameDigest(actual, expected.candidateArtifactDigest)
    || !sameDigest(actual, expected.qualifiedArtifactDigest)
    || !sameDigest(actual, expected.proposedPromotionArtifactDigest)
  ) {
    return invalid('ARTIFACT_DIGEST_MISMATCH', 'Candidate artifact bytes do not match release evidence.')
  }
}

async function assertLockBindings(
  bindingDirectory: string,
  bindings: ReleaseFileBindingsV1,
  releaseEvidence: ReleaseQualificationInputV1['releaseEvidence'],
): Promise<void> {
  const expected = new Map(releaseEvidence.dependencyLocks.map(item => [
    item.lockKind,
    item.lockDigest,
  ]))
  if (expected.size !== bindings.dependencyLockFiles.length) {
    return invalid('LOCK_SET_MISMATCH', 'Dependency lock files do not match release evidence.')
  }
  for (const lock of bindings.dependencyLockFiles) {
    const expectedDigest = expected.get(lock.lockKind)
    if (expectedDigest === undefined || expectedDigest.canonicalization !== 'raw-bytes') {
      return invalid('LOCK_SET_MISMATCH', 'Dependency lock files do not match release evidence.')
    }
    const actual = await digestRawFile(resolve(bindingDirectory, lock.path), lock.mediaType)
    if (!sameDigest(actual, lock.digest) || !sameDigest(actual, expectedDigest)) {
      return invalid('LOCK_DIGEST_MISMATCH', 'Dependency lock bytes do not match release evidence.')
    }
  }
}

function qualificationVerdict(
  manifest: ReleaseEvidenceManifestV1,
): ReleaseQualificationVerdictV1 {
  const qualification = manifest.verification.decision !== 'VERIFIED'
    ? manifest.verification.decision === 'BLOCKED' ? 'BLOCKED' as const : 'INCONCLUSIVE' as const
    : manifest.releaseConstitution.decision
  return releaseQualificationVerdictV1Schema.parse({
    schemaVersion: 1,
    engineId: RELEASE_QUALIFICATION_CLI_ENGINE_ID,
    evaluatedAtEpochMs: manifest.assembledAtEpochMs,
    sourceRevision: manifest.sourceRevision,
    manifestId: manifest.manifestId,
    releaseCandidateId: manifest.releaseCandidateId,
    candidateArtifactDigest: manifest.candidateArtifactDigest,
    releaseDecision: manifest.releaseConstitution.decision,
    manifestVerification: manifest.verification.decision,
    qualification,
  })
}

function serialized(value: unknown): string {
  return `${JSON.stringify(value, null, 2)}\n`
}

async function writePortfolio(
  outputPath: string,
  manifest: ReleaseEvidenceManifestV1,
  verdict: ReleaseQualificationVerdictV1,
): Promise<void> {
  const parent = dirname(outputPath)
  await mkdir(parent, { recursive: true })
  const staging = await mkdtemp(resolve(parent, `.${basename(outputPath)}-`))
  let committed = false
  try {
    await Promise.all([
      writeFile(
        resolve(staging, 'release-evidence-manifest.json'),
        serialized(manifest),
        { encoding: 'utf8', flag: 'wx', mode: 0o600 },
      ),
      writeFile(
        resolve(staging, 'public-security-scorecard.json'),
        serialized(manifest.publicScorecard),
        { encoding: 'utf8', flag: 'wx', mode: 0o600 },
      ),
      writeFile(
        resolve(staging, 'release-qualification-verdict.json'),
        serialized(verdict),
        { encoding: 'utf8', flag: 'wx', mode: 0o600 },
      ),
    ])
    await rename(staging, outputPath)
    committed = true
  } catch {
    return invalid('OUTPUT_WRITE_FAILED', 'Release qualification output could not be committed.')
  } finally {
    if (!committed) await rm(staging, { recursive: true, force: true })
  }
}

async function runReleaseQualificationCli(
  args: readonly string[],
  io: ReleaseQualificationIo = process,
): Promise<number> {
  try {
    const parsedArguments = parseArguments(args)
    await assertOutputAbsent(parsedArguments.outputPath)
    const input = await parseInput(parsedArguments.inputPath)
    const inputDirectory = dirname(parsedArguments.inputPath)
    const bindingPath = resolve(inputDirectory, input.releaseFileBindingsPath)
    const bindings = await parseBindings(bindingPath)
    const bindingDirectory = dirname(bindingPath)
    await assertSource(bindingDirectory, bindings, input.releaseEvidence.sourceRevision)
    await assertArtifactBinding(
      bindingDirectory,
      bindings,
      input.releaseEvidence.releaseEvaluation.candidate,
    )
    await assertLockBindings(bindingDirectory, bindings, input.releaseEvidence)
    await assertSource(bindingDirectory, bindings, input.releaseEvidence.sourceRevision)
    let manifest: ReleaseEvidenceManifestV1
    try {
      manifest = assembleReleaseEvidenceManifestV1(input.releaseEvidence)
    } catch {
      return invalid('INVALID_RELEASE_EVIDENCE', 'Release evidence is internally inconsistent.')
    }
    const verdict = qualificationVerdict(manifest)
    await writePortfolio(parsedArguments.outputPath, manifest, verdict)
    io.stdout.write(serialized(verdict))
    return verdict.qualification === 'PROMOTE' ? 0 : 2
  } catch (error) {
    const failure = error instanceof ReleaseFileBoundaryError
      ? error
      : new ReleaseFileBoundaryError(
          'RELEASE_QUALIFICATION_FAILED',
          'Release qualification failed closed.',
        )
    io.stderr.write(serialized({ code: failure.code, message: failure.message }))
    return 1
  }
}

const invokedPath = process.argv[1]
if (invokedPath !== undefined && pathToFileURL(resolve(invokedPath)).href === import.meta.url) {
  process.exitCode = await runReleaseQualificationCli(process.argv.slice(2))
}
