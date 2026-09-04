#!/usr/bin/env node

import { lstat } from 'node:fs/promises'
import { link, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { basename, dirname, relative, resolve } from 'node:path'
import { pathToFileURL } from 'node:url'

import {
  ReleaseFileBoundaryError,
  digestRawFile,
  inspectCleanSourceRevision,
  releaseFileFailure,
} from './internal/release-file-verification.ts'
import {
  RELEASE_FILE_BINDINGS_ENGINE_ID,
  releaseFileBindingInputV1Schema,
  releaseFileBindingsV1Schema,
  type ReleaseFileBindingInputV1,
  type ReleaseFileBindingsV1,
} from './release-file-bindings.ts'

const maximumInputBytes = 1024 * 1024

type ReleaseBindingIo = {
  readonly stderr: { write(value: string): unknown }
}

type CliArguments = {
  readonly inputPath: string
  readonly outputPath: string
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
        'Usage: dsh-security-assurance-release-bind --input <files.json> --output <bindings.json>',
      )
    }
    values.set(flag, value)
  }
  const inputPath = values.get('--input')
  const outputPath = values.get('--output')
  if (normalizedArgs.length !== 4 || inputPath === undefined || outputPath === undefined) {
    return releaseFileFailure(
      'INVALID_ARGUMENTS',
      'Usage: dsh-security-assurance-release-bind --input <files.json> --output <bindings.json>',
    )
  }
  return { inputPath: resolve(inputPath), outputPath: resolve(outputPath) }
}

async function parseInput(inputPath: string): Promise<ReleaseFileBindingInputV1> {
  let bytes: string
  try {
    const inputStat = await lstat(inputPath)
    if (!inputStat.isFile() || inputStat.size > maximumInputBytes) {
      return releaseFileFailure('INVALID_INPUT', 'Release file binding input is invalid.')
    }
    bytes = await readFile(inputPath, 'utf8')
  } catch {
    return releaseFileFailure('INVALID_INPUT', 'Release file binding input is invalid.')
  }
  let decoded: unknown
  try {
    decoded = JSON.parse(bytes)
  } catch {
    return releaseFileFailure('INVALID_INPUT', 'Release file binding input is invalid.')
  }
  const parsed = releaseFileBindingInputV1Schema.safeParse(decoded)
  if (!parsed.success) {
    return releaseFileFailure('INVALID_INPUT', 'Release file binding input is invalid.')
  }
  return parsed.data
}

async function assertOutputAbsent(outputPath: string): Promise<void> {
  try {
    await lstat(outputPath)
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return
    return releaseFileFailure('OUTPUT_UNAVAILABLE', 'Release file bindings cannot be prepared.')
  }
  return releaseFileFailure('OUTPUT_ALREADY_EXISTS', 'Release file bindings already exist.')
}

function outputRelativePath(outputPath: string, targetPath: string): string {
  const rebased = relative(dirname(outputPath), targetPath)
  return (rebased.length === 0 ? '.' : rebased).replaceAll('\\', '/')
}

async function assembleBindings(
  inputPath: string,
  outputPath: string,
  input: ReleaseFileBindingInputV1,
): Promise<ReleaseFileBindingsV1> {
  const inputDirectory = dirname(inputPath)
  const repository = resolve(inputDirectory, input.sourceRepositoryPath)
  const artifact = resolve(inputDirectory, input.candidateArtifact.path)
  const sourceRevision = await inspectCleanSourceRevision(repository)
  const [candidateDigest, lockDigests] = await Promise.all([
    digestRawFile(artifact, input.candidateArtifact.mediaType),
    Promise.all(input.dependencyLockFiles.map(lock => digestRawFile(
      resolve(inputDirectory, lock.path),
      lock.mediaType,
    ))),
  ])
  const confirmedSourceRevision = await inspectCleanSourceRevision(repository)
  if (confirmedSourceRevision !== sourceRevision) {
    return releaseFileFailure(
      'SOURCE_CHANGED_DURING_BINDING',
      'The source revision changed while release files were being bound.',
    )
  }
  return releaseFileBindingsV1Schema.parse({
    schemaVersion: 1,
    engineId: RELEASE_FILE_BINDINGS_ENGINE_ID,
    sourceRepositoryPath: outputRelativePath(outputPath, repository),
    sourceRevision,
    candidateArtifact: {
      path: outputRelativePath(outputPath, artifact),
      mediaType: input.candidateArtifact.mediaType,
      digest: candidateDigest,
    },
    dependencyLockFiles: input.dependencyLockFiles.map((lock, index) => ({
      lockKind: lock.lockKind,
      path: outputRelativePath(outputPath, resolve(inputDirectory, lock.path)),
      mediaType: lock.mediaType,
      digest: lockDigests[index],
    })),
  })
}

function serialized(value: unknown): string {
  return `${JSON.stringify(value, null, 2)}\n`
}

async function writeBindings(outputPath: string, bindings: ReleaseFileBindingsV1): Promise<void> {
  const parent = dirname(outputPath)
  await mkdir(parent, { recursive: true })
  const staging = await mkdtemp(resolve(parent, `.${basename(outputPath)}-`))
  const stagedFile = resolve(staging, basename(outputPath))
  try {
    await writeFile(stagedFile, serialized(bindings), {
      encoding: 'utf8',
      flag: 'wx',
      mode: 0o600,
    })
    await link(stagedFile, outputPath)
  } catch {
    return releaseFileFailure(
      'OUTPUT_WRITE_FAILED',
      'Release file bindings could not be committed.',
    )
  } finally {
    await rm(staging, { recursive: true, force: true }).catch(() => undefined)
  }
}

async function runReleaseBindingCli(
  args: readonly string[],
  io: ReleaseBindingIo = process,
): Promise<number> {
  try {
    const parsedArguments = parseArguments(args)
    await assertOutputAbsent(parsedArguments.outputPath)
    const input = await parseInput(parsedArguments.inputPath)
    const bindings = await assembleBindings(
      parsedArguments.inputPath,
      parsedArguments.outputPath,
      input,
    )
    await writeBindings(parsedArguments.outputPath, bindings)
    return 0
  } catch (error) {
    const failure = error instanceof ReleaseFileBoundaryError
      ? error
      : new ReleaseFileBoundaryError(
          'RELEASE_FILE_BINDING_FAILED',
          'Release file binding failed closed.',
        )
    io.stderr.write(serialized({ code: failure.code, message: failure.message }))
    return 1
  }
}

const invokedPath = process.argv[1]
if (invokedPath !== undefined && pathToFileURL(resolve(invokedPath)).href === import.meta.url) {
  process.exitCode = await runReleaseBindingCli(process.argv.slice(2))
}
