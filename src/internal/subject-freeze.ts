import { randomUUID } from 'node:crypto'
import {
  chmod,
  lstat,
  mkdir,
  open,
  readFile,
  readlink,
  readdir,
  realpath,
  rename,
  rm,
  writeFile,
  type FileHandle,
} from 'node:fs/promises'
import { constants } from 'node:fs'
import type { BigIntStats } from 'node:fs'
import { dirname, isAbsolute, join, relative, resolve, sep } from 'node:path'
import type { SubprocessRuntime } from '@deepseek-ai/dsh-subprocess'
import type {
  AssessmentSubjectSourceV1,
  AssessmentTargetSelectorV1,
  DigestEnvelopeV1,
} from '../contracts.ts'
import { digestEnvelopeV1Schema } from '../contracts.ts'
import { binaryDigest, canonicalJson, structuredDigest } from './canonical.ts'

const MAX_SUBJECT_FILES = 10_000
const MAX_SUBJECT_BYTES = 64 * 1024 * 1024
const MAX_GIT_OUTPUT_BYTES = 80 * 1024 * 1024
const MAX_PATH_BYTES = 1_024
const MAX_ANALYZER_SOURCE_SLICES = 256
const MAX_ANALYZER_SLICE_BYTES = 1024 * 1024
const MAX_ANALYZER_SOURCE_BYTES = 4 * 1024 * 1024
const TARGET_SELECTOR_MEDIA_TYPE = 'application/vnd.dsh.security.target-selector+json'
const WINDOWS_RENAME_RETRY_DELAYS_MS = [5, 10, 25, 50, 100, 200] as const
const SUBJECT_STAGING_REMOVE_MAX_RETRIES = 6
const SUBJECT_STAGING_REMOVE_RETRY_DELAY_MS = 25

export type SubjectFreezeErrorCode =
  | 'invalid_subject'
  | 'unstable_subject'
  | 'resource_limit'
  | 'canceled'
  | 'integrity_failure'

export class SubjectFreezeError extends Error {
  constructor(
    readonly code: SubjectFreezeErrorCode,
    message: string,
  ) {
    super(message)
    this.name = 'SubjectFreezeError'
  }
}

interface FileEntry {
  readonly path: string
  readonly kind: 'file'
  readonly mode: '100644' | '100755'
  readonly digest: DigestEnvelopeV1
}

interface SymbolicLinkEntry {
  readonly path: string
  readonly kind: 'symbolic_link'
  readonly mode: '120000'
  readonly target: string
  readonly targetScope: 'inside_subject_root' | 'outside_subject_root'
  readonly digest: DigestEnvelopeV1
}

interface SubmoduleEntry {
  readonly path: string
  readonly kind: 'submodule'
  readonly mode: '160000'
  readonly revision: string
}

type SubjectManifestEntryV1 = FileEntry | SymbolicLinkEntry | SubmoduleEntry

interface SubjectManifestPayloadV1 {
  readonly schemaVersion: 1
  readonly subject: Readonly<Record<string, unknown>>
  readonly target: AssessmentTargetSelectorV1
  readonly targetDigest: DigestEnvelopeV1
  readonly entries: readonly SubjectManifestEntryV1[]
  readonly exclusions: readonly (
    | {
        readonly kind: 'policy'
        readonly reason: 'git_ignored_and_repository_metadata_not_admitted'
      }
    | {
        readonly kind: 'workspace_deleted'
        readonly path: string
      }
  )[]
  readonly totals: {
    readonly files: number
    readonly bytes: number
    readonly symbolicLinks: number
    readonly submodules: number
  }
}

export interface FrozenSubject {
  readonly source: AssessmentSubjectSourceV1
  readonly manifestDigest: DigestEnvelopeV1
  readonly targetDigest: DigestEnvelopeV1
  readonly files: number
  readonly bytes: number
  readonly symbolicLinks: number
  readonly submodules: number
}

/** One immutable, verified and authority-free text slice supplied to a Pure Analyzer. */
export interface VerifiedSubjectTextSliceV1 {
  readonly path: string
  readonly digest: DigestEnvelopeV1
  readonly text: string
}

export interface FreezeSubjectOptions {
  readonly subprocess: SubprocessRuntime
  readonly repositoryRoot: string
  readonly securityRoot: string
  readonly source: AssessmentSubjectSourceV1
  readonly target: AssessmentTargetSelectorV1
  readonly signal?: AbortSignal | undefined
}

/** Remove abandoned Subject staging trees left by a hard process termination. */
export async function reapSubjectStaging(securityRoot: string): Promise<void> {
  const stagingParent = join(securityRoot, 'staging')
  let entries
  try {
    entries = await readdir(stagingParent, { withFileTypes: true })
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return
    throw error
  }
  await Promise.all(entries
    .filter(entry => entry.isDirectory() && /^subject-[0-9a-f-]{36}$/u.test(entry.name))
    .map(entry => rm(join(stagingParent, entry.name), {
      recursive: true,
      force: true,
      maxRetries: SUBJECT_STAGING_REMOVE_MAX_RETRIES,
      retryDelay: SUBJECT_STAGING_REMOVE_RETRY_DELAY_MS,
    })))
}

interface GitTreeEntry {
  readonly mode: string
  readonly type: 'blob' | 'commit'
  readonly objectId: string
  readonly path: string
}

interface StableFile {
  readonly bytes: Buffer
  readonly signature: string
}

function canceled(signal: AbortSignal | undefined): void {
  if (signal?.aborted) throw new SubjectFreezeError('canceled', 'Subject Freeze was canceled')
}

/** @internal Managed Git execution seam; exported only for boundary tests. */
export async function runGit(
  subprocess: SubprocessRuntime,
  repositoryRoot: string,
  args: readonly string[],
  signal?: AbortSignal,
): Promise<Buffer> {
  canceled(signal)
  const gitEnvironment: NodeJS.ProcessEnv = {
    GIT_TERMINAL_PROMPT: '0',
    GCM_INTERACTIVE: 'Never',
    GIT_OPTIONAL_LOCKS: '0',
    GIT_CONFIG_COUNT: undefined,
    GIT_CONFIG_PARAMETERS: undefined,
    GIT_DIR: undefined,
    GIT_WORK_TREE: undefined,
    GIT_INDEX_FILE: undefined,
    GIT_OBJECT_DIRECTORY: undefined,
    GIT_ALTERNATE_OBJECT_DIRECTORIES: undefined,
    GIT_CEILING_DIRECTORIES: undefined,
  }
  let executable: string
  try {
    executable = await subprocess.resolveExecutable('git', undefined, signal)
  } catch {
    if (signal?.aborted) throw new SubjectFreezeError('canceled', 'Subject Freeze was canceled')
    throw new SubjectFreezeError('invalid_subject', 'Git is unavailable')
  }

  let handle: ReturnType<SubprocessRuntime['spawn']>
  try {
    handle = subprocess.spawn({
      argv: [
        executable,
        '-c',
        'core.fsmonitor=false',
        '--no-replace-objects',
        '--literal-pathspecs',
        ...args,
      ],
      cwd: repositoryRoot,
      stdio: {
        stdin: 'ignore',
        stdout: 'pipe',
        stderr: { maxBytes: 8_192 },
      },
      graceMs: 1_000,
      signal,
      env: gitEnvironment,
    })
  } catch {
    if (signal?.aborted) throw new SubjectFreezeError('canceled', 'Subject Freeze was canceled')
    throw new SubjectFreezeError('invalid_subject', 'Git is unavailable')
  }
  const stdout = handle.stdout
  if (stdout === undefined) {
    handle.terminate()
    await handle.waitForExit()
    throw new SubjectFreezeError('invalid_subject', 'Git is unavailable')
  }

  const chunks: Buffer[] = []
  let outputBytes = 0
  let outputExceeded = false
  const outputComplete = new Promise<void>((resolvePromise, rejectPromise) => {
    stdout.on('data', (chunk: Buffer) => {
      if (outputExceeded) return
      outputBytes += chunk.byteLength
      if (outputBytes > MAX_GIT_OUTPUT_BYTES) {
        outputExceeded = true
        handle.terminate()
        return
      }
      chunks.push(chunk)
    })
    stdout.once('end', resolvePromise)
    stdout.once('error', rejectPromise)
  })

  try {
    const [outcome] = await Promise.all([handle.done, outputComplete])
    if (signal?.aborted) {
      throw new SubjectFreezeError('canceled', 'Subject Freeze was canceled')
    }
    if (outputExceeded) {
      throw new SubjectFreezeError('resource_limit', 'Git output exceeded the Subject limit')
    }
    if (outcome.exitCode !== 0) {
      throw new SubjectFreezeError('invalid_subject', 'Git could not resolve the exact Subject identity')
    }
    return Buffer.concat(chunks, outputBytes)
  } catch (error) {
    handle.terminate()
    await handle.waitForExit()
    if (error instanceof SubjectFreezeError) throw error
    if (signal?.aborted) throw new SubjectFreezeError('canceled', 'Subject Freeze was canceled')
    if (outputExceeded) {
      throw new SubjectFreezeError('resource_limit', 'Git output exceeded the Subject limit')
    }
    throw new SubjectFreezeError('invalid_subject', 'Git is unavailable')
  }
}

function decodeUtf8(bytes: Uint8Array): string {
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes)
  } catch {
    throw new SubjectFreezeError('invalid_subject', 'Subject paths must be valid UTF-8')
  }
}

function nullSeparated(bytes: Buffer): readonly string[] {
  if (bytes.byteLength === 0) return []
  const values = decodeUtf8(bytes).split('\0')
  if (values.at(-1) === '') values.pop()
  return values
}

function validateRelativePath(path: string, seen: Set<string>): string {
  const canonical = path.normalize('NFC')
  const segments = canonical.split('/')
  const reserved = /^(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\..*)?$/iu
  if (
    canonical !== path
    || Buffer.byteLength(canonical, 'utf8') > MAX_PATH_BYTES
    || canonical.length === 0
    || canonical.startsWith('/')
    || canonical.includes('\\')
    || canonical.includes('\0')
    || Array.from(canonical).some(character => (character.codePointAt(0) ?? 0) <= 0x1f)
    || segments.some(segment => (
      segment.length === 0
      || segment === '.'
      || segment === '..'
      || segment.toLowerCase() === '.git'
      || segment.endsWith('.')
      || segment.endsWith(' ')
      || segment.includes(':')
      || reserved.test(segment)
    ))
  ) {
    throw new SubjectFreezeError('invalid_subject', 'Subject contains a non-portable or unsafe path')
  }
  const collisionKey = canonical.toLocaleLowerCase('en-US')
  if (seen.has(collisionKey)) {
    throw new SubjectFreezeError('invalid_subject', 'Subject contains colliding portable paths')
  }
  seen.add(collisionKey)
  return canonical
}

function parseGitTree(bytes: Buffer): readonly GitTreeEntry[] {
  const seen = new Set<string>()
  return nullSeparated(bytes).map(record => {
    const match = /^(\d{6}) (blob|commit) ([0-9a-f]{40})\t([\s\S]+)$/u.exec(record)
    if (match === null) throw new SubjectFreezeError('invalid_subject', 'Git tree entry is malformed')
    const [, mode, type, objectId, unsafePath] = match
    if (mode === undefined || type === undefined || objectId === undefined || unsafePath === undefined) {
      throw new SubjectFreezeError('invalid_subject', 'Git tree entry is incomplete')
    }
    return {
      mode,
      type: type as 'blob' | 'commit',
      objectId,
      path: validateRelativePath(unsafePath, seen),
    }
  })
}

async function exactCommit(
  subprocess: SubprocessRuntime,
  repositoryRoot: string,
  commit: string,
  signal?: AbortSignal,
): Promise<string> {
  const resolved = decodeUtf8(await runGit(subprocess, repositoryRoot, [
    'rev-parse',
    '--verify',
    `${commit}^{commit}`,
  ], signal)).trim()
  if (resolved !== commit) {
    throw new SubjectFreezeError('invalid_subject', 'Git commit identity did not resolve exactly')
  }
  return resolved
}

function assertSubjectBounds(entries: readonly SubjectManifestEntryV1[]): void {
  const files = entries.filter(entry => entry.kind === 'file')
  const bytes = files.reduce((sum, entry) => sum + entry.digest.byteLength, 0)
  if (files.length > MAX_SUBJECT_FILES || bytes > MAX_SUBJECT_BYTES) {
    throw new SubjectFreezeError('resource_limit', 'Subject exceeds the v0.1 file or byte limit')
  }
}

async function writeMaterializedFile(root: string, entryPath: string, bytes: Uint8Array, executable: boolean): Promise<void> {
  const destination = join(root, ...entryPath.split('/'))
  await mkdir(dirname(destination), { recursive: true })
  await writeFile(destination, bytes, { flag: 'wx', mode: executable ? 0o555 : 0o444 })
  await chmod(destination, executable ? 0o555 : 0o444)
}

async function materializeGitTree(
  subprocess: SubprocessRuntime,
  repositoryRoot: string,
  commit: string,
  contentRoot: string,
  signal?: AbortSignal,
): Promise<readonly SubjectManifestEntryV1[]> {
  const tree = parseGitTree(await runGit(subprocess, repositoryRoot, ['ls-tree', '-rz', '--full-tree', commit], signal))
  if (tree.length > MAX_SUBJECT_FILES) {
    throw new SubjectFreezeError('resource_limit', 'Subject exceeds the v0.1 entry limit')
  }
  const entries: SubjectManifestEntryV1[] = []
  let totalBytes = 0
  for (const item of tree) {
    canceled(signal)
    if (item.mode === '160000' && item.type === 'commit') {
      entries.push({ path: item.path, kind: 'submodule', mode: '160000', revision: item.objectId })
      continue
    }
    if (item.type !== 'blob' || !['100644', '100755', '120000'].includes(item.mode)) {
      throw new SubjectFreezeError('invalid_subject', 'Git tree contains an unsupported object kind')
    }
    const bytes = await runGit(subprocess, repositoryRoot, ['cat-file', 'blob', item.objectId], signal)
    totalBytes += bytes.byteLength
    if (totalBytes > MAX_SUBJECT_BYTES) {
      throw new SubjectFreezeError('resource_limit', 'Subject exceeds the v0.1 byte limit')
    }
    if (item.mode === '120000') {
      const target = decodeUtf8(bytes)
      const lexicalTarget = resolve(repositoryRoot, dirname(item.path), target)
      const targetRelative = relative(repositoryRoot, lexicalTarget)
      const inside = targetRelative !== '..'
        && !targetRelative.startsWith(`..${sep}`)
        && !isAbsolute(targetRelative)
      entries.push({
        path: item.path,
        kind: 'symbolic_link',
        mode: '120000',
        target,
        targetScope: inside ? 'inside_subject_root' : 'outside_subject_root',
        digest: binaryDigest('text/plain', bytes),
      })
      continue
    }
    await writeMaterializedFile(contentRoot, item.path, bytes, item.mode === '100755')
    entries.push({
      path: item.path,
      kind: 'file',
      mode: item.mode === '100755' ? '100755' : '100644',
      digest: binaryDigest('application/octet-stream', bytes),
    })
  }
  return entries
}

function statSignature(stat: BigIntStats): string {
  return [stat.dev, stat.ino, stat.size, stat.mtimeNs, stat.ctimeNs].map(String).join(':')
}

async function readBounded(handle: FileHandle, maxBytes: number): Promise<Buffer> {
  const chunks: Buffer[] = []
  let totalBytes = 0
  while (totalBytes <= maxBytes) {
    const chunk = Buffer.allocUnsafe(Math.min(64 * 1024, maxBytes + 1 - totalBytes))
    const { bytesRead } = await handle.read(chunk, 0, chunk.byteLength, null)
    if (bytesRead === 0) break
    chunks.push(chunk.subarray(0, bytesRead))
    totalBytes += bytesRead
    if (totalBytes > maxBytes) {
      throw new SubjectFreezeError('resource_limit', 'Workspace file exceeds the Subject byte limit')
    }
  }
  return Buffer.concat(chunks, totalBytes)
}

async function stableFile(path: string): Promise<StableFile> {
  const entry = await lstat(path)
  if (!entry.isFile()) throw new SubjectFreezeError('invalid_subject', 'Workspace entry is not a regular file')
  if (entry.size > MAX_SUBJECT_BYTES) {
    throw new SubjectFreezeError('resource_limit', 'Workspace file exceeds the Subject byte limit')
  }
  const nonBlocking = process.platform === 'win32' ? 0 : constants.O_NONBLOCK
  const handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | nonBlocking)
  try {
    const before = await handle.stat({ bigint: true })
    if (!before.isFile()) throw new SubjectFreezeError('invalid_subject', 'Workspace entry is not a regular file')
    if (before.size > BigInt(MAX_SUBJECT_BYTES)) {
      throw new SubjectFreezeError('resource_limit', 'Workspace file exceeds the Subject byte limit')
    }
    const bytes = await readBounded(handle, MAX_SUBJECT_BYTES)
    const after = await handle.stat({ bigint: true })
    if (after.size > BigInt(MAX_SUBJECT_BYTES)) {
      throw new SubjectFreezeError('resource_limit', 'Workspace file exceeds the Subject byte limit')
    }
    if (statSignature(before) !== statSignature(after) || BigInt(bytes.byteLength) !== after.size) {
      throw new SubjectFreezeError('unstable_subject', 'Workspace file changed during Subject Freeze')
    }
    return { bytes, signature: statSignature(after) }
  } finally {
    await handle.close()
  }
}

function assertPathWithinRoot(root: string, candidate: string): void {
  const candidateRelative = relative(root, candidate)
  if (
    candidateRelative === '..'
    || candidateRelative.startsWith(`..${sep}`)
    || isAbsolute(candidateRelative)
  ) {
    throw new SubjectFreezeError('invalid_subject', 'Workspace entry resolves outside the repository')
  }
}

/** Reject parent-directory links before a workspace file can be opened. */
async function assertWorkspacePathWithinRoot(repositoryRoot: string, sourcePath: string, checkFinalPath: boolean): Promise<void> {
  const resolvedParent = await realpath(dirname(sourcePath))
  assertPathWithinRoot(repositoryRoot, resolvedParent)
  if (checkFinalPath) assertPathWithinRoot(repositoryRoot, await realpath(sourcePath))
}

function parseIndexModes(bytes: Buffer): ReadonlyMap<string, { readonly mode: string; readonly objectId: string }> {
  const modes = new Map<string, { readonly mode: string; readonly objectId: string }>()
  for (const record of nullSeparated(bytes)) {
    const match = /^(\d{6}) ([0-9a-f]{40}) ([0-3])\t([\s\S]+)$/u.exec(record)
    if (match === null) throw new SubjectFreezeError('invalid_subject', 'Git index entry is malformed')
    const [, mode, objectId, stage, path] = match
    if (mode === undefined || objectId === undefined || stage === undefined || path === undefined || stage !== '0') {
      throw new SubjectFreezeError('invalid_subject', 'Workspace has unresolved Git index stages')
    }
    modes.set(path, { mode, objectId })
  }
  return modes
}

async function materializeWorkspace(
  subprocess: SubprocessRuntime,
  repositoryRoot: string,
  contentRoot: string,
  signal?: AbortSignal,
): Promise<{
  readonly entries: readonly SubjectManifestEntryV1[]
  readonly headCommit: string
  readonly selectionDigest: DigestEnvelopeV1
  readonly exclusions: readonly { readonly kind: 'workspace_deleted'; readonly path: string }[]
}> {
  const resolvedRepositoryRoot = await realpath(repositoryRoot)
  const selectionArgs = ['ls-files', '-z', '--cached', '--others', '--exclude-standard'] as const
  const beforeSelection = await runGit(subprocess, repositoryRoot, selectionArgs, signal)
  const beforeDeleted = await runGit(subprocess, repositoryRoot, ['ls-files', '-z', '--deleted'], signal)
  const beforeHead = decodeUtf8(await runGit(subprocess, repositoryRoot, [
    'rev-parse', '--verify', 'HEAD^{commit}',
  ], signal)).trim()
  if (!/^[0-9a-f]{40}$/u.test(beforeHead)) {
    throw new SubjectFreezeError('invalid_subject', 'Workspace does not have an exact HEAD commit')
  }
  const indexModes = parseIndexModes(await runGit(subprocess, repositoryRoot, ['ls-files', '-s', '-z'], signal))
  const unsafePaths = nullSeparated(beforeSelection)
  if (unsafePaths.length > MAX_SUBJECT_FILES) {
    throw new SubjectFreezeError('resource_limit', 'Workspace exceeds the v0.1 entry limit')
  }
  const seen = new Set<string>()
  const paths = unsafePaths.map(path => validateRelativePath(path, seen))
  const deletedSeen = new Set<string>()
  const deletedPaths = nullSeparated(beforeDeleted).map(path => validateRelativePath(path, deletedSeen))
  const deleted = new Set(deletedPaths)
  const entries: SubjectManifestEntryV1[] = []
  const stableFiles = new Map<string, { readonly signature: string; readonly digest: DigestEnvelopeV1 }>()
  let totalBytes = 0

  for (const path of paths) {
    canceled(signal)
    if (deleted.has(path)) continue
    const index = indexModes.get(path)
    if (index?.mode === '160000') {
      entries.push({ path, kind: 'submodule', mode: '160000', revision: index.objectId })
      continue
    }
    const sourcePath = join(repositoryRoot, ...path.split('/'))
    const metadata = await lstat(sourcePath, { bigint: true })
    if (metadata.isSymbolicLink()) {
      const target = await readlink(sourcePath)
      const targetBytes = Buffer.from(target, 'utf8')
      const lexicalTarget = resolve(dirname(sourcePath), target)
      const targetRelative = relative(repositoryRoot, lexicalTarget)
      const inside = targetRelative !== '..'
        && !targetRelative.startsWith(`..${sep}`)
        && !isAbsolute(targetRelative)
      entries.push({
        path,
        kind: 'symbolic_link',
        mode: '120000',
        target,
        targetScope: inside ? 'inside_subject_root' : 'outside_subject_root',
        digest: binaryDigest('text/plain', targetBytes),
      })
      continue
    }
    await assertWorkspacePathWithinRoot(resolvedRepositoryRoot, sourcePath, true)
    const captured = await stableFile(sourcePath)
    await assertWorkspacePathWithinRoot(resolvedRepositoryRoot, sourcePath, true)
    totalBytes += captured.bytes.byteLength
    if (totalBytes > MAX_SUBJECT_BYTES) {
      throw new SubjectFreezeError('resource_limit', 'Workspace exceeds the v0.1 byte limit')
    }
    const executable = index?.mode === '100755' || (index === undefined && (metadata.mode & 0o111n) !== 0n)
    await writeMaterializedFile(contentRoot, path, captured.bytes, executable)
    const digest = binaryDigest('application/octet-stream', captured.bytes)
    stableFiles.set(path, { signature: captured.signature, digest })
    entries.push({ path, kind: 'file', mode: executable ? '100755' : '100644', digest })
  }

  for (const [path, expected] of stableFiles) {
    canceled(signal)
    const sourcePath = join(repositoryRoot, ...path.split('/'))
    await assertWorkspacePathWithinRoot(resolvedRepositoryRoot, sourcePath, true)
    const observed = await stableFile(sourcePath)
    await assertWorkspacePathWithinRoot(resolvedRepositoryRoot, sourcePath, true)
    if (
      observed.signature !== expected.signature
      || binaryDigest('application/octet-stream', observed.bytes).value !== expected.digest.value
    ) {
      throw new SubjectFreezeError('unstable_subject', 'Workspace changed across the stable-read boundary')
    }
  }
  const afterSelection = await runGit(subprocess, repositoryRoot, selectionArgs, signal)
  const afterDeleted = await runGit(subprocess, repositoryRoot, ['ls-files', '-z', '--deleted'], signal)
  const afterHead = decodeUtf8(await runGit(subprocess, repositoryRoot, [
    'rev-parse', '--verify', 'HEAD^{commit}',
  ], signal)).trim()
  if (!beforeSelection.equals(afterSelection) || !beforeDeleted.equals(afterDeleted) || beforeHead !== afterHead) {
    throw new SubjectFreezeError('unstable_subject', 'Workspace identity changed during Subject Freeze')
  }
  return {
    entries,
    headCommit: beforeHead,
    selectionDigest: binaryDigest('application/vnd.dsh.git.path-selection', beforeSelection),
    exclusions: deletedPaths.map(path => ({ kind: 'workspace_deleted', path })),
  }
}

async function lockTree(path: string): Promise<void> {
  const entries = await readdir(path, { withFileTypes: true })
  for (const entry of entries) {
    const child = join(path, entry.name)
    if (entry.isDirectory()) await lockTree(child)
    else await chmod(child, 0o444)
  }
  await chmod(path, 0o555)
}

function recordValue(value: unknown): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new SubjectFreezeError('integrity_failure', 'Subject Manifest is not a record')
  }
  return value as Record<string, unknown>
}

async function materializedFilePaths(
  contentRoot: string,
  directory = contentRoot,
): Promise<readonly string[]> {
  const paths: string[] = []
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const child = join(directory, entry.name)
    if (entry.isDirectory()) {
      paths.push(...await materializedFilePaths(contentRoot, child))
    } else if (entry.isFile()) {
      paths.push(relative(contentRoot, child).split(sep).join('/'))
    } else {
      throw new SubjectFreezeError('integrity_failure', 'Subject materialization contains a special object')
    }
  }
  return paths
}

async function verifyPublishedSnapshot(
  publishedRoot: string,
  expectedDigest: DigestEnvelopeV1,
): Promise<Record<string, unknown>> {
  const manifest = recordValue(JSON.parse(await readFile(join(publishedRoot, 'manifest.json'), 'utf8')))
  const declaredDigest = manifest.rootDigest
  const payload = Object.fromEntries(Object.entries(manifest).filter(([key]) => key !== 'rootDigest'))
  const recomputed = structuredDigest('application/vnd.dsh.security.subject-manifest+json', payload)
  if (
    canonicalJson(declaredDigest) !== canonicalJson(expectedDigest)
    || canonicalJson(recomputed) !== canonicalJson(expectedDigest)
  ) {
    throw new SubjectFreezeError('integrity_failure', 'Subject Manifest digest verification failed')
  }
  if (!Array.isArray(manifest.entries)) {
    throw new SubjectFreezeError('integrity_failure', 'Subject Manifest entries are invalid')
  }
  const seen = new Set<string>()
  const expectedFiles: string[] = []
  for (const value of manifest.entries) {
    const entry = recordValue(value)
    if (typeof entry.path !== 'string' || typeof entry.kind !== 'string') {
      throw new SubjectFreezeError('integrity_failure', 'Subject Manifest entry is invalid')
    }
    const path = validateRelativePath(entry.path, seen)
    if (entry.kind !== 'file') continue
    const declaredFileDigest = recordValue(entry.digest)
    const captured = await stableFile(join(publishedRoot, 'content', ...path.split('/')))
    const recomputedFileDigest = binaryDigest('application/octet-stream', captured.bytes)
    if (canonicalJson(declaredFileDigest) !== canonicalJson(recomputedFileDigest)) {
      throw new SubjectFreezeError('integrity_failure', 'Subject file digest verification failed')
    }
    expectedFiles.push(path)
  }
  const actualFiles = [...await materializedFilePaths(join(publishedRoot, 'content'))].sort()
  expectedFiles.sort()
  if (canonicalJson(actualFiles) !== canonicalJson(expectedFiles)) {
    throw new SubjectFreezeError('integrity_failure', 'Subject materialization does not match its Manifest')
  }
  return manifest
}

/** Freeze one exact Subject and atomically publish its private content-addressed Snapshot. */
export async function freezeSubject(options: FreezeSubjectOptions): Promise<FrozenSubject> {
  canceled(options.signal)
  const stagingParent = join(options.securityRoot, 'staging')
  const subjectsRoot = join(options.securityRoot, 'subjects')
  await mkdir(stagingParent, { recursive: true, mode: 0o700 })
  await mkdir(subjectsRoot, { recursive: true, mode: 0o700 })
  const stagingRoot = join(stagingParent, `subject-${randomUUID()}`)
  const contentRoot = join(stagingRoot, 'content')
  await mkdir(contentRoot, { recursive: true, mode: 0o700 })
  let published = false
  try {
    let entries: readonly SubjectManifestEntryV1[]
    let resolvedSubject: Readonly<Record<string, unknown>>
    let subjectExclusions: readonly { readonly kind: 'workspace_deleted'; readonly path: string }[] = []
    if (options.source.kind === 'git_revision') {
      const commit = await exactCommit(options.subprocess, options.repositoryRoot, options.source.commit, options.signal)
      entries = await materializeGitTree(options.subprocess, options.repositoryRoot, commit, contentRoot, options.signal)
      resolvedSubject = { kind: 'git_revision', commit }
    } else if (options.source.kind === 'change') {
      const baseCommit = await exactCommit(options.subprocess, options.repositoryRoot, options.source.baseCommit, options.signal)
      const headCommit = await exactCommit(options.subprocess, options.repositoryRoot, options.source.headCommit, options.signal)
      const changeSet = await runGit(options.subprocess, options.repositoryRoot, [
        'diff', '--raw', '-z', '--no-renames', '--no-ext-diff', '--no-textconv', baseCommit, headCommit,
      ], options.signal)
      entries = await materializeGitTree(options.subprocess, options.repositoryRoot, headCommit, contentRoot, options.signal)
      resolvedSubject = {
        kind: 'change',
        baseCommit,
        headCommit,
        changeSetDigest: binaryDigest('application/vnd.dsh.git.raw-diff', changeSet),
      }
    } else {
      const workspace = await materializeWorkspace(options.subprocess, options.repositoryRoot, contentRoot, options.signal)
      entries = workspace.entries
      subjectExclusions = workspace.exclusions
      resolvedSubject = {
        kind: 'workspace_snapshot',
        headCommit: workspace.headCommit,
        selectionDigest: workspace.selectionDigest,
      }
    }
    assertSubjectBounds(entries)
    const targetDigest = structuredDigest(TARGET_SELECTOR_MEDIA_TYPE, options.target)
    const payload: SubjectManifestPayloadV1 = {
      schemaVersion: 1,
      subject: resolvedSubject,
      target: options.target,
      targetDigest,
      entries: [...entries].sort((left, right) => left.path.localeCompare(right.path, 'en-US')),
      exclusions: [{
        kind: 'policy',
        reason: 'git_ignored_and_repository_metadata_not_admitted',
      }, ...subjectExclusions],
      totals: {
        files: entries.filter(entry => entry.kind === 'file').length,
        bytes: entries
          .filter((entry): entry is FileEntry => entry.kind === 'file')
          .reduce((sum, entry) => sum + entry.digest.byteLength, 0),
        symbolicLinks: entries.filter(entry => entry.kind === 'symbolic_link').length,
        submodules: entries.filter(entry => entry.kind === 'submodule').length,
      },
    }
    const rootDigest = structuredDigest('application/vnd.dsh.security.subject-manifest+json', payload)
    const manifest = { ...payload, rootDigest }
    await writeFile(join(stagingRoot, 'manifest.json'), `${canonicalJson(manifest)}\n`, {
      encoding: 'utf8',
      flag: 'wx',
      mode: 0o444,
    })
    const publishedRoot = join(subjectsRoot, rootDigest.value)
    let renamed = false
    for (let attempt = 0; !renamed; attempt += 1) {
      try {
        await rename(stagingRoot, publishedRoot)
        renamed = true
        published = true
        await verifyPublishedSnapshot(publishedRoot, rootDigest)
        await lockTree(publishedRoot)
      } catch (error) {
        const code = (error as NodeJS.ErrnoException).code
        const delay = WINDOWS_RENAME_RETRY_DELAYS_MS[attempt]
        let destinationExists = false
        if (code === 'EPERM' || code === 'EACCES' || code === 'EBUSY') {
          try {
            const destinationStatus = await lstat(publishedRoot)
            destinationExists = destinationStatus.isDirectory() && !destinationStatus.isSymbolicLink()
          } catch {
            destinationExists = false
          }
        }
        if (destinationExists) {
          await verifyPublishedSnapshot(publishedRoot, rootDigest)
          await rm(stagingRoot, { recursive: true, force: true })
          published = true
          renamed = true
          continue
        }
        if (
          process.platform === 'win32'
          && delay !== undefined
          && (code === 'EPERM' || code === 'EBUSY' || code === 'EACCES')
        ) {
          await new Promise(resolve => setTimeout(resolve, delay))
          continue
        }
        if (code !== 'EEXIST' && code !== 'ENOTEMPTY') throw error
        await verifyPublishedSnapshot(publishedRoot, rootDigest)
        await rm(stagingRoot, { recursive: true, force: true })
        published = true
        renamed = true
      }
    }
    canceled(options.signal)
    return {
      source: options.source,
      manifestDigest: rootDigest,
      targetDigest,
      files: payload.totals.files,
      bytes: payload.totals.bytes,
      symbolicLinks: payload.totals.symbolicLinks,
      submodules: payload.totals.submodules,
    }
  } catch (error) {
    if (!published) await rm(stagingRoot, { recursive: true, force: true })
    if (error instanceof SubjectFreezeError) throw error
    const code = (error as NodeJS.ErrnoException).code
    if (code === 'ENOENT' || code === 'ELOOP' || code === 'ENOTDIR' || code === 'EPERM' || code === 'EACCES') {
      throw new SubjectFreezeError('invalid_subject', 'Subject content could not be read safely')
    }
    throw error
  }
}

/**
 * Reverify one content-addressed Subject Snapshot and return only bounded Node
 * package manifests. Absolute private paths never enter the Analyzer input.
 */
export async function readVerifiedNodePackageManifestSlices(
  securityRoot: string,
  subjectDigest: DigestEnvelopeV1,
  signal?: AbortSignal,
): Promise<readonly VerifiedSubjectTextSliceV1[]> {
  canceled(signal)
  if (
    subjectDigest.algorithm !== 'sha256'
    || subjectDigest.mediaType !== 'application/vnd.dsh.security.subject-manifest+json'
    || !/^[0-9a-f]{64}$/u.test(subjectDigest.value)
  ) {
    throw new SubjectFreezeError('integrity_failure', 'Subject identity is not a supported Manifest digest')
  }
  const publishedRoot = join(securityRoot, 'subjects', subjectDigest.value)
  const manifest = await verifyPublishedSnapshot(publishedRoot, subjectDigest)
  if (!Array.isArray(manifest.entries)) {
    throw new SubjectFreezeError('integrity_failure', 'Subject Manifest entries are invalid')
  }
  const packageEntries = manifest.entries.map(recordValue).filter(entry => (
    entry.kind === 'file'
    && typeof entry.path === 'string'
    && entry.path.split('/').at(-1) === 'package.json'
  ))
  if (packageEntries.length > MAX_ANALYZER_SOURCE_SLICES) {
    throw new SubjectFreezeError('resource_limit', 'Node package manifest count exceeds the Analyzer input limit')
  }
  let totalBytes = 0
  const slices: VerifiedSubjectTextSliceV1[] = []
  for (const entry of packageEntries) {
    canceled(signal)
    const path = entry.path as string
    const digest = digestEnvelopeV1Schema.parse(entry.digest)
    const captured = await stableFile(join(publishedRoot, 'content', ...path.split('/')))
    if (captured.bytes.byteLength > MAX_ANALYZER_SLICE_BYTES) {
      throw new SubjectFreezeError('resource_limit', 'Node package manifest exceeds the Analyzer slice limit')
    }
    totalBytes += captured.bytes.byteLength
    if (totalBytes > MAX_ANALYZER_SOURCE_BYTES) {
      throw new SubjectFreezeError('resource_limit', 'Node package manifests exceed the Analyzer input budget')
    }
    const observed = binaryDigest('application/octet-stream', captured.bytes)
    if (canonicalJson(digest) !== canonicalJson(observed)) {
      throw new SubjectFreezeError('integrity_failure', 'Analyzer source slice failed digest verification')
    }
    slices.push({ path, digest: observed, text: decodeUtf8(captured.bytes) })
  }
  return slices
}

/**
 * Reverify one content-addressed Subject Snapshot and return only bounded
 * external tool reports captured at conventional Subject-relative paths.
 * Reports are produced outside the Pure boundary (CI or operator), frozen
 * with the Subject, and digest-verified exactly like source slices.
 */
export async function readVerifiedExternalToolReportSlices(
  securityRoot: string,
  subjectDigest: DigestEnvelopeV1,
  reportBaseNames: readonly string[],
  signal?: AbortSignal,
): Promise<readonly VerifiedSubjectTextSliceV1[]> {
  canceled(signal)
  if (reportBaseNames.length === 0) return []
  const accepted = new Set(reportBaseNames)
  if (
    subjectDigest.algorithm !== 'sha256'
    || subjectDigest.mediaType !== 'application/vnd.dsh.security.subject-manifest+json'
    || !/^[0-9a-f]{64}$/u.test(subjectDigest.value)
  ) {
    throw new SubjectFreezeError('integrity_failure', 'Subject identity is not a supported Manifest digest')
  }
  const publishedRoot = join(securityRoot, 'subjects', subjectDigest.value)
  const manifest = await verifyPublishedSnapshot(publishedRoot, subjectDigest)
  if (!Array.isArray(manifest.entries)) {
    throw new SubjectFreezeError('integrity_failure', 'Subject Manifest entries are invalid')
  }
  const reportEntries = manifest.entries.map(recordValue).filter(entry => (
    entry.kind === 'file'
    && typeof entry.path === 'string'
    && accepted.has(entry.path.split('/').at(-1) as string)
  ))
  if (reportEntries.length > MAX_ANALYZER_SOURCE_SLICES) {
    throw new SubjectFreezeError('resource_limit', 'External tool report count exceeds the Analyzer input limit')
  }
  let totalBytes = 0
  const slices: VerifiedSubjectTextSliceV1[] = []
  for (const entry of reportEntries) {
    canceled(signal)
    const path = entry.path as string
    const digest = digestEnvelopeV1Schema.parse(entry.digest)
    const captured = await stableFile(join(publishedRoot, 'content', ...path.split('/')))
    if (captured.bytes.byteLength > MAX_ANALYZER_SLICE_BYTES) {
      throw new SubjectFreezeError('resource_limit', 'External tool report exceeds the Analyzer slice limit')
    }
    totalBytes += captured.bytes.byteLength
    if (totalBytes > MAX_ANALYZER_SOURCE_BYTES) {
      throw new SubjectFreezeError('resource_limit', 'External tool reports exceed the Analyzer input budget')
    }
    const observed = binaryDigest('application/octet-stream', captured.bytes)
    if (canonicalJson(digest) !== canonicalJson(observed)) {
      throw new SubjectFreezeError('integrity_failure', 'External tool report slice failed digest verification')
    }
    slices.push({ path, digest: observed, text: decodeUtf8(captured.bytes) })
  }
  return slices
}
