import { chmod, lstat, readdir, realpath, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { isAbsolute, relative, resolve, sep } from 'node:path'

function isMissing(error: unknown): boolean {
  return error instanceof Error && 'code' in error && error.code === 'ENOENT'
}

function isNestedPath(root: string, target: string): boolean {
  const relativeTarget = relative(root, target)
  return relativeTarget !== ''
    && relativeTarget !== '..'
    && !relativeTarget.startsWith(`..${sep}`)
    && !isAbsolute(relativeTarget)
}

async function assertSystemTemporaryPath(path: string): Promise<string> {
  const target = resolve(path)
  const configuredTemporaryRoot = resolve(tmpdir())
  const canonicalTemporaryRoot = await realpath(configuredTemporaryRoot)
  if (
    !isNestedPath(configuredTemporaryRoot, target)
    && !isNestedPath(canonicalTemporaryRoot, target)
  ) {
    throw new Error(`Refusing to remove a path outside the system temporary directory: ${target}`)
  }
  return target
}

async function restoreWritableModes(path: string): Promise<void> {
  let metadata
  try {
    metadata = await lstat(path)
  } catch (error) {
    if (isMissing(error)) return
    throw error
  }

  if (metadata.isSymbolicLink()) return
  if (!metadata.isDirectory()) {
    await chmod(path, 0o600)
    return
  }

  await chmod(path, 0o700)
  const entries = await readdir(path)
  await Promise.all(entries.map(entry => restoreWritableModes(resolve(path, entry))))
}

export async function removeTemporaryRoot(path: string): Promise<void> {
  const target = await assertSystemTemporaryPath(path)
  await restoreWritableModes(target)
  await rm(target, { recursive: true, force: true, maxRetries: 3, retryDelay: 50 })
}

export async function removeTemporaryRoots(paths: string[]): Promise<void> {
  await Promise.all(paths.splice(0).map(removeTemporaryRoot))
}
