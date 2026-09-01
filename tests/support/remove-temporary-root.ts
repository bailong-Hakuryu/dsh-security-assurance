import { chmod, lstat, readdir, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { isAbsolute, relative, resolve } from 'node:path'

function isMissing(error: unknown): boolean {
  return error instanceof Error && 'code' in error && error.code === 'ENOENT'
}

function assertSystemTemporaryPath(path: string): string {
  const target = resolve(path)
  const relativeTarget = relative(resolve(tmpdir()), target)
  if (relativeTarget === '' || relativeTarget === '..' || relativeTarget.startsWith(`..${process.platform === 'win32' ? '\\' : '/'}`) || isAbsolute(relativeTarget)) {
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
  const target = assertSystemTemporaryPath(path)
  await restoreWritableModes(target)
  await rm(target, { recursive: true, force: true, maxRetries: 3, retryDelay: 50 })
}

export async function removeTemporaryRoots(paths: string[]): Promise<void> {
  await Promise.all(paths.splice(0).map(removeTemporaryRoot))
}
