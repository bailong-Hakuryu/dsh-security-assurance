import { rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { isAbsolute, relative, resolve, sep } from 'node:path'

const RETRYABLE_REMOVE_CODES = new Set(['EACCES', 'EBUSY', 'ENOTEMPTY', 'EPERM'])

function isNestedPath(root, target) {
  const relativeTarget = relative(root, target)
  return relativeTarget !== ''
    && relativeTarget !== '..'
    && !relativeTarget.startsWith(`..${sep}`)
    && !isAbsolute(relativeTarget)
}

function retryableRemoveError(error) {
  return error instanceof Error
    && 'code' in error
    && RETRYABLE_REMOVE_CODES.has(error.code)
}

function delay(milliseconds) {
  return new Promise(resolveDelay => setTimeout(resolveDelay, milliseconds))
}

/** Remove one script-owned temporary tree, tolerating transient Windows locks. */
export async function removeTemporaryRoot(path, options = {}) {
  const target = resolve(path)
  const temporaryDirectory = resolve(tmpdir())
  if (!isNestedPath(temporaryDirectory, target)) {
    throw new Error(`Refusing to remove a path outside the system temporary directory: ${target}`)
  }

  const remove = options.remove ?? rm
  const wait = options.wait ?? delay
  const maxRetries = options.maxRetries ?? 10
  const retryDelayMs = options.retryDelayMs ?? 100

  for (let attempt = 0; ; attempt += 1) {
    try {
      await remove(target, { recursive: true, force: true })
      return
    } catch (error) {
      if (!retryableRemoveError(error) || attempt >= maxRetries) throw error
      await wait(retryDelayMs * (attempt + 1))
    }
  }
}
