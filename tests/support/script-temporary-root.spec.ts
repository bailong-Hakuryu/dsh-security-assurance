import { access, mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { describe, expect, it, vi } from 'vitest'
import {
  removeTemporaryRoot,
  type RemoveDirectory,
} from '../../scripts/support/remove-temporary-root.mjs'

describe('script temporary-root cleanup', () => {
  it('retries a transient Windows-style EBUSY failure before giving up', async () => {
    const root = await mkdtemp(join(tmpdir(), 'dsh-script-cleanup-'))
    const busy = Object.assign(new Error('resource busy or locked'), { code: 'EBUSY' })
    const remove: RemoveDirectory = vi.fn()
      .mockRejectedValueOnce(busy)
      .mockImplementation((path, options) => rm(path, options))

    try {
      await removeTemporaryRoot(root, {
        remove,
        wait: async () => {},
        maxRetries: 2,
        retryDelayMs: 1,
      })

      expect(remove).toHaveBeenCalledTimes(2)
      await expect(access(root)).rejects.toMatchObject({ code: 'ENOENT' })
    } finally {
      await rm(root, { recursive: true, force: true })
    }
  })

  it('refuses to remove paths outside the system temporary directory', async () => {
    const remove = vi.fn<RemoveDirectory>()

    await expect(removeTemporaryRoot(process.cwd(), { remove })).rejects.toThrow(
      'Refusing to remove a path outside the system temporary directory',
    )
    expect(remove).not.toHaveBeenCalled()
  })
})
