import { access, chmod, mkdir, mkdtemp, readFile, realpath, symlink, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { removeTemporaryRoot } from './remove-temporary-root.ts'

describe('removeTemporaryRoot', () => {
  it('removes read-only fixture trees without following directory links', async () => {
    const root = await realpath(await mkdtemp(join(tmpdir(), 'dsh-security-cleanup-root-')))
    const outside = await realpath(await mkdtemp(join(tmpdir(), 'dsh-security-cleanup-outside-')))
    const nested = join(root, 'subjects', 'digest', 'content')
    const manifest = join(root, 'subjects', 'digest', 'manifest.json')
    const outsideSentinel = join(outside, 'sentinel.txt')

    try {
      await mkdir(nested, { recursive: true })
      await writeFile(manifest, '{}\n', 'utf8')
      await writeFile(outsideSentinel, 'preserve\n', 'utf8')
      await symlink(outside, join(nested, 'outside'), 'junction')
      await chmod(manifest, 0o444)
      await chmod(nested, 0o555)
      await chmod(join(root, 'subjects', 'digest'), 0o555)
      await chmod(join(root, 'subjects'), 0o555)

      await removeTemporaryRoot(root)

      await expect(access(root)).rejects.toMatchObject({ code: 'ENOENT' })
      await expect(readFile(outsideSentinel, 'utf8')).resolves.toBe('preserve\n')
    } finally {
      await removeTemporaryRoot(root)
      await removeTemporaryRoot(outside)
    }
  })
})
