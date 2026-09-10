import { execFile } from 'node:child_process'
import { mkdtemp, symlink } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { promisify } from 'node:util'
import { describe, expect, it } from 'vitest'

const execute = promisify(execFile)
const sourceDirectory = fileURLToPath(new URL('../src', import.meta.url))
const entries = [
  'release-bind.ts',
  'release-collect.ts',
  'release-assemble.ts',
  'release-qualify.ts',
  'release-handoff.ts',
] as const

describe('packaged release CLI entry detection', () => {
  it.each(entries)('executes %s through a linked package path', async entry => {
    const root = await mkdtemp(join(tmpdir(), 'dsh-release-cli-entry-'))
    const linkedSource = join(root, 'linked-source')
    await symlink(
      sourceDirectory,
      linkedSource,
      process.platform === 'win32' ? 'junction' : 'dir',
    )

    await expect(execute(process.execPath, [
      '--experimental-strip-types',
      join(linkedSource, entry),
    ], { windowsHide: true })).rejects.toMatchObject({
      code: 1,
      stderr: expect.stringContaining('INVALID_ARGUMENTS'),
    })
  })
})
