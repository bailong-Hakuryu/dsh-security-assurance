import { Readable } from 'node:stream'
import type {
  SubprocessHandle,
  SubprocessOutcome,
  SubprocessRuntime,
  SubprocessSpawnSpec,
} from '@deepseek-ai/dsh-subprocess'
import { describe, expect, it, vi } from 'vitest'
import { runGit, SubjectFreezeError } from '../src/internal/subject-freeze.ts'

const gitExecutable = process.platform === 'win32' ? 'C:\\Git\\bin\\git.exe' : '/usr/bin/git'

function runtimeFor(
  chunks: readonly Buffer[],
  outcome: SubprocessOutcome = { exitCode: 0, signal: null },
): {
  readonly runtime: SubprocessRuntime
  readonly spawn: ReturnType<typeof vi.fn<(spec: SubprocessSpawnSpec) => SubprocessHandle>>
  readonly terminate: ReturnType<typeof vi.fn<() => void>>
  readonly waitForExit: ReturnType<typeof vi.fn<() => Promise<boolean>>>
} {
  const terminate = vi.fn<() => void>()
  const waitForExit = vi.fn(async () => true)
  const spawn = vi.fn<(spec: SubprocessSpawnSpec) => SubprocessHandle>(() => ({
    pid: 42,
    stdin: undefined,
    stdout: Readable.from(chunks),
    stderr: undefined,
    collected: {},
    done: Promise.resolve(outcome),
    terminate,
    waitForExit,
  }))
  return {
    runtime: {
      resolveExecutable: vi.fn(async () => gitExecutable),
      spawn,
    } as unknown as SubprocessRuntime,
    spawn,
    terminate,
    waitForExit,
  }
}

describe('Subject Freeze managed subprocess boundary', () => {
  it('uses the Host subprocess provider without a shell and preserves binary stdout', async () => {
    const expected = Buffer.from([0, 1, 2, 255, 0, 127])
    const fixture = runtimeFor([expected.subarray(0, 3), expected.subarray(3)])

    const actual = await runGit(fixture.runtime, 'D:\\repository', ['cat-file', 'blob', 'object-id'])

    expect(actual).toEqual(expected)
    expect(fixture.spawn).toHaveBeenCalledOnce()
    expect(fixture.spawn.mock.calls[0]?.[0]).toMatchObject({
      argv: [
        gitExecutable,
        '-c',
        'core.fsmonitor=false',
        '--no-replace-objects',
        '--literal-pathspecs',
        'cat-file',
        'blob',
        'object-id',
      ],
      cwd: 'D:\\repository',
      stdio: {
        stdin: 'ignore',
        stdout: 'pipe',
        stderr: { maxBytes: 8_192 },
      },
      graceMs: 1_000,
      env: {
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
      },
    })
  })

  it('maps a non-zero Git exit after joining the managed process tree', async () => {
    const fixture = runtimeFor([], { exitCode: 128, signal: null })

    await expect(runGit(fixture.runtime, 'D:\\repository', ['rev-parse', 'HEAD'])).rejects.toMatchObject({
      code: 'invalid_subject',
      message: 'Git could not resolve the exact Subject identity',
    } satisfies Partial<SubjectFreezeError>)
    expect(fixture.terminate).toHaveBeenCalledOnce()
    expect(fixture.waitForExit).toHaveBeenCalledOnce()
  })

  it('maps provider resolution and spawn failures without leaking their detail', async () => {
    const resolutionFailure = {
      resolveExecutable: vi.fn(async () => { throw new Error('sensitive provider detail') }),
      spawn: vi.fn(),
    } as unknown as SubprocessRuntime
    await expect(runGit(resolutionFailure, 'D:\\repository', ['status'])).rejects.toMatchObject({
      code: 'invalid_subject',
      message: 'Git is unavailable',
    } satisfies Partial<SubjectFreezeError>)

    const spawnFailure = {
      resolveExecutable: vi.fn(async () => gitExecutable),
      spawn: vi.fn(() => { throw new Error('sensitive spawn detail') }),
    } as unknown as SubprocessRuntime
    await expect(runGit(spawnFailure, 'D:\\repository', ['status'])).rejects.toMatchObject({
      code: 'invalid_subject',
      message: 'Git is unavailable',
    } satisfies Partial<SubjectFreezeError>)
  })

  it('terminates and joins the process tree before reporting the output ceiling', async () => {
    const mebibyte = Buffer.alloc(1024 * 1024)
    const fixture = runtimeFor(Array.from({ length: 81 }, () => mebibyte))

    await expect(runGit(fixture.runtime, 'D:\\repository', ['cat-file', 'blob', 'large'])).rejects.toMatchObject({
      code: 'resource_limit',
    } satisfies Partial<SubjectFreezeError>)
    expect(fixture.terminate).toHaveBeenCalled()
    expect(fixture.waitForExit).toHaveBeenCalledOnce()
  })

  it('reports cancellation before consulting the provider', async () => {
    const controller = new AbortController()
    controller.abort()
    const fixture = runtimeFor([])

    await expect(runGit(fixture.runtime, 'D:\\repository', ['status'], controller.signal)).rejects.toMatchObject({
      code: 'canceled',
    } satisfies Partial<SubjectFreezeError>)
    expect(fixture.spawn).not.toHaveBeenCalled()
  })
})
