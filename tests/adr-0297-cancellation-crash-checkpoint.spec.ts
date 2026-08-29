import { readFile } from 'node:fs/promises'
import { join } from 'node:path'
import { describe, expect, it, vi } from 'vitest'
import {
  installControlPlaneCancellationCrashCheckpoint,
  reachControlPlaneCancellationCrashCheckpoint,
} from '../src/internal/control-plane-cancellation-crash-checkpoint.ts'

describe('ADR 0297 cancellation Crash Checkpoint preserves the exact Assessment', () => {
  it('installs one package-private non-enumerable checkpoint and emits a frozen exact identity', async () => {
    const owner = {}
    const checkpoint = vi.fn()
    const dispose = installControlPlaneCancellationCrashCheckpoint(owner, checkpoint)

    expect(Object.keys(owner)).toEqual([])
    expect(() => installControlPlaneCancellationCrashCheckpoint(owner, vi.fn())).toThrow(
      'already installed',
    )
    await reachControlPlaneCancellationCrashCheckpoint(
      owner,
      'after_assessment_canceled_before_provider_outcome',
      'asm-00000000-0000-0000-0000-000000000297',
    )
    expect(checkpoint).toHaveBeenCalledWith({
      name: 'after_assessment_canceled_before_provider_outcome',
      assessmentId: 'asm-00000000-0000-0000-0000-000000000297',
    })
    expect(Object.isFrozen(checkpoint.mock.calls[0]?.[0])).toBe(true)

    dispose()
    await reachControlPlaneCancellationCrashCheckpoint(
      owner,
      'after_assessment_canceled_before_provider_outcome',
      'asm-00000000-0000-0000-0000-000000000297',
    )
    expect(checkpoint).toHaveBeenCalledOnce()
  })

  it('reaches the checkpoint only after CANCELED verification and before returning proof', async () => {
    const source = await readFile(join(import.meta.dirname, '..', 'src', 'index.ts'), 'utf8')
    const start = source.indexOf('  private async cancelControlPlaneAssessment(')
    const end = source.indexOf('  private admitsMutations(', start)
    const cancellation = source.slice(start, end)
    const verify = cancellation.indexOf("terminal.value.state !== 'CANCELED'")
    const checkpoint = cancellation.indexOf("'after_assessment_canceled_before_provider_outcome'")
    const outcome = cancellation.indexOf("kind: 'EXTERNAL_ASSESSMENT_CANCELED'", checkpoint)

    expect(verify).toBeGreaterThan(-1)
    expect(checkpoint).toBeGreaterThan(verify)
    expect(outcome).toBeGreaterThan(checkpoint)

    const packageJson = JSON.parse(await readFile(
      join(import.meta.dirname, '..', 'package.json'),
      'utf8',
    )) as { readonly exports?: Record<string, unknown> }
    expect(Object.keys(packageJson.exports ?? {})).not.toContain(
      './internal/control-plane-cancellation-crash-checkpoint',
    )
  })
})
