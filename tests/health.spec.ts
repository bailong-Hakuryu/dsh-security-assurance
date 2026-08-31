import { SecurityAssuranceTestComposition } from './support/security-assurance-test-composition.ts'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { Context } from '@deepseek-ai/cordis'
import { afterEach, describe, expect, it } from 'vitest'
import { runtimeHealthSnapshotSchema } from '../src/index.ts'
import type { GetHealthRequest, SecurityInvocation } from '../src/index.ts'
import { referenceHostInvocation } from './support/reference-host.ts'

const liveContexts: Context[] = []
const temporaryHomes: string[] = []

afterEach(async () => {
  await Promise.all(liveContexts.splice(0).map(async context => context.fiber.dispose()))
  await Promise.all(temporaryHomes.splice(0).map(path => rm(path, { recursive: true, force: true })))
})

async function harness() {
  const dshHome = await mkdtemp(join(tmpdir(), 'dsh-security-health-home-'))
  temporaryHomes.push(dshHome)
  const ctx = new Context()
  liveContexts.push(ctx)
  const fiber = ctx.plugin(SecurityAssuranceTestComposition, { dshHome })
  await fiber
  return {
    ctx,
    fiber,
    invocation: referenceHostInvocation(ctx.securityAssurance),
  }
}

describe('SecurityAssuranceService health tracer', () => {
  it('mounts through Cordis and returns READY health to a Resolver-issued invocation', async () => {
    const { ctx, fiber, invocation } = await harness()
    const result = await ctx.securityAssurance.getHealth(invocation, { schemaVersion: 1 })

    expect(ctx.reflect.get('securityAssurance') !== undefined).toBe(true)
    expect(result.ok).toBe(true)
    if (!result.ok) throw new Error(`expected health success, received ${result.error.code}`)
    expect(runtimeHealthSnapshotSchema.parse(result.value)).toMatchObject({
      schemaVersion: 1,
      product: {
        name: 'dsh-security-assurance',
        version: '0.1.0-rc.10',
      },
      compatibility: {
        targetHarnessVersion: '0.1.2-alpha.1',
        requiredNodeRange: '^22.19.0 || >=24.0.0',
      },
      state: 'READY',
    })

    await fiber.dispose()
    expect(ctx.reflect.get('securityAssurance')).toBeUndefined()
  })

  it('rejects absent, foreign, copied, and deserialized Invocations', async () => {
    const { ctx, invocation } = await harness()
    const forged = [
      undefined,
      Object.freeze({}),
      { ...invocation },
      JSON.parse(JSON.stringify(invocation)) as unknown,
    ]

    for (const candidate of forged) {
      const result = await ctx.securityAssurance.getHealth(
        candidate as SecurityInvocation,
        { schemaVersion: 1 },
      )
      expect(result).toMatchObject({
        ok: false,
        error: {
          schemaVersion: 1,
          code: 'UNAUTHORIZED',
          retryable: false,
        },
      })
      if (result.ok) throw new Error('expected unauthorized result')
      expect(result.error.message).not.toContain('reference-host-operator')
    }
  })

  it('rejects malformed and authority-bearing request fields', async () => {
    const { ctx, invocation } = await harness()
    const malformed = [
      {},
      { schemaVersion: 2 },
      { schemaVersion: 1, principalId: 'self-declared-admin' },
    ]

    for (const request of malformed) {
      const result = await ctx.securityAssurance.getHealth(
        invocation,
        request as unknown as GetHealthRequest,
      )
      expect(result).toMatchObject({ ok: false, error: { code: 'INVALID_REQUEST' } })
    }
  })

  it('honors process-local cancellation and bounded deadlines', async () => {
    const { ctx, invocation } = await harness()
    const controller = new AbortController()
    controller.abort()

    await expect(ctx.securityAssurance.getHealth(
      invocation,
      { schemaVersion: 1 },
      { signal: controller.signal },
    )).resolves.toMatchObject({ ok: false, error: { code: 'CANCELED' } })

    await expect(ctx.securityAssurance.getHealth(
      invocation,
      { schemaVersion: 1 },
      { deadlineEpochMs: 0 },
    )).resolves.toMatchObject({ ok: false, error: { code: 'DEADLINE_EXCEEDED', retryable: true } })

    await expect(ctx.securityAssurance.getHealth(
      invocation,
      { schemaVersion: 1 },
      { deadlineEpochMs: Number.NaN },
    )).resolves.toMatchObject({ ok: false, error: { code: 'INVALID_REQUEST' } })
  })

  it('redacts unexpected failures instead of leaking raw exceptions', async () => {
    const { ctx, invocation } = await harness()
    const hostileRequest = new Proxy({}, {
      ownKeys() {
        throw new Error('sensitive internal marker')
      },
    })

    const result = await ctx.securityAssurance.getHealth(
      invocation,
      hostileRequest as GetHealthRequest,
    )

    expect(result).toMatchObject({ ok: false, error: { code: 'INTERNAL', retryable: true } })
    if (result.ok) throw new Error('expected redacted internal result')
    expect(result.error.message).not.toContain('sensitive internal marker')
  })

  it('returns recursively immutable public values', async () => {
    const { ctx, invocation } = await harness()
    const result = await ctx.securityAssurance.getHealth(invocation, { schemaVersion: 1 })
    if (!result.ok) throw new Error(`expected health success, received ${result.error.code}`)

    expect(Object.isFrozen(result)).toBe(true)
    expect(Object.isFrozen(result.value)).toBe(true)
    expect(Object.isFrozen(result.value.compatibility)).toBe(true)
    expect(Object.isFrozen(result.value.checks)).toBe(true)
    expect(Object.isFrozen(result.value.checks[0])).toBe(true)
  })
})
