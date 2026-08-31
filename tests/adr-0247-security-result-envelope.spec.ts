import { SecurityAssuranceTestComposition } from './support/security-assurance-test-composition.ts'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { Context } from '@deepseek-ai/cordis'
import { afterEach, describe, expect, it } from 'vitest'
import SecurityAssuranceService from '../src/index.js'
import {
  publicSecurityErrorSchema,
  type InvocationOptions,
  type SecurityInvocation,
  type SecurityResult,
} from '../src/contracts.js'
import { referenceHostInvocation } from './support/reference-host.js'

const temporaryRoots: string[] = []
const contexts: Context[] = []

const publicOperationNames = [
  'getHealth',
  'getCatalog',
  'registerRepository',
  'updateRepository',
  'disableRepository',
  'getRepository',
  'listRepositories',
  'startAssessment',
  'resumeAssessment',
  'cancelAssessment',
  'listAssessments',
  'getAssessment',
  'listFindings',
  'getFinding',
  'getEvidenceView',
  'recordRiskDecision',
  'waitForAssessmentRevision',
  'getBundleManifest',
  'getAssuranceSubmission',
  'requestExport',
  'getExport',
] as const satisfies readonly (keyof SecurityAssuranceService)[]

type PublicOperationName = typeof publicOperationNames[number]
type PublicOperationResult = {
  [Name in PublicOperationName]: Awaited<ReturnType<SecurityAssuranceService[Name]>>
}[PublicOperationName]
type AllOperationResultsUseEnvelope = [PublicOperationResult] extends [SecurityResult<unknown>]
  ? true
  : false
type UniformPublicOperation = (
  this: SecurityAssuranceService,
  invocation: SecurityInvocation,
  request: unknown,
  options?: InvocationOptions,
) => Promise<SecurityResult<unknown>>

const allOperationSignaturesUseEnvelope: AllOperationResultsUseEnvelope = true

afterEach(async () => {
  await Promise.all(contexts.splice(0).map(ctx => ctx.fiber.dispose()))
  await Promise.all(temporaryRoots.splice(0).map(path => rm(path, { recursive: true, force: true })))
})

describe('ADR 0247: Public operations return one typed Security Result envelope', () => {

  it('keeps the reviewed catalog of 21 operation signatures inside SecurityResult<T>', () => {
    expect(publicOperationNames).toHaveLength(21)
    expect(allOperationSignaturesUseEnvelope).toBe(true)
  })

  it('returns one validated UNAUTHORIZED envelope from every public operation', async () => {
    const dshHome = await mkdtemp(join(tmpdir(), 'dsh-security-adr-0247-home-'))
    temporaryRoots.push(dshHome)
    const ctx = new Context()
    contexts.push(ctx)
    await ctx.plugin(SecurityAssuranceTestComposition, { dshHome })
    await ctx.securityAssurance.whenReady()
    const invalidInvocation = {} as SecurityInvocation

    for (const name of publicOperationNames) {
      const invoke = ctx.securityAssurance[name] as unknown as UniformPublicOperation
      const result = await invoke.call(ctx.securityAssurance, invalidInvocation, {})

      expect(result, name).toMatchObject({
        ok: false,
        error: {
          schemaVersion: 1,
          code: 'UNAUTHORIZED',
          retryable: false,
        },
      })
      if (!result.ok) {
        expect(publicSecurityErrorSchema.safeParse(result.error).success, name).toBe(true)
      }
    }
  })

  it('redacts unexpected failures at every public Service seam', async () => {
    const dshHome = await mkdtemp(join(tmpdir(), 'dsh-security-adr-0247-home-'))
    temporaryRoots.push(dshHome)
    const ctx = new Context()
    contexts.push(ctx)
    await ctx.plugin(SecurityAssuranceTestComposition, { dshHome })
    await ctx.securityAssurance.whenReady()
    const invocation = referenceHostInvocation(ctx.securityAssurance, 'adr-0247-principal')
    const hostileRequest = new Proxy({}, {
      get() {
        throw new Error('sensitive internal marker')
      },
      ownKeys() {
        throw new Error('sensitive internal marker')
      },
    })

    for (const name of publicOperationNames) {
      const invoke = ctx.securityAssurance[name] as unknown as UniformPublicOperation
      const result = await invoke.call(ctx.securityAssurance, invocation, hostileRequest)

      expect(result, name).toMatchObject({
        ok: false,
        error: {
          schemaVersion: 1,
          code: 'INTERNAL',
          retryable: true,
        },
      })
      if (!result.ok) {
        expect(result.error.message.length, name).toBeGreaterThan(0)
        expect(result.error.message, name).not.toContain('sensitive internal marker')
        expect(publicSecurityErrorSchema.safeParse(result.error).success, name).toBe(true)
      }
    }
  })

  describe('Expected failures return typed errors, not exceptions', () => {
    it('UNAUTHORIZED for missing authority returns SecurityResult', async () => {
      const dshHome = await mkdtemp(join(tmpdir(), 'dsh-security-adr-0247-home-'))
      temporaryRoots.push(dshHome)
      const ctx = new Context()
      contexts.push(ctx)
      await ctx.plugin(SecurityAssuranceTestComposition, { dshHome })
      await ctx.securityAssurance.whenReady()

      const invalidInvocation = {} as any

      const result = await ctx.securityAssurance.getHealth(invalidInvocation, { schemaVersion: 1 })

      expect(result.ok).toBe(false)
      if (!result.ok) {
        expect(result.error.code).toBe('UNAUTHORIZED')
        expect(result.error.message).toContain('not authorized')
        expect(result.error.retryable).toBe(false)
      }
    })

    it('INVALID_REQUEST for schema validation returns SecurityResult', async () => {
      const dshHome = await mkdtemp(join(tmpdir(), 'dsh-security-adr-0247-home-'))
      temporaryRoots.push(dshHome)
      const ctx = new Context()
      contexts.push(ctx)
      await ctx.plugin(SecurityAssuranceTestComposition, { dshHome })
      await ctx.securityAssurance.whenReady()

      const invocation = referenceHostInvocation(ctx.securityAssurance, 'test-principal')
      const result = await ctx.securityAssurance.getHealth(invocation, { schemaVersion: 999 } as any)

      expect(result.ok).toBe(false)
      if (!result.ok) {
        expect(result.error.code).toBe('INVALID_REQUEST')
        expect(result.error.message).toContain('schema')
        expect(result.error.retryable).toBe(false)
      }
    })

    it('NOT_FOUND for missing entity returns SecurityResult', async () => {
      const dshHome = await mkdtemp(join(tmpdir(), 'dsh-security-adr-0247-home-'))
      temporaryRoots.push(dshHome)
      const ctx = new Context()
      contexts.push(ctx)
      await ctx.plugin(SecurityAssuranceTestComposition, { dshHome })
      await ctx.securityAssurance.whenReady()

      const invocation = referenceHostInvocation(ctx.securityAssurance, 'test-principal')
      const result = await ctx.securityAssurance.getRepository(invocation, {
        schemaVersion: 1,
        repositoryId: 'repo-00000000-0000-4000-8000-000000000000' as any,
      })

      expect(result.ok).toBe(false)
      if (!result.ok) {
        expect(result.error.code).toBe('NOT_FOUND')
        expect(result.error.message).toContain('does not exist')
        expect(result.error.retryable).toBe(false)
      }
    })

    it('CANCELED for explicit cancellation returns SecurityResult', async () => {
      const dshHome = await mkdtemp(join(tmpdir(), 'dsh-security-adr-0247-home-'))
      temporaryRoots.push(dshHome)
      const ctx = new Context()
      contexts.push(ctx)
      await ctx.plugin(SecurityAssuranceTestComposition, { dshHome })
      await ctx.securityAssurance.whenReady()

      const invocation = referenceHostInvocation(ctx.securityAssurance, 'test-principal')
      const abortController = new AbortController()
      abortController.abort()

      const result = await ctx.securityAssurance.getHealth(
        invocation,
        { schemaVersion: 1 },
        { signal: abortController.signal },
      )

      expect(result.ok).toBe(false)
      if (!result.ok) {
        expect(result.error.code).toBe('CANCELED')
        expect(result.error.message).toContain('canceled')
        expect(result.error.retryable).toBe(false)
      }
    })

    it('DEADLINE_EXCEEDED for timeout returns SecurityResult', async () => {
      const dshHome = await mkdtemp(join(tmpdir(), 'dsh-security-adr-0247-home-'))
      temporaryRoots.push(dshHome)
      const ctx = new Context()
      contexts.push(ctx)
      await ctx.plugin(SecurityAssuranceTestComposition, { dshHome })
      await ctx.securityAssurance.whenReady()

      const invocation = referenceHostInvocation(ctx.securityAssurance, 'test-principal')
      const result = await ctx.securityAssurance.getHealth(
        invocation,
        { schemaVersion: 1 },
        { deadlineEpochMs: Date.now() - 1000 },
      )

      expect(result.ok).toBe(false)
      if (!result.ok) {
        expect(result.error.code).toBe('DEADLINE_EXCEEDED')
        expect(result.error.message).toContain('deadline')
        expect(result.error.retryable).toBe(true)
      }
    })
  })

  describe('Consistent error code semantics', () => {
    it('UNAUTHORIZED errors are not retryable', async () => {
      const dshHome = await mkdtemp(join(tmpdir(), 'dsh-security-adr-0247-home-'))
      temporaryRoots.push(dshHome)
      const ctx = new Context()
      contexts.push(ctx)
      await ctx.plugin(SecurityAssuranceTestComposition, { dshHome })
      await ctx.securityAssurance.whenReady()

      const invalidInvocation = {} as any
      const result = await ctx.securityAssurance.getHealth(invalidInvocation, { schemaVersion: 1 })

      expect(result.ok).toBe(false)
      if (!result.ok) {
        expect(result.error.code).toBe('UNAUTHORIZED')
        expect(result.error.retryable).toBe(false)
      }
    })

    it('INVALID_REQUEST errors are not retryable', async () => {
      const dshHome = await mkdtemp(join(tmpdir(), 'dsh-security-adr-0247-home-'))
      temporaryRoots.push(dshHome)
      const ctx = new Context()
      contexts.push(ctx)
      await ctx.plugin(SecurityAssuranceTestComposition, { dshHome })
      await ctx.securityAssurance.whenReady()

      const invocation = referenceHostInvocation(ctx.securityAssurance, 'test-principal')
      const result = await ctx.securityAssurance.getHealth(invocation, { schemaVersion: 999 } as any)

      expect(result.ok).toBe(false)
      if (!result.ok) {
        expect(result.error.code).toBe('INVALID_REQUEST')
        expect(result.error.retryable).toBe(false)
      }
    })

    it('NOT_FOUND errors are not retryable', async () => {
      const dshHome = await mkdtemp(join(tmpdir(), 'dsh-security-adr-0247-home-'))
      temporaryRoots.push(dshHome)
      const ctx = new Context()
      contexts.push(ctx)
      await ctx.plugin(SecurityAssuranceTestComposition, { dshHome })
      await ctx.securityAssurance.whenReady()

      const invocation = referenceHostInvocation(ctx.securityAssurance, 'test-principal')
      const result = await ctx.securityAssurance.getRepository(invocation, {
        schemaVersion: 1,
        repositoryId: 'repo-00000000-0000-4000-8000-000000000000' as any,
      })

      expect(result.ok).toBe(false)
      if (!result.ok) {
        expect(result.error.code).toBe('NOT_FOUND')
        expect(result.error.retryable).toBe(false)
      }
    })

    it('DEADLINE_EXCEEDED errors are retryable', async () => {
      const dshHome = await mkdtemp(join(tmpdir(), 'dsh-security-adr-0247-home-'))
      temporaryRoots.push(dshHome)
      const ctx = new Context()
      contexts.push(ctx)
      await ctx.plugin(SecurityAssuranceTestComposition, { dshHome })
      await ctx.securityAssurance.whenReady()

      const invocation = referenceHostInvocation(ctx.securityAssurance, 'test-principal')
      const result = await ctx.securityAssurance.getHealth(
        invocation,
        { schemaVersion: 1 },
        { deadlineEpochMs: Date.now() - 1000 },
      )

      expect(result.ok).toBe(false)
      if (!result.ok) {
        expect(result.error.code).toBe('DEADLINE_EXCEEDED')
        expect(result.error.retryable).toBe(true)
      }
    })
  })

  describe('All operations use SecurityResult envelope', () => {
    it('getHealth returns SecurityResult', async () => {
      const dshHome = await mkdtemp(join(tmpdir(), 'dsh-security-adr-0247-home-'))
      temporaryRoots.push(dshHome)
      const ctx = new Context()
      contexts.push(ctx)
      await ctx.plugin(SecurityAssuranceTestComposition, { dshHome })
      await ctx.securityAssurance.whenReady()

      const invocation = referenceHostInvocation(ctx.securityAssurance, 'test-principal')
      const result = await ctx.securityAssurance.getHealth(invocation, { schemaVersion: 1 })

      expect(result).toHaveProperty('ok')
      expect(typeof result.ok).toBe('boolean')
    })

    it('getCatalog returns SecurityResult', async () => {
      const dshHome = await mkdtemp(join(tmpdir(), 'dsh-security-adr-0247-home-'))
      temporaryRoots.push(dshHome)
      const ctx = new Context()
      contexts.push(ctx)
      await ctx.plugin(SecurityAssuranceTestComposition, { dshHome })
      await ctx.securityAssurance.whenReady()

      const invocation = referenceHostInvocation(ctx.securityAssurance, 'test-principal')
      const result = await ctx.securityAssurance.getCatalog(invocation, { schemaVersion: 1 })

      expect(result).toHaveProperty('ok')
      expect(typeof result.ok).toBe('boolean')
    })

    it('listRepositories returns SecurityResult', async () => {
      const dshHome = await mkdtemp(join(tmpdir(), 'dsh-security-adr-0247-home-'))
      temporaryRoots.push(dshHome)
      const ctx = new Context()
      contexts.push(ctx)
      await ctx.plugin(SecurityAssuranceTestComposition, { dshHome })
      await ctx.securityAssurance.whenReady()

      const invocation = referenceHostInvocation(ctx.securityAssurance, 'test-principal')
      const result = await ctx.securityAssurance.listRepositories(invocation, { schemaVersion: 1, limit: 100 })

      expect(result).toHaveProperty('ok')
      expect(typeof result.ok).toBe('boolean')
    })

    it('listAssessments returns SecurityResult', async () => {
      const dshHome = await mkdtemp(join(tmpdir(), 'dsh-security-adr-0247-home-'))
      temporaryRoots.push(dshHome)
      const ctx = new Context()
      contexts.push(ctx)
      await ctx.plugin(SecurityAssuranceTestComposition, { dshHome })
      await ctx.securityAssurance.whenReady()

      const invocation = referenceHostInvocation(ctx.securityAssurance, 'test-principal')
      const result = await ctx.securityAssurance.listAssessments(invocation, { schemaVersion: 1, limit: 100 })

      expect(result).toHaveProperty('ok')
      expect(typeof result.ok).toBe('boolean')
    })
  })

  describe('Success results contain value, failure results contain error', () => {
    it('successful operation has ok:true and value', async () => {
      const dshHome = await mkdtemp(join(tmpdir(), 'dsh-security-adr-0247-home-'))
      temporaryRoots.push(dshHome)
      const ctx = new Context()
      contexts.push(ctx)
      await ctx.plugin(SecurityAssuranceTestComposition, { dshHome })
      await ctx.securityAssurance.whenReady()

      const invocation = referenceHostInvocation(ctx.securityAssurance, 'test-principal')
      const result = await ctx.securityAssurance.getHealth(invocation, { schemaVersion: 1 })

      expect(result.ok).toBe(true)
      if (result.ok) {
        expect(result.value).toBeDefined()
        expect(result.value.schemaVersion).toBe(1)
      }
    })

    it('failed operation has ok:false and error', async () => {
      const dshHome = await mkdtemp(join(tmpdir(), 'dsh-security-adr-0247-home-'))
      temporaryRoots.push(dshHome)
      const ctx = new Context()
      contexts.push(ctx)
      await ctx.plugin(SecurityAssuranceTestComposition, { dshHome })
      await ctx.securityAssurance.whenReady()

      const invocation = referenceHostInvocation(ctx.securityAssurance, 'test-principal')
      const result = await ctx.securityAssurance.getHealth(invocation, { schemaVersion: 999 } as any)

      expect(result.ok).toBe(false)
      if (!result.ok) {
        expect(result.error).toBeDefined()
        expect(result.error.code).toBeDefined()
        expect(result.error.message).toBeDefined()
        expect(typeof result.error.retryable).toBe('boolean')
      }
    })
  })
})
