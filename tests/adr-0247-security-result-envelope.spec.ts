import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { Context } from '@deepseek-ai/cordis'
import { afterEach, describe, expect, it } from 'vitest'
import SecurityAssuranceService from '../src/index.js'
import { referenceHostInvocation } from './support/reference-host.js'

const temporaryRoots: string[] = []
const contexts: Context[] = []

afterEach(async () => {
  await Promise.all(contexts.splice(0).map(ctx => ctx.fiber.dispose()))
  await Promise.all(temporaryRoots.splice(0).map(path => rm(path, { recursive: true, force: true })))
})

describe('ADR 0247: Public operations return one typed Security Result envelope', () => {

  describe('Expected failures return typed errors, not exceptions', () => {
    it('UNAUTHORIZED for missing authority returns SecurityResult', async () => {
      const dshHome = await mkdtemp(join(tmpdir(), 'dsh-security-adr-0247-home-'))
      temporaryRoots.push(dshHome)
      const ctx = new Context()
      contexts.push(ctx)
      await ctx.plugin(SecurityAssuranceService, { dshHome })
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
      await ctx.plugin(SecurityAssuranceService, { dshHome })
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
      await ctx.plugin(SecurityAssuranceService, { dshHome })
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
      await ctx.plugin(SecurityAssuranceService, { dshHome })
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
      await ctx.plugin(SecurityAssuranceService, { dshHome })
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
      await ctx.plugin(SecurityAssuranceService, { dshHome })
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
      await ctx.plugin(SecurityAssuranceService, { dshHome })
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
      await ctx.plugin(SecurityAssuranceService, { dshHome })
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
      await ctx.plugin(SecurityAssuranceService, { dshHome })
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
      await ctx.plugin(SecurityAssuranceService, { dshHome })
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
      await ctx.plugin(SecurityAssuranceService, { dshHome })
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
      await ctx.plugin(SecurityAssuranceService, { dshHome })
      await ctx.securityAssurance.whenReady()

      const invocation = referenceHostInvocation(ctx.securityAssurance, 'test-principal')
      const result = await ctx.securityAssurance.listRepositories(invocation, { schemaVersion: 1 })

      expect(result).toHaveProperty('ok')
      expect(typeof result.ok).toBe('boolean')
    })

    it('listAssessments returns SecurityResult', async () => {
      const dshHome = await mkdtemp(join(tmpdir(), 'dsh-security-adr-0247-home-'))
      temporaryRoots.push(dshHome)
      const ctx = new Context()
      contexts.push(ctx)
      await ctx.plugin(SecurityAssuranceService, { dshHome })
      await ctx.securityAssurance.whenReady()

      const invocation = referenceHostInvocation(ctx.securityAssurance, 'test-principal')
      const result = await ctx.securityAssurance.listAssessments(invocation, { schemaVersion: 1 })

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
      await ctx.plugin(SecurityAssuranceService, { dshHome })
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
      await ctx.plugin(SecurityAssuranceService, { dshHome })
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
