import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { Context } from '@deepseek-ai/cordis'
import { afterEach, describe, expect, it } from 'vitest'
import SecurityAssuranceService from '../src/index.ts'
import type {
  InvocationOptions,
  SecurityInvocation,
  SecurityResult,
} from '../src/contracts.ts'
import { referenceHostInvocation } from './support/reference-host.ts'

const temporaryRoots: string[] = []
const contexts: Context[] = []

const runtimeOperations = [
  'getHealth',
  'getCatalog',
  'registerRepository',
  'updateRepository',
  'disableRepository',
  'getRepository',
  'listRepositories',
  'startAssessment',
  'getAssessment',
  'listAssessments',
  'waitForAssessmentRevision',
  'resumeAssessment',
  'cancelAssessment',
  'listFindings',
  'getFinding',
  'getEvidenceView',
  'recordRiskDecision',
  'getBundleManifest',
  'getAssuranceSubmission',
  'requestExport',
  'getExport',
] as const

type RuntimeOperationName = typeof runtimeOperations[number]
type HasSeparatedInvocation<Name extends RuntimeOperationName> =
  SecurityAssuranceService[Name] extends (
    invocation: SecurityInvocation,
    request: infer Request,
    options?: InvocationOptions,
  ) => Promise<SecurityResult<unknown>>
    ? Request extends { readonly schemaVersion: number } ? true : false
    : false
type AllOperationsSeparateInvocation = [{
  [Name in RuntimeOperationName]: HasSeparatedInvocation<Name>
}[RuntimeOperationName]] extends [true] ? true : false
type ExactInvocationOptionKeys = [keyof InvocationOptions] extends ['signal' | 'deadlineEpochMs']
  ? ['signal' | 'deadlineEpochMs'] extends [keyof InvocationOptions] ? true : false
  : false

const allOperationsSeparateInvocation: AllOperationsSeparateInvocation = true
const exactInvocationOptionKeys: ExactInvocationOptionKeys = true

afterEach(async () => {
  await Promise.all(contexts.splice(0).map(ctx => ctx.fiber.dispose()))
  await Promise.all(temporaryRoots.splice(0).map(path => rm(path, { recursive: true, force: true })))
})

describe('ADR 0257: Invocation, Request, and local options are separate', () => {
  it('keeps all runtime signatures and local option keys structurally separate', () => {
    expect(allOperationsSeparateInvocation).toBe(true)
    expect(exactInvocationOptionKeys).toBe(true)
  })

  it('rejects authority and local-capability fields injected into a Request DTO', async () => {
    const dshHome = await mkdtemp(join(tmpdir(), 'dsh-security-adr-0257-home-'))
    temporaryRoots.push(dshHome)
    const ctx = new Context()
    contexts.push(ctx)
    await ctx.plugin(SecurityAssuranceService, { dshHome })
    await ctx.securityAssurance.whenReady()
    const invocation = referenceHostInvocation(ctx.securityAssurance, 'adr-0257-principal')
    const controller = new AbortController()

    for (const request of [
      { schemaVersion: 1, principalId: 'forged-principal' },
      { schemaVersion: 1, permissions: ['risk:break-glass'] },
      { schemaVersion: 1, deadlineEpochMs: Date.now() + 1_000 },
      { schemaVersion: 1, signal: controller.signal },
      { schemaVersion: 1, headers: { authorization: 'Bearer must-not-be-authority' } },
    ]) {
      await expect(ctx.securityAssurance.getHealth(invocation, request as never)).resolves.toMatchObject({
        ok: false,
        error: { code: 'INVALID_REQUEST' },
      })
    }
  })

  it('maps process-local cancellation and bounded deadlines without serializing them', async () => {
    const dshHome = await mkdtemp(join(tmpdir(), 'dsh-security-adr-0257-home-'))
    temporaryRoots.push(dshHome)
    const ctx = new Context()
    contexts.push(ctx)
    await ctx.plugin(SecurityAssuranceService, { dshHome })
    await ctx.securityAssurance.whenReady()
    const invocation = referenceHostInvocation(ctx.securityAssurance, 'adr-0257-principal')
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
      { deadlineEpochMs: Date.now() - 1 },
    )).resolves.toMatchObject({ ok: false, error: { code: 'DEADLINE_EXCEEDED' } })

    await expect(ctx.securityAssurance.getHealth(
      invocation,
      { schemaVersion: 1 },
      { deadlineEpochMs: Number.NaN },
    )).resolves.toMatchObject({ ok: false, error: { code: 'INVALID_REQUEST' } })
  })
})
