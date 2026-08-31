import { SecurityAssuranceTestComposition } from './support/security-assurance-test-composition.ts'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { Context } from '@deepseek-ai/cordis'
import { afterEach, describe, expect, it } from 'vitest'
import type {
  InvocationOptions,
  SecurityInvocation,
  SecurityResult,
} from '../src/contracts.ts'
import {
  createAnalyzerConformanceFixtureV1,
  createReferenceAnalyzerFactoryV1,
} from '../src/conformance.ts'

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

type UniformRuntimeOperation = (
  invocation: SecurityInvocation,
  request: unknown,
  options?: InvocationOptions,
) => Promise<SecurityResult<unknown>>

afterEach(async () => {
  await Promise.all(contexts.splice(0).map(ctx => ctx.fiber.dispose()))
  await Promise.all(temporaryRoots.splice(0).map(path => rm(path, { recursive: true, force: true })))
})

describe('ADR 0256: runtime operations are asynchronous Security Results', () => {
  it('returns a Promise envelope immediately from every runtime operation', async () => {
    const dshHome = await mkdtemp(join(tmpdir(), 'dsh-security-adr-0256-home-'))
    temporaryRoots.push(dshHome)
    const ctx = new Context()
    contexts.push(ctx)
    await ctx.plugin(SecurityAssuranceTestComposition, { dshHome })
    await ctx.securityAssurance.whenReady()
    const invalidInvocation = {} as SecurityInvocation

    for (const name of runtimeOperations) {
      const operation = ctx.securityAssurance[name] as unknown as UniformRuntimeOperation
      const pending = operation.call(ctx.securityAssurance, invalidInvocation, {})

      expect(pending, name).toBeInstanceOf(Promise)
      await expect(pending, name).resolves.toMatchObject({
        ok: false,
        error: { code: 'UNAUTHORIZED' },
      })
    }
  })

  it('keeps local Analyzer registration synchronous and disposer-owned', async () => {
    const dshHome = await mkdtemp(join(tmpdir(), 'dsh-security-adr-0256-home-'))
    temporaryRoots.push(dshHome)
    const ctx = new Context()
    contexts.push(ctx)
    await ctx.plugin(SecurityAssuranceTestComposition, { dshHome })
    await ctx.securityAssurance.whenReady()
    const fixture = createAnalyzerConformanceFixtureV1()

    const disposer = ctx.securityAssurance.registerAnalyzer(
      fixture.descriptor,
      createReferenceAnalyzerFactoryV1(),
    )

    expect(typeof disposer).toBe('function')
    expect(disposer).not.toBeInstanceOf(Promise)
    disposer()
  })
})
