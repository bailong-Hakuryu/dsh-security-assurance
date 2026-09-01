import { SecurityAssuranceTestComposition } from './support/security-assurance-test-composition.ts'
import { removeTemporaryRoots } from './support/remove-temporary-root.ts'
import { mkdtemp } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { Context } from '@deepseek-ai/cordis'
import { afterEach, describe, expect, it } from 'vitest'
import SecurityAssuranceControlPlaneProvider from '../src/control-plane-provider.ts'
import {
  createAnalyzerConformanceFixtureV1,
  createReferenceAnalyzerFactoryV1,
} from '../src/conformance.ts'
import SecurityAssuranceTools from '../src/tools.ts'
import SecurityAssuranceWorkbenchRemote from '../src/workbench-remote.ts'

const temporaryRoots: string[] = []
const contexts: Context[] = []

afterEach(async () => {
  await Promise.all(contexts.splice(0).map(ctx => ctx.fiber.dispose()))
  await removeTemporaryRoots(temporaryRoots)
})

describe('ADR 0258: Analyzer registration is local composition and effect-owned', () => {
  it('keeps registration absent from Remote, tools, and Control Plane surfaces', () => {
    expect('registerAnalyzer' in SecurityAssuranceWorkbenchRemote.prototype).toBe(false)
    expect('registerAnalyzer' in SecurityAssuranceTools).toBe(false)
    expect('registerAnalyzer' in SecurityAssuranceControlPlaneProvider).toBe(false)
  })

  it('validates registration synchronously before returning a disposer', async () => {
    const dshHome = await mkdtemp(join(tmpdir(), 'dsh-security-adr-0258-home-'))
    temporaryRoots.push(dshHome)
    const ctx = new Context()
    contexts.push(ctx)
    await ctx.plugin(SecurityAssuranceTestComposition, { dshHome })
    await ctx.securityAssurance.whenReady()
    const fixture = createAnalyzerConformanceFixtureV1()
    const factory = createReferenceAnalyzerFactoryV1()

    expect(() => ctx.securityAssurance.registerAnalyzer(
      { ...fixture.descriptor, schemaVersion: 2 } as never,
      factory,
    )).toThrow()
    expect(() => ctx.securityAssurance.registerAnalyzer(
      fixture.descriptor,
      undefined as never,
    )).toThrow('Analyzer Factory must be callable')

    const disposer = ctx.securityAssurance.registerAnalyzer(fixture.descriptor, factory)
    expect(typeof disposer).toBe('function')
    expect(() => ctx.securityAssurance.registerAnalyzer(fixture.descriptor, factory)).toThrow(
      `Analyzer '${fixture.descriptor.analyzerId}@${fixture.descriptor.analyzerVersion}' is already registered`,
    )
    disposer()
    disposer()
  })

  it('revokes one contribution automatically when its Cordis Fiber is disposed', async () => {
    const dshHome = await mkdtemp(join(tmpdir(), 'dsh-security-adr-0258-home-'))
    temporaryRoots.push(dshHome)
    const ctx = new Context()
    contexts.push(ctx)
    await ctx.plugin(SecurityAssuranceTestComposition, { dshHome })
    await ctx.securityAssurance.whenReady()
    const fixture = createAnalyzerConformanceFixtureV1()
    const factory = createReferenceAnalyzerFactoryV1()
    const contributor = Object.assign((composition: Context) => {
      composition.effect(() => composition.securityAssurance.registerAnalyzer(
        fixture.descriptor,
        factory,
      ))
    }, { inject: ['securityAssurance'] })

    const contributorFiber = await ctx.plugin(contributor)
    expect(() => ctx.securityAssurance.registerAnalyzer(fixture.descriptor, factory)).toThrow(
      `Analyzer '${fixture.descriptor.analyzerId}@${fixture.descriptor.analyzerVersion}' is already registered`,
    )

    await contributorFiber.dispose()

    const replacementDisposer = ctx.securityAssurance.registerAnalyzer(fixture.descriptor, factory)
    expect(typeof replacementDisposer).toBe('function')
    replacementDisposer()
  })
})
