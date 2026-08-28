import { execFile } from 'node:child_process'
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { promisify } from 'node:util'
import { Context } from '@deepseek-ai/cordis'
import type { Agent } from '@deepseek-ai/dsh-agent'
import SubagentRuntime from '@deepseek-ai/dsh-subagent'
import type { SubagentProvider } from '@deepseek-ai/dsh-subagent'
import LocalSubprocessRuntime from '@deepseek-ai/dsh-subprocess-local'
import EngineeringControlPlane from 'dsh-engineering-control-plane'
import { afterEach, describe, expect, it } from 'vitest'
import SecurityAssuranceService from '../src/index.ts'
import type { AnalyzerDescriptorV1 } from '../src/analyzer.ts'
import SecurityAssuranceControlPlaneProvider, {
  SECURITY_ASSURANCE_CONTROL_PLANE_DESCRIPTOR,
} from '../src/control-plane-provider.ts'
import {
  assertConformanceReportV1,
  createAssuranceProviderConformanceFixtureV1,
  createReferenceAssuranceProviderFactoryV1,
  runAssuranceProviderContractSuiteV1,
} from '../src/conformance.ts'
import { installControlPlaneCancellationCrashCheckpoint } from '../src/internal/control-plane-cancellation-crash-checkpoint.ts'
import { referenceHostInvocation } from './support/reference-host.ts'

const run = promisify(execFile)
const temporaryRoots: string[] = []

afterEach(async () => {
  await Promise.all(temporaryRoots.splice(0).map(path => rm(path, { recursive: true, force: true })))
})

async function nodeRepositoryFixture(packageJson: unknown, extraPackages = 0): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), 'dsh-security-control-plane-repo-'))
  temporaryRoots.push(root)
  await run('git', ['init', '-b', 'main'], { cwd: root })
  await run('git', ['config', 'user.email', 'fixture@example.invalid'], { cwd: root })
  await run('git', ['config', 'user.name', 'Fixture'], { cwd: root })
  await writeFile(join(root, 'package.json'), JSON.stringify(packageJson, null, 2) + '\n', 'utf8')
  await writeFile(join(root, 'index.js'), 'export const answer = 42\n', 'utf8')
  await Promise.all(Array.from({ length: extraPackages }, async (_value, index) => {
    const directory = join(root, 'fixtures', `package-${index}`)
    await mkdir(directory, { recursive: true })
    await writeFile(join(directory, 'package.json'), JSON.stringify({
      name: `recovery-fixture-${index}`,
      version: '1.0.0',
    }), 'utf8')
  }))
  await run('git', ['add', '.'], { cwd: root })
  await run('git', ['commit', '-m', 'safe node fixture'], { cwd: root })
  return root
}

function registerScriptedEngineeringProvider(ctx: Context): () => void {
  const outputs = {
    planner: {
      schemaVersion: 1,
      outcome: 'planned',
      summary: 'Run the bounded dual-plugin fixture.',
      steps: [{ id: 'step-1', objective: 'Assess the fixture', acceptanceSignals: ['gate closes'] }],
      risks: ['security'],
      verificationFocus: ['functional', 'negative', 'regression', 'security'],
    },
    developer: {
      schemaVersion: 1,
      outcome: 'implemented',
      summary: 'No repository mutation is required.',
      changedAreas: [],
      notes: [],
    },
    tester: {
      schemaVersion: 1,
      outcome: 'assessed',
      summary: 'Host verification completed.',
      findings: [],
    },
    reviewer: {
      schemaVersion: 1,
      outcome: 'reviewed',
      summary: 'No blocking engineering finding remains.',
      findings: [],
    },
  } as const
  let sequence = 0
  const provider: SubagentProvider = {
    name: 'spawn',
    capabilities: { outputSchema: true, depthLimit: true, toolFilter: true, persona: true },
    inheritsParentContext: false,
    async start(request) {
      const role = request.label?.split(' · ')[0]
      if (role !== 'planner' && role !== 'developer' && role !== 'tester' && role !== 'reviewer') {
        throw new Error('Scripted Provider received an unknown Role')
      }
      return {
        id: `security-control-plane-scripted-${++sequence}` as never,
        localAgent: undefined,
        result: Promise.resolve({ output: [], structured: outputs[role], stopReason: 'completed' }),
        dispose: () => Promise.resolve(),
      }
    },
  }
  return ctx.subagents.registerProvider(provider)
}

function registerBlockingCancellationAnalyzer(
  ctx: Context,
  onStarted: (assessmentId: string) => void,
): () => void {
  const descriptor: AnalyzerDescriptorV1 = {
    schemaVersion: 1,
    analyzerId: 'fixture/blocking-cancellation',
    analyzerVersion: '1.0.0',
    descriptorSchemaVersion: 1,
    buildDigest: {
      schemaVersion: 1,
      algorithm: 'sha256',
      mediaType: 'application/vnd.fixture.blocking-cancellation-analyzer+json',
      byteLength: 1,
      canonicalization: 'dsh-canonical-json-v1',
      value: '9'.repeat(64),
    },
    executionClass: 'PURE',
    supportedAssessmentModes: ['REPOSITORY'],
    supportedPolicyIds: ['security/node-package-lifecycle'],
    coverageObligationIds: ['application-security-analysis'],
    evidenceSchemaIds: ['fixture/blocking-cancellation-evidence'],
    egress: 'NONE',
  }
  return ctx.securityAssurance.registerAnalyzer(descriptor, normalizedDescriptor => ({
    descriptor: normalizedDescriptor,
    analyze(input, options) {
      onStarted(input.assessmentId)
      return new Promise<never>((_resolve, reject) => {
        const signal = options?.signal
        if (signal === undefined) return
        const rejectAbort = () => reject(signal.reason ?? new Error('Analyzer invocation aborted'))
        if (signal.aborted) rejectAbort()
        else signal.addEventListener('abort', rejectAbort, { once: true })
      })
    },
    async dispose() {},
  }))
}

async function waitForTerminalMission(ctx: Context, agent: Agent, missionId: string) {
  const deadline = Date.now() + 15_000
  let last = await ctx.engineeringControlPlane.status(agent, missionId, new AbortController().signal)
  while (!['APPROVED', 'REWORK_REQUIRED', 'BLOCKED', 'CANCELLED'].includes(last.status)) {
    if (Date.now() >= deadline) throw new Error(`Mission did not settle (last status: ${last.status})`)
    await new Promise(resolve => setTimeout(resolve, 20))
    last = await ctx.engineeringControlPlane.status(agent, missionId, new AbortController().signal)
  }
  return last
}

async function waitForProviderInvocation(
  ctx: Context,
  agent: Agent,
  missionId: string,
  states: readonly string[],
) {
  const deadline = Date.now() + 15_000
  let last = await ctx.engineeringControlPlane.status(agent, missionId, new AbortController().signal)
  while (!states.includes(last.assuranceProviderInvocations?.[0]?.state ?? 'missing')) {
    if (Date.now() >= deadline) {
      throw new Error(
        `Provider invocation did not reach ${states.join('/')} (last: ${last.assuranceProviderInvocations?.[0]?.state ?? 'missing'})`,
      )
    }
    await new Promise(resolve => setTimeout(resolve, 10))
    last = await ctx.engineeringControlPlane.status(agent, missionId, new AbortController().signal)
  }
  return last
}

async function cancelMissionAtLatestRevision(
  ctx: Context,
  agent: Agent,
  missionId: string,
  reason: string,
) {
  for (let attempt = 0; attempt < 6; attempt += 1) {
    const current = await ctx.engineeringControlPlane.status(
      agent,
      missionId,
      new AbortController().signal,
    )
    try {
      return await ctx.engineeringControlPlane.cancel(agent, {
        missionId,
        expectedRevision: current.revision,
        reason,
      }, new AbortController().signal)
    } catch (error) {
      if ((error as { code?: unknown }).code === 'revision_conflict') continue
      throw error
    }
  }
  throw new Error('Mission revision did not stabilize for cancellation')
}

async function waitForApprovedMission(ctx: Context, agent: Agent, missionId: string) {
  const deadline = Date.now() + 20_000
  let last = await ctx.engineeringControlPlane.status(agent, missionId, new AbortController().signal)
  while (last.status !== 'APPROVED') {
    if (last.status === 'REWORK_REQUIRED' || last.status === 'CANCELLED') return last
    if (Date.now() >= deadline) {
      throw new Error(`Mission did not approve: ${JSON.stringify({
        status: last.status,
        blocked: last.blocked,
        invocations: last.assuranceProviderInvocations,
        results: last.assuranceResults,
        gate: last.gate,
      })}`)
    }
    await new Promise(resolve => setTimeout(resolve, 20))
    last = await ctx.engineeringControlPlane.status(agent, missionId, new AbortController().signal)
  }
  return last
}

function controlPlaneConfig(repository: string, dshHome: string, repositoryId: string) {
  const notApplicable = { mode: 'not_applicable' as const, reason: 'Not required by this fixture.' }
  return {
    dshHome,
    subagentProvider: 'spawn' as const,
    maxSubagentDepth: 1,
    rolePolicies: {
      planner: { allowTools: [], denyTools: [] },
      developer: { allowTools: [], denyTools: [] },
      tester: { allowTools: [], denyTools: [] },
      reviewer: { allowTools: [], denyTools: [] },
    },
    repositories: [{
      root: repository,
      verificationProfile: 'dual-plugin-fixture',
      assuranceProviders: [{
        providerId: SECURITY_ASSURANCE_CONTROL_PLANE_DESCRIPTOR.providerId,
        providerVersion: SECURITY_ASSURANCE_CONTROL_PLANE_DESCRIPTOR.providerVersion,
        activation: 'required' as const,
        configuration: { repositoryId },
      }],
    }],
    verificationProfiles: [{
      name: 'dual-plugin-fixture',
      categories: {
        functional: notApplicable,
        negative: notApplicable,
        regression: notApplicable,
        security: notApplicable,
      },
    }],
  }
}

describe('Security Assurance Control Plane Provider', () => {
  it.each([
    { scenario: 'SATISFIED' as const, outcome: 'satisfied' as const, status: 'APPROVED' as const },
    { scenario: 'FAILED' as const, outcome: 'failed' as const, status: 'REWORK_REQUIRED' as const },
    { scenario: 'INDETERMINATE' as const, outcome: 'indeterminate' as const, status: 'BLOCKED' as const },
    { scenario: 'EXTERNAL_FAILURE' as const, outcome: 'indeterminate' as const, status: 'BLOCKED' as const },
  ])('runs the $scenario Reference Provider through a real public Control Plane composition', async ({
    scenario,
    outcome,
    status,
  }) => {
    const repository = await nodeRepositoryFixture({
      name: 'reference-provider-conformance-fixture',
      version: '1.0.0',
      type: 'module',
    })
    const dshHome = await mkdtemp(join(tmpdir(), 'dsh-reference-provider-conformance-home-'))
    temporaryRoots.push(dshHome)
    const fixture = createAssuranceProviderConformanceFixtureV1()
    const factory = await createReferenceAssuranceProviderFactoryV1(scenario)
    const ctx = new Context()
    const subprocessFiber = await ctx.plugin(LocalSubprocessRuntime)
    const subagentFiber = await ctx.plugin(SubagentRuntime)
    const disposeScriptedProvider = registerScriptedEngineeringProvider(ctx)
    const notApplicable = { mode: 'not_applicable' as const, reason: 'Not required by this fixture.' }
    const controlPlaneFiber = await ctx.plugin(EngineeringControlPlane, {
      dshHome,
      subagentProvider: 'spawn',
      maxSubagentDepth: 1,
      rolePolicies: {
        planner: { allowTools: [], denyTools: [] },
        developer: { allowTools: [], denyTools: [] },
        tester: { allowTools: [], denyTools: [] },
        reviewer: { allowTools: [], denyTools: [] },
      },
      repositories: [{
        root: repository,
        verificationProfile: 'reference-provider-conformance',
        assuranceProviders: [{
          providerId: fixture.descriptor.providerId,
          providerVersion: fixture.descriptor.providerVersion,
          activation: 'required',
        }],
      }],
      verificationProfiles: [{
        name: 'reference-provider-conformance',
        categories: {
          functional: notApplicable,
          negative: notApplicable,
          regression: notApplicable,
          security: notApplicable,
        },
      }],
    })
    await ctx.engineeringControlPlane.whenReady()
    const disposeProvider = ctx.engineeringControlPlane.registerAssuranceProvider(
      fixture.descriptor,
      factory,
    )

    try {
      const agent = {
        id: 'agent-reference-provider-conformance',
        session: { header: { cwd: repository } },
      } as unknown as Agent
      const receipt = await ctx.engineeringControlPlane.start(agent, {
        idempotencyKey: `reference-provider-conformance:${scenario.toLowerCase()}:start:1`,
        objective: 'Prove the public Reference Assurance Provider contract',
      }, new AbortController().signal)
      const snapshot = await waitForTerminalMission(ctx, agent, receipt.missionId)

      expect(snapshot).toMatchObject({
        status,
        assuranceProviderInvocations: [scenario === 'EXTERNAL_FAILURE'
          ? {
              descriptor: fixture.descriptor,
              state: 'external_failed',
              failure: {
                schemaVersion: 1,
                reason: 'failed',
                code: 'reference_provider_failure',
              },
            }
          : {
              descriptor: fixture.descriptor,
              state: 'settled',
              outcome: { kind: 'sealed_submission', claimedOutcome: outcome },
            }],
        assuranceResults: [{
          requirementId: `external-provider:${fixture.descriptor.providerId}@${fixture.descriptor.providerVersion}`,
          outcome,
        }],
      })
    } finally {
      disposeProvider()
      await controlPlaneFiber.dispose()
      disposeScriptedProvider()
      await subagentFiber.dispose()
      await subprocessFiber.dispose()
    }
  })

  it.each([
    {
      caseName: 'satisfied Security Verdict',
      packageJson: { name: 'safe-control-plane-fixture', version: '1.0.0', type: 'module' },
      assuranceOutcome: 'satisfied' as const,
      missionStatus: 'APPROVED' as const,
      gate: { kind: 'approved' as const, reasons: [] },
    },
    {
      caseName: 'failed Security Verdict',
      packageJson: {
        name: 'unsafe-control-plane-fixture',
        version: '1.0.0',
        scripts: { postinstall: 'node setup.js' },
      },
      assuranceOutcome: 'failed' as const,
      missionStatus: 'REWORK_REQUIRED' as const,
      gate: {
        kind: 'rework_required' as const,
        reasons: [{
          code: 'assurance_failed',
          source: `external-provider:${SECURITY_ASSURANCE_CONTROL_PLANE_DESCRIPTOR.providerId}@${SECURITY_ASSURANCE_CONTROL_PLANE_DESCRIPTOR.providerVersion}`,
        }],
      },
    },
    {
      caseName: 'indeterminate Security Verdict',
      packageJson: {
        name: 'indeterminate-control-plane-fixture',
        version: '1.0.0',
        scripts: { postinstall: 42 },
      },
      assuranceOutcome: 'indeterminate' as const,
      missionStatus: 'BLOCKED' as const,
      gate: {
        kind: 'blocked' as const,
        reasons: [{
          code: 'assurance_indeterminate',
          source: `external-provider:${SECURITY_ASSURANCE_CONTROL_PLANE_DESCRIPTOR.providerId}@${SECURITY_ASSURANCE_CONTROL_PLANE_DESCRIPTOR.providerVersion}`,
        }],
      },
    },
    {
      caseName: 'missing repository binding',
      packageJson: { name: 'unbound-control-plane-fixture', version: '1.0.0', type: 'module' },
      assuranceOutcome: 'indeterminate' as const,
      missionStatus: 'BLOCKED' as const,
      configurationMissing: true,
      gate: {
        kind: 'blocked' as const,
        reasons: [{
          code: 'assurance_indeterminate',
          source: `external-provider:${SECURITY_ASSURANCE_CONTROL_PLANE_DESCRIPTOR.providerId}@${SECURITY_ASSURANCE_CONTROL_PLANE_DESCRIPTOR.providerVersion}`,
        }],
      },
    },
  ])('maps a $caseName through the Control Plane-owned Gate', async ({
    packageJson,
    assuranceOutcome,
    missionStatus,
    gate,
    configurationMissing,
  }) => {
    const repository = await nodeRepositoryFixture(packageJson)
    const dshHome = await mkdtemp(join(tmpdir(), 'dsh-security-control-plane-home-'))
    temporaryRoots.push(dshHome)
    const ctx = new Context()
    const subprocessFiber = await ctx.plugin(LocalSubprocessRuntime)
    const subagentFiber = await ctx.plugin(SubagentRuntime)
    const disposeScriptedProvider = registerScriptedEngineeringProvider(ctx)
    const securityFiber = await ctx.plugin(SecurityAssuranceService, { dshHome })
    await ctx.securityAssurance.whenReady()
    const invocation = referenceHostInvocation(ctx.securityAssurance)
    const platform = process.platform
    if (platform !== 'win32' && platform !== 'linux' && platform !== 'darwin') {
      throw new Error(`unsupported test platform: ${platform}`)
    }
    const registered = await ctx.securityAssurance.registerRepository(invocation, {
      schemaVersion: 1,
      contractVersion: 1 as const,
      idempotencyKey: 'control-plane-provider-register-1',
      root: repository,
      displayName: 'Control Plane Provider fixture',
      bindings: {
        policyId: 'security/node-package-lifecycle',
        assessmentProfileId: 'security/standard',
        evidenceProtectionId: 'evidence/local-protected',
        dataEgressPolicyId: 'egress/deny-by-default',
        platform,
        deliveryDestinationIds: [],
      },
    })
    if (!registered.ok) throw new Error(`registration failed: ${registered.error.code}`)
    const notApplicable = { mode: 'not_applicable' as const, reason: 'Not required by this fixture.' }
    const controlPlaneFiber = await ctx.plugin(EngineeringControlPlane, {
      dshHome,
      subagentProvider: 'spawn',
      maxSubagentDepth: 1,
      rolePolicies: {
        planner: { allowTools: [], denyTools: [] },
        developer: { allowTools: [], denyTools: [] },
        tester: { allowTools: [], denyTools: [] },
        reviewer: { allowTools: [], denyTools: [] },
      },
      repositories: [{
        root: repository,
        verificationProfile: 'dual-plugin-fixture',
        assuranceProviders: [{
          providerId: SECURITY_ASSURANCE_CONTROL_PLANE_DESCRIPTOR.providerId,
          providerVersion: SECURITY_ASSURANCE_CONTROL_PLANE_DESCRIPTOR.providerVersion,
          activation: 'required',
          ...configurationMissing
            ? {}
            : { configuration: { repositoryId: registered.value.repositoryId } },
        }],
      }],
      verificationProfiles: [{
        name: 'dual-plugin-fixture',
        categories: {
          functional: notApplicable,
          negative: notApplicable,
          regression: notApplicable,
          security: notApplicable,
        },
      }],
    })
    await ctx.engineeringControlPlane.whenReady()
    const adapterFiber = await ctx.plugin(SecurityAssuranceControlPlaneProvider)

    try {
      const agent = {
        id: 'agent-security-control-plane-provider-fixture',
        session: { header: { cwd: repository } },
      } as unknown as Agent
      const receipt = await ctx.engineeringControlPlane.start(agent, {
        idempotencyKey: 'security-control-plane-provider:start:1',
        objective: 'Close the Mission Gate with the real Security Assurance Provider',
      }, new AbortController().signal)
      const snapshot = await waitForTerminalMission(ctx, agent, receipt.missionId)

      const conformance = await runAssuranceProviderContractSuiteV1({
        schemaVersion: 1,
        descriptor: SECURITY_ASSURANCE_CONTROL_PLANE_DESCRIPTOR,
      }, async () => {
        const invocation = snapshot.assuranceProviderInvocations?.[0]
        if (invocation === undefined) throw new Error('Control Plane did not retain the Provider invocation')
        if (invocation.state === 'settled') {
          return {
            schemaVersion: 1,
            descriptor: invocation.descriptor,
            invocationState: 'settled',
            outcomeKind: 'sealed_submission',
            claimedOutcome: invocation.outcome.claimedOutcome,
          }
        }
        if (invocation.state === 'external_failed') {
          return {
            schemaVersion: 1,
            descriptor: invocation.descriptor,
            invocationState: 'external_failed',
            outcomeKind: 'external_failure',
            claimedOutcome: null,
          }
        }
        throw new Error(`Provider invocation did not settle: ${invocation.state}`)
      })
      expect(() => assertConformanceReportV1(conformance)).not.toThrow()

      expect(snapshot).toMatchObject({
        status: missionStatus,
        assuranceAssessments: [{
          assessor: { kind: 'machine_provider', provider: SECURITY_ASSURANCE_CONTROL_PLANE_DESCRIPTOR },
          outcome: assuranceOutcome,
          reasonCodes: [configurationMissing ? 'external_assessment_failed' : 'eligible_submission'],
        }],
        assuranceResults: [{
          requirementId: `external-provider:${SECURITY_ASSURANCE_CONTROL_PLANE_DESCRIPTOR.providerId}@${SECURITY_ASSURANCE_CONTROL_PLANE_DESCRIPTOR.providerVersion}`,
          outcome: assuranceOutcome,
        }],
        gate,
      })
      expect(snapshot.assuranceProviderInvocations).toEqual([
        configurationMissing
          ? expect.objectContaining({
              descriptor: SECURITY_ASSURANCE_CONTROL_PLANE_DESCRIPTOR,
              state: 'external_failed',
              failure: {
                schemaVersion: 1,
                reason: 'failed',
                code: 'invalid_provider_configuration',
              },
            })
          : expect.objectContaining({
              descriptor: SECURITY_ASSURANCE_CONTROL_PLANE_DESCRIPTOR,
              state: 'settled',
              outcome: expect.objectContaining({
                kind: 'sealed_submission',
                claimedOutcome: assuranceOutcome,
              }),
            }),
      ])
    } finally {
      await adapterFiber.dispose()
      await controlPlaneFiber.dispose()
      await securityFiber.dispose()
      disposeScriptedProvider()
      await subagentFiber.dispose()
      await subprocessFiber.dispose()
    }
  })

  it('blocks when the configured Security Repository is not the Control Plane Mission Repository', async () => {
    const missionRepository = await nodeRepositoryFixture({
      name: 'control-plane-binding-mission-fixture',
      version: '1.0.0',
      type: 'module',
    })
    const securityRepository = await nodeRepositoryFixture({
      name: 'control-plane-binding-wrong-security-fixture',
      version: '1.0.0',
      type: 'module',
    })
    const dshHome = await mkdtemp(join(tmpdir(), 'dsh-security-control-plane-binding-home-'))
    temporaryRoots.push(dshHome)
    const platform = process.platform
    if (platform !== 'win32' && platform !== 'linux' && platform !== 'darwin') {
      throw new Error(`unsupported test platform: ${platform}`)
    }
    const ctx = new Context()
    const subprocessFiber = await ctx.plugin(LocalSubprocessRuntime)
    const subagentFiber = await ctx.plugin(SubagentRuntime)
    const disposeScriptedProvider = registerScriptedEngineeringProvider(ctx)
    const securityFiber = await ctx.plugin(SecurityAssuranceService, { dshHome })
    await ctx.securityAssurance.whenReady()
    const invocation = referenceHostInvocation(ctx.securityAssurance)
    const registered = await ctx.securityAssurance.registerRepository(invocation, {
      schemaVersion: 1,
      contractVersion: 1 as const,
      idempotencyKey: 'control-plane-repository-binding-register-1',
      root: securityRepository,
      displayName: 'Wrong Security Repository binding fixture',
      bindings: {
        policyId: 'security/node-package-lifecycle',
        assessmentProfileId: 'security/standard',
        evidenceProtectionId: 'evidence/local-protected',
        dataEgressPolicyId: 'egress/deny-by-default',
        platform,
        deliveryDestinationIds: [],
      },
    })
    if (!registered.ok) throw new Error(`registration failed: ${registered.error.code}`)
    const controlPlaneFiber = await ctx.plugin(
      EngineeringControlPlane,
      controlPlaneConfig(missionRepository, dshHome, registered.value.repositoryId),
    )
    await ctx.engineeringControlPlane.whenReady()
    const adapterFiber = await ctx.plugin(SecurityAssuranceControlPlaneProvider)

    try {
      const agent = {
        id: 'agent-security-control-plane-repository-binding-fixture',
        session: { header: { cwd: missionRepository } },
      } as unknown as Agent
      const receipt = await ctx.engineeringControlPlane.start(agent, {
        idempotencyKey: 'security-control-plane-provider:repository-binding:1',
        objective: 'Reject Security Evidence produced for a different registered Repository',
      }, new AbortController().signal)
      const snapshot = await waitForTerminalMission(ctx, agent, receipt.missionId)

      expect(snapshot).toMatchObject({
        status: 'BLOCKED',
        assuranceProviderInvocations: [{
          state: 'external_failed',
          failure: {
            schemaVersion: 1,
            reason: 'failed',
            code: 'repository_binding_mismatch',
          },
        }],
        assuranceAssessments: [{
          outcome: 'indeterminate',
          reasonCodes: ['external_assessment_failed'],
        }],
        gate: {
          kind: 'blocked',
          reasons: [{
            code: 'assurance_indeterminate',
            source: `external-provider:${SECURITY_ASSURANCE_CONTROL_PLANE_DESCRIPTOR.providerId}@${SECURITY_ASSURANCE_CONTROL_PLANE_DESCRIPTOR.providerVersion}`,
          }],
        },
      })
    } finally {
      await adapterFiber.dispose()
      await controlPlaneFiber.dispose()
      await securityFiber.dispose()
      disposeScriptedProvider()
      await subagentFiber.dispose()
      await subprocessFiber.dispose()
    }
  })

  it('starts a new Security Assessment only after explicit Assurance Retry', async () => {
    const repository = await nodeRepositoryFixture({
      name: 'security-assurance-retry-control-plane-fixture',
      version: '1.0.0',
      type: 'module',
    }, 150)
    const dshHome = await mkdtemp(join(tmpdir(), 'dsh-security-control-plane-assurance-retry-home-'))
    temporaryRoots.push(dshHome)
    const platform = process.platform
    if (platform !== 'win32' && platform !== 'linux' && platform !== 'darwin') {
      throw new Error(`unsupported test platform: ${platform}`)
    }
    const ctx = new Context()
    const subprocessFiber = await ctx.plugin(LocalSubprocessRuntime)
    const subagentFiber = await ctx.plugin(SubagentRuntime)
    const disposeScriptedProvider = registerScriptedEngineeringProvider(ctx)
    const securityFiber = await ctx.plugin(SecurityAssuranceService, { dshHome })
    await ctx.securityAssurance.whenReady()
    const invocation = referenceHostInvocation(ctx.securityAssurance)
    const registered = await ctx.securityAssurance.registerRepository(invocation, {
      schemaVersion: 1,
      contractVersion: 1 as const,
      idempotencyKey: 'control-plane-assurance-retry-register-1',
      root: repository,
      displayName: 'Control Plane Assurance Retry fixture',
      bindings: {
        policyId: 'security/node-package-lifecycle',
        assessmentProfileId: 'security/standard',
        evidenceProtectionId: 'evidence/local-protected',
        dataEgressPolicyId: 'egress/deny-by-default',
        platform,
        deliveryDestinationIds: [],
      },
    })
    if (!registered.ok) throw new Error(`registration failed: ${registered.error.code}`)
    const controlPlaneFiber = await ctx.plugin(
      EngineeringControlPlane,
      controlPlaneConfig(repository, dshHome, registered.value.repositoryId),
    )
    await ctx.engineeringControlPlane.whenReady()
    const adapterFiber = await ctx.plugin(SecurityAssuranceControlPlaneProvider)
    const assessmentIds: string[] = []
    let resolveFirstAssessment!: (assessmentId: string) => void
    const firstAssessmentStarted = new Promise<string>(resolve => { resolveFirstAssessment = resolve })
    let releaseFirstAssessment!: () => void
    const firstAssessmentHold = new Promise<void>(resolve => { releaseFirstAssessment = resolve })
    const disposeCheckpoint = installControlPlaneCancellationCrashCheckpoint(
      ctx.securityAssurance,
      async event => {
        if (event.name !== 'after_assessment_started') return
        assessmentIds.push(event.assessmentId)
        if (assessmentIds.length !== 1) return
        resolveFirstAssessment(event.assessmentId)
        await firstAssessmentHold
      },
    )

    try {
      const agent = {
        id: 'agent-security-control-plane-assurance-retry-fixture',
        session: { header: { cwd: repository } },
      } as unknown as Agent
      const receipt = await ctx.engineeringControlPlane.start(agent, {
        idempotencyKey: 'security-control-plane-provider:assurance-retry:1',
        objective: 'Retry one canceled Security Assessment without rewriting its history',
      }, new AbortController().signal)
      await waitForProviderInvocation(ctx, agent, receipt.missionId, ['begun'])
      const firstAssessmentId = await Promise.race([
        firstAssessmentStarted,
        new Promise<never>((_resolve, reject) => {
          setTimeout(() => reject(new Error('First Security Assessment did not start')), 15_000)
        }),
      ])
      let firstAssessment = await ctx.securityAssurance.getAssessment(invocation, {
        schemaVersion: 1,
        assessmentId: firstAssessmentId as never,
      })
      const runningDeadline = Date.now() + 5_000
      while (firstAssessment.ok && firstAssessment.value.state === 'CREATED' && Date.now() < runningDeadline) {
        await new Promise(resolve => setTimeout(resolve, 10))
        firstAssessment = await ctx.securityAssurance.getAssessment(invocation, {
          schemaVersion: 1,
          assessmentId: firstAssessmentId as never,
        })
      }
      if (!firstAssessment.ok || firstAssessment.value.state !== 'RUNNING') {
        throw new Error(`First Security Assessment was not cancellable: ${JSON.stringify(firstAssessment)}`)
      }
      const canceled = await ctx.securityAssurance.cancelAssessment(invocation, {
        schemaVersion: 1,
        contractVersion: 1 as const,
        assessmentId: firstAssessment.value.assessmentId,
        expectedAssessmentRevision: firstAssessment.value.assessmentRevision,
        idempotencyKey: 'control-plane-assurance-retry-cancel-1',
        reason: {
          code: 'OPERATOR_REQUEST',
          summary: 'Create a deterministic External Assessment Failure for Assurance Retry conformance.',
        },
      })
      expect(canceled).toMatchObject({ ok: true, value: { acceptedState: 'RUNNING' } })
      releaseFirstAssessment()

      const blocked = await waitForTerminalMission(ctx, agent, receipt.missionId)
      expect(blocked).toMatchObject({
        status: 'BLOCKED',
        assuranceProviderInvocations: [{
          state: 'external_failed',
          failure: { reason: 'canceled', code: 'assessment_canceled' },
        }],
        assuranceResults: [{
          outcome: 'indeterminate',
          reasonCodes: ['external_assessment_canceled'],
        }],
      })
      const failedInvocationId = blocked.assuranceProviderInvocations?.[0]?.invocationId
      if (failedInvocationId === undefined) throw new Error('Failed Control Plane Invocation is missing')

      await ctx.engineeringControlPlane.resume(agent, {
        missionId: blocked.missionId,
        expectedRevision: blocked.revision,
        supplementalContext: 'Start a fresh Security Assessment; do not reuse the canceled Assessment.',
      }, new AbortController().signal)
      const approved = await waitForApprovedMission(ctx, agent, blocked.missionId)
      expect(approved.status).toBe('APPROVED')
      expect(assessmentIds).toHaveLength(2)
      expect(assessmentIds[1]).not.toBe(assessmentIds[0])
      expect(approved.assuranceProviderInvocations).toEqual([
        expect.objectContaining({
          invocationId: failedInvocationId,
          state: 'external_failed',
        }),
        expect.objectContaining({
          replacementForInvocationId: failedInvocationId,
          state: 'settled',
          outcome: expect.objectContaining({ claimedOutcome: 'satisfied' }),
        }),
      ])
      await expect(ctx.securityAssurance.getAssessment(invocation, {
        schemaVersion: 1,
        assessmentId: assessmentIds[0] as never,
      })).resolves.toMatchObject({ ok: true, value: { state: 'CANCELED', verdict: null, seal: null } })
      await expect(ctx.securityAssurance.getAssessment(invocation, {
        schemaVersion: 1,
        assessmentId: assessmentIds[1] as never,
      })).resolves.toMatchObject({ ok: true, value: { state: 'SEALED', verdict: 'SATISFIED' } })
    } finally {
      releaseFirstAssessment()
      disposeCheckpoint()
      await adapterFiber.dispose()
      await controlPlaneFiber.dispose()
      await securityFiber.dispose()
      disposeScriptedProvider()
      await subagentFiber.dispose()
      await subprocessFiber.dispose()
    }
  }, 40_000)

  it('reconciles one begun invocation across both plugin restarts only after explicit Mission resume', async () => {
    const repository = await nodeRepositoryFixture({
      name: 'safe-recovery-control-plane-fixture',
      version: '1.0.0',
      type: 'module',
    }, 250)
    const dshHome = await mkdtemp(join(tmpdir(), 'dsh-security-control-plane-recovery-home-'))
    temporaryRoots.push(dshHome)
    const platform = process.platform
    if (platform !== 'win32' && platform !== 'linux' && platform !== 'darwin') {
      throw new Error(`unsupported test platform: ${platform}`)
    }
    const agent = {
      id: 'agent-security-control-plane-recovery-fixture',
      session: { header: { cwd: repository } },
    } as unknown as Agent
    const missionRequest = {
      idempotencyKey: 'security-control-plane-provider:recovery:1',
      objective: 'Recover the exact Security Assessment after both plugin hosts restart',
    }

    const firstContext = new Context()
    const firstSubprocessFiber = await firstContext.plugin(LocalSubprocessRuntime)
    const firstSubagentFiber = await firstContext.plugin(SubagentRuntime)
    const disposeFirstScriptedProvider = registerScriptedEngineeringProvider(firstContext)
    const firstSecurityFiber = await firstContext.plugin(SecurityAssuranceService, { dshHome })
    await firstContext.securityAssurance.whenReady()
    const firstInvocation = referenceHostInvocation(firstContext.securityAssurance)
    const registered = await firstContext.securityAssurance.registerRepository(firstInvocation, {
      schemaVersion: 1,
      contractVersion: 1 as const,
      idempotencyKey: 'control-plane-recovery-register-1',
      root: repository,
      displayName: 'Control Plane recovery fixture',
      bindings: {
        policyId: 'security/node-package-lifecycle',
        assessmentProfileId: 'security/standard',
        evidenceProtectionId: 'evidence/local-protected',
        dataEgressPolicyId: 'egress/deny-by-default',
        platform,
        deliveryDestinationIds: [],
      },
    })
    if (!registered.ok) throw new Error(`registration failed: ${registered.error.code}`)
    const firstControlPlaneFiber = await firstContext.plugin(
      EngineeringControlPlane,
      controlPlaneConfig(repository, dshHome, registered.value.repositoryId),
    )
    await firstContext.engineeringControlPlane.whenReady()
    const firstAdapterFiber = await firstContext.plugin(SecurityAssuranceControlPlaneProvider)

    let missionId: string
    try {
      const receipt = await firstContext.engineeringControlPlane.start(
        agent,
        missionRequest,
        new AbortController().signal,
      )
      missionId = receipt.missionId
      const begun = await waitForProviderInvocation(firstContext, agent, missionId, ['begun'])
      expect(begun.assuranceProviderInvocations).toEqual([expect.objectContaining({
        descriptor: SECURITY_ASSURANCE_CONTROL_PLANE_DESCRIPTOR,
        state: 'begun',
      })])
    } finally {
      await firstAdapterFiber.dispose()
      await firstControlPlaneFiber.dispose()
      await firstSecurityFiber.dispose()
      disposeFirstScriptedProvider()
      await firstSubagentFiber.dispose()
      await firstSubprocessFiber.dispose()
    }

    const restartedContext = new Context()
    const restartedSubprocessFiber = await restartedContext.plugin(LocalSubprocessRuntime)
    const restartedSubagentFiber = await restartedContext.plugin(SubagentRuntime)
    const disposeRestartedScriptedProvider = registerScriptedEngineeringProvider(restartedContext)
    const restartedSecurityFiber = await restartedContext.plugin(SecurityAssuranceService, { dshHome })
    await restartedContext.securityAssurance.whenReady()
    const restartedControlPlaneFiber = await restartedContext.plugin(
      EngineeringControlPlane,
      controlPlaneConfig(repository, dshHome, registered.value.repositoryId),
    )
    await restartedContext.engineeringControlPlane.whenReady()
    const restartedAdapterFiber = await restartedContext.plugin(SecurityAssuranceControlPlaneProvider)

    try {
      const recovered = await restartedContext.engineeringControlPlane.status(
        agent,
        missionId!,
        new AbortController().signal,
      )
      expect(recovered).toMatchObject({
        status: 'BLOCKED',
        blocked: { reason: { code: 'host_restarted' } },
        assuranceProviderInvocations: [{ state: 'begun' }],
      })

      await restartedContext.engineeringControlPlane.resume(agent, {
        missionId: missionId!,
        expectedRevision: recovered.revision,
        supplementalContext: 'Explicitly reconcile the exact Security Assessment and Provider invocation.',
      }, new AbortController().signal)
      const approved = await waitForApprovedMission(restartedContext, agent, missionId!)

      expect(approved).toMatchObject({
        status: 'APPROVED',
        assuranceProviderInvocations: [{
          state: 'settled',
          outcome: { kind: 'sealed_submission', claimedOutcome: 'satisfied' },
        }],
        assuranceAssessments: [{ outcome: 'satisfied', reasonCodes: ['eligible_submission'] }],
        assuranceResults: [{ outcome: 'satisfied' }],
        gate: { kind: 'approved', reasons: [] },
      })
    } finally {
      await restartedAdapterFiber.dispose()
      await restartedControlPlaneFiber.dispose()
      await restartedSecurityFiber.dispose()
      disposeRestartedScriptedProvider()
      await restartedSubagentFiber.dispose()
      await restartedSubprocessFiber.dispose()
    }
  }, 30_000)

  it('propagates explicit Mission cancellation to the active Security Assessment', async () => {
    const repository = await nodeRepositoryFixture({
      name: 'cancel-active-control-plane-fixture',
      version: '1.0.0',
      type: 'module',
    })
    const dshHome = await mkdtemp(join(tmpdir(), 'dsh-security-control-plane-cancel-home-'))
    temporaryRoots.push(dshHome)
    const platform = process.platform
    if (platform !== 'win32' && platform !== 'linux' && platform !== 'darwin') {
      throw new Error(`unsupported test platform: ${platform}`)
    }
    const ctx = new Context()
    const subprocessFiber = await ctx.plugin(LocalSubprocessRuntime)
    const subagentFiber = await ctx.plugin(SubagentRuntime)
    const disposeScriptedProvider = registerScriptedEngineeringProvider(ctx)
    const securityFiber = await ctx.plugin(SecurityAssuranceService, { dshHome })
    await ctx.securityAssurance.whenReady()
    let resolveAnalyzerStarted!: (assessmentId: string) => void
    const analyzerStarted = new Promise<string>(resolve => { resolveAnalyzerStarted = resolve })
    const disposeBlockingAnalyzer = registerBlockingCancellationAnalyzer(ctx, resolveAnalyzerStarted)
    const invocation = referenceHostInvocation(ctx.securityAssurance)
    const registered = await ctx.securityAssurance.registerRepository(invocation, {
      schemaVersion: 1,
      contractVersion: 1 as const,
      idempotencyKey: 'control-plane-cancel-register-1',
      root: repository,
      displayName: 'Control Plane cancellation fixture',
      bindings: {
        policyId: 'security/node-package-lifecycle',
        assessmentProfileId: 'security/standard',
        evidenceProtectionId: 'evidence/local-protected',
        dataEgressPolicyId: 'egress/deny-by-default',
        platform,
        deliveryDestinationIds: [],
      },
    })
    if (!registered.ok) throw new Error(`registration failed: ${registered.error.code}`)
    const controlPlaneFiber = await ctx.plugin(
      EngineeringControlPlane,
      controlPlaneConfig(repository, dshHome, registered.value.repositoryId),
    )
    await ctx.engineeringControlPlane.whenReady()
    const adapterFiber = await ctx.plugin(SecurityAssuranceControlPlaneProvider)

    try {
      const agent = {
        id: 'agent-security-control-plane-cancel-fixture',
        session: { header: { cwd: repository } },
      } as unknown as Agent
      const receipt = await ctx.engineeringControlPlane.start(agent, {
        idempotencyKey: 'security-control-plane-provider:cancel:1',
        objective: 'Cancel the active external Security Assessment with the Mission',
      }, new AbortController().signal)
      await waitForProviderInvocation(ctx, agent, receipt.missionId, ['begun'])
      const activeAssessmentId = await Promise.race([
        analyzerStarted,
        new Promise<never>((_resolve, reject) => {
          setTimeout(() => reject(new Error('Blocking Security Analyzer was not invoked')), 15_000)
        }),
      ])
      await expect(ctx.securityAssurance.getAssessment(invocation, {
        schemaVersion: 1,
        assessmentId: activeAssessmentId as never,
      })).resolves.toMatchObject({ ok: true, value: { state: 'RUNNING' } })
      const active = await ctx.engineeringControlPlane.status(
        agent,
        receipt.missionId,
        new AbortController().signal,
      )
      expect(active.assuranceProviderInvocations?.[0]?.state).toBe('begun')

      const rebound = await ctx.securityAssurance.updateRepository(invocation, {
        schemaVersion: 1,
        contractVersion: 1 as const,
        idempotencyKey: 'control-plane-cancel-rebind-1',
        repositoryId: registered.value.repositoryId,
        expectedRepositoryRevision: 1,
        bindings: {
          policyId: 'security/node-package-lifecycle',
          assessmentProfileId: 'security/strict-after-start',
          evidenceProtectionId: 'evidence/local-protected',
          dataEgressPolicyId: 'egress/deny-by-default',
          platform,
          deliveryDestinationIds: [],
        },
      })
      expect(rebound).toMatchObject({
        ok: true,
        value: { repositoryRevision: 2 },
      })

      try {
        await cancelMissionAtLatestRevision(
          ctx,
          agent,
          active.missionId,
          'The owning user explicitly canceled the Mission.',
        )
      } catch (error) {
        const failed = await ctx.engineeringControlPlane.status(
          agent,
          active.missionId,
          new AbortController().signal,
        )
        throw new Error(`Mission cancellation failed from ${JSON.stringify(failed.blocked)}: ${String(error)}`)
      }
      const canceledMission = await ctx.engineeringControlPlane.status(
        agent,
        active.missionId,
        new AbortController().signal,
      )
      expect(canceledMission.status).toBe('CANCELLED')
      const terminated = canceledMission.assuranceProviderInvocations?.[0]
      expect(terminated).toMatchObject({
        state: 'terminated',
        outcome: {
          kind: 'external_assessment_canceled',
          externalAssessmentId: activeAssessmentId,
        },
      })
      if (terminated?.state !== 'terminated' || !('externalAssessmentId' in terminated.outcome)) {
        throw new Error('Control Plane did not retain the canceled external Assessment identity')
      }
      await expect(ctx.securityAssurance.getAssessment(invocation, {
        schemaVersion: 1,
        assessmentId: terminated.outcome.externalAssessmentId as never,
      })).resolves.toMatchObject({
        ok: true,
        value: {
          assessmentId: terminated.outcome.externalAssessmentId,
          state: 'CANCELED',
          verdict: null,
          seal: null,
        },
      })
    } finally {
      await adapterFiber.dispose()
      await controlPlaneFiber.dispose()
      disposeBlockingAnalyzer()
      await securityFiber.dispose()
      disposeScriptedProvider()
      await subagentFiber.dispose()
      await subprocessFiber.dispose()
    }
  }, 40_000)

  it('reconciles the same canceled Security Assessment after interruption before Provider termination', async () => {
    const repository = await nodeRepositoryFixture({
      name: 'cancel-recovery-control-plane-fixture',
      version: '1.0.0',
      type: 'module',
    }, 150)
    const dshHome = await mkdtemp(join(tmpdir(), 'dsh-security-control-plane-cancel-recovery-home-'))
    temporaryRoots.push(dshHome)
    const platform = process.platform
    if (platform !== 'win32' && platform !== 'linux' && platform !== 'darwin') {
      throw new Error(`unsupported test platform: ${platform}`)
    }
    const agent = {
      id: 'agent-security-control-plane-cancel-recovery-fixture',
      session: { header: { cwd: repository } },
    } as unknown as Agent

    const firstContext = new Context()
    const firstSubprocessFiber = await firstContext.plugin(LocalSubprocessRuntime)
    const firstSubagentFiber = await firstContext.plugin(SubagentRuntime)
    const disposeFirstScriptedProvider = registerScriptedEngineeringProvider(firstContext)
    const firstSecurityFiber = await firstContext.plugin(SecurityAssuranceService, { dshHome })
    await firstContext.securityAssurance.whenReady()
    const firstInvocation = referenceHostInvocation(firstContext.securityAssurance)
    const registered = await firstContext.securityAssurance.registerRepository(firstInvocation, {
      schemaVersion: 1,
      contractVersion: 1 as const,
      idempotencyKey: 'control-plane-cancel-recovery-register-1',
      root: repository,
      displayName: 'Control Plane cancellation recovery fixture',
      bindings: {
        policyId: 'security/node-package-lifecycle',
        assessmentProfileId: 'security/standard',
        evidenceProtectionId: 'evidence/local-protected',
        dataEgressPolicyId: 'egress/deny-by-default',
        platform,
        deliveryDestinationIds: [],
      },
    })
    if (!registered.ok) throw new Error(`registration failed: ${registered.error.code}`)
    const firstControlPlaneFiber = await firstContext.plugin(
      EngineeringControlPlane,
      controlPlaneConfig(repository, dshHome, registered.value.repositoryId),
    )
    await firstContext.engineeringControlPlane.whenReady()
    const firstAdapterFiber = await firstContext.plugin(SecurityAssuranceControlPlaneProvider)
    let resolveAssessmentStarted!: (assessmentId: string) => void
    const assessmentStarted = new Promise<string>(resolve => { resolveAssessmentStarted = resolve })
    let interruptedAssessmentId: string | undefined
    const disposeCheckpoint = installControlPlaneCancellationCrashCheckpoint(
      firstContext.securityAssurance,
      event => {
        if (event.name === 'after_assessment_started') {
          resolveAssessmentStarted(event.assessmentId)
          return
        }
        interruptedAssessmentId = event.assessmentId
        throw new Error('Simulated host interruption after Security cancellation committed')
      },
    )

    let missionId: string
    try {
      const receipt = await firstContext.engineeringControlPlane.start(agent, {
        idempotencyKey: 'security-control-plane-provider:cancel-recovery:1',
        objective: 'Recover the same canceled Security Assessment after host interruption',
      }, new AbortController().signal)
      missionId = receipt.missionId
      await waitForProviderInvocation(firstContext, agent, missionId, ['begun'])
      const startedAssessmentId = await Promise.race([
        assessmentStarted,
        new Promise<never>((_resolve, reject) => {
          setTimeout(() => reject(new Error('Security Assessment did not reach the start checkpoint')), 15_000)
        }),
      ])

      await expect(cancelMissionAtLatestRevision(
        firstContext,
        agent,
        missionId,
        'Interrupt this host after the external cancellation commit.',
      )).rejects.toThrow(
        'Simulated host interruption after Security cancellation committed',
      )
      const quarantined = await firstContext.engineeringControlPlane.status(
        agent,
        missionId,
        new AbortController().signal,
      )
      expect(quarantined).toMatchObject({
        status: 'BLOCKED',
        blocked: { reason: { code: 'evidence_incomplete' } },
        assuranceProviderInvocations: [{ state: 'begun' }],
      })
      expect(interruptedAssessmentId).toEqual(expect.any(String))
      expect(interruptedAssessmentId).toBe(startedAssessmentId)
      await expect(firstContext.securityAssurance.getAssessment(firstInvocation, {
        schemaVersion: 1,
        assessmentId: interruptedAssessmentId as never,
      })).resolves.toMatchObject({
        ok: true,
        value: { state: 'CANCELED', verdict: null, seal: null },
      })
    } finally {
      disposeCheckpoint()
      await firstAdapterFiber.dispose()
      await firstControlPlaneFiber.dispose()
      await firstSecurityFiber.dispose()
      disposeFirstScriptedProvider()
      await firstSubagentFiber.dispose()
      await firstSubprocessFiber.dispose()
    }

    const restartedContext = new Context()
    const restartedSubprocessFiber = await restartedContext.plugin(LocalSubprocessRuntime)
    const restartedSubagentFiber = await restartedContext.plugin(SubagentRuntime)
    const disposeRestartedScriptedProvider = registerScriptedEngineeringProvider(restartedContext)
    const restartedSecurityFiber = await restartedContext.plugin(SecurityAssuranceService, { dshHome })
    await restartedContext.securityAssurance.whenReady()
    const restartedInvocation = referenceHostInvocation(restartedContext.securityAssurance)
    const restartedControlPlaneFiber = await restartedContext.plugin(
      EngineeringControlPlane,
      controlPlaneConfig(repository, dshHome, registered.value.repositoryId),
    )
    await restartedContext.engineeringControlPlane.whenReady()
    const restartedAdapterFiber = await restartedContext.plugin(SecurityAssuranceControlPlaneProvider)

    try {
      const recovered = await restartedContext.engineeringControlPlane.status(
        agent,
        missionId!,
        new AbortController().signal,
      )
      expect(recovered.assuranceProviderInvocations?.[0]?.state).toBe('begun')
      await cancelMissionAtLatestRevision(
        restartedContext,
        agent,
        missionId!,
        'Reconcile the same already canceled Security Assessment.',
      )
      const canceledMission = await restartedContext.engineeringControlPlane.status(
        agent,
        missionId!,
        new AbortController().signal,
      )

      expect(canceledMission).toMatchObject({
        status: 'CANCELLED',
        assuranceProviderInvocations: [{
          state: 'terminated',
          outcome: {
            kind: 'external_assessment_terminal',
            externalAssessmentId: interruptedAssessmentId,
            terminalState: 'canceled',
          },
        }],
      })
      await expect(restartedContext.securityAssurance.getAssessment(restartedInvocation, {
        schemaVersion: 1,
        assessmentId: interruptedAssessmentId as never,
      })).resolves.toMatchObject({
        ok: true,
        value: {
          assessmentId: interruptedAssessmentId,
          state: 'CANCELED',
          verdict: null,
          seal: null,
        },
      })
    } finally {
      await restartedAdapterFiber.dispose()
      await restartedControlPlaneFiber.dispose()
      await restartedSecurityFiber.dispose()
      disposeRestartedScriptedProvider()
      await restartedSubagentFiber.dispose()
      await restartedSubprocessFiber.dispose()
    }
  }, 50_000)
})
