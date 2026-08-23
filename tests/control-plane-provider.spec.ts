import { execFile } from 'node:child_process'
import { mkdtemp, rm, writeFile } from 'node:fs/promises'
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
import SecurityAssuranceControlPlaneProvider, {
  SECURITY_ASSURANCE_CONTROL_PLANE_DESCRIPTOR,
} from '../src/control-plane-provider.ts'
import { referenceHostInvocation } from './support/reference-host.ts'

const run = promisify(execFile)
const temporaryRoots: string[] = []

afterEach(async () => {
  await Promise.all(temporaryRoots.splice(0).map(path => rm(path, { recursive: true, force: true })))
})

async function nodeRepositoryFixture(packageJson: unknown): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), 'dsh-security-control-plane-repo-'))
  temporaryRoots.push(root)
  await run('git', ['init', '-b', 'main'], { cwd: root })
  await run('git', ['config', 'user.email', 'fixture@example.invalid'], { cwd: root })
  await run('git', ['config', 'user.name', 'Fixture'], { cwd: root })
  await writeFile(join(root, 'package.json'), JSON.stringify(packageJson, null, 2) + '\n', 'utf8')
  await writeFile(join(root, 'index.js'), 'export const answer = 42\n', 'utf8')
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

describe('Security Assurance Control Plane Provider', () => {
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

      expect(snapshot).toMatchObject({
        status: missionStatus,
        assuranceAssessments: [{
          assessor: { kind: 'machine_provider', provider: SECURITY_ASSURANCE_CONTROL_PLANE_DESCRIPTOR },
          outcome: assuranceOutcome,
          reasonCodes: [configurationMissing ? 'provider_incomplete' : 'eligible_submission'],
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
              state: 'begun',
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
})
