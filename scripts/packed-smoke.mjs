import { execFile } from 'node:child_process'
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { promisify } from 'node:util'

const execute = promisify(execFile)
const projectRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const controlPlaneRoot = resolve(projectRoot, '..', 'DSH Engineering Control Plane')
const temporaryRoot = await mkdtemp(join(tmpdir(), 'dsh-security-assurance-pack-'))
const artifactRoot = join(temporaryRoot, 'artifacts')
const consumerRoot = join(temporaryRoot, 'consumer')
const npmCache = join(temporaryRoot, 'npm-cache')
const repositoryRoot = join(temporaryRoot, 'repository')
const securityHome = join(temporaryRoot, 'dsh-home')

function executeNpm(args, options) {
  if (process.platform === 'win32') {
    const npmCli = join(dirname(process.execPath), 'node_modules', 'npm', 'bin', 'npm-cli.js')
    return execute(process.execPath, [npmCli, ...args], options)
  }
  return execute('npm', args, options)
}

try {
  await mkdir(artifactRoot)
  await mkdir(consumerRoot)
  await mkdir(repositoryRoot)
  await writeFile(join(repositoryRoot, 'package.json'), `${JSON.stringify({
    name: 'dsh-packed-integration-fixture',
    version: '1.0.0',
    type: 'module',
  }, null, 2)}\n`, 'utf8')
  await writeFile(join(repositoryRoot, 'index.js'), 'export const answer = 42\n', 'utf8')
  await execute('git', ['init', '-b', 'main'], { cwd: repositoryRoot, windowsHide: true })
  await execute('git', ['config', 'user.email', 'fixture@example.invalid'], {
    cwd: repositoryRoot,
    windowsHide: true,
  })
  await execute('git', ['config', 'user.name', 'Fixture'], {
    cwd: repositoryRoot,
    windowsHide: true,
  })
  await execute('git', ['add', '.'], { cwd: repositoryRoot, windowsHide: true })
  await execute('git', ['commit', '-m', 'packed integration baseline'], {
    cwd: repositoryRoot,
    windowsHide: true,
  })

  const packed = await executeNpm([
    '--cache', npmCache,
    'pack',
    '--json',
    '--pack-destination', artifactRoot,
  ], {
    cwd: projectRoot,
    windowsHide: true,
  })
  const manifest = JSON.parse(packed.stdout)
  const filename = manifest[0]?.filename
  if (typeof filename !== 'string') throw new Error('npm pack did not report an artifact filename')
  const tarball = join(artifactRoot, filename)
  const packedControlPlane = await executeNpm([
    '--cache', npmCache,
    'pack',
    '--json',
    '--pack-destination', artifactRoot,
  ], {
    cwd: controlPlaneRoot,
    windowsHide: true,
  })
  const controlPlaneManifest = JSON.parse(packedControlPlane.stdout)
  const controlPlaneFilename = controlPlaneManifest[0]?.filename
  if (typeof controlPlaneFilename !== 'string') {
    throw new Error('Control Plane npm pack did not report an artifact filename')
  }
  const controlPlaneTarball = join(artifactRoot, controlPlaneFilename)

  await writeFile(join(consumerRoot, 'package.json'), `${JSON.stringify({
    name: 'dsh-security-assurance-packed-smoke',
    version: '0.0.0',
    private: true,
    type: 'module',
    dependencies: {
      '@deepseek-ai/cordis': '4.0.1',
      '@deepseek-ai/dsh-agent': '0.1.1-rc.2',
      '@deepseek-ai/dsh-attachment': '0.1.1-rc.2',
      '@deepseek-ai/dsh-brand': '0.1.1-rc.2',
      '@deepseek-ai/dsh-code-runtime': '0.1.1-rc.2',
      '@deepseek-ai/dsh-home-paths': '0.1.1-rc.2',
      '@deepseek-ai/dsh-invariants': '0.1.1-rc.2',
      '@deepseek-ai/dsh-llm': '0.1.1-rc.2',
      '@deepseek-ai/dsh-scope': '0.1.1-rc.2',
      '@deepseek-ai/dsh-session': '0.1.1-rc.2',
      '@deepseek-ai/dsh-subagent': '0.1.1-rc.2',
      '@deepseek-ai/dsh-subprocess': '0.1.1-rc.2',
      '@deepseek-ai/dsh-subprocess-local': '0.1.1-rc.2',
      '@deepseek-ai/dsh-system-prompt': '0.1.1-rc.2',
      '@deepseek-ai/dsh-timeout': '0.1.1-rc.2',
      '@deepseek-ai/dsh-tools': '0.1.1-rc.2',
      '@deepseek-ai/dsh-typert-protocol': '0.1.1-rc.2',
      '@deepseek-ai/dsh-user-approval': '0.1.1-rc.2',
      '@deepseek-ai/schemastery': '3.18.1',
      'dsh-security-assurance': pathToFileURL(tarball).href,
    },
  }, null, 2)}\n`, 'utf8')

  await executeNpm([
    '--cache', npmCache,
    'install',
    '--ignore-scripts',
    '--no-audit',
    '--no-fund',
    '--legacy-peer-deps',
  ], {
    cwd: consumerRoot,
    windowsHide: true,
  })

  const probePath = join(consumerRoot, 'probe.mjs')
  await writeFile(probePath, `
const contracts = await import('dsh-security-assurance/contracts')
if ('SecurityAuthorityResolver' in contracts || 'resolveTrustedInvocation' in contracts) {
  throw new Error('contracts export leaked authority minting')
}
const root = await import('dsh-security-assurance')
if ('SecurityPersistence' in root || 'freezeSubject' in root || 'SecurityAuthorityResolver' in root) {
  throw new Error('root export leaked a package-private implementation boundary')
}
const hostRepositories = await import('dsh-security-assurance/host-repository-provider')
if ('resolveTrustedInvocation' in hostRepositories || 'SecurityAuthorityResolver' in hostRepositories) {
  throw new Error('Host Repository Provider export leaked authority minting')
}
const { Context } = await import('@deepseek-ai/cordis')
const ctx = new Context()
if (ctx.reflect.get('securityAssurance') !== undefined) {
  throw new Error('package import activated the Service')
}
const fiber = ctx.plugin(root.default, { dshHome: ${JSON.stringify(securityHome)} })
await fiber
if (ctx.reflect.get('securityAssurance') === undefined) {
  throw new Error('Cordis activation did not mount securityAssurance')
}
const repositoryConfig = {
  repositories: [{
    schemaVersion: 1,
    bindingId: 'packed-mission-repository',
    idempotencyKey: 'packed-host-repository-provider:v1',
    root: ${JSON.stringify(repositoryRoot)},
    displayName: 'Packed Mission Repository',
    bindings: {
      policyId: 'security/node-package-lifecycle',
      assessmentProfileId: 'security/standard',
      evidenceProtectionId: 'evidence/local-protected',
      dataEgressPolicyId: 'egress/deny-by-default',
      platform: ${JSON.stringify(process.platform)},
      deliveryDestinationIds: [],
    },
  }],
}
const hostFiber = ctx.plugin(hostRepositories.default, repositoryConfig)
await hostFiber
const firstBinding = await ctx.securityAssuranceHostRepositories.resolve('packed-mission-repository')
if (!/^repo-[0-9a-f-]{36}$/.test(firstBinding?.repositoryId ?? '')) {
  throw new Error('Host Repository Provider did not expose a path-free Repository binding')
}
if (JSON.stringify(firstBinding).includes(${JSON.stringify(repositoryRoot)})) {
  throw new Error('Host Repository Provider exposed its configured root')
}
await hostFiber.dispose()
if (ctx.reflect.get('securityAssuranceHostRepositories') !== undefined) {
  throw new Error('Host Repository Provider disposal did not remove its Service')
}
const restartedHostFiber = ctx.plugin(hostRepositories.default, repositoryConfig)
await restartedHostFiber
const restartedBinding = await ctx.securityAssuranceHostRepositories.resolve('packed-mission-repository')
if (restartedBinding?.repositoryId !== firstBinding.repositoryId) {
  throw new Error('Host Repository Provider restart did not preserve the registered Repository')
}
await restartedHostFiber.dispose()
await fiber.dispose()
if (ctx.reflect.get('securityAssurance') !== undefined) {
  throw new Error('Fiber disposal did not remove securityAssurance')
}
process.stdout.write(JSON.stringify({
  packedImport: 'PASS',
  lifecycle: 'PASS',
  hostRepositoryProvider: 'PASS',
  repositoryId: firstBinding.repositoryId,
}))
`, 'utf8')

  const probe = await execute(process.execPath, [probePath], {
    cwd: consumerRoot,
    windowsHide: true,
  })
  const result = JSON.parse(probe.stdout)
  if (result.packedImport !== 'PASS' || result.lifecycle !== 'PASS') {
    throw new Error('packed smoke probe returned an invalid result')
  }

  await executeNpm([
    '--cache', npmCache,
    'install',
    pathToFileURL(controlPlaneTarball).href,
    '--ignore-scripts',
    '--no-audit',
    '--no-fund',
    '--legacy-peer-deps',
  ], {
    cwd: consumerRoot,
    windowsHide: true,
  })
  const adapterProbePath = join(consumerRoot, 'adapter-probe.mjs')
  await writeFile(adapterProbePath, `
const adapter = await import('dsh-security-assurance/control-plane-provider')
if (adapter.SECURITY_ASSURANCE_CONTROL_PLANE_DESCRIPTOR.providerId !== 'dsh/security-assurance') {
  throw new Error('packed Control Plane Provider descriptor is invalid')
}
const { Context } = await import('@deepseek-ai/cordis')
const importContext = new Context()
if (importContext.reflect.get('securityAssurance') !== undefined
  || importContext.reflect.get('engineeringControlPlane') !== undefined) {
  throw new Error('Control Plane Provider import activated a Service')
}
const SecurityAssuranceService = (await import('dsh-security-assurance')).default
const EngineeringControlPlane = (await import('dsh-engineering-control-plane')).default
const SubagentRuntime = (await import('@deepseek-ai/dsh-subagent')).default
const LocalSubprocessRuntime = (await import('@deepseek-ai/dsh-subprocess-local')).default

const outputs = {
  planner: {
    schemaVersion: 1,
    outcome: 'planned',
    summary: 'Run the packed dual-plugin fixture.',
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
    summary: 'Packed Host verification completed.',
    findings: [],
  },
  reviewer: {
    schemaVersion: 1,
    outcome: 'reviewed',
    summary: 'No blocking engineering finding remains.',
    findings: [],
  },
}
const notApplicable = { mode: 'not_applicable', reason: 'Not required by packed integration.' }

function registerScriptedProvider(ctx, prefix) {
  let sequence = 0
  return ctx.subagents.registerProvider({
    name: 'spawn',
    capabilities: { outputSchema: true, depthLimit: true, toolFilter: true, persona: true },
    inheritsParentContext: false,
    async start(request) {
      const role = request.label?.split(' · ')[0]
      if (typeof role !== 'string' || !(role in outputs)) {
        throw new Error('Packed scripted Provider received an unknown Role')
      }
      return {
        id: prefix + '-' + (++sequence),
        localAgent: undefined,
        result: Promise.resolve({ output: [], structured: outputs[role], stopReason: 'completed' }),
        dispose: () => Promise.resolve(),
      }
    },
  })
}

function controlPlaneConfig(dshHome, activation) {
  return {
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
      root: ${JSON.stringify(repositoryRoot)},
      verificationProfile: 'packed-integration',
      assuranceProviders: [{
        providerId: adapter.SECURITY_ASSURANCE_CONTROL_PLANE_DESCRIPTOR.providerId,
        providerVersion: adapter.SECURITY_ASSURANCE_CONTROL_PLANE_DESCRIPTOR.providerVersion,
        activation,
        configuration: { repositoryId: ${JSON.stringify(result.repositoryId)} },
      }],
    }],
    verificationProfiles: [{
      name: 'packed-integration',
      categories: {
        functional: notApplicable,
        negative: notApplicable,
        regression: notApplicable,
        security: notApplicable,
      },
    }],
  }
}

async function waitForTerminalMission(ctx, agent, missionId) {
  const deadline = Date.now() + 20000
  let snapshot = await ctx.engineeringControlPlane.status(
    agent,
    missionId,
    new AbortController().signal,
  )
  while (!['APPROVED', 'REWORK_REQUIRED', 'BLOCKED', 'CANCELLED'].includes(snapshot.status)) {
    if (Date.now() >= deadline) throw new Error('Packed Mission did not settle')
    await new Promise(resolve => setTimeout(resolve, 20))
    snapshot = await ctx.engineeringControlPlane.status(
      agent,
      missionId,
      new AbortController().signal,
    )
  }
  return snapshot
}

async function runUnavailablePolicy(activation, dshHome) {
  const ctx = new Context()
  const subprocessFiber = await ctx.plugin(LocalSubprocessRuntime)
  const subagentFiber = await ctx.plugin(SubagentRuntime)
  const disposeProvider = registerScriptedProvider(ctx, 'packed-' + activation)
  const controlPlaneFiber = await ctx.plugin(
    EngineeringControlPlane,
    controlPlaneConfig(dshHome, activation),
  )
  await ctx.engineeringControlPlane.whenReady()
  try {
    const agent = {
      id: 'packed-' + activation + '-agent',
      session: { header: { cwd: ${JSON.stringify(repositoryRoot)} } },
    }
    if (activation === 'required') {
      let rejected = false
      try {
        await ctx.engineeringControlPlane.start(agent, {
          idempotencyKey: 'packed-required-absent:start:1',
          objective: 'Reject a missing required Security Provider',
        }, new AbortController().signal)
      } catch (error) {
        rejected = String(error).includes('Required Assurance Provider')
      }
      if (!rejected) throw new Error('Missing required packed Provider did not fail closed')
      return
    }
    const receipt = await ctx.engineeringControlPlane.start(agent, {
      idempotencyKey: 'packed-' + activation + ':start:1',
      objective: 'Run without an unselected Security Provider',
    }, new AbortController().signal)
    const snapshot = await waitForTerminalMission(ctx, agent, receipt.missionId)
    if (snapshot.status !== 'APPROVED' || snapshot.assuranceProviderInvocations?.length !== 0) {
      throw new Error('Packed ' + activation + ' policy did not remain standalone')
    }
  } finally {
    await controlPlaneFiber.dispose()
    disposeProvider()
    await subagentFiber.dispose()
    await subprocessFiber.dispose()
  }
}

await runUnavailablePolicy('disabled', ${JSON.stringify(join(temporaryRoot, 'disabled-home'))})
await runUnavailablePolicy('when-available', ${JSON.stringify(join(temporaryRoot, 'when-available-home'))})
await runUnavailablePolicy('required', ${JSON.stringify(join(temporaryRoot, 'required-absent-home'))})

const ctx = new Context()
const subprocessFiber = await ctx.plugin(LocalSubprocessRuntime)
const subagentFiber = await ctx.plugin(SubagentRuntime)
const disposeProvider = registerScriptedProvider(ctx, 'packed-integrated')
const securityFiber = await ctx.plugin(SecurityAssuranceService, { dshHome: ${JSON.stringify(securityHome)} })
await ctx.securityAssurance.whenReady()
const controlPlaneFiber = await ctx.plugin(
  EngineeringControlPlane,
  controlPlaneConfig(${JSON.stringify(securityHome)}, 'required'),
)
await ctx.engineeringControlPlane.whenReady()
const adapterFiber = await ctx.plugin(adapter.default)
let adapterDisposed = false
let approvedMissionId
try {
  const agent = {
    id: 'packed-integration-agent',
    session: { header: { cwd: ${JSON.stringify(repositoryRoot)} } },
  }
  const receipt = await ctx.engineeringControlPlane.start(agent, {
    idempotencyKey: 'packed-integration:start:1',
    objective: 'Prove packed Security Assurance and Control Plane integration',
  }, new AbortController().signal)
  const snapshot = await waitForTerminalMission(ctx, agent, receipt.missionId)
  if (snapshot.status !== 'APPROVED' || snapshot.gate?.kind !== 'approved') {
    throw new Error('Packed required Security Provider did not approve the safe fixture: '
      + JSON.stringify({ status: snapshot.status, gate: snapshot.gate, results: snapshot.assuranceResults }))
  }
  if (snapshot.assuranceResults?.[0]?.outcome !== 'satisfied') {
    throw new Error('Packed required Security Submission was not imported as satisfied assurance')
  }
  approvedMissionId = receipt.missionId
  await adapterFiber.dispose()
  adapterDisposed = true
  const preserved = await ctx.engineeringControlPlane.status(
    agent,
    receipt.missionId,
    new AbortController().signal,
  )
  if (preserved.status !== 'APPROVED') {
    throw new Error('Adapter unload changed an already approved Mission')
  }
  let rejected = false
  try {
    await ctx.engineeringControlPlane.start(agent, {
      idempotencyKey: 'packed-integration:after-adapter-unload:1',
      objective: 'Reject new work after the required Adapter unloads',
    }, new AbortController().signal)
  } catch (error) {
    rejected = String(error).includes('Required Assurance Provider')
  }
  if (!rejected) throw new Error('Adapter unload did not remove its Provider registration')
} finally {
  if (!adapterDisposed) await adapterFiber.dispose()
  await controlPlaneFiber.dispose()
  await securityFiber.dispose()
  disposeProvider()
  await subagentFiber.dispose()
  await subprocessFiber.dispose()
}
if (approvedMissionId === undefined) throw new Error('Packed integrated Mission identity was not recorded')

const restartedContext = new Context()
const restartedSubprocessFiber = await restartedContext.plugin(LocalSubprocessRuntime)
const restartedSubagentFiber = await restartedContext.plugin(SubagentRuntime)
const disposeRestartedProvider = registerScriptedProvider(restartedContext, 'packed-restarted')
const restartedSecurityFiber = await restartedContext.plugin(
  SecurityAssuranceService,
  { dshHome: ${JSON.stringify(securityHome)} },
)
await restartedContext.securityAssurance.whenReady()
const restartedControlPlaneFiber = await restartedContext.plugin(
  EngineeringControlPlane,
  controlPlaneConfig(${JSON.stringify(securityHome)}, 'required'),
)
await restartedContext.engineeringControlPlane.whenReady()
const restartedAdapterFiber = await restartedContext.plugin(adapter.default)
try {
  const restartedAgent = {
    id: 'packed-integration-agent',
    session: { header: { cwd: ${JSON.stringify(repositoryRoot)} } },
  }
  const recovered = await restartedContext.engineeringControlPlane.status(
    restartedAgent,
    approvedMissionId,
    new AbortController().signal,
  )
  if (recovered.status !== 'APPROVED' || recovered.assuranceResults?.[0]?.outcome !== 'satisfied') {
    throw new Error('Packed profile restart did not recover the approved dual-plugin Mission')
  }
  const restartedReceipt = await restartedContext.engineeringControlPlane.start(restartedAgent, {
    idempotencyKey: 'packed-integration:restart:1',
    objective: 'Prove the required Adapter works after full profile restart',
  }, new AbortController().signal)
  const restartedSnapshot = await waitForTerminalMission(
    restartedContext,
    restartedAgent,
    restartedReceipt.missionId,
  )
  if (restartedSnapshot.status !== 'APPROVED'
    || restartedSnapshot.assuranceResults?.[0]?.outcome !== 'satisfied') {
    throw new Error('Packed restarted required Security Provider did not approve the safe fixture')
  }
} finally {
  await restartedAdapterFiber.dispose()
  await restartedControlPlaneFiber.dispose()
  await restartedSecurityFiber.dispose()
  disposeRestartedProvider()
  await restartedSubagentFiber.dispose()
  await restartedSubprocessFiber.dispose()
}
process.stdout.write(JSON.stringify({
  adapterImport: 'PASS',
  sideEffectFree: 'PASS',
  hostPolicyMatrix: 'PASS',
  requiredIntegration: 'PASS',
  unloadAndRestart: 'PASS',
}))
`, 'utf8')
  const adapterProbe = await execute(process.execPath, [adapterProbePath], {
    cwd: consumerRoot,
    windowsHide: true,
  })
  const adapterResult = JSON.parse(adapterProbe.stdout)
  if (adapterResult.adapterImport !== 'PASS' || adapterResult.sideEffectFree !== 'PASS') {
    throw new Error('packed Adapter smoke probe returned an invalid result')
  }

  const installedManifest = JSON.parse(await readFile(
    join(consumerRoot, 'node_modules', 'dsh-security-assurance', 'package.json'),
    'utf8',
  ))
  process.stdout.write(`${JSON.stringify({
    artifact: filename,
    controlPlaneArtifact: controlPlaneFilename,
    packageVersion: installedManifest.version,
    packedImport: result.packedImport,
    lifecycle: result.lifecycle,
    hostRepositoryProvider: result.hostRepositoryProvider,
    ...adapterResult,
  })}\n`)
} finally {
  await rm(temporaryRoot, { recursive: true, force: true })
}
