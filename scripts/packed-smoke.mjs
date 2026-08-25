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
const failedRepositoryRoot = join(temporaryRoot, 'failed-repository')
const indeterminateRepositoryRoot = join(temporaryRoot, 'indeterminate-repository')
const securityHome = join(temporaryRoot, 'dsh-home')

function executeNpm(args, options) {
  if (process.platform === 'win32') {
    const npmCli = join(dirname(process.execPath), 'node_modules', 'npm', 'bin', 'npm-cli.js')
    return execute(process.execPath, [npmCli, ...args], options)
  }
  return execute('npm', args, options)
}

async function createFixtureRepository(root, manifest, commitMessage) {
  await mkdir(root)
  await writeFile(join(root, 'package.json'), `${JSON.stringify(manifest, null, 2)}\n`, 'utf8')
  await writeFile(join(root, 'index.js'), 'export const answer = 42\n', 'utf8')
  await execute('git', ['init', '-b', 'main'], { cwd: root, windowsHide: true })
  await execute('git', ['config', 'user.email', 'fixture@example.invalid'], {
    cwd: root,
    windowsHide: true,
  })
  await execute('git', ['config', 'user.name', 'Fixture'], {
    cwd: root,
    windowsHide: true,
  })
  await execute('git', ['add', '.'], { cwd: root, windowsHide: true })
  await execute('git', ['commit', '-m', commitMessage], { cwd: root, windowsHide: true })
}

try {
  await mkdir(artifactRoot)
  await mkdir(consumerRoot)
  await createFixtureRepository(repositoryRoot, {
    name: 'dsh-packed-integration-fixture',
    version: '1.0.0',
    type: 'module',
  }, 'packed integration baseline')
  await createFixtureRepository(failedRepositoryRoot, {
    name: 'dsh-packed-failed-fixture',
    version: '1.0.0',
    type: 'module',
    scripts: { postinstall: 'node setup.js' },
  }, 'packed failed baseline')
  await createFixtureRepository(indeterminateRepositoryRoot, {
    name: 'dsh-packed-indeterminate-fixture',
    version: '1.0.0',
    type: 'module',
    scripts: { postinstall: 42 },
  }, 'packed indeterminate baseline')

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
      '@deepseek-ai/dsh-api-gateway': '0.1.1-rc.2',
      '@deepseek-ai/dsh-client-locale': '0.1.1-rc.2',
      '@deepseek-ai/dsh-client-runtime': '0.1.1-rc.2',
      '@deepseek-ai/dsh-client-ui-layout': '0.1.1-rc.2',
      '@deepseek-ai/dsh-client-ui-primitives': '0.1.1-rc.2',
      '@deepseek-ai/dsh-client-ui-sidebar': '0.1.1-rc.2',
      '@deepseek-ai/dsh-client-ui-slots': '0.1.1-rc.2',
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
      '@deepseek-ai/dsh-typert-registry': '0.1.1-rc.2',
      '@deepseek-ai/dsh-user-approval': '0.1.1-rc.2',
      '@deepseek-ai/schemastery': '3.18.1',
      'dsh-security-assurance': pathToFileURL(tarball).href,
      'react': '^18.2.0',
      'react-dom': '^18.2.0',
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
if (
  typeof contracts.listAssessmentsRequestSchema?.parse !== 'function'
  || typeof contracts.assessmentListItemV1Schema?.parse !== 'function'
  || typeof contracts.assessmentListPageV1Schema?.parse !== 'function'
  || typeof contracts.assessmentListResultSchema?.parse !== 'function'
  || typeof contracts.listFindingsRequestSchema?.parse !== 'function'
  || typeof contracts.findingListResultSchema?.parse !== 'function'
  || typeof contracts.getFindingRequestSchema?.parse !== 'function'
  || typeof contracts.findingDetailViewV1Schema?.parse !== 'function'
  || typeof contracts.findingDetailResultSchema?.parse !== 'function'
  || typeof contracts.getEvidenceViewRequestSchema?.parse !== 'function'
  || typeof contracts.evidenceViewV1Schema?.parse !== 'function'
  || typeof contracts.evidenceViewResultSchema?.parse !== 'function'
  || typeof contracts.recordRiskDecisionRequestSchema?.parse !== 'function'
  || typeof contracts.availableRiskDecisionOptionV1Schema?.parse !== 'function'
  || typeof contracts.assessmentAvailableActionV1Schema?.parse !== 'function'
  || typeof contracts.assessmentBlockedRecoveryV1Schema?.parse !== 'function'
  || typeof contracts.riskDecisionAttestationV1Schema?.parse !== 'function'
  || typeof contracts.riskDecisionRecordV1Schema?.parse !== 'function'
  || typeof contracts.riskDecisionReceiptResultSchema?.parse !== 'function'
  || typeof contracts.getExportRequestSchema?.parse !== 'function'
  || typeof contracts.requestExportRequestSchema?.parse !== 'function'
  || typeof contracts.exportPreviewV1Schema?.parse !== 'function'
  || typeof contracts.exportStatusV1Schema?.parse !== 'function'
  || typeof contracts.exportDownloadV1Schema?.parse !== 'function'
  || typeof contracts.exportRequestReceiptResultSchema?.parse !== 'function'
  || typeof contracts.exportViewResultSchema?.parse !== 'function'
  || contracts.CRITICAL_BREAK_GLASS_CONTROL_ID !== 'security/critical-break-glass-v1'
) {
  throw new Error('packed Finding, Evidence, Risk Decision, and Export contracts are incomplete')
}
const analyzer = await import('dsh-security-assurance/analyzer')
if (
  typeof analyzer.parseAnalyzerDescriptorV1 !== 'function'
  || typeof analyzer.analyzerContributionV1Schema?.parse !== 'function'
  || typeof analyzer.analyzerCandidateFindingV1Schema?.parse !== 'function'
  || typeof analyzer.analyzerQualificationRecordV1Schema?.parse !== 'function'
) {
  throw new Error('packed Analyzer Contract Entry is incomplete')
}
const root = await import('dsh-security-assurance')
if ('SecurityPersistence' in root || 'freezeSubject' in root || 'SecurityAuthorityResolver' in root) {
  throw new Error('root export leaked a package-private implementation boundary')
}
const modelTools = await import('dsh-security-assurance/tools')
if (
  typeof modelTools.default?.apply !== 'function'
  || modelTools.default?.name !== 'dsh-security-assurance-tools'
  || JSON.stringify(modelTools.default?.inject) !== JSON.stringify([
    'agents', 'securityAssurance', 'tools',
  ])
  || 'resolveTrustedInvocation' in modelTools
  || 'SecurityAuthorityResolver' in modelTools
) {
  throw new Error('packed model Tool entry is incomplete or leaked authority minting')
}
const hostRepositories = await import('dsh-security-assurance/host-repository-provider')
if ('resolveTrustedInvocation' in hostRepositories || 'SecurityAuthorityResolver' in hostRepositories) {
  throw new Error('Host Repository Provider export leaked authority minting')
}
const workbenchRemote = await import('dsh-security-assurance/workbench-remote')
const typertContribution = await import('dsh-security-assurance/typert')
const clientRemoteContribution = await import('dsh-security-assurance/remote')
if (
  typeof workbenchRemote.default !== 'function'
  || typertContribution.TYPERT?.invocations?.length !== 18
    || clientRemoteContribution.default?.descriptors?.length !== 18
    || !clientRemoteContribution.default.descriptors.some(descriptor =>
      descriptor.method === 'getHealth')
    || !clientRemoteContribution.default.descriptors.some(descriptor =>
      descriptor.method === 'getBundleManifest')
    || !clientRemoteContribution.default.descriptors.some(descriptor =>
      descriptor.method === 'getExport')
    || !clientRemoteContribution.default.descriptors.some(descriptor =>
      descriptor.method === 'requestExport')
    || !clientRemoteContribution.default.descriptors.some(descriptor =>
      descriptor.method === 'getRepository')
    || !clientRemoteContribution.default.descriptors.some(descriptor =>
      descriptor.method === 'listRepositories')
    || !clientRemoteContribution.default.descriptors.some(descriptor =>
      descriptor.method === 'getCatalog')
    || !clientRemoteContribution.default.descriptors.some(descriptor =>
      descriptor.method === 'startAssessment')
  || !clientRemoteContribution.default.descriptors.some(descriptor =>
    descriptor.method === 'listAssessments')
  || !clientRemoteContribution.default.descriptors.some(descriptor =>
    descriptor.method === 'listFindings')
  || !clientRemoteContribution.default.descriptors.some(descriptor =>
    descriptor.method === 'getFinding')
  || !clientRemoteContribution.default.descriptors.some(descriptor =>
    descriptor.method === 'getEvidenceView')
  || !clientRemoteContribution.default.descriptors.some(descriptor =>
    descriptor.method === 'discloseEvidence')
  || !clientRemoteContribution.default.descriptors.some(descriptor =>
    descriptor.method === 'waitForAssessmentRevision')
  || !clientRemoteContribution.default.descriptors.some(descriptor =>
    descriptor.method === 'resumeAssessment')
  || !clientRemoteContribution.default.descriptors.some(descriptor =>
    descriptor.method === 'cancelAssessment')
  || typertContribution.TYPERT.invocations.some(invocation =>
    invocation.parameters[0]?.wire !== 'securityAssuranceWorkbenchContextId'
      || invocation.parameters[0]?.lookup !== 'securityAssuranceWorkbenchContext'
      || invocation.parameters[0]?.codec?.mode !== 'strict')
) {
  throw new Error('packed Workbench Remote Typert artifacts are incomplete or non-strict')
}
const cordisClientRuntime = await import('@deepseek-ai/cordis')
const reactClientRuntime = await import('react')
const reactJsxRuntime = await import('react/jsx-runtime')
const primitiveClientRuntime = {
  IconCloseOutline16() { return null },
  IconDataOutline16() { return null },
}
let clientRegistration
globalThis.window = {
  __ModuleLoader__: {
    load(registration) { clientRegistration = registration },
  },
}
await import('dsh-security-assurance/client')
delete globalThis.window
if (clientRegistration?.id !== 'dsh-security-assurance') {
  throw new Error('packed Workbench Client did not register with the Harness module loader')
}
const workbenchClient = clientRegistration.factory(specifier => {
  if (specifier === '@deepseek-ai/cordis') return cordisClientRuntime
  if (specifier === 'react') return reactClientRuntime
  if (specifier === 'react/jsx-runtime') return reactJsxRuntime
  if (specifier === '@deepseek-ai/dsh-client-ui-primitives') return primitiveClientRuntime
  throw new Error('packed Workbench Client requested an undeclared external: ' + specifier)
})
if (
  typeof workbenchClient.apply !== 'function'
  || workbenchClient.inject?.length !== 3
  || workbenchClient.inject[0] !== 'remote'
  || workbenchClient.inject[1] !== 'slots'
  || workbenchClient.inject[2] !== 'locale'
  || typeof workbenchClient.SecurityAssuranceWorkbenchController !== 'function'
    || typeof workbenchClient.SecurityAssuranceWorkbenchController.prototype.loadMoreAssessments !== 'function'
    || typeof workbenchClient.SecurityAssuranceWorkbenchController.prototype.openRuntimeHealth !== 'function'
    || typeof workbenchClient.SecurityAssuranceWorkbenchController.prototype.refreshRuntimeHealth !== 'function'
    || typeof workbenchClient.SecurityAssuranceWorkbenchController.prototype.openBundle !== 'function'
    || typeof workbenchClient.SecurityAssuranceWorkbenchController.prototype.previewExport !== 'function'
    || typeof workbenchClient.SecurityAssuranceWorkbenchController.prototype.requestExport !== 'function'
    || typeof workbenchClient.SecurityAssuranceWorkbenchController.prototype.downloadExport !== 'function'
    || typeof workbenchClient.SecurityAssuranceWorkbenchController.prototype.backToAssessmentDetail !== 'function'
    || typeof workbenchClient.SecurityAssuranceWorkbenchController.prototype.openRepositories !== 'function'
    || typeof workbenchClient.SecurityAssuranceWorkbenchController.prototype.selectRepository !== 'function'
    || typeof workbenchClient.SecurityAssuranceWorkbenchController.prototype.requestStartPreflight !== 'function'
    || typeof workbenchClient.SecurityAssuranceWorkbenchController.prototype.cancelStartPreflight !== 'function'
    || typeof workbenchClient.SecurityAssuranceWorkbenchController.prototype.confirmStartAssessment !== 'function'
    || typeof workbenchClient.SecurityAssuranceWorkbenchController.prototype.backToAssessmentSelection !== 'function'
  || typeof workbenchClient.SecurityAssuranceWorkbenchController.prototype.openFindings !== 'function'
  || typeof workbenchClient.SecurityAssuranceWorkbenchController.prototype.loadMoreFindings !== 'function'
  || typeof workbenchClient.SecurityAssuranceWorkbenchController.prototype.selectFinding !== 'function'
  || typeof workbenchClient.SecurityAssuranceWorkbenchController.prototype.backToFindingList !== 'function'
  || typeof workbenchClient.SecurityAssuranceWorkbenchController.prototype.recordRiskDecision !== 'function'
  || typeof workbenchClient.SecurityAssuranceWorkbenchController.prototype.resumeAssessment !== 'function'
  || typeof workbenchClient.SecurityAssuranceWorkbenchController.prototype.cancelAssessment !== 'function'
  || typeof workbenchClient.SecurityAssuranceWorkbenchController.prototype.selectEvidence !== 'function'
  || typeof workbenchClient.SecurityAssuranceWorkbenchController.prototype.discloseEvidence !== 'function'
  || typeof workbenchClient.SecurityAssuranceWorkbenchController.prototype.hideEvidenceDisclosure !== 'function'
  || typeof workbenchClient.SecurityAssuranceWorkbenchController.prototype.backToFindingDetail !== 'function'
) {
  throw new Error('packed Workbench Client entry is incomplete')
}
const { Context } = await import('@deepseek-ai/cordis')
const agentRuntime = await import('@deepseek-ai/dsh-agent')
const AgentRegistry = agentRuntime.default
const { Inbox } = agentRuntime
const { createUserMessage } = await import('@deepseek-ai/dsh-llm')
const { Session, SessionId } = await import('@deepseek-ai/dsh-session')
const SystemPrompt = (await import('@deepseek-ai/dsh-system-prompt')).default
const ToolRuntime = (await import('@deepseek-ai/dsh-tools')).default
const TypertRegistry = (await import('@deepseek-ai/dsh-typert-registry')).default
const TypertGatewayService = (await import('@deepseek-ai/dsh-api-gateway')).default
const ctx = new Context()
if (ctx.reflect.get('securityAssurance') !== undefined) {
  throw new Error('package import activated the Service')
}
const systemPromptFiber = ctx.plugin(SystemPrompt)
await systemPromptFiber
const agentFiber = ctx.plugin(AgentRegistry)
await agentFiber
const toolRuntimeFiber = ctx.plugin(ToolRuntime)
await toolRuntimeFiber
const typertFiber = ctx.plugin(TypertRegistry)
await typertFiber
const fiber = ctx.plugin(root.default, { dshHome: ${JSON.stringify(securityHome)} })
await fiber
if (ctx.reflect.get('securityAssurance') === undefined) {
  throw new Error('Cordis activation did not mount securityAssurance')
}
if (
  typeof ctx.securityAssurance.registerAnalyzer !== 'function'
  || typeof ctx.securityAssurance.registerAnalyzerQualification !== 'function'
  || typeof ctx.securityAssurance.listAssessments !== 'function'
  || typeof ctx.securityAssurance.getFinding !== 'function'
  || typeof ctx.securityAssurance.getEvidenceView !== 'function'
  || typeof ctx.securityAssurance.recordRiskDecision !== 'function'
  || typeof ctx.securityAssurance.requestExport !== 'function'
  || typeof ctx.securityAssurance.getExport !== 'function'
) {
  throw new Error('Cordis activation did not expose Finding/Evidence/Risk Decision or local Analyzer composition')
}
const modelToolsFiber = ctx.plugin(modelTools.default)
await modelToolsFiber
const packedStartTool = ctx.tools.get('security_assessment_start')
const packedStatusTool = ctx.tools.get('security_assessment_status')
const packedFindingsTool = ctx.tools.get('security_assessment_findings')
const packedResumeTool = ctx.tools.get('security_assessment_resume')
const packedCancelTool = ctx.tools.get('security_assessment_cancel')
const packedExportTool = ctx.tools.get('security_assessment_export')
const packedStartMode = ctx.tools.executionMode({
  callId: 'packed-security-start-mode',
  name: 'security_assessment_start',
  arguments: {
    idempotency_key: 'packed-security-start-mode-v1',
    repository_id: 'repo-00000000-0000-0000-0000-000000000000',
    subject: { kind: 'workspace_snapshot' },
    assessment_mode: 'REPOSITORY',
    assessment_profile_id: 'security/standard',
    target: { kind: 'repository' },
    requested_stronger_control_ids: [],
  },
  signal: new AbortController().signal,
})
const packedStatusMode = ctx.tools.executionMode({
  callId: 'packed-security-status-mode',
  name: 'security_assessment_status',
  arguments: { assessment_id: 'asm-00000000-0000-0000-0000-000000000000' },
  signal: new AbortController().signal,
})
const packedFindingsMode = ctx.tools.executionMode({
  callId: 'packed-security-findings-mode',
  name: 'security_assessment_findings',
  arguments: {
    assessment_id: 'asm-00000000-0000-0000-0000-000000000000',
    limit: 20,
  },
  signal: new AbortController().signal,
})
const packedResumeMode = ctx.tools.executionMode({
  callId: 'packed-security-resume-mode',
  name: 'security_assessment_resume',
  arguments: {
    assessment_id: 'asm-00000000-0000-0000-0000-000000000000',
    expected_assessment_revision: 3,
    idempotency_key: 'packed-security-resume-mode-v1',
    reason: { code: 'OPERATOR_RETRY', summary: 'Retry the interrupted assessment.' },
  },
  signal: new AbortController().signal,
})
const packedCancelMode = ctx.tools.executionMode({
  callId: 'packed-security-cancel-mode',
  name: 'security_assessment_cancel',
  arguments: {
    assessment_id: 'asm-00000000-0000-0000-0000-000000000000',
    expected_assessment_revision: 3,
    idempotency_key: 'packed-security-cancel-mode-v1',
    reason: { code: 'OPERATOR_REQUEST', summary: 'Cancel the current assessment.' },
  },
  signal: new AbortController().signal,
})
const packedExportMode = ctx.tools.executionMode({
  callId: 'packed-security-export-mode',
  name: 'security_assessment_export',
  arguments: {
    assessment_id: 'asm-00000000-0000-0000-0000-000000000000',
    expected_assessment_revision: 3,
    idempotency_key: 'packed-security-export-mode-v1',
    export_profile_id: 'security/export/internal-json-v1',
    delivery_destination_id: 'delivery/local-audit',
  },
  signal: new AbortController().signal,
})
if (
  packedStartTool?.name !== 'security_assessment_start'
  || packedStatusTool?.name !== 'security_assessment_status'
  || packedFindingsTool?.name !== 'security_assessment_findings'
  || packedResumeTool?.name !== 'security_assessment_resume'
  || packedCancelTool?.name !== 'security_assessment_cancel'
  || packedExportTool?.name !== 'security_assessment_export'
  || packedStartMode.kind !== 'exclusive'
  || packedStatusMode.kind !== 'parallel'
  || packedFindingsMode.kind !== 'parallel'
  || packedResumeMode.kind !== 'exclusive'
  || packedCancelMode.kind !== 'exclusive'
  || packedExportMode.kind !== 'exclusive'
) {
  throw new Error('packed model Tool entry did not register all six operation modes')
}
const packedAgentlessFindings = await ctx.tools.execute({
  callId: 'packed-security-findings-agentless',
  name: 'security_assessment_findings',
  arguments: {
    assessment_id: 'asm-00000000-0000-0000-0000-000000000000',
    limit: 20,
  },
  signal: new AbortController().signal,
})
if (packedAgentlessFindings.error?.info?.code !== 'SECURITY_TOOL_AGENT_REQUIRED') {
  throw new Error('packed Finding tool did not enforce live Harness session authority')
}
const disposeTypertContribution = ctx.typert.register(typertContribution.TYPERT)
const workbenchFiber = ctx.plugin(workbenchRemote.default, {
  resolveAuthorityContext(contextId) {
    if (contextId !== 'packed-workbench-context-v1') return undefined
    return {
      principalId: 'packed-workbench-operator',
      permissions: [
        'health:read',
        'repository:read',
        'assessment:read',
        'risk:decide',
        'export:read',
        'export:request',
        'export:download',
      ],
    }
  },
})
await workbenchFiber
const gatewayFiber = ctx.plugin(TypertGatewayService)
await gatewayFiber
const assessmentList = await ctx.typertGateway.invoke({
  namespace: 'securityAssuranceWorkbench',
  method: 'listAssessments',
  args: {
    securityAssuranceWorkbenchContextId: 'packed-workbench-context-v1',
    request: { schemaVersion: 1, limit: 50 },
  },
})
if (
  assessmentList?.ok !== true
  || assessmentList.value?.assessments?.length !== 0
  || typeof assessmentList.value?.consistencyWatermark !== 'string'
) {
  throw new Error('packed strict Workbench Remote did not list redacted Assessments')
}
const runtimeHealth = await ctx.typertGateway.invoke({
  namespace: 'securityAssuranceWorkbench',
  method: 'getHealth',
  args: {
    securityAssuranceWorkbenchContextId: 'packed-workbench-context-v1',
    request: { schemaVersion: 1 },
  },
})
if (
  runtimeHealth?.ok !== true
  || runtimeHealth.value?.state !== 'READY'
  || runtimeHealth.value?.admission?.queries !== true
  || !runtimeHealth.value?.checks?.some(check => check.id === 'persistence.sqlite')
) {
  throw new Error('packed strict Workbench Remote did not return Runtime Health')
}
const missingBundle = await ctx.typertGateway.invoke({
  namespace: 'securityAssuranceWorkbench',
  method: 'getBundleManifest',
  args: {
    securityAssuranceWorkbenchContextId: 'packed-workbench-context-v1',
    request: {
      schemaVersion: 1,
      assessmentId: 'asm-00000000-0000-0000-0000-000000000000',
    },
  },
})
const missingRepository = await ctx.typertGateway.invoke({
  namespace: 'securityAssuranceWorkbench',
  method: 'getRepository',
  args: {
    securityAssuranceWorkbenchContextId: 'packed-workbench-context-v1',
    request: {
      schemaVersion: 1,
      repositoryId: 'repo-00000000-0000-0000-0000-000000000000',
    },
  },
})
const missingExportPreview = await ctx.typertGateway.invoke({
  namespace: 'securityAssuranceWorkbench',
  method: 'getExport',
  args: {
    securityAssuranceWorkbenchContextId: 'packed-workbench-context-v1',
    request: {
      schemaVersion: 1,
      kind: 'PREVIEW',
      assessmentId: 'asm-00000000-0000-0000-0000-000000000000',
      exportProfileId: 'security/export/internal-json-v1',
      deliveryDestinationId: 'delivery/local-audit',
    },
  },
})
const missingExportRequest = await ctx.typertGateway.invoke({
  namespace: 'securityAssuranceWorkbench',
  method: 'requestExport',
  args: {
    securityAssuranceWorkbenchContextId: 'packed-workbench-context-v1',
    request: {
      schemaVersion: 1,
      idempotencyKey: 'packed-missing-export-request-v1',
      assessmentId: 'asm-00000000-0000-0000-0000-000000000000',
      expectedAssessmentRevision: 1,
      exportProfileId: 'security/export/internal-json-v1',
      deliveryDestinationId: 'delivery/local-audit',
    },
  },
})
const missingExportDownload = await ctx.typertGateway.invoke({
  namespace: 'securityAssuranceWorkbench',
  method: 'getExport',
  args: {
    securityAssuranceWorkbenchContextId: 'packed-workbench-context-v1',
    request: {
      schemaVersion: 1,
      kind: 'DOWNLOAD',
      exportId: 'export-${'0'.repeat(64)}',
      artifactId: 'export-${'0'.repeat(64)}/artifact',
      expectedDigest: {
        schemaVersion: 1,
        algorithm: 'sha256',
        mediaType: 'application/vnd.dsh.security.export+json',
        byteLength: 1,
        canonicalization: 'raw-bytes',
        value: '${'0'.repeat(64)}',
      },
    },
  },
})
if (
  missingBundle?.ok !== false
  || missingBundle.error?.code !== 'NOT_FOUND'
  || missingRepository?.ok !== false
  || missingRepository.error?.code !== 'NOT_FOUND'
  || missingExportPreview?.ok !== false
  || missingExportPreview.error?.code !== 'NOT_FOUND'
  || missingExportRequest?.ok !== false
  || missingExportRequest.error?.code !== 'NOT_FOUND'
  || missingExportDownload?.ok !== false
  || missingExportDownload.error?.code !== 'NOT_FOUND'
) {
  throw new Error('packed strict Workbench Remote did not delegate Bundle, Repository, and Export operations')
}
const missingAssessment = await ctx.typertGateway.invoke({
  namespace: 'securityAssuranceWorkbench',
  method: 'getAssessment',
  args: {
    securityAssuranceWorkbenchContextId: 'packed-workbench-context-v1',
    request: {
      schemaVersion: 1,
      assessmentId: 'asm-00000000-0000-0000-0000-000000000000',
    },
  },
})
if (missingAssessment?.ok !== false || missingAssessment.error?.code !== 'NOT_FOUND') {
  throw new Error('packed strict Workbench Remote did not delegate to the root Service')
}
const missingFindingList = await ctx.typertGateway.invoke({
  namespace: 'securityAssuranceWorkbench',
  method: 'listFindings',
  args: {
    securityAssuranceWorkbenchContextId: 'packed-workbench-context-v1',
    request: {
      schemaVersion: 1,
      assessmentId: 'asm-00000000-0000-0000-0000-000000000000',
      limit: 50,
    },
  },
})
const missingFinding = await ctx.typertGateway.invoke({
  namespace: 'securityAssuranceWorkbench',
  method: 'getFinding',
  args: {
    securityAssuranceWorkbenchContextId: 'packed-workbench-context-v1',
    request: {
      schemaVersion: 1,
      assessmentId: 'asm-00000000-0000-0000-0000-000000000000',
      assessmentRevision: 1,
      recordId: 'finding-${'0'.repeat(64)}',
      recordRevision: 1,
    },
  },
})
const missingEvidence = await ctx.typertGateway.invoke({
  namespace: 'securityAssuranceWorkbench',
  method: 'getEvidenceView',
  args: {
    securityAssuranceWorkbenchContextId: 'packed-workbench-context-v1',
    request: {
      schemaVersion: 1,
      assessmentId: 'asm-00000000-0000-0000-0000-000000000000',
      assessmentRevision: 1,
      context: {
        kind: 'finding',
        recordId: 'finding-${'0'.repeat(64)}',
        recordRevision: 1,
      },
      evidenceArtifactId: 'evidence/missing',
      evidenceDigest: {
        schemaVersion: 1,
        algorithm: 'sha256',
        mediaType: 'application/vnd.dsh.canonical-json',
        byteLength: 1,
        canonicalization: 'dsh-canonical-json-v1',
        value: '${'0'.repeat(64)}',
      },
      purpose: 'FINDING_TRIAGE',
      viewProfileId: 'security/evidence-view/metadata-only-v1',
    },
  },
})
const missingDisclosure = await ctx.typertGateway.invoke({
  namespace: 'securityAssuranceWorkbench',
  method: 'discloseEvidence',
  args: {
    securityAssuranceWorkbenchContextId: 'packed-workbench-context-v1',
    request: {
      schemaVersion: 1,
      assessmentId: 'asm-00000000-0000-0000-0000-000000000000',
      assessmentRevision: 1,
      context: {
        kind: 'finding',
        recordId: 'finding-${'0'.repeat(64)}',
        recordRevision: 1,
      },
      evidenceArtifactId: 'evidence/missing',
      evidenceDigest: {
        schemaVersion: 1,
        algorithm: 'sha256',
        mediaType: 'application/vnd.dsh.canonical-json',
        byteLength: 1,
        canonicalization: 'dsh-canonical-json-v1',
        value: '${'0'.repeat(64)}',
      },
      purpose: 'VALIDATION_REVIEW',
      viewProfileId: 'security/evidence-view/bounded-json-v1',
    },
  },
})
let boundedEvidenceRejected = false
try {
  await ctx.typertGateway.invoke({
    namespace: 'securityAssuranceWorkbench',
    method: 'getEvidenceView',
    args: {
      securityAssuranceWorkbenchContextId: 'packed-workbench-context-v1',
      request: {
        schemaVersion: 1,
        assessmentId: 'asm-00000000-0000-0000-0000-000000000000',
        assessmentRevision: 1,
        context: {
          kind: 'finding',
          recordId: 'finding-${'0'.repeat(64)}',
          recordRevision: 1,
        },
        evidenceArtifactId: 'evidence/missing',
        evidenceDigest: {
          schemaVersion: 1,
          algorithm: 'sha256',
          mediaType: 'application/vnd.dsh.canonical-json',
          byteLength: 1,
          canonicalization: 'dsh-canonical-json-v1',
          value: '${'0'.repeat(64)}',
        },
        purpose: 'VALIDATION_REVIEW',
        viewProfileId: 'security/evidence-view/bounded-json-v1',
      },
    },
  })
} catch (error) {
  boundedEvidenceRejected = error?.code === 'input-invalid'
}
if (
  missingFindingList?.ok !== false
  || missingFindingList.error?.code !== 'NOT_FOUND'
  || missingFinding?.ok !== false
  || missingFinding.error?.code !== 'NOT_FOUND'
  || missingEvidence?.ok !== false
  || missingEvidence.error?.code !== 'NOT_FOUND'
  || missingDisclosure?.ok !== false
  || missingDisclosure.error?.code !== 'NOT_FOUND'
  || !boundedEvidenceRejected
) {
  throw new Error('packed strict Workbench Remote did not expose separate metadata and disclosure Evidence queries')
}
await workbenchFiber.dispose()
if (ctx.typert.lookups.get('securityAssuranceWorkbenchContext') !== undefined) {
  throw new Error('packed Workbench Remote did not withdraw its authority lookup')
}
await gatewayFiber.dispose()
await disposeTypertContribution()
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
      deliveryDestinationIds: ['delivery/local-audit'],
    },
  }, {
    schemaVersion: 1,
    bindingId: 'packed-failed-repository',
    idempotencyKey: 'packed-host-repository-provider:failed:v1',
    root: ${JSON.stringify(failedRepositoryRoot)},
    displayName: 'Packed Failed Repository',
    bindings: {
      policyId: 'security/node-package-lifecycle',
      assessmentProfileId: 'security/standard',
      evidenceProtectionId: 'evidence/local-protected',
      dataEgressPolicyId: 'egress/deny-by-default',
      platform: ${JSON.stringify(process.platform)},
      deliveryDestinationIds: [],
    },
  }, {
    schemaVersion: 1,
    bindingId: 'packed-indeterminate-repository',
    idempotencyKey: 'packed-host-repository-provider:indeterminate:v1',
    root: ${JSON.stringify(indeterminateRepositoryRoot)},
    displayName: 'Packed Indeterminate Repository',
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
const failedBinding = await ctx.securityAssuranceHostRepositories.resolve('packed-failed-repository')
const indeterminateBinding = await ctx.securityAssuranceHostRepositories.resolve(
  'packed-indeterminate-repository',
)
if (!/^repo-[0-9a-f-]{36}$/.test(firstBinding?.repositoryId ?? '')) {
  throw new Error('Host Repository Provider did not expose a path-free Repository binding')
}
if (JSON.stringify(firstBinding).includes(${JSON.stringify(repositoryRoot)})) {
  throw new Error('Host Repository Provider exposed its configured root')
}
if (!/^repo-[0-9a-f-]{36}$/.test(failedBinding?.repositoryId ?? '')) {
  throw new Error('Host Repository Provider did not expose the failed Repository binding')
}
if (!/^repo-[0-9a-f-]{36}$/.test(indeterminateBinding?.repositoryId ?? '')) {
  throw new Error('Host Repository Provider did not expose the indeterminate Repository binding')
}
const modelSession = Session.create(SessionId('packed-security-model-session'))
const packedModelAgent = {
  id: modelSession.id,
  options: {},
  session: modelSession,
  inbox: new Inbox(modelSession, { inserted() {}, discarded() {}, claimed() {} }),
  get status() { return 'running' },
  ctx: new Context(),
  send() {},
  followup() {},
  steer: () => ({ outcome: Promise.resolve({ status: 'rejected' }) }),
  inject(input) { this.inbox.append('next-step', input) },
  cancel() {},
  runMaintenance: task => task(new AbortController().signal),
  whenIdle: () => Promise.resolve(),
}
const disposePackedModelAgent = ctx.agents.register(packedModelAgent)
let packedModelTurnOpen = false
let packedModelCallSequence = 0
const packedToolValue = (name, result) => {
  if (result.isError || typeof result.value !== 'object' || result.value === null) {
    throw new Error(name + ' failed: ' + (result.error?.info?.code ?? result.error?.message ?? 'invalid result'))
  }
  const rendered = result.content[0]
  if (rendered?.type !== 'text' || JSON.stringify(JSON.parse(rendered.text)) !== JSON.stringify(result.value)) {
    throw new Error(name + ' did not render its canonical structured value')
  }
  return result.value
}
const executePackedModelTool = (name, args) => ctx.agents.withInitiator(
  packedModelAgent,
  () => ctx.tools.execute({
    callId: 'packed-security-live-' + String(++packedModelCallSequence),
    name,
    arguments: args,
    signal: new AbortController().signal,
    agent: packedModelAgent,
  }),
)
try {
  packedModelAgent.inbox.append('next-turn', createUserMessage({
    content: [{ type: 'text', text: 'Run the packed Security Assessment lifecycle.' }],
    source: { kind: 'user' },
  }))
  const admitted = packedModelAgent.inbox.claim('next-turn', 1)
  modelSession.append('turn/start', { turn: 1 })
  packedModelTurnOpen = true
  for (const message of admitted) modelSession.append('user/message', message, { surfaceOp: 'append' })

  const packedStart = packedToolValue('security_assessment_start', await executePackedModelTool(
    'security_assessment_start',
    {
      idempotency_key: 'packed-security-live-start-v1',
      repository_id: firstBinding.repositoryId,
      subject: { kind: 'workspace_snapshot' },
      assessment_mode: 'REPOSITORY',
      assessment_profile_id: 'security/standard',
      target: { kind: 'repository' },
      requested_stronger_control_ids: [],
    },
  ))
  if (
    packedStart.operation !== 'start_assessment'
    || packedStart.state !== 'CREATED'
    || packedStart.assessmentRevision !== 1
    || !/^asm-[0-9a-f-]{36}$/.test(packedStart.assessmentId ?? '')
    || JSON.stringify(Object.keys(packedStart).sort()) !== JSON.stringify([
      'assessmentId',
      'assessmentRevision',
      'idempotencyKey',
      'operation',
      'schemaVersion',
      'state',
    ])
  ) {
    throw new Error('packed start tool did not return its bounded canonical receipt')
  }

  let packedStatus
  for (let attempt = 0; attempt < 50; attempt += 1) {
    packedStatus = packedToolValue('security_assessment_status', await executePackedModelTool(
      'security_assessment_status',
      { assessment_id: packedStart.assessmentId },
    ))
    if (packedStatus.state === 'SEALED') break
    if (packedStatus.state === 'BLOCKED' || packedStatus.state === 'CANCELED') {
      throw new Error('packed assessment reached unexpected state ' + packedStatus.state)
    }
    await new Promise(resolve => setTimeout(resolve, 100))
  }
  if (
    packedStatus?.state !== 'SEALED'
    || packedStatus.verdict !== 'SATISFIED'
    || JSON.stringify(Object.keys(packedStatus).sort()) !== JSON.stringify([
      'assessmentId',
      'assessmentRevision',
      'coverage',
      'schemaVersion',
      'state',
      'verdict',
    ])
  ) {
    throw new Error('packed status tool did not reach a bounded SEALED result')
  }

  const packedFindings = packedToolValue('security_assessment_findings', await executePackedModelTool(
    'security_assessment_findings',
    { assessment_id: packedStart.assessmentId, limit: 20 },
  ))
  if (
    !Array.isArray(packedFindings.findings)
    || packedFindings.findings.length !== 0
    || packedFindings.nextCursor !== null
    || JSON.stringify(Object.keys(packedFindings).sort()) !== JSON.stringify([
      'assessmentId',
      'assessmentRevision',
      'findings',
      'nextCursor',
      'schemaVersion',
    ])
  ) {
    throw new Error('packed findings tool did not return its bounded empty page')
  }

  const packedExportArgs = {
    assessment_id: packedStart.assessmentId,
    expected_assessment_revision: packedStatus.assessmentRevision,
    idempotency_key: 'packed-security-live-export-v1',
    export_profile_id: 'security/export/internal-json-v1',
    delivery_destination_id: 'delivery/local-audit',
  }
  const packedExport = packedToolValue('security_assessment_export', await executePackedModelTool(
    'security_assessment_export',
    packedExportArgs,
  ))
  const packedExportReplay = packedToolValue('security_assessment_export replay', await executePackedModelTool(
    'security_assessment_export',
    packedExportArgs,
  ))
  if (
    packedExport.operation !== 'request_export'
    || packedExport.acceptedState !== 'PENDING'
    || packedExport.assessmentId !== packedStart.assessmentId
    || packedExport.assessmentRevision !== packedStatus.assessmentRevision
    || !/^export-[0-9a-f]{64}$/.test(packedExport.exportId ?? '')
    || JSON.stringify(Object.keys(packedExport).sort()) !== JSON.stringify([
      'acceptedState',
      'assessmentId',
      'assessmentRevision',
      'exportId',
      'idempotencyKey',
      'operation',
      'schemaVersion',
    ])
    || JSON.stringify(packedExportReplay) !== JSON.stringify(packedExport)
  ) {
    throw new Error('packed export tool did not return and replay its bounded PENDING receipt')
  }
  const packedModelDisclosure = JSON.stringify({
    start: packedStart,
    status: packedStatus,
    findings: packedFindings,
    export: packedExport,
  })
  for (const forbidden of [
    ${JSON.stringify(repositoryRoot)},
    firstBinding.repositoryId,
    'delivery/local-audit',
    'security/export/internal-json-v1',
    'principalId',
    'permissions',
    'artifact',
    'digest',
    'download',
  ]) {
    if (packedModelDisclosure.includes(forbidden)) {
      throw new Error('packed model tool lifecycle disclosed ' + forbidden)
    }
  }
} finally {
  if (packedModelTurnOpen) {
    modelSession.append('turn/end', { turn: 1, reason: { kind: 'completed' } })
  }
  disposePackedModelAgent()
}
await hostFiber.dispose()
if (ctx.reflect.get('securityAssuranceHostRepositories') !== undefined) {
  throw new Error('Host Repository Provider disposal did not remove its Service')
}
const restartedHostFiber = ctx.plugin(hostRepositories.default, repositoryConfig)
await restartedHostFiber
const restartedBinding = await ctx.securityAssuranceHostRepositories.resolve('packed-mission-repository')
const restartedFailedBinding = await ctx.securityAssuranceHostRepositories.resolve('packed-failed-repository')
const restartedIndeterminateBinding = await ctx.securityAssuranceHostRepositories.resolve(
  'packed-indeterminate-repository',
)
if (restartedBinding?.repositoryId !== firstBinding.repositoryId) {
  throw new Error('Host Repository Provider restart did not preserve the registered Repository')
}
if (restartedFailedBinding?.repositoryId !== failedBinding.repositoryId) {
  throw new Error('Host Repository Provider restart did not preserve the failed Repository')
}
if (restartedIndeterminateBinding?.repositoryId !== indeterminateBinding.repositoryId) {
  throw new Error('Host Repository Provider restart did not preserve the indeterminate Repository')
}
await restartedHostFiber.dispose()
await modelToolsFiber.dispose()
if (
  ctx.tools.get('security_assessment_start') !== undefined
  || ctx.tools.get('security_assessment_status') !== undefined
  || ctx.tools.get('security_assessment_findings') !== undefined
  || ctx.tools.get('security_assessment_resume') !== undefined
  || ctx.tools.get('security_assessment_cancel') !== undefined
  || ctx.tools.get('security_assessment_export') !== undefined
) {
  throw new Error('packed model Tool entry did not withdraw its registered tools')
}
await fiber.dispose()
await typertFiber.dispose()
await toolRuntimeFiber.dispose()
await agentFiber.dispose()
await systemPromptFiber.dispose()
if (ctx.reflect.get('securityAssurance') !== undefined) {
  throw new Error('Fiber disposal did not remove securityAssurance')
}
process.stdout.write(JSON.stringify({
  packedImport: 'PASS',
  analyzerContract: 'PASS',
  modelTools: 'PASS',
  modelToolLiveSession: 'PASS',
  lifecycle: 'PASS',
  hostRepositoryProvider: 'PASS',
  workbenchRemote: 'PASS',
  workbenchClient: 'PASS',
  repositoryId: firstBinding.repositoryId,
  failedRepositoryId: failedBinding.repositoryId,
  indeterminateRepositoryId: indeterminateBinding.repositoryId,
}))
`, 'utf8')

  const probe = await execute(process.execPath, [probePath], {
    cwd: consumerRoot,
    windowsHide: true,
  })
  const result = JSON.parse(probe.stdout)
  if (
    result.packedImport !== 'PASS'
    || result.analyzerContract !== 'PASS'
    || result.modelTools !== 'PASS'
    || result.modelToolLiveSession !== 'PASS'
    || result.lifecycle !== 'PASS'
    || result.workbenchRemote !== 'PASS'
    || result.workbenchClient !== 'PASS'
  ) {
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
const { sealAssuranceSubmissionV1 } = await import('dsh-engineering-control-plane/assurance-provider')
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
const malformedDescriptor = {
  schemaVersion: 1,
  providerId: 'fixture/packed-malformed-provider',
  providerVersion: '1.0.0-fixture.1',
}

function sealedReferenceSubmission(context, descriptor) {
  const evidence = [{
    artifactId: 'packed-reference-evidence-1',
    schemaId: 'fixture/provider-evidence',
    schemaVersion: 1,
    value: { check: 'fixture/check', outcome: 'passed' },
  }]
  const artifact = (artifactId, schemaId, value) => ({
    artifactId,
    schemaId,
    schemaVersion: 1,
    value,
  })
  const draft = {
    schemaVersion: 1,
    binding: {
      invocationId: context.invocationId,
      missionId: context.missionId,
      attempt: context.attempt,
      provider: descriptor,
      subject: context.subject,
      effectivePolicyDigest: context.effectivePolicyDigest,
    },
    externalAssessment: {
      state: 'sealed',
      assessmentId: 'packed-reference-assessment-1',
      claimedOutcome: 'satisfied',
    },
    providerComposition: artifact(
      'packed-reference-composition-1',
      'dsh/assurance-provider-composition',
      {
        schemaVersion: 1,
        provider: descriptor,
        components: [{ componentId: 'fixture/packed-reference', componentVersion: '1.0.0' }],
      },
    ),
    providerPolicy: artifact(
      'packed-reference-policy-1',
      'dsh/assurance-provider-policy',
      { schemaVersion: 1, effectivePolicyDigest: context.effectivePolicyDigest },
    ),
    coverage: artifact(
      'packed-reference-coverage-1',
      'dsh/assurance-provider-coverage',
      {
        schemaVersion: 1,
        status: 'complete',
        dimensions: [{ dimensionId: 'fixture/check', status: 'covered' }],
      },
    ),
    provenance: artifact(
      'packed-reference-provenance-1',
      'dsh/assurance-provider-provenance',
      {
        schemaVersion: 1,
        assessor: { kind: 'machine_provider', provider: descriptor },
      },
    ),
    evidence,
  }
  const sourceSeal = evidenceDigests => artifact(
    'packed-reference-source-seal-1',
    'dsh/assurance-provider-source-seal',
    {
      schemaVersion: 1,
      state: 'sealed',
      subject: context.subject,
      evidenceDigests,
    },
  )
  const provisional = sealAssuranceSubmissionV1({ ...draft, sourceSeal: sourceSeal([]) })
  return sealAssuranceSubmissionV1({
    ...draft,
    sourceSeal: sourceSeal(provisional.payload.evidence.map(item => item.digest.value)),
  })
}

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

function registerPausableDeveloperProvider(ctx, prefix) {
  let sequence = 0
  let notifyDeveloperStarted
  let releaseDeveloperResult
  const developerStarted = new Promise(resolve => { notifyDeveloperStarted = resolve })
  const developerReleased = new Promise(resolve => { releaseDeveloperResult = resolve })
  const dispose = ctx.subagents.registerProvider({
    name: 'spawn',
    capabilities: { outputSchema: true, depthLimit: true, toolFilter: true, persona: true },
    inheritsParentContext: false,
    async start(request) {
      const role = request.label?.split(' · ')[0]
      if (typeof role !== 'string' || !(role in outputs)) {
        throw new Error('Packed pausable Provider received an unknown Role')
      }
      if (role === 'developer') notifyDeveloperStarted()
      const complete = () => ({ output: [], structured: outputs[role], stopReason: 'completed' })
      return {
        id: prefix + '-' + (++sequence),
        localAgent: undefined,
        result: role === 'developer' ? developerReleased.then(complete) : Promise.resolve(complete()),
        dispose: () => Promise.resolve(),
      }
    },
  })
  return {
    dispose,
    developerStarted,
    releaseDeveloper: () => releaseDeveloperResult(),
  }
}

function controlPlaneConfig(dshHome, activation, repository = {
  root: ${JSON.stringify(repositoryRoot)},
  repositoryId: ${JSON.stringify(result.repositoryId)},
}) {
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
      root: repository.root,
      verificationProfile: 'packed-integration',
      assuranceProviders: [{
        providerId: adapter.SECURITY_ASSURANCE_CONTROL_PLANE_DESCRIPTOR.providerId,
        providerVersion: adapter.SECURITY_ASSURANCE_CONTROL_PLANE_DESCRIPTOR.providerVersion,
        activation,
        configuration: { repositoryId: repository.repositoryId },
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

function referenceControlPlaneConfig(dshHome, descriptor) {
  const config = controlPlaneConfig(dshHome, 'required')
  return {
    ...config,
    repositories: [{
      ...config.repositories[0],
      assuranceProviders: [{
        providerId: descriptor.providerId,
        providerVersion: descriptor.providerVersion,
        activation: 'required',
      }],
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

async function waitForProviderInvocationState(ctx, agent, missionId, states) {
  const deadline = Date.now() + 20000
  let observed = []
  while (Date.now() < deadline) {
    const snapshot = await ctx.engineeringControlPlane.status(
      agent,
      missionId,
      new AbortController().signal,
    )
    observed = (snapshot.assuranceProviderInvocations ?? []).map(item => item.state)
    if (observed.some(state => states.includes(state))) return snapshot
    await new Promise(resolve => setTimeout(resolve, 20))
  }
  throw new Error('Packed Provider invocation did not reach ' + states.join(' or ')
    + '; observed ' + observed.join(', '))
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

const failedContext = new Context()
const failedSubprocessFiber = await failedContext.plugin(LocalSubprocessRuntime)
const failedSubagentFiber = await failedContext.plugin(SubagentRuntime)
const disposeFailedProvider = registerScriptedProvider(failedContext, 'packed-failed')
const failedSecurityFiber = await failedContext.plugin(
  SecurityAssuranceService,
  { dshHome: ${JSON.stringify(securityHome)} },
)
await failedContext.securityAssurance.whenReady()
const failedControlPlaneFiber = await failedContext.plugin(
  EngineeringControlPlane,
  controlPlaneConfig(${JSON.stringify(join(temporaryRoot, 'failed-home'))}, 'required', {
    root: ${JSON.stringify(failedRepositoryRoot)},
    repositoryId: ${JSON.stringify(result.failedRepositoryId)},
  }),
)
await failedContext.engineeringControlPlane.whenReady()
const failedAdapterFiber = await failedContext.plugin(adapter.default)
try {
  const failedAgent = {
    id: 'packed-failed-agent',
    session: { header: { cwd: ${JSON.stringify(failedRepositoryRoot)} } },
  }
  const failedReceipt = await failedContext.engineeringControlPlane.start(failedAgent, {
    idempotencyKey: 'packed-failed:start:1',
    objective: 'Reject a package install lifecycle script through the real packed Security Provider',
  }, new AbortController().signal)
  const failedSnapshot = await waitForTerminalMission(
    failedContext,
    failedAgent,
    failedReceipt.missionId,
  )
  if (failedSnapshot.status !== 'REWORK_REQUIRED'
    || failedSnapshot.gate?.kind !== 'rework_required'
    || failedSnapshot.assuranceResults?.[0]?.outcome !== 'failed'
    || failedSnapshot.gate.reasons?.[0]?.code !== 'assurance_failed') {
    throw new Error('Packed failed Security verdict did not close the Control Plane Gate: '
      + JSON.stringify({
        status: failedSnapshot.status,
        gate: failedSnapshot.gate,
        results: failedSnapshot.assuranceResults,
      }))
  }
} finally {
  await failedAdapterFiber.dispose()
  await failedControlPlaneFiber.dispose()
  await failedSecurityFiber.dispose()
  disposeFailedProvider()
  await failedSubagentFiber.dispose()
  await failedSubprocessFiber.dispose()
}

const indeterminateContext = new Context()
const indeterminateSubprocessFiber = await indeterminateContext.plugin(LocalSubprocessRuntime)
const indeterminateSubagentFiber = await indeterminateContext.plugin(SubagentRuntime)
const disposeIndeterminateProvider = registerScriptedProvider(
  indeterminateContext,
  'packed-indeterminate',
)
const indeterminateSecurityFiber = await indeterminateContext.plugin(
  SecurityAssuranceService,
  { dshHome: ${JSON.stringify(securityHome)} },
)
await indeterminateContext.securityAssurance.whenReady()
const indeterminateControlPlaneFiber = await indeterminateContext.plugin(
  EngineeringControlPlane,
  controlPlaneConfig(${JSON.stringify(join(temporaryRoot, 'indeterminate-home'))}, 'required', {
    root: ${JSON.stringify(indeterminateRepositoryRoot)},
    repositoryId: ${JSON.stringify(result.indeterminateRepositoryId)},
  }),
)
await indeterminateContext.engineeringControlPlane.whenReady()
const indeterminateAdapterFiber = await indeterminateContext.plugin(adapter.default)
try {
  const indeterminateAgent = {
    id: 'packed-indeterminate-agent',
    session: { header: { cwd: ${JSON.stringify(indeterminateRepositoryRoot)} } },
  }
  const indeterminateReceipt = await indeterminateContext.engineeringControlPlane.start(
    indeterminateAgent,
    {
      idempotencyKey: 'packed-indeterminate:start:1',
      objective: 'Block when the real packed Security Provider cannot determine a verdict',
    },
    new AbortController().signal,
  )
  const indeterminateSnapshot = await waitForTerminalMission(
    indeterminateContext,
    indeterminateAgent,
    indeterminateReceipt.missionId,
  )
  if (indeterminateSnapshot.status !== 'BLOCKED'
    || indeterminateSnapshot.gate?.kind !== 'blocked'
    || indeterminateSnapshot.assuranceResults?.[0]?.outcome !== 'indeterminate'
    || indeterminateSnapshot.gate.reasons?.[0]?.code !== 'assurance_indeterminate') {
    throw new Error('Packed indeterminate Security verdict did not block the Control Plane Gate: '
      + JSON.stringify({
        status: indeterminateSnapshot.status,
        gate: indeterminateSnapshot.gate,
        results: indeterminateSnapshot.assuranceResults,
      }))
  }
} finally {
  await indeterminateAdapterFiber.dispose()
  await indeterminateControlPlaneFiber.dispose()
  await indeterminateSecurityFiber.dispose()
  disposeIndeterminateProvider()
  await indeterminateSubagentFiber.dispose()
  await indeterminateSubprocessFiber.dispose()
}

const malformedContext = new Context()
const malformedSubprocessFiber = await malformedContext.plugin(LocalSubprocessRuntime)
const malformedSubagentFiber = await malformedContext.plugin(SubagentRuntime)
const disposeMalformedRoleProvider = registerScriptedProvider(
  malformedContext,
  'packed-malformed',
)
const malformedControlPlaneFiber = await malformedContext.plugin(
  EngineeringControlPlane,
  referenceControlPlaneConfig(
    ${JSON.stringify(join(temporaryRoot, 'malformed-home'))},
    malformedDescriptor,
  ),
)
await malformedContext.engineeringControlPlane.whenReady()
const malformedContributorFiber = await malformedContext.plugin({
  name: 'packed-malformed-reference-provider',
  inject: ['engineeringControlPlane'],
  apply(contributorContext) {
    return contributorContext.engineeringControlPlane.registerAssuranceProvider(
      malformedDescriptor,
      descriptor => ({
        descriptor,
        async assess(context) {
          const candidate = JSON.parse(JSON.stringify(
            sealedReferenceSubmission(context, descriptor),
          ))
          candidate.payload.externalAssessment.claimedOutcome = 'failed'
          return { kind: 'sealed_submission', submission: candidate }
        },
      }),
    )
  },
})
try {
  const malformedAgent = {
    id: 'packed-malformed-agent',
    session: { header: { cwd: ${JSON.stringify(repositoryRoot)} } },
  }
  const malformedReceipt = await malformedContext.engineeringControlPlane.start(
    malformedAgent,
    {
      idempotencyKey: 'packed-malformed:start:1',
      objective: 'Reject a digest-tampered packed Provider Submission',
    },
    new AbortController().signal,
  )
  const malformedSnapshot = await waitForProviderInvocationState(
    malformedContext,
    malformedAgent,
    malformedReceipt.missionId,
    ['rejected'],
  )
  const malformedInvocation = malformedSnapshot.assuranceProviderInvocations?.[0]
  if (malformedInvocation?.state !== 'rejected'
    || malformedInvocation.failureCode !== 'digest_mismatch'
    || malformedSnapshot.evidence.records.some(
      record => record.kind === 'assurance-provider-submission',
    )) {
    throw new Error('Packed malformed Submission was not rejected before Evidence import: '
      + JSON.stringify({
        status: malformedSnapshot.status,
        invocation: malformedInvocation,
        evidence: malformedSnapshot.evidence.records,
      }))
  }
  const malformedTerminal = await waitForTerminalMission(
    malformedContext,
    malformedAgent,
    malformedReceipt.missionId,
  )
  if (malformedTerminal.status !== 'BLOCKED') {
    throw new Error('Packed malformed Submission did not fail the Mission closed')
  }
} finally {
  await malformedContributorFiber.dispose()
  await malformedControlPlaneFiber.dispose()
  disposeMalformedRoleProvider()
  await malformedSubagentFiber.dispose()
  await malformedSubprocessFiber.dispose()
}

const providerLossContext = new Context()
const providerLossSubprocessFiber = await providerLossContext.plugin(LocalSubprocessRuntime)
const providerLossSubagentFiber = await providerLossContext.plugin(SubagentRuntime)
const pausableRoleProvider = registerPausableDeveloperProvider(
  providerLossContext,
  'packed-provider-loss',
)
const providerLossSecurityFiber = await providerLossContext.plugin(
  SecurityAssuranceService,
  { dshHome: ${JSON.stringify(securityHome)} },
)
await providerLossContext.securityAssurance.whenReady()
const providerLossControlPlaneFiber = await providerLossContext.plugin(
  EngineeringControlPlane,
  controlPlaneConfig(${JSON.stringify(join(temporaryRoot, 'provider-loss-home'))}, 'required'),
)
await providerLossContext.engineeringControlPlane.whenReady()
const providerLossAdapterFiber = await providerLossContext.plugin(adapter.default)
let providerLossAdapterDisposed = false
let replacementContributorFiber
let replacementFactoryCalls = 0
let replacementAssessCalls = 0
const replacementDescriptor = {
  ...adapter.SECURITY_ASSURANCE_CONTROL_PLANE_DESCRIPTOR,
  providerVersion: '99.0.0-fixture.1',
}
replacementContributorFiber = await providerLossContext.plugin({
  name: 'packed-provider-loss-wrong-version',
  inject: ['engineeringControlPlane'],
  apply(contributorContext) {
    return contributorContext.engineeringControlPlane.registerAssuranceProvider(
      replacementDescriptor,
      descriptor => {
        replacementFactoryCalls++
        return {
          descriptor,
          async assess() {
            replacementAssessCalls++
            throw new Error('A different Provider version must never replace the frozen version')
          },
        }
      },
    )
  },
})
try {
  const providerLossAgent = {
    id: 'packed-provider-loss-agent',
    session: { header: { cwd: ${JSON.stringify(repositoryRoot)} } },
  }
  const providerLossReceipt = await providerLossContext.engineeringControlPlane.start(
    providerLossAgent,
    {
      idempotencyKey: 'packed-provider-loss:start:1',
      objective: 'Fail closed when the exact frozen Security Provider disappears mid-Attempt',
    },
    new AbortController().signal,
  )
  await Promise.race([
    pausableRoleProvider.developerStarted,
    new Promise((_, reject) => setTimeout(
      () => reject(new Error('Packed Developer did not reach the Provider-loss pause')),
      20000,
    )),
  ])
  const frozenSnapshot = await providerLossContext.engineeringControlPlane.status(
    providerLossAgent,
    providerLossReceipt.missionId,
    new AbortController().signal,
  )
  if (frozenSnapshot.assuranceProviderInvocations?.[0]?.state !== 'prepared') {
    throw new Error('Packed Security Provider was not frozen before Adapter disposal')
  }
  await providerLossAdapterFiber.dispose()
  providerLossAdapterDisposed = true
  pausableRoleProvider.releaseDeveloper()
  const unavailableSnapshot = await waitForProviderInvocationState(
    providerLossContext,
    providerLossAgent,
    providerLossReceipt.missionId,
    ['unavailable'],
  )
  const unavailableInvocation = unavailableSnapshot.assuranceProviderInvocations?.[0]
  if (unavailableInvocation?.state !== 'unavailable'
    || unavailableInvocation.failureCode !== 'registration_missing'
    || replacementFactoryCalls !== 0
    || replacementAssessCalls !== 0) {
    throw new Error('Packed frozen Provider loss was skipped or substituted: '
      + JSON.stringify({
        invocation: unavailableInvocation,
        replacementFactoryCalls,
        replacementAssessCalls,
      }))
  }
  const providerLossTerminal = await waitForTerminalMission(
    providerLossContext,
    providerLossAgent,
    providerLossReceipt.missionId,
  )
  if (providerLossTerminal.status !== 'BLOCKED'
    || providerLossTerminal.gate?.kind !== 'blocked'
    || providerLossTerminal.assuranceResults?.[0]?.outcome !== 'indeterminate'
    || providerLossTerminal.assuranceResults[0].reasonCodes?.[0] !== 'provider_unavailable'
    || providerLossTerminal.gate.reasons?.[0]?.code !== 'assurance_indeterminate') {
    throw new Error('Packed frozen Provider loss did not block the Gate: '
      + JSON.stringify({
        status: providerLossTerminal.status,
        gate: providerLossTerminal.gate,
        results: providerLossTerminal.assuranceResults,
      }))
  }
} finally {
  pausableRoleProvider.releaseDeveloper()
  if (replacementContributorFiber !== undefined) await replacementContributorFiber.dispose()
  if (!providerLossAdapterDisposed) await providerLossAdapterFiber.dispose()
  await providerLossControlPlaneFiber.dispose()
  await providerLossSecurityFiber.dispose()
  pausableRoleProvider.dispose()
  await providerLossSubagentFiber.dispose()
  await providerLossSubprocessFiber.dispose()
}

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
  failedGate: 'PASS',
  indeterminateGate: 'PASS',
  malformedSubmission: 'PASS',
  frozenProviderLoss: 'PASS',
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
    analyzerContract: result.analyzerContract,
    modelTools: result.modelTools,
    modelToolLiveSession: result.modelToolLiveSession,
    lifecycle: result.lifecycle,
    hostRepositoryProvider: result.hostRepositoryProvider,
    workbenchRemote: result.workbenchRemote,
    workbenchClient: result.workbenchClient,
    ...adapterResult,
  })}\n`)
} finally {
  await rm(temporaryRoot, { recursive: true, force: true })
}
