import { SecurityAssuranceTestComposition } from './support/security-assurance-test-composition.ts'
import { removeTemporaryRoots } from './support/remove-temporary-root.ts'
import { execFile } from 'node:child_process'
import { mkdtemp, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { promisify } from 'node:util'
import { Context } from '@deepseek-ai/cordis'
import AgentRegistry, { Inbox } from '@deepseek-ai/dsh-agent'
import type { Agent, AgentStatus } from '@deepseek-ai/dsh-agent'
import CommandRuntime from '@deepseek-ai/dsh-commands'
import { ToolCallId as CallId, createUserMessage } from '@deepseek-ai/dsh-llm'
import { Session, SessionId } from '@deepseek-ai/dsh-session'
import SystemPrompt from '@deepseek-ai/dsh-system-prompt'
import ToolRuntime from '@deepseek-ai/dsh-tools'
import type { ToolExecutionResult } from '@deepseek-ai/dsh-tools'
import { afterEach, describe, expect, it, vi } from 'vitest'
import SecurityAssuranceService from '../src/index.ts'
import SecurityAssuranceTools from '../src/tools.ts'
import type { AssessmentId, SecurityInvocation } from '../src/contracts.ts'
import { referenceHostInvocation } from './support/reference-host.ts'
import { readSessionEvents } from '../src/internal/session-events.ts'

const run = promisify(execFile)
const temporaryRoots: string[] = []
const toolSignal = new AbortController().signal

afterEach(async () => {
  await removeTemporaryRoots(temporaryRoots)
})

interface StubAgent {
  readonly agent: Agent
  readonly session: Session
  readonly steered: ReturnType<typeof createUserMessage>[]
  setStatus(status: AgentStatus): void
}

function stubAgent(rawId: string, supplied?: Session): StubAgent {
  const session = supplied ?? Session.create(SessionId(rawId))
  let status: AgentStatus = 'running'
  const steered: ReturnType<typeof createUserMessage>[] = []
  const agent: Agent = {
    id: session.id,
    options: {},
    session,
    inbox: new Inbox(session, { inserted: () => {}, discarded: () => {}, claimed: () => {} }),
    get status() { return status },
    ctx: new Context(),
    send: () => {},
    followup: () => {},
    steer: message => { steered.push(message) },
    inject(input) { this.inbox.append('next-step', input) },
    cancel() {},
    runMaintenance: task => task(new AbortController().signal),
    whenIdle: () => Promise.resolve(),
  }
  return { agent, session, steered, setStatus(value) { status = value } }
}

function openTurn(stub: StubAgent): number {
  const turn = readSessionEvents(stub.session)
    .filter(event => event.type === 'turn/start')
    .reduce((maximum, event) => Math.max(maximum, event.data.turn), 0) + 1
  stub.agent.inbox.append('next-turn', createUserMessage({
    content: [{ type: 'text', text: 'Read the current assessment status.' }],
    source: { kind: 'user' },
  }))
  const admitted = stub.agent.inbox.claim('next-turn', turn)
  stub.session.append('turn/start', { turn })
  for (const message of admitted) stub.session.append('user/message', message, { surfaceOp: 'append' })
  return turn
}

function closeTurn(stub: StubAgent, turn: number): void {
  stub.session.append('turn/end', { turn, reason: { kind: 'completed' } })
}

async function execute(
  ctx: Context,
  args: unknown,
  agent?: Agent,
  initiator: Agent | null | undefined = agent,
  signal: AbortSignal = toolSignal,
): Promise<ToolExecutionResult> {
  return executeTool(ctx, 'security_assessment_status', args, agent, initiator, signal)
}

async function executeTool(
  ctx: Context,
  name: 'security_assessment_start'
    | 'security_repositories'
    | 'security_catalog'
    | 'security_assessment_status'
    | 'security_assessment_findings'
    | 'security_assessment_resume'
    | 'security_assessment_cancel'
    | 'security_assessment_export',
  args: unknown,
  agent?: Agent,
  initiator: Agent | null | undefined = agent,
  signal: AbortSignal = toolSignal,
): Promise<ToolExecutionResult> {
  const invoke = () => ctx.tools.execute({
    callId: CallId(`${name}-${Math.random()}`),
    name,
    arguments: args,
    signal,
    ...agent === undefined ? {} : { agent },
  })
  return initiator == null ? invoke() : ctx.agents.withInitiator(initiator, invoke)
}

function startArgs(repositoryId: string, idempotencyKey = 'security-tool-start-v1') {
  return {
    idempotency_key: idempotencyKey,
    repository_id: repositoryId,
    subject: { kind: 'workspace_snapshot' as const },
    assessment_mode: 'REPOSITORY' as const,
    assessment_profile_id: 'security/standard',
    target: { kind: 'repository' as const },
    requested_stronger_control_ids: [],
  }
}

async function harness() {
  const dshHome = await mkdtemp(join(tmpdir(), 'dsh-security-tools-home-'))
  temporaryRoots.push(dshHome)
  const ctx = new Context()
  const systemPromptFiber = await ctx.plugin(SystemPrompt)
  const agentFiber = await ctx.plugin(AgentRegistry)
  const commandFiber = await ctx.plugin(CommandRuntime)
  const toolRuntimeFiber = await ctx.plugin(ToolRuntime)
  let serviceFiber = await ctx.plugin(SecurityAssuranceTestComposition, { dshHome })
  await ctx.securityAssurance.whenReady()
  let toolsFiber = await ctx.plugin(SecurityAssuranceTools)
  return {
    ctx,
    get toolsFiber() { return toolsFiber },
    async restartService() {
      await toolsFiber.dispose()
      await serviceFiber.dispose()
      serviceFiber = await ctx.plugin(SecurityAssuranceTestComposition, { dshHome })
      await ctx.securityAssurance.whenReady()
      toolsFiber = await ctx.plugin(SecurityAssuranceTools)
    },
    async dispose() {
      await toolsFiber.dispose()
      await serviceFiber.dispose()
      await toolRuntimeFiber.dispose()
      await commandFiber.dispose()
      await agentFiber.dispose()
      await systemPromptFiber.dispose()
    },
  }
}

async function repositoryFixture(packageJson?: unknown): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), 'dsh-security-tools-repository-'))
  temporaryRoots.push(root)
  await run('git', ['init', '-b', 'main'], { cwd: root })
  await run('git', ['config', 'user.email', 'fixture@example.invalid'], { cwd: root })
  await run('git', ['config', 'user.name', 'Fixture'], { cwd: root })
  await writeFile(join(root, 'README.md'), '# model tool status fixture\n', 'utf8')
  if (packageJson !== undefined) {
    await writeFile(join(root, 'package.json'), `${JSON.stringify(packageJson, null, 2)}\n`, 'utf8')
  }
  await run('git', ['add', '.'], { cwd: root })
  await run('git', ['commit', '-m', 'model tool status baseline'], { cwd: root })
  return root
}

async function waitUntilSealed(
  service: SecurityAssuranceService,
  invocation: SecurityInvocation,
  assessmentId: AssessmentId,
): Promise<void> {
  let revision = 1
  for (let attempt = 0; attempt < 5; attempt += 1) {
    const changed = await service.waitForAssessmentRevision(invocation, {
      schemaVersion: 1,
      assessmentId,
      afterRevision: revision,
      timeoutMs: 5_000,
    })
    if (!changed.ok) throw new Error(`wait failed: ${changed.error.code}`)
    const snapshot = await service.getAssessment(invocation, { schemaVersion: 1, assessmentId })
    if (!snapshot.ok) throw new Error(`status failed: ${snapshot.error.code}`)
    if (snapshot.value.state === 'SEALED') return
    revision = snapshot.value.assessmentRevision
  }
  throw new Error('Assessment did not seal')
}

function resultValue(result: ToolExecutionResult): Record<string, unknown> {
  expect(result.isError).toBe(false)
  if (result.isError || typeof result.value !== 'object' || result.value === null) {
    throw new Error('expected successful structured tool value')
  }
  const block = result.content[0]
  if (block?.type !== 'text') throw new Error('expected rendered text result')
  expect(JSON.parse(block.text)).toEqual(result.value)
  return result.value as Record<string, unknown>
}

describe('security assessment tool registration', () => {
  it('registers exclusive start plus parallel reads and withdraws all tools on disposal', async () => {
    const fixture = await harness()
    try {
      expect(SecurityAssuranceTools).toMatchObject({
        name: 'dsh-security-assurance-tools',
        inject: ['agents', 'securityAssurance', 'tools'],
      })
      const start = fixture.ctx.tools.get('security_assessment_start')
      const repositories = fixture.ctx.tools.get('security_repositories')
      const catalog = fixture.ctx.tools.get('security_catalog')
      const status = fixture.ctx.tools.get('security_assessment_status')
      const findings = fixture.ctx.tools.get('security_assessment_findings')
      const resume = fixture.ctx.tools.get('security_assessment_resume')
      const cancel = fixture.ctx.tools.get('security_assessment_cancel')
      const exportAssessment = fixture.ctx.tools.get('security_assessment_export')
      expect(start?.name).toBe('security_assessment_start')
      expect(repositories?.name).toBe('security_repositories')
      expect(catalog?.name).toBe('security_catalog')
      expect(status?.name).toBe('security_assessment_status')
      expect(findings?.name).toBe('security_assessment_findings')
      expect(resume?.name).toBe('security_assessment_resume')
      expect(cancel?.name).toBe('security_assessment_cancel')
      expect(exportAssessment?.name).toBe('security_assessment_export')
      expect(fixture.ctx.tools.executionMode({
        callId: CallId('security-repositories-mode'),
        name: 'security_repositories',
        arguments: { limit: 20, state: 'ENABLED' },
        signal: toolSignal,
      })).toEqual({ kind: 'parallel' })
      expect(fixture.ctx.tools.executionMode({
        callId: CallId('security-catalog-mode'),
        name: 'security_catalog',
        arguments: {},
        signal: toolSignal,
      })).toEqual({ kind: 'parallel' })
      expect(fixture.ctx.tools.executionMode({
        callId: CallId('security-start-mode'),
        name: 'security_assessment_start',
        arguments: startArgs('repo-00000000-0000-0000-0000-000000000000'),
        signal: toolSignal,
      })).toEqual({ kind: 'exclusive' })
      expect(fixture.ctx.tools.executionMode({
        callId: CallId('security-export-mode'),
        name: 'security_assessment_export',
        arguments: {
          assessment_id: 'asm-00000000-0000-0000-0000-000000000000',
          expected_assessment_revision: 3,
          idempotency_key: 'security-export-mode-v1',
          export_profile_id: 'security/export/internal-json-v1',
          delivery_destination_id: 'delivery/local-audit',
        },
        signal: toolSignal,
      })).toEqual({ kind: 'exclusive' })
      expect(fixture.ctx.tools.executionMode({
        callId: CallId('security-cancel-mode'),
        name: 'security_assessment_cancel',
        arguments: {
          assessment_id: 'asm-00000000-0000-0000-0000-000000000000',
          expected_assessment_revision: 3,
          idempotency_key: 'security-cancel-mode-v1',
          reason: { code: 'OPERATOR_REQUEST', summary: 'Cancel the current assessment.' },
        },
        signal: toolSignal,
      })).toEqual({ kind: 'exclusive' })
      expect(fixture.ctx.tools.executionMode({
        callId: CallId('security-status-mode'),
        name: 'security_assessment_status',
        arguments: { assessment_id: 'asm-00000000-0000-0000-0000-000000000000' },
        signal: toolSignal,
      })).toEqual({ kind: 'parallel' })
      expect(fixture.ctx.tools.executionMode({
        callId: CallId('security-resume-mode'),
        name: 'security_assessment_resume',
        arguments: {
          assessment_id: 'asm-00000000-0000-0000-0000-000000000000',
          expected_assessment_revision: 3,
          idempotency_key: 'security-resume-mode-v1',
          reason: { code: 'OPERATOR_RETRY', summary: 'Retry the interrupted assessment.' },
        },
        signal: toolSignal,
      })).toEqual({ kind: 'exclusive' })
      expect(fixture.ctx.tools.executionMode({
        callId: CallId('security-findings-mode'),
        name: 'security_assessment_findings',
        arguments: {
          assessment_id: 'asm-00000000-0000-0000-0000-000000000000',
          limit: 20,
        },
        signal: toolSignal,
      })).toEqual({ kind: 'parallel' })
      expect(start?.presentCall?.(startArgs(
        'repo-00000000-0000-0000-0000-000000000000',
      ))).toEqual({
        card: 'generic',
        title: 'Start security assessment',
        kind: 'other',
        rawInput: 'repo-00000000-0000-0000-0000-000000000000',
      })
      expect(status?.presentCall?.({
        assessment_id: 'asm-00000000-0000-0000-0000-000000000000',
      })).toEqual({
        card: 'generic',
        title: 'Read security assessment status',
        kind: 'read',
        rawInput: 'asm-00000000-0000-0000-0000-000000000000',
      })
      expect(findings?.presentCall?.({
        assessment_id: 'asm-00000000-0000-0000-0000-000000000000',
        limit: 20,
      })).toEqual({
        card: 'generic',
        title: 'List security assessment findings',
        kind: 'read',
        rawInput: 'asm-00000000-0000-0000-0000-000000000000',
      })
      expect(resume?.presentCall?.({
        assessment_id: 'asm-00000000-0000-0000-0000-000000000000',
        expected_assessment_revision: 3,
        idempotency_key: 'security-resume-present-v1',
        reason: { code: 'OPERATOR_RETRY', summary: 'Retry the interrupted assessment.' },
      })).toEqual({
        card: 'generic',
        title: 'Resume security assessment',
        kind: 'other',
        rawInput: 'asm-00000000-0000-0000-0000-000000000000',
      })
      expect(cancel?.presentCall?.({
        assessment_id: 'asm-00000000-0000-0000-0000-000000000000',
        expected_assessment_revision: 3,
        idempotency_key: 'security-cancel-present-v1',
        reason: { code: 'OPERATOR_REQUEST', summary: 'Cancel the current assessment.' },
      })).toEqual({
        card: 'generic',
        title: 'Cancel security assessment',
        kind: 'other',
        rawInput: 'asm-00000000-0000-0000-0000-000000000000',
      })
      expect(exportAssessment?.presentCall?.({
        assessment_id: 'asm-00000000-0000-0000-0000-000000000000',
        expected_assessment_revision: 3,
        idempotency_key: 'security-export-present-v1',
        export_profile_id: 'security/export/internal-json-v1',
        delivery_destination_id: 'delivery/local-audit',
      })).toEqual({
        card: 'generic',
        title: 'Request security assessment export',
        kind: 'other',
        rawInput: 'asm-00000000-0000-0000-0000-000000000000',
      })
      expect(start?.presentCall?.({ forged: true })).toBeUndefined()
      expect(repositories?.presentCall?.({ limit: 20 })).toEqual({
        card: 'generic',
        title: 'List security repositories',
        kind: 'read',
      })
      expect(catalog?.presentCall?.({})).toEqual({
        card: 'generic',
        title: 'Read security assessment catalog',
        kind: 'read',
        rawInput: undefined,
      })
      expect(status?.presentCall?.({ forged: true })).toBeUndefined()
      expect(findings?.presentCall?.({ forged: true })).toBeUndefined()
      expect(resume?.presentCall?.({ forged: true })).toBeUndefined()
      expect(cancel?.presentCall?.({ forged: true })).toBeUndefined()
      expect(exportAssessment?.presentCall?.({ forged: true })).toBeUndefined()

      await fixture.toolsFiber.dispose()
      expect(fixture.ctx.tools.get('security_assessment_start')).toBeUndefined()
      expect(fixture.ctx.tools.get('security_repositories')).toBeUndefined()
      expect(fixture.ctx.tools.get('security_catalog')).toBeUndefined()
      expect(fixture.ctx.tools.get('security_assessment_status')).toBeUndefined()
      expect(fixture.ctx.tools.get('security_assessment_findings')).toBeUndefined()
      expect(fixture.ctx.tools.get('security_assessment_resume')).toBeUndefined()
      expect(fixture.ctx.tools.get('security_assessment_cancel')).toBeUndefined()
      expect(fixture.ctx.tools.get('security_assessment_export')).toBeUndefined()
      expect(fixture.ctx.reflect.get('securityAssurance')).toBeDefined()
    } finally {
      await fixture.dispose()
    }
  })

  it('registers /security and steers the catalog-first standalone workflow', async () => {
    const fixture = await harness()
    const root = stubAgent(`security-command-${Math.random()}`)
    try {
      expect(fixture.ctx.commands.list(root.agent)).toContainEqual({
        name: 'security',
        description: 'Run a standalone repository security assessment',
        input: { hint: '[scope]' },
      })
      const execution = await fixture.ctx.commands.execute(
        root.agent,
        '/security review package lifecycle scripts',
        [],
        toolSignal,
      )
      expect(execution?.result).toEqual({
        kind: 'success',
        text: 'Security assessment request submitted.',
      })
      expect(root.steered).toHaveLength(1)
      expect(root.steered[0]?.content).toEqual([{
        type: 'text',
        text: expect.stringContaining('First call security_repositories, then call security_catalog'),
      }])
      expect(root.steered[0]?.content).toEqual([{
        type: 'text',
        text: expect.stringContaining('review package lifecycle scripts'),
      }])
      expect(fixture.ctx.tools.get('security_repositories')?.description).toContain(
        'First step for a top-level standalone security assessment',
      )
    } finally {
      await fixture.dispose()
    }
  })
})

describe('security assessment tool transport conformance', () => {
  it('keeps all eight model-visible input and output surfaces closed and explicitly bounded', async () => {
    const fixture = await harness()
    try {
      const contracts = {
        security_repositories: {
          input: ['limit', 'state'],
          required: ['limit'],
          output: ['repositories', 'schemaVersion', 'truncated'],
        },
        security_catalog: {
          input: ['repository_id'],
          required: [],
          output: [
            'assessmentModes',
            'assessmentProfiles',
            'repository',
            'schemaVersion',
            'strongerControls',
            'supportedEcosystemIds',
            'supportedPlatforms',
          ],
        },
        security_assessment_start: {
          input: [
            'assessment_mode',
            'assessment_profile_id',
            'idempotency_key',
            'repository_id',
            'requested_stronger_control_ids',
            'start_preflight_digest',
            'subject',
            'target',
          ],
          required: [
            'assessment_mode',
            'assessment_profile_id',
            'idempotency_key',
            'repository_id',
            'requested_stronger_control_ids',
            'subject',
            'target',
          ],
          output: [
            'assessmentId',
            'assessmentRevision',
            'idempotencyKey',
            'operation',
            'schemaVersion',
            'state',
          ],
        },
        security_assessment_status: {
          input: ['assessment_id'],
          required: ['assessment_id'],
          output: ['assessmentId', 'assessmentRevision', 'coverage', 'schemaVersion', 'state', 'verdict'],
        },
        security_assessment_findings: {
          input: ['assessment_id', 'cursor', 'limit', 'validation_states'],
          required: ['assessment_id', 'limit'],
          output: ['assessmentId', 'assessmentRevision', 'findings', 'nextCursor', 'schemaVersion'],
        },
        security_assessment_resume: {
          input: ['assessment_id', 'expected_assessment_revision', 'idempotency_key', 'reason'],
          required: ['assessment_id', 'expected_assessment_revision', 'idempotency_key', 'reason'],
          output: [
            'assessmentId',
            'assessmentRevision',
            'idempotencyKey',
            'operation',
            'schemaVersion',
            'state',
          ],
        },
        security_assessment_cancel: {
          input: ['assessment_id', 'expected_assessment_revision', 'idempotency_key', 'reason'],
          required: ['assessment_id', 'expected_assessment_revision', 'idempotency_key', 'reason'],
          output: [
            'acceptedState',
            'assessmentId',
            'assessmentRevision',
            'idempotencyKey',
            'operation',
            'schemaVersion',
          ],
        },
        security_assessment_export: {
          input: [
            'assessment_id',
            'delivery_destination_id',
            'expected_assessment_revision',
            'export_profile_id',
            'idempotency_key',
          ],
          required: [
            'assessment_id',
            'delivery_destination_id',
            'expected_assessment_revision',
            'export_profile_id',
            'idempotency_key',
          ],
          output: [
            'acceptedState',
            'assessmentId',
            'assessmentRevision',
            'exportId',
            'idempotencyKey',
            'operation',
            'schemaVersion',
          ],
        },
      } as const

      for (const [name, contract] of Object.entries(contracts)) {
        const definition = fixture.ctx.tools.get(name)
        expect(definition, `${name} must remain registered`).toBeDefined()
        const parameters = definition?.parameters as {
          readonly properties?: Readonly<Record<string, unknown>>
          readonly required?: readonly string[]
          readonly type?: string
        }
        expect(parameters.type).toBe('object')
        expect(Object.keys(parameters.properties ?? {}).sort()).toEqual([...contract.input].sort())
        expect([...(parameters.required ?? [])].sort()).toEqual([...contract.required].sort())
        const output = definition?.output.schema as {
          readonly additionalProperties?: boolean
          readonly properties?: Readonly<Record<string, unknown>>
        }
        expect(output.additionalProperties, `${name} output must fail closed`).toBe(false)
        expect(Object.keys(output.properties ?? {}).sort()).toEqual([...contract.output].sort())
      }
    } finally {
      await fixture.dispose()
    }
  })

  it('mints only the operation authority and forwards each live execution signal exactly once', async () => {
    const fixture = await harness()
    const root = stubAgent(`security-tool-conformance-${Math.random()}`)
    const disposeRoot = fixture.ctx.agents.register(root.agent)
    try {
      openTurn(root)
      const missingRepositoryId = 'repo-00000000-0000-0000-0000-000000000000'
      const missingAssessmentId = 'asm-00000000-0000-0000-0000-000000000000'
      const startSpy = vi.spyOn(fixture.ctx.securityAssurance, 'startAssessment')
      const statusSpy = vi.spyOn(fixture.ctx.securityAssurance, 'getAssessment')
      const findingsSpy = vi.spyOn(fixture.ctx.securityAssurance, 'listFindings')
      const resumeSpy = vi.spyOn(fixture.ctx.securityAssurance, 'resumeAssessment')
      const cancelSpy = vi.spyOn(fixture.ctx.securityAssurance, 'cancelAssessment')
      const exportSpy = vi.spyOn(fixture.ctx.securityAssurance, 'requestExport')

      const startController = new AbortController()
      const start = await executeTool(
        fixture.ctx,
        'security_assessment_start',
        startArgs(missingRepositoryId, 'security-conformance-start-v1'),
        root.agent,
        root.agent,
        startController.signal,
      )
      expect(start.error?.info?.code).toBe('SECURITY_NOT_FOUND')
      expect(startSpy).toHaveBeenCalledOnce()
      expect(startSpy.mock.calls[0]?.[2]?.signal).toBe(startController.signal)

      const statusController = new AbortController()
      const status = await executeTool(
        fixture.ctx,
        'security_assessment_status',
        { assessment_id: missingAssessmentId },
        root.agent,
        root.agent,
        statusController.signal,
      )
      expect(status.error?.info?.code).toBe('SECURITY_NOT_FOUND')
      expect(statusSpy).toHaveBeenCalledOnce()
      expect(statusSpy.mock.calls[0]?.[2]?.signal).toBe(statusController.signal)

      const findingsController = new AbortController()
      const findings = await executeTool(
        fixture.ctx,
        'security_assessment_findings',
        { assessment_id: missingAssessmentId, limit: 20 },
        root.agent,
        root.agent,
        findingsController.signal,
      )
      expect(findings.error?.info?.code).toBe('SECURITY_NOT_FOUND')
      expect(findingsSpy).toHaveBeenCalledOnce()
      expect(findingsSpy.mock.calls[0]?.[2]?.signal).toBe(findingsController.signal)

      const resumeController = new AbortController()
      const resume = await executeTool(
        fixture.ctx,
        'security_assessment_resume',
        {
          assessment_id: missingAssessmentId,
          expected_assessment_revision: 3,
          idempotency_key: 'security-conformance-resume-v1',
          reason: { code: 'OPERATOR_RETRY', summary: 'Retry the interrupted assessment.' },
        },
        root.agent,
        root.agent,
        resumeController.signal,
      )
      expect(resume.error?.info?.code).toBe('SECURITY_NOT_FOUND')
      expect(resumeSpy).toHaveBeenCalledOnce()
      expect(resumeSpy.mock.calls[0]?.[2]?.signal).toBe(resumeController.signal)

      const cancelController = new AbortController()
      const cancel = await executeTool(
        fixture.ctx,
        'security_assessment_cancel',
        {
          assessment_id: missingAssessmentId,
          expected_assessment_revision: 3,
          idempotency_key: 'security-conformance-cancel-v1',
          reason: { code: 'OPERATOR_REQUEST', summary: 'Cancel the current assessment.' },
        },
        root.agent,
        root.agent,
        cancelController.signal,
      )
      expect(cancel.error?.info?.code).toBe('SECURITY_NOT_FOUND')
      expect(cancelSpy).toHaveBeenCalledOnce()
      expect(cancelSpy.mock.calls[0]?.[2]?.signal).toBe(cancelController.signal)

      const exportController = new AbortController()
      const exportAssessment = await executeTool(
        fixture.ctx,
        'security_assessment_export',
        {
          assessment_id: missingAssessmentId,
          expected_assessment_revision: 3,
          idempotency_key: 'security-conformance-export-v1',
          export_profile_id: 'security/export/internal-json-v1',
          delivery_destination_id: 'delivery/local-audit',
        },
        root.agent,
        root.agent,
        exportController.signal,
      )
      expect(exportAssessment.error?.info?.code).toBe('SECURITY_NOT_FOUND')
      expect(exportSpy).toHaveBeenCalledOnce()
      expect(exportSpy.mock.calls[0]?.[2]?.signal).toBe(exportController.signal)
    } finally {
      vi.restoreAllMocks()
      disposeRoot()
      await fixture.dispose()
    }
  })
})

describe('security_assessment_export integration', () => {
  it('requests a registered SEALED delivery and returns only a bounded session-owned receipt', async () => {
    const repository = await repositoryFixture()
    const fixture = await harness()
    const root = stubAgent(`security-tool-export-${Math.random()}`)
    const other = stubAgent(`security-tool-export-other-${Math.random()}`)
    const disposeRoot = fixture.ctx.agents.register(root.agent)
    const disposeOther = fixture.ctx.agents.register(other.agent)
    try {
      const platform = process.platform
      if (platform !== 'win32' && platform !== 'linux' && platform !== 'darwin') {
        throw new Error(`unsupported test platform: ${platform}`)
      }
      const invocation = referenceHostInvocation(fixture.ctx.securityAssurance)
      const registered = await fixture.ctx.securityAssurance.registerRepository(invocation, {
        schemaVersion: 1,
        contractVersion: 1 as const,
        idempotencyKey: 'security-tool-export-repository-v1',
        root: repository,
        displayName: 'Model export tool fixture',
        bindings: {
          policyId: 'security/default',
          assessmentProfileId: 'security/standard',
          evidenceProtectionId: 'evidence/local-protected',
          dataEgressPolicyId: 'egress/deny-by-default',
          platform,
          deliveryDestinationIds: ['delivery/local-audit'],
        },
      })
      if (!registered.ok) throw new Error(`registration failed: ${registered.error.code}`)
      const started = await fixture.ctx.securityAssurance.startAssessment(invocation, {
        schemaVersion: 1,
        contractVersion: 1 as const,
        idempotencyKey: 'security-tool-export-assessment-v1',
        repositoryId: registered.value.repositoryId,
        subject: { kind: 'workspace_snapshot' },
        assessmentMode: 'REPOSITORY',
        assessmentProfileId: 'security/standard',
        target: { kind: 'repository' },
        requestedStrongerControlIds: [],
      })
      if (!started.ok) throw new Error(`start failed: ${started.error.code}`)
      await waitUntilSealed(fixture.ctx.securityAssurance, invocation, started.value.assessmentId)
      const sealed = await fixture.ctx.securityAssurance.getAssessment(invocation, {
        schemaVersion: 1,
        assessmentId: started.value.assessmentId,
      })
      if (!sealed.ok) throw new Error(`sealed query failed: ${sealed.error.code}`)
      expect(sealed.value.state).toBe('SEALED')

      const args = {
        assessment_id: started.value.assessmentId,
        expected_assessment_revision: sealed.value.assessmentRevision,
        idempotency_key: 'security-tool-export-command-v1',
        export_profile_id: 'security/export/internal-json-v1',
        delivery_destination_id: 'delivery/local-audit',
      }
      const agentless = await executeTool(
        fixture.ctx,
        'security_assessment_export',
        args,
      )
      expect(agentless.error?.info?.code).toBe('SECURITY_TOOL_AGENT_REQUIRED')

      openTurn(root)
      const driverless = await executeTool(
        fixture.ctx,
        'security_assessment_export',
        args,
        root.agent,
        null,
      )
      expect(driverless.error?.info?.code).toBe('SECURITY_TOOL_DRIVER_REQUIRED')

      const requested = resultValue(await executeTool(
        fixture.ctx,
        'security_assessment_export',
        {
          ...args,
          principal_id: 'forged-export-operator',
          permissions: ['export:download', 'risk:break-glass'],
        },
        root.agent,
      ))
      expect(requested).toEqual({
        schemaVersion: 1,
        operation: 'request_export',
        exportId: expect.stringMatching(/^export-[0-9a-f]{64}$/u),
        assessmentId: started.value.assessmentId,
        assessmentRevision: sealed.value.assessmentRevision,
        idempotencyKey: args.idempotency_key,
        acceptedState: 'PENDING',
      })
      const serialized = JSON.stringify(requested)
      for (const forbidden of [
        repository,
        registered.value.repositoryId,
        args.export_profile_id,
        args.delivery_destination_id,
        'destination',
        'artifact',
        'digest',
        'download',
        'path',
        'acceptedAt',
        'correlationId',
        'principalId',
        'forged-export-operator',
        String(root.agent.id),
      ]) expect(serialized).not.toContain(forbidden)

      const replay = resultValue(await executeTool(
        fixture.ctx,
        'security_assessment_export',
        args,
        root.agent,
      ))
      expect(replay).toEqual(requested)

      const staleRevision = await executeTool(
        fixture.ctx,
        'security_assessment_export',
        {
          ...args,
          expected_assessment_revision: sealed.value.assessmentRevision - 1,
          idempotency_key: 'security-tool-export-stale-v1',
        },
        root.agent,
      )
      expect(staleRevision.error?.info?.code).toBe('SECURITY_CONFLICT')

      const unfrozenDestination = await executeTool(
        fixture.ctx,
        'security_assessment_export',
        {
          ...args,
          idempotency_key: 'security-tool-export-destination-v1',
          delivery_destination_id: 'delivery/not-frozen',
        },
        root.agent,
      )
      expect(unfrozenDestination.error?.info?.code).toBe('SECURITY_CONFLICT')

      const invalid = await executeTool(
        fixture.ctx,
        'security_assessment_export',
        {
          ...args,
          idempotency_key: 'security-tool-export-invalid-v1',
          export_profile_id: 'security/export/arbitrary-v1',
        },
        root.agent,
      )
      expect(invalid.error?.info?.code).toBe('INVALID_ARGS')

      const missing = await executeTool(
        fixture.ctx,
        'security_assessment_export',
        {
          ...args,
          assessment_id: 'asm-00000000-0000-0000-0000-000000000000',
          idempotency_key: 'security-tool-export-missing-v1',
        },
        root.agent,
      )
      expect(missing.error?.info?.code).toBe('SECURITY_NOT_FOUND')

      const hostCannotReadSessionOwnedExport = await fixture.ctx.securityAssurance.getExport(invocation, {
        schemaVersion: 1,
        kind: 'STATUS',
        exportId: requested['exportId'] as `export-${string}`,
      })
      expect(hostCannotReadSessionOwnedExport).toMatchObject({
        ok: false,
        error: { code: 'NOT_FOUND' },
      })

      openTurn(other)
      const otherSessionResult = await executeTool(
        fixture.ctx,
        'security_assessment_export',
        args,
        other.agent,
      )
      if (otherSessionResult.isError) {
        throw new Error(`cross-session Export failed: ${JSON.stringify(otherSessionResult.error)}`)
      }
      const otherSession = resultValue(otherSessionResult)
      expect(otherSession['exportId']).not.toBe(requested['exportId'])
      expect(otherSession).toMatchObject({
        assessmentId: started.value.assessmentId,
        acceptedState: 'PENDING',
      })
    } finally {
      disposeOther()
      disposeRoot()
      await fixture.dispose()
    }
  })
})

describe('security_assessment_cancel integration', () => {
  it('cancels only an exact nonterminal revision without claiming terminal state in the receipt', async () => {
    const repository = await repositoryFixture()
    const fixture = await harness()
    const root = stubAgent(`security-tool-cancel-${Math.random()}`)
    const other = stubAgent(`security-tool-cancel-other-${Math.random()}`)
    const disposeRoot = fixture.ctx.agents.register(root.agent)
    const disposeOther = fixture.ctx.agents.register(other.agent)
    try {
      const platform = process.platform
      if (platform !== 'win32' && platform !== 'linux' && platform !== 'darwin') {
        throw new Error(`unsupported test platform: ${platform}`)
      }
      const firstInvocation = referenceHostInvocation(fixture.ctx.securityAssurance)
      const registered = await fixture.ctx.securityAssurance.registerRepository(firstInvocation, {
        schemaVersion: 1,
        contractVersion: 1 as const,
        idempotencyKey: 'security-tool-cancel-repository-v1',
        root: repository,
        displayName: 'Model cancel tool fixture',
        bindings: {
          policyId: 'security/default',
          assessmentProfileId: 'security/standard',
          evidenceProtectionId: 'evidence/local-protected',
          dataEgressPolicyId: 'egress/deny-by-default',
          platform,
          deliveryDestinationIds: [],
        },
      })
      if (!registered.ok) throw new Error(`registration failed: ${registered.error.code}`)
      const started = await fixture.ctx.securityAssurance.startAssessment(firstInvocation, {
        schemaVersion: 1,
        contractVersion: 1 as const,
        idempotencyKey: 'security-tool-cancel-assessment-v1',
        repositoryId: registered.value.repositoryId,
        subject: { kind: 'workspace_snapshot' },
        assessmentMode: 'REPOSITORY',
        assessmentProfileId: 'security/standard',
        target: { kind: 'repository' },
        requestedStrongerControlIds: [],
      })
      if (!started.ok) throw new Error(`start failed: ${started.error.code}`)

      await fixture.restartService()
      const invocation = referenceHostInvocation(fixture.ctx.securityAssurance)
      const blocked = await fixture.ctx.securityAssurance.getAssessment(invocation, {
        schemaVersion: 1,
        assessmentId: started.value.assessmentId,
      })
      if (!blocked.ok) throw new Error(`blocked query failed: ${blocked.error.code}`)
      expect(blocked.value).toMatchObject({ state: 'BLOCKED' })

      const args = {
        assessment_id: started.value.assessmentId,
        expected_assessment_revision: blocked.value.assessmentRevision,
        idempotency_key: 'security-tool-cancel-command-v1',
        reason: {
          code: 'OPERATOR_REQUEST',
          summary: 'Cancel the interrupted assessment through the model tool.',
        },
      }
      const agentless = await executeTool(
        fixture.ctx,
        'security_assessment_cancel',
        args,
      )
      expect(agentless.error?.info?.code).toBe('SECURITY_TOOL_AGENT_REQUIRED')

      openTurn(root)
      const driverless = await executeTool(
        fixture.ctx,
        'security_assessment_cancel',
        args,
        root.agent,
        null,
      )
      expect(driverless.error?.info?.code).toBe('SECURITY_TOOL_DRIVER_REQUIRED')

      const canceled = resultValue(await executeTool(
        fixture.ctx,
        'security_assessment_cancel',
        args,
        root.agent,
      ))
      expect(canceled).toEqual({
        schemaVersion: 1,
        operation: 'cancel_assessment',
        assessmentId: started.value.assessmentId,
        assessmentRevision: blocked.value.assessmentRevision + 1,
        acceptedState: 'BLOCKED',
        idempotencyKey: args.idempotency_key,
      })
      const serialized = JSON.stringify(canceled)
      for (const forbidden of [
        repository,
        registered.value.repositoryId,
        args.reason.code,
        args.reason.summary,
        'reason',
        'acceptedAt',
        'correlationId',
        'CANCELED',
        'verdict',
        'evidence',
        'principalId',
        String(root.agent.id),
      ]) expect(serialized).not.toContain(forbidden)

      const terminal = await fixture.ctx.securityAssurance.getAssessment(invocation, {
        schemaVersion: 1,
        assessmentId: started.value.assessmentId,
      })
      expect(terminal).toMatchObject({
        ok: true,
        value: {
          state: 'CANCELED',
          assessmentRevision: blocked.value.assessmentRevision + 2,
          verdict: null,
        },
      })

      const forgedReplay = resultValue(await executeTool(
        fixture.ctx,
        'security_assessment_cancel',
        {
          ...args,
          principal_id: 'forged-cancel-operator',
          permissions: ['assessment:resume', 'risk:break-glass'],
        },
        root.agent,
      ))
      expect(forgedReplay).toEqual(canceled)

      const idempotencyConflict = await executeTool(
        fixture.ctx,
        'security_assessment_cancel',
        {
          ...args,
          reason: { ...args.reason, summary: 'Attempt a conflicting cancel replay.' },
        },
        root.agent,
      )
      expect(idempotencyConflict.error?.info?.code).toBe('SECURITY_IDEMPOTENCY_CONFLICT')

      const invalid = await executeTool(
        fixture.ctx,
        'security_assessment_cancel',
        {
          ...args,
          idempotency_key: 'security-tool-cancel-invalid-v1',
          reason: { code: 'invalid-code', summary: 'Invalid reason code.' },
        },
        root.agent,
      )
      expect(invalid.error?.info?.code).toBe('SECURITY_INVALID_REQUEST')

      const staleRevision = await executeTool(
        fixture.ctx,
        'security_assessment_cancel',
        {
          ...args,
          idempotency_key: 'security-tool-cancel-stale-v1',
        },
        root.agent,
      )
      expect(staleRevision.error?.info?.code).toBe('SECURITY_CONFLICT')

      const missing = await executeTool(
        fixture.ctx,
        'security_assessment_cancel',
        {
          ...args,
          assessment_id: 'asm-00000000-0000-0000-0000-000000000000',
          idempotency_key: 'security-tool-cancel-missing-v1',
        },
        root.agent,
      )
      expect(missing.error?.info?.code).toBe('SECURITY_NOT_FOUND')

      openTurn(other)
      const otherSession = await executeTool(
        fixture.ctx,
        'security_assessment_cancel',
        args,
        other.agent,
      )
      expect(otherSession.error?.info?.code).toBe('SECURITY_CONFLICT')
    } finally {
      disposeOther()
      disposeRoot()
      await fixture.dispose()
    }
  })
})

describe('security_assessment_resume integration', () => {
  it('resumes only an exact BLOCKED revision and returns a bounded session-owned receipt', async () => {
    const repository = await repositoryFixture()
    const fixture = await harness()
    const root = stubAgent(`security-tool-resume-${Math.random()}`)
    const other = stubAgent(`security-tool-resume-other-${Math.random()}`)
    const disposeRoot = fixture.ctx.agents.register(root.agent)
    const disposeOther = fixture.ctx.agents.register(other.agent)
    try {
      const platform = process.platform
      if (platform !== 'win32' && platform !== 'linux' && platform !== 'darwin') {
        throw new Error(`unsupported test platform: ${platform}`)
      }
      const firstInvocation = referenceHostInvocation(fixture.ctx.securityAssurance)
      const registered = await fixture.ctx.securityAssurance.registerRepository(firstInvocation, {
        schemaVersion: 1,
        contractVersion: 1 as const,
        idempotencyKey: 'security-tool-resume-repository-v1',
        root: repository,
        displayName: 'Model resume tool fixture',
        bindings: {
          policyId: 'security/default',
          assessmentProfileId: 'security/standard',
          evidenceProtectionId: 'evidence/local-protected',
          dataEgressPolicyId: 'egress/deny-by-default',
          platform,
          deliveryDestinationIds: [],
        },
      })
      if (!registered.ok) throw new Error(`registration failed: ${registered.error.code}`)
      const started = await fixture.ctx.securityAssurance.startAssessment(firstInvocation, {
        schemaVersion: 1,
        contractVersion: 1 as const,
        idempotencyKey: 'security-tool-resume-assessment-v1',
        repositoryId: registered.value.repositoryId,
        subject: { kind: 'workspace_snapshot' },
        assessmentMode: 'REPOSITORY',
        assessmentProfileId: 'security/standard',
        target: { kind: 'repository' },
        requestedStrongerControlIds: [],
      })
      if (!started.ok) throw new Error(`start failed: ${started.error.code}`)

      await fixture.restartService()
      const invocation = referenceHostInvocation(fixture.ctx.securityAssurance)
      const blocked = await fixture.ctx.securityAssurance.getAssessment(invocation, {
        schemaVersion: 1,
        assessmentId: started.value.assessmentId,
      })
      if (!blocked.ok) throw new Error(`blocked query failed: ${blocked.error.code}`)
      expect(blocked.value).toMatchObject({
        state: 'BLOCKED',
        verdict: null,
        availableActions: expect.arrayContaining([{
          kind: 'RESUME_ASSESSMENT',
          expectedAssessmentRevision: blocked.value.assessmentRevision,
        }]),
      })

      const args = {
        assessment_id: started.value.assessmentId,
        expected_assessment_revision: blocked.value.assessmentRevision,
        idempotency_key: 'security-tool-resume-command-v1',
        reason: {
          code: 'OPERATOR_RETRY',
          summary: 'Resume the interrupted assessment through the model tool.',
        },
      }
      const agentless = await executeTool(
        fixture.ctx,
        'security_assessment_resume',
        args,
      )
      expect(agentless.error?.info?.code).toBe('SECURITY_TOOL_AGENT_REQUIRED')

      openTurn(root)
      const driverless = await executeTool(
        fixture.ctx,
        'security_assessment_resume',
        args,
        root.agent,
        null,
      )
      expect(driverless.error?.info?.code).toBe('SECURITY_TOOL_DRIVER_REQUIRED')

      const resumed = resultValue(await executeTool(
        fixture.ctx,
        'security_assessment_resume',
        args,
        root.agent,
      ))
      expect(resumed).toEqual({
        schemaVersion: 1,
        operation: 'resume_assessment',
        assessmentId: started.value.assessmentId,
        assessmentRevision: blocked.value.assessmentRevision + 1,
        state: 'CREATED',
        idempotencyKey: args.idempotency_key,
      })
      const serialized = JSON.stringify(resumed)
      for (const forbidden of [
        repository,
        registered.value.repositoryId,
        args.reason.code,
        args.reason.summary,
        'reason',
        'acceptedAt',
        'correlationId',
        'subject',
        'policy',
        'coverage',
        'provider',
        'budget',
        'principalId',
        String(root.agent.id),
      ]) expect(serialized).not.toContain(forbidden)

      const forgedReplay = resultValue(await executeTool(
        fixture.ctx,
        'security_assessment_resume',
        {
          ...args,
          principal_id: 'forged-resume-operator',
          permissions: ['assessment:cancel', 'risk:break-glass'],
        },
        root.agent,
      ))
      expect(forgedReplay).toEqual(resumed)
      expect(JSON.stringify(forgedReplay)).not.toContain('forged-resume-operator')

      const idempotencyConflict = await executeTool(
        fixture.ctx,
        'security_assessment_resume',
        {
          ...args,
          reason: { ...args.reason, summary: 'Attempt a conflicting resume replay.' },
        },
        root.agent,
      )
      expect(idempotencyConflict.error?.info?.code).toBe('SECURITY_IDEMPOTENCY_CONFLICT')

      const invalid = await executeTool(
        fixture.ctx,
        'security_assessment_resume',
        {
          ...args,
          idempotency_key: 'security-tool-resume-invalid-v1',
          reason: { code: 'invalid-code', summary: 'Invalid reason code.' },
        },
        root.agent,
      )
      expect(invalid.error?.info?.code).toBe('SECURITY_INVALID_REQUEST')

      const staleRevision = await executeTool(
        fixture.ctx,
        'security_assessment_resume',
        {
          ...args,
          idempotency_key: 'security-tool-resume-stale-v1',
        },
        root.agent,
      )
      expect(staleRevision.error?.info?.code).toBe('SECURITY_CONFLICT')

      const missing = await executeTool(
        fixture.ctx,
        'security_assessment_resume',
        {
          ...args,
          assessment_id: 'asm-00000000-0000-0000-0000-000000000000',
          idempotency_key: 'security-tool-resume-missing-v1',
        },
        root.agent,
      )
      expect(missing.error?.info?.code).toBe('SECURITY_NOT_FOUND')

      openTurn(other)
      const otherSession = await executeTool(
        fixture.ctx,
        'security_assessment_resume',
        args,
        other.agent,
      )
      expect(otherSession.error?.info?.code).toBe('SECURITY_CONFLICT')

      await waitUntilSealed(
        fixture.ctx.securityAssurance,
        invocation,
        started.value.assessmentId,
      )
    } finally {
      disposeOther()
      disposeRoot()
      await fixture.dispose()
    }
  })
})

describe('security_assessment_findings disclosure', () => {
  it('lists paginated redacted summaries through session authority and rejects cursor transfer', async () => {
    const repository = await repositoryFixture({
      name: 'security-tool-findings-fixture',
      version: '1.0.0',
      scripts: {
        preinstall: 'node preinstall.js',
        postinstall: 'node postinstall.js',
      },
    })
    const fixture = await harness()
    const root = stubAgent(`security-tool-findings-${Math.random()}`)
    const other = stubAgent(`security-tool-findings-other-${Math.random()}`)
    const disposeRoot = fixture.ctx.agents.register(root.agent)
    const disposeOther = fixture.ctx.agents.register(other.agent)
    try {
      const platform = process.platform
      if (platform !== 'win32' && platform !== 'linux' && platform !== 'darwin') {
        throw new Error(`unsupported test platform: ${platform}`)
      }
      const invocation = referenceHostInvocation(fixture.ctx.securityAssurance)
      const registered = await fixture.ctx.securityAssurance.registerRepository(invocation, {
        schemaVersion: 1,
        contractVersion: 1 as const,
        idempotencyKey: 'security-tool-findings-repository-v1',
        root: repository,
        displayName: 'Model findings tool fixture',
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
      const started = await fixture.ctx.securityAssurance.startAssessment(invocation, {
        schemaVersion: 1,
        contractVersion: 1 as const,
        idempotencyKey: 'security-tool-findings-assessment-v1',
        repositoryId: registered.value.repositoryId,
        subject: { kind: 'workspace_snapshot' },
        assessmentMode: 'REPOSITORY',
        assessmentProfileId: 'security/standard',
        target: { kind: 'repository' },
        requestedStrongerControlIds: [],
      })
      if (!started.ok) throw new Error(`start failed: ${started.error.code}`)
      await waitUntilSealed(fixture.ctx.securityAssurance, invocation, started.value.assessmentId)

      const baseArgs = {
        assessment_id: started.value.assessmentId,
        limit: 1,
        validation_states: ['VALIDATED'],
      }
      const agentless = await executeTool(
        fixture.ctx,
        'security_assessment_findings',
        baseArgs,
      )
      expect(agentless.error?.info?.code).toBe('SECURITY_TOOL_AGENT_REQUIRED')

      openTurn(root)
      const driverless = await executeTool(
        fixture.ctx,
        'security_assessment_findings',
        baseArgs,
        root.agent,
        null,
      )
      expect(driverless.error?.info?.code).toBe('SECURITY_TOOL_DRIVER_REQUIRED')

      const first = resultValue(await executeTool(
        fixture.ctx,
        'security_assessment_findings',
        {
          ...baseArgs,
          principal_id: 'forged-findings-operator',
          permissions: ['evidence:disclose:validation-review'],
        },
        root.agent,
      ))
      expect(first).toEqual({
        schemaVersion: 1,
        assessmentId: started.value.assessmentId,
        assessmentRevision: expect.any(Number),
        findings: [{
          schemaVersion: 1,
          assessmentId: started.value.assessmentId,
          assessmentRevision: expect.any(Number),
          recordKind: 'FINDING',
          recordId: expect.stringMatching(/^finding-[0-9a-f]{64}$/u),
          candidateId: expect.stringMatching(/^candidate-[0-9a-f]{64}$/u),
          recordRevision: 1,
          validationState: 'VALIDATED',
          validationContractId: 'dsh-node-package-install-lifecycle-validation-v1',
          weaknessClassification: {
            primary: 'DSH-NODE-POLICY-001',
            secondary: [],
          },
          technicalSeverity: 'MEDIUM',
          evidenceConfidence: 'HIGH',
          policySignificance: 'BLOCKING',
          component: 'repository-root',
          sensitivity: 'PROTECTED_DETAIL',
          coverageRelations: [{
            obligationId: 'node-package-install-lifecycle-policy',
            state: 'SATISFIED',
          }],
          hasProtectedDetail: true,
        }],
        nextCursor: expect.stringMatching(/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/u),
      })
      const serialized = JSON.stringify(first)
      for (const forbidden of [
        repository,
        registered.value.repositoryId,
        'node preinstall.js',
        'node postinstall.js',
        'sourceAnchor',
        'evidenceLinks',
        'attackPath',
        'digest',
        'riskDecision',
        'principalId',
        'forged-findings-operator',
        String(root.agent.id),
      ]) expect(serialized).not.toContain(forbidden)

      const second = resultValue(await executeTool(
        fixture.ctx,
        'security_assessment_findings',
        {
          ...baseArgs,
          cursor: first['nextCursor'],
        },
        root.agent,
      ))
      expect(second).toMatchObject({
        assessmentId: started.value.assessmentId,
        assessmentRevision: first['assessmentRevision'],
        findings: [{
          recordKind: 'FINDING',
          validationState: 'VALIDATED',
        }],
        nextCursor: null,
      })
      const firstFinding = (first['findings'] as Array<Record<string, unknown>>)[0]
      const secondFinding = (second['findings'] as Array<Record<string, unknown>>)[0]
      expect(secondFinding?.['recordId']).not.toBe(firstFinding?.['recordId'])

      const invalid = await executeTool(
        fixture.ctx,
        'security_assessment_findings',
        { ...baseArgs, limit: 101 },
        root.agent,
      )
      expect(invalid.error?.info?.code).toBe('SECURITY_INVALID_REQUEST')

      const missing = await executeTool(
        fixture.ctx,
        'security_assessment_findings',
        {
          assessment_id: 'asm-00000000-0000-0000-0000-000000000000',
          limit: 10,
        },
        root.agent,
      )
      expect(missing.error?.info?.code).toBe('SECURITY_NOT_FOUND')

      openTurn(other)
      const transferredCursor = await executeTool(
        fixture.ctx,
        'security_assessment_findings',
        {
          ...baseArgs,
          cursor: first['nextCursor'],
        },
        other.agent,
      )
      expect(transferredCursor.error?.info?.code).toBe('SECURITY_INVALID_REQUEST')
    } finally {
      disposeOther()
      disposeRoot()
      await fixture.dispose()
    }
  })
})

describe('security_assessment_status authority', () => {
  it('requires the exact live calling session, an open turn, and no caller-supplied authority', async () => {
    const fixture = await harness()
    const root = stubAgent(`security-tool-root-${Math.random()}`)
    const disposeAgent = fixture.ctx.agents.register(root.agent)
    try {
      const agentless = await execute(fixture.ctx, {
        assessment_id: 'asm-00000000-0000-0000-0000-000000000000',
      })
      expect(agentless.error?.info?.code).toBe('SECURITY_TOOL_AGENT_REQUIRED')

      const turn = openTurn(root)
      const driverless = await execute(fixture.ctx, {
        assessment_id: 'asm-00000000-0000-0000-0000-000000000000',
      }, root.agent, null)
      expect(driverless.error?.info?.code).toBe('SECURITY_TOOL_DRIVER_REQUIRED')

      const forged = await execute(fixture.ctx, {
        assessment_id: 'asm-00000000-0000-0000-0000-000000000000',
        principal_id: 'forged-operator',
        permissions: ['risk:break-glass'],
      }, root.agent)
      expect(forged.error?.info?.code).toBe('SECURITY_NOT_FOUND')
      expect(JSON.stringify(forged)).not.toContain('forged-operator')
      expect(JSON.stringify(forged)).not.toContain('risk:break-glass')

      const invalid = await execute(fixture.ctx, { assessment_id: 'not-an-assessment' }, root.agent)
      expect(invalid.error?.info?.code).toBe('SECURITY_INVALID_REQUEST')

      const missing = await execute(fixture.ctx, {
        assessment_id: 'asm-00000000-0000-0000-0000-000000000000',
      }, root.agent)
      expect(missing.error?.info?.code).toBe('SECURITY_NOT_FOUND')
      expect(JSON.stringify(missing)).not.toContain('correlationId')
      expect(JSON.stringify(missing)).not.toContain(String(root.agent.id))

      const stale = stubAgent('security-tool-stale', root.session).agent
      const staleResult = await execute(fixture.ctx, {
        assessment_id: 'asm-00000000-0000-0000-0000-000000000000',
      }, stale, stale)
      expect(staleResult.error?.info?.code).toBe('SECURITY_TOOL_DRIVER_REQUIRED')

      root.setStatus('idle')
      const idle = await execute(fixture.ctx, {
        assessment_id: 'asm-00000000-0000-0000-0000-000000000000',
      }, root.agent)
      expect(idle.error?.info?.code).toBe('SECURITY_TOOL_DRIVER_REQUIRED')
      root.setStatus('running')
      closeTurn(root, turn)
      const after = await execute(fixture.ctx, {
        assessment_id: 'asm-00000000-0000-0000-0000-000000000000',
      }, root.agent)
      expect(after.error?.info?.code).toBe('SECURITY_TOOL_DRIVER_REQUIRED')
    } finally {
      disposeAgent()
      await fixture.dispose()
    }
  })
})

describe('security repository and catalog selection tools', () => {
  it('projects one registered Repository and its effective start choices without paths', async () => {
    const repository = await repositoryFixture({ name: 'security-selection-fixture', version: '1.0.0' })
    const fixture = await harness()
    const root = stubAgent(`security-tool-selection-${Math.random()}`)
    const disposeRoot = fixture.ctx.agents.register(root.agent)
    try {
      const platform = process.platform
      if (platform !== 'win32' && platform !== 'linux' && platform !== 'darwin') {
        throw new Error(`unsupported test platform: ${platform}`)
      }
      const registered = await fixture.ctx.securityAssurance.registerRepository(
        referenceHostInvocation(fixture.ctx.securityAssurance),
        {
          schemaVersion: 1,
          contractVersion: 1,
          idempotencyKey: 'security-tool-selection-repository-v1',
          root: repository,
          displayName: 'Security selection fixture',
          bindings: {
            policyId: 'security/node-package-lifecycle',
            assessmentProfileId: 'security/standard',
            evidenceProtectionId: 'evidence/local-protected',
            dataEgressPolicyId: 'egress/deny-by-default',
            platform,
            deliveryDestinationIds: [],
          },
        },
      )
      if (!registered.ok) throw new Error(`registration failed: ${registered.error.code}`)

      openTurn(root)
      const repositories = resultValue(await executeTool(
        fixture.ctx,
        'security_repositories',
        { limit: 20, state: 'ENABLED' },
        root.agent,
      ))
      expect(repositories).toEqual({
        schemaVersion: 1,
        repositories: [{
          repositoryId: registered.value.repositoryId,
          repositoryRevision: 1,
          state: 'ENABLED',
          displayName: 'Security selection fixture',
          policyId: 'security/node-package-lifecycle',
          assessmentProfileId: 'security/standard',
          platform,
        }],
        truncated: false,
      })
      expect(JSON.stringify(repositories)).not.toContain(repository)
      expect(JSON.stringify(repositories)).not.toContain('rootIdentityDigest')

      const catalog = resultValue(await executeTool(
        fixture.ctx,
        'security_catalog',
        { repository_id: registered.value.repositoryId },
        root.agent,
      ))
      expect(catalog).toMatchObject({
        schemaVersion: 1,
        repository: {
          repositoryId: registered.value.repositoryId,
          repositoryRevision: 1,
          state: 'ENABLED',
          displayName: 'Security selection fixture',
        },
        assessmentProfiles: [{ assessmentProfileId: 'security/standard' }],
      })
      expect(JSON.stringify(catalog)).not.toContain(repository)
      expect(JSON.stringify(catalog)).not.toContain('rootIdentityDigest')
    } finally {
      disposeRoot()
      await fixture.dispose()
    }
  })
})

describe('security_assessment_start integration', () => {
  it('starts through session authority, replays per session, and returns only a bounded receipt', async () => {
    const repository = await repositoryFixture()
    const fixture = await harness()
    const root = stubAgent(`security-tool-start-${Math.random()}`)
    const other = stubAgent(`security-tool-start-other-${Math.random()}`)
    const disposeRoot = fixture.ctx.agents.register(root.agent)
    const disposeOther = fixture.ctx.agents.register(other.agent)
    try {
      const platform = process.platform
      if (platform !== 'win32' && platform !== 'linux' && platform !== 'darwin') {
        throw new Error(`unsupported test platform: ${platform}`)
      }
      const hostInvocation = referenceHostInvocation(fixture.ctx.securityAssurance)
      const registered = await fixture.ctx.securityAssurance.registerRepository(hostInvocation, {
        schemaVersion: 1,
        contractVersion: 1 as const,
        idempotencyKey: 'security-tool-start-repository-v1',
        root: repository,
        displayName: 'Model start tool fixture',
        bindings: {
          policyId: 'security/default',
          assessmentProfileId: 'security/standard',
          evidenceProtectionId: 'evidence/local-protected',
          dataEgressPolicyId: 'egress/deny-by-default',
          platform,
          deliveryDestinationIds: [],
        },
      })
      if (!registered.ok) throw new Error(`registration failed: ${registered.error.code}`)

      const agentlessStart = await executeTool(
        fixture.ctx,
        'security_assessment_start',
        startArgs(registered.value.repositoryId, 'security-tool-start-agentless-v1'),
      )
      expect(agentlessStart.error?.info?.code).toBe('SECURITY_TOOL_AGENT_REQUIRED')

      openTurn(root)
      const driverlessStart = await executeTool(
        fixture.ctx,
        'security_assessment_start',
        startArgs(registered.value.repositoryId, 'security-tool-start-driverless-v1'),
        root.agent,
        null,
      )
      expect(driverlessStart.error?.info?.code).toBe('SECURITY_TOOL_DRIVER_REQUIRED')

      const args = startArgs(registered.value.repositoryId)
      const started = resultValue(await executeTool(
        fixture.ctx,
        'security_assessment_start',
        args,
        root.agent,
      ))
      expect(started).toEqual({
        schemaVersion: 1,
        operation: 'start_assessment',
        assessmentId: expect.stringMatching(/^asm-[0-9a-f-]{36}$/u),
        assessmentRevision: 1,
        state: 'CREATED',
        idempotencyKey: args.idempotency_key,
      })
      const serialized = JSON.stringify(started)
      for (const forbidden of [
        repository,
        registered.value.repositoryId,
        'repositoryId',
        'repositoryRevision',
        'subject',
        'digest',
        'acceptedAt',
        'correlationId',
        'principalId',
        String(root.agent.id),
      ]) expect(serialized).not.toContain(forbidden)

      const forgedReplay = resultValue(await executeTool(
        fixture.ctx,
        'security_assessment_start',
        {
          ...args,
          principal_id: 'forged-start-operator',
          permissions: ['risk:break-glass', 'repository:admin'],
        },
        root.agent,
      ))
      expect(forgedReplay).toEqual(started)
      expect(JSON.stringify(forgedReplay)).not.toContain('forged-start-operator')

      const idempotencyConflict = await executeTool(
        fixture.ctx,
        'security_assessment_start',
        {
          ...args,
          assessment_mode: 'TARGETED',
          target: { kind: 'targeted', relative_paths: ['README.md'] },
        },
        root.agent,
      )
      expect(idempotencyConflict.error?.info?.code).toBe('SECURITY_IDEMPOTENCY_CONFLICT')
      expect(JSON.stringify(idempotencyConflict)).not.toContain('correlationId')

      const inconsistent = await executeTool(
        fixture.ctx,
        'security_assessment_start',
        {
          ...args,
          idempotency_key: 'security-tool-start-inconsistent-v1',
          subject: {
            kind: 'change',
            base_commit: '0'.repeat(40),
            head_commit: '1'.repeat(40),
          },
        },
        root.agent,
      )
      expect(inconsistent.error?.info?.code).toBe('SECURITY_INVALID_REQUEST')

      const missing = await executeTool(
        fixture.ctx,
        'security_assessment_start',
        startArgs(
          'repo-00000000-0000-0000-0000-000000000000',
          'security-tool-start-missing-v1',
        ),
        root.agent,
      )
      expect(missing.error?.info?.code).toBe('SECURITY_NOT_FOUND')

      const stalePreflight = await executeTool(
        fixture.ctx,
        'security_assessment_start',
        {
          ...args,
          idempotency_key: 'security-tool-start-stale-preflight-v1',
          start_preflight_digest: {
            schema_version: 1,
            algorithm: 'sha256',
            media_type: 'application/vnd.dsh.canonical-json',
            byte_length: 0,
            canonicalization: 'dsh-canonical-json-v1',
            value: '0'.repeat(64),
          },
        },
        root.agent,
      )
      expect(stalePreflight.error?.info?.code).toBe('SECURITY_CONFLICT')

      const status = resultValue(await execute(fixture.ctx, {
        assessment_id: started['assessmentId'],
      }, root.agent))
      expect(status).toMatchObject({ assessmentId: started['assessmentId'] })

      openTurn(other)
      const otherSessionStart = resultValue(await executeTool(
        fixture.ctx,
        'security_assessment_start',
        args,
        other.agent,
      ))
      expect(otherSessionStart['assessmentId']).not.toBe(started['assessmentId'])
      expect(otherSessionStart).toMatchObject({
        assessmentRevision: 1,
        state: 'CREATED',
        idempotencyKey: args.idempotency_key,
      })
    } finally {
      disposeOther()
      disposeRoot()
      await fixture.dispose()
    }
  })
})

describe('security_assessment_status disclosure', () => {
  it('delegates through the real Service and returns only revision, state, coverage, and sealed Verdict', async () => {
    const repository = await repositoryFixture()
    const fixture = await harness()
    const root = stubAgent(`security-tool-sealed-${Math.random()}`)
    const disposeAgent = fixture.ctx.agents.register(root.agent)
    try {
      const platform = process.platform
      if (platform !== 'win32' && platform !== 'linux' && platform !== 'darwin') {
        throw new Error(`unsupported test platform: ${platform}`)
      }
      const invocation = referenceHostInvocation(fixture.ctx.securityAssurance)
      const registered = await fixture.ctx.securityAssurance.registerRepository(invocation, {
        schemaVersion: 1,
        contractVersion: 1 as const,
        idempotencyKey: 'security-tool-status-repository-v1',
        root: repository,
        displayName: 'Model tool disclosure fixture',
        bindings: {
          policyId: 'security/default',
          assessmentProfileId: 'security/standard',
          evidenceProtectionId: 'evidence/local-protected',
          dataEgressPolicyId: 'egress/deny-by-default',
          platform,
          deliveryDestinationIds: [],
        },
      })
      if (!registered.ok) throw new Error(`registration failed: ${registered.error.code}`)
      const started = await fixture.ctx.securityAssurance.startAssessment(invocation, {
        schemaVersion: 1,
        contractVersion: 1 as const,
        idempotencyKey: 'security-tool-status-assessment-v1',
        repositoryId: registered.value.repositoryId,
        subject: { kind: 'workspace_snapshot' },
        assessmentMode: 'REPOSITORY',
        assessmentProfileId: 'security/standard',
        target: { kind: 'repository' },
        requestedStrongerControlIds: [],
      })
      if (!started.ok) throw new Error(`start failed: ${started.error.code}`)
      await waitUntilSealed(fixture.ctx.securityAssurance, invocation, started.value.assessmentId)

      openTurn(root)
      const value = resultValue(await execute(fixture.ctx, {
        assessment_id: started.value.assessmentId,
      }, root.agent))
      expect(value).toEqual({
        schemaVersion: 1,
        assessmentId: started.value.assessmentId,
        assessmentRevision: 3,
        state: 'SEALED',
        coverage: {
          status: 'GAP',
          mandatoryObligations: 1,
          satisfiedObligations: 0,
          gapObligations: 1,
        },
        verdict: 'INDETERMINATE',
      })
      const serialized = JSON.stringify(value)
      for (const forbidden of [
        repository,
        registered.value.repositoryId,
        'repository',
        'subject',
        'policy',
        'digest',
        'resolutions',
        'blockedRecovery',
        'availableActions',
        'sealId',
        'createdAt',
        'updatedAt',
        'principalId',
        String(root.agent.id),
      ]) expect(serialized).not.toContain(forbidden)
    } finally {
      disposeAgent()
      await fixture.dispose()
    }
  })
})
