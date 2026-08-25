import { execFile } from 'node:child_process'
import { mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { promisify } from 'node:util'
import { Context } from '@deepseek-ai/cordis'
import AgentRegistry, { Inbox } from '@deepseek-ai/dsh-agent'
import type { Agent, AgentStatus } from '@deepseek-ai/dsh-agent'
import { CallId, createUserMessage } from '@deepseek-ai/dsh-llm'
import { Session, SessionId } from '@deepseek-ai/dsh-session'
import SystemPrompt from '@deepseek-ai/dsh-system-prompt'
import ToolRuntime from '@deepseek-ai/dsh-tools'
import type { ToolExecutionResult } from '@deepseek-ai/dsh-tools'
import { afterEach, describe, expect, it } from 'vitest'
import SecurityAssuranceService from '../src/index.ts'
import SecurityAssuranceTools from '../src/tools.ts'
import type { AssessmentId, SecurityInvocation } from '../src/contracts.ts'
import { referenceHostInvocation } from './support/reference-host.ts'

const run = promisify(execFile)
const temporaryRoots: string[] = []
const toolSignal = new AbortController().signal

afterEach(async () => {
  await Promise.all(temporaryRoots.splice(0).map(path => rm(path, { recursive: true, force: true })))
})

interface StubAgent {
  readonly agent: Agent
  readonly session: Session
  setStatus(status: AgentStatus): void
}

function stubAgent(rawId: string, supplied?: Session): StubAgent {
  const session = supplied ?? Session.create(SessionId(rawId))
  let status: AgentStatus = 'running'
  const agent: Agent = {
    id: session.id,
    options: {},
    session,
    inbox: new Inbox(session, { inserted: () => {}, discarded: () => {}, claimed: () => {} }),
    get status() { return status },
    ctx: new Context(),
    send: () => {},
    followup: () => {},
    steer: () => ({ outcome: Promise.resolve({ status: 'rejected' as const }) }),
    inject(input) { this.inbox.append('next-step', input) },
    cancel() {},
    runMaintenance: task => task(new AbortController().signal),
    whenIdle: () => Promise.resolve(),
  }
  return { agent, session, setStatus(value) { status = value } }
}

function openTurn(stub: StubAgent): number {
  const turn = stub.session.events
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
  const invoke = () => ctx.tools.execute({
    callId: CallId(`security-status-${Math.random()}`),
    name: 'security_assessment_status',
    arguments: args,
    signal,
    ...agent === undefined ? {} : { agent },
  })
  return initiator == null ? invoke() : ctx.agents.withInitiator(initiator, invoke)
}

async function harness() {
  const dshHome = await mkdtemp(join(tmpdir(), 'dsh-security-tools-home-'))
  temporaryRoots.push(dshHome)
  const ctx = new Context()
  const systemPromptFiber = await ctx.plugin(SystemPrompt)
  const agentFiber = await ctx.plugin(AgentRegistry)
  const toolRuntimeFiber = await ctx.plugin(ToolRuntime)
  const serviceFiber = await ctx.plugin(SecurityAssuranceService, { dshHome })
  await ctx.securityAssurance.whenReady()
  const toolsFiber = await ctx.plugin(SecurityAssuranceTools)
  return {
    ctx,
    toolsFiber,
    async dispose() {
      await toolsFiber.dispose()
      await serviceFiber.dispose()
      await toolRuntimeFiber.dispose()
      await agentFiber.dispose()
      await systemPromptFiber.dispose()
    },
  }
}

async function repositoryFixture(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), 'dsh-security-tools-repository-'))
  temporaryRoots.push(root)
  await run('git', ['init', '-b', 'main'], { cwd: root })
  await run('git', ['config', 'user.email', 'fixture@example.invalid'], { cwd: root })
  await run('git', ['config', 'user.name', 'Fixture'], { cwd: root })
  await writeFile(join(root, 'README.md'), '# model tool status fixture\n', 'utf8')
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

describe('security_assessment_status registration', () => {
  it('registers one parallel read tool and withdraws only that entry on disposal', async () => {
    const fixture = await harness()
    try {
      expect(SecurityAssuranceTools).toMatchObject({
        name: 'dsh-security-assurance-tools',
        inject: ['agents', 'securityAssurance', 'tools'],
      })
      const definition = fixture.ctx.tools.get('security_assessment_status')
      expect(definition?.name).toBe('security_assessment_status')
      expect(fixture.ctx.tools.executionMode({
        callId: CallId('security-status-mode'),
        name: 'security_assessment_status',
        arguments: { assessment_id: 'asm-00000000-0000-0000-0000-000000000000' },
        signal: toolSignal,
      })).toEqual({ kind: 'parallel' })
      expect(definition?.presentCall?.({
        assessment_id: 'asm-00000000-0000-0000-0000-000000000000',
      })).toEqual({
        card: 'generic',
        title: 'Read security assessment status',
        kind: 'read',
        rawInput: 'asm-00000000-0000-0000-0000-000000000000',
      })
      expect(definition?.presentCall?.({ forged: true })).toBeUndefined()

      await fixture.toolsFiber.dispose()
      expect(fixture.ctx.tools.get('security_assessment_status')).toBeUndefined()
      expect(fixture.ctx.reflect.get('securityAssurance')).toBeDefined()
    } finally {
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
