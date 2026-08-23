import { execFile } from 'node:child_process'
import { mkdir, mkdtemp, readdir, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { promisify } from 'node:util'
import { Context } from '@deepseek-ai/cordis'
import { afterEach, describe, expect, it } from 'vitest'
import SecurityAssuranceService from '../src/index.ts'
import type { AssessmentId, RepositoryId, SecurityInvocation } from '../src/index.ts'
import { referenceHostInvocation } from './support/reference-host.ts'

const run = promisify(execFile)
const temporaryRoots: string[] = []

afterEach(async () => {
  await Promise.all(temporaryRoots.splice(0).map(path => rm(path, { recursive: true, force: true })))
})

async function repositoryFixture(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), 'dsh-security-deterministic-repository-'))
  temporaryRoots.push(root)
  await run('git', ['init', '-b', 'main'], { cwd: root })
  await run('git', ['config', 'user.email', 'fixture@example.invalid'], { cwd: root })
  await run('git', ['config', 'user.name', 'Fixture'], { cwd: root })
  await writeFile(join(root, 'README.md'), '# deterministic assessment fixture\n', 'utf8')
  await run('git', ['add', '.'], { cwd: root })
  await run('git', ['commit', '-m', 'deterministic baseline'], { cwd: root })
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
    const assessment = await service.getAssessment(invocation, { schemaVersion: 1, assessmentId })
    if (!assessment.ok) throw new Error(`assessment query failed: ${assessment.error.code}`)
    if (assessment.value.state === 'SEALED') return
    revision = assessment.value.assessmentRevision
  }
  throw new Error('Assessment did not seal')
}

describe('SecurityAssuranceService deterministic Assessment path', () => {
  it('seals an honest INDETERMINATE result and serves its Bundle and self-contained Submission', async () => {
    const repository = await repositoryFixture()
    const dshHome = await mkdtemp(join(tmpdir(), 'dsh-security-deterministic-home-'))
    temporaryRoots.push(dshHome)
    const ctx = new Context()
    const fiber = await ctx.plugin(SecurityAssuranceService, { dshHome })
    const platform = process.platform
    if (platform !== 'win32' && platform !== 'linux' && platform !== 'darwin') {
      throw new Error(`unsupported test platform: ${platform}`)
    }

    try {
      const invocation = referenceHostInvocation(ctx.securityAssurance)
      const registered = await ctx.securityAssurance.registerRepository(invocation, {
        schemaVersion: 1,
        idempotencyKey: 'deterministic-repository-register-1',
        root: repository,
        displayName: 'Deterministic fixture',
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

      const started = await ctx.securityAssurance.startAssessment(invocation, {
        schemaVersion: 1,
        idempotencyKey: 'deterministic-assessment-start-1',
        repositoryId: registered.value.repositoryId,
        subject: { kind: 'workspace_snapshot' },
        assessmentMode: 'REPOSITORY',
        assessmentProfileId: 'security/standard',
        target: { kind: 'repository' },
        requestedStrongerControlIds: [],
      })
      if (!started.ok) throw new Error(`start failed: ${started.error.code}`)

      let revision: number = started.value.assessmentRevision
      let assessment: Awaited<ReturnType<typeof ctx.securityAssurance.getAssessment>> | undefined
      for (let attempt = 0; attempt < 5; attempt += 1) {
        const changed = await ctx.securityAssurance.waitForAssessmentRevision(invocation, {
          schemaVersion: 1,
          assessmentId: started.value.assessmentId,
          afterRevision: revision,
          timeoutMs: 5_000,
        })
        expect(changed).toMatchObject({ ok: true, value: { kind: 'CHANGED' } })
        assessment = await ctx.securityAssurance.getAssessment(invocation, {
          schemaVersion: 1,
          assessmentId: started.value.assessmentId,
        })
        if (!assessment.ok) throw new Error(`assessment query failed: ${assessment.error.code}`)
        revision = assessment.value.assessmentRevision
        if (assessment.value.state === 'SEALED') break
      }

      expect(assessment).toMatchObject({
        ok: true,
        value: {
          schemaVersion: 1,
          assessmentId: started.value.assessmentId,
          assessmentRevision: 3,
          state: 'SEALED',
          verdict: 'INDETERMINATE',
          coverage: {
            status: 'GAP',
            mandatoryObligations: 1,
            satisfiedObligations: 0,
            gapObligations: 1,
            resolutions: [{
              obligationId: 'application-security-analysis',
              state: 'GAP',
              reason: 'NO_ELIGIBLE_ANALYZER',
            }],
          },
          seal: {
            schemaVersion: 1,
            sealId: expect.stringMatching(/^seal-[0-9a-f-]{36}$/u),
            digest: { algorithm: 'sha256', canonicalization: 'dsh-canonical-json-v1' },
          },
        },
      })

      const bundle = await ctx.securityAssurance.getBundleManifest(invocation, {
        schemaVersion: 1,
        assessmentId: started.value.assessmentId,
      })
      expect(bundle).toMatchObject({
        ok: true,
        value: {
          schemaVersion: 1,
          assessmentId: started.value.assessmentId,
          assessmentRevision: 3,
          verdict: 'INDETERMINATE',
          records: expect.arrayContaining([
            expect.objectContaining({ schemaId: 'dsh/security-subject' }),
            expect.objectContaining({ schemaId: 'dsh/security-policy' }),
            expect.objectContaining({ schemaId: 'dsh/security-coverage' }),
            expect.objectContaining({ schemaId: 'dsh/security-findings' }),
            expect.objectContaining({ schemaId: 'dsh/security-verdict' }),
            expect.objectContaining({ schemaId: 'dsh/security-provenance' }),
          ]),
          omissions: [{ schemaId: 'dsh/security-threat-model', reason: 'NO_ELIGIBLE_ANALYZER' }],
        },
      })

      const submission = await ctx.securityAssurance.getAssuranceSubmission(invocation, {
        schemaVersion: 1,
        assessmentId: started.value.assessmentId,
      })
      expect(submission).toMatchObject({
        ok: true,
        value: {
          schemaVersion: 1,
          payload: {
            assessment: {
              assessmentId: started.value.assessmentId,
              assessmentRevision: 3,
              state: 'SEALED',
              verdict: 'INDETERMINATE',
            },
            binding: {
              repositoryId: registered.value.repositoryId,
              repositoryRevision: 1,
              policyId: 'security/default',
            },
            coverage: expect.objectContaining({ schemaId: 'dsh/security-coverage' }),
            sourceSeal: expect.objectContaining({
              schemaId: 'dsh/security-source-seal',
              value: expect.objectContaining({
                seal: expect.objectContaining({ verdict: 'INDETERMINATE' }),
                binding: expect.objectContaining({
                  assessmentId: started.value.assessmentId,
                  repositoryId: registered.value.repositoryId,
                }),
              }),
            }),
            evidence: expect.arrayContaining([
              expect.objectContaining({ schemaId: 'dsh/security-subject-inventory' }),
              expect.objectContaining({ schemaId: 'dsh/security-evaluation-trace' }),
            ]),
          },
          digest: {
            algorithm: 'sha256',
            mediaType: 'application/vnd.dsh.security.assurance-submission+json',
            canonicalization: 'dsh-canonical-json-v1',
            value: expect.stringMatching(/^[0-9a-f]{64}$/u),
          },
        },
      })
      expect(JSON.stringify(submission)).not.toContain(repository)
      expect(Object.isFrozen(submission)).toBe(true)
      if (submission.ok) expect(Object.isFrozen(submission.value.payload.evidence)).toBe(true)
    } finally {
      await fiber.dispose()
    }
  })

  it('resumes one interrupted Assessment only through an explicit revision-bound command', async () => {
    const repository = await repositoryFixture()
    await writeFile(join(repository, 'package.json'), JSON.stringify({
      name: 'interrupted-assessment-fixture',
      version: '1.0.0',
      scripts: { postinstall: 'node ./postinstall.js' },
    }), 'utf8')
    await writeFile(join(repository, 'postinstall.js'), 'process.stdout.write("fixture")\n', 'utf8')
    const dshHome = await mkdtemp(join(tmpdir(), 'dsh-security-resume-home-'))
    temporaryRoots.push(dshHome)
    const platform = process.platform
    if (platform !== 'win32' && platform !== 'linux' && platform !== 'darwin') {
      throw new Error(`unsupported test platform: ${platform}`)
    }

    const firstContext = new Context()
    const firstFiber = await firstContext.plugin(SecurityAssuranceService, { dshHome })
    const firstInvocation = referenceHostInvocation(firstContext.securityAssurance)
    const registered = await firstContext.securityAssurance.registerRepository(firstInvocation, {
      schemaVersion: 1,
      idempotencyKey: 'resume-repository-register-1',
      root: repository,
      displayName: 'Resume fixture',
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
    const startRequest = {
      schemaVersion: 1 as const,
      idempotencyKey: 'resume-assessment-start-1',
      repositoryId: registered.value.repositoryId,
      subject: { kind: 'workspace_snapshot' as const },
      assessmentMode: 'REPOSITORY' as const,
      assessmentProfileId: 'security/standard',
      target: { kind: 'repository' as const },
      requestedStrongerControlIds: [],
    }
    const started = await firstContext.securityAssurance.startAssessment(firstInvocation, startRequest)
    if (!started.ok) throw new Error(`start failed: ${started.error.code}`)
    await firstFiber.dispose()

    const restartedContext = new Context()
    const restartedFiber = await restartedContext.plugin(SecurityAssuranceService, { dshHome })
    try {
      const invocation = referenceHostInvocation(restartedContext.securityAssurance)
      await restartedContext.securityAssurance.whenReady()
      const interrupted = await restartedContext.securityAssurance.getAssessment(invocation, {
        schemaVersion: 1,
        assessmentId: started.value.assessmentId,
      })
      expect(interrupted).toMatchObject({
        ok: true,
        value: { state: 'BLOCKED', verdict: null, seal: null },
      })
      if (!interrupted.ok) throw new Error(`assessment query failed: ${interrupted.error.code}`)

      const replayedStart = await restartedContext.securityAssurance.startAssessment(invocation, startRequest)
      expect(replayedStart).toEqual(started)
      await new Promise(resolve => setTimeout(resolve, 25))
      await expect(restartedContext.securityAssurance.getAssessment(invocation, {
        schemaVersion: 1,
        assessmentId: started.value.assessmentId,
      })).resolves.toMatchObject({ ok: true, value: { state: 'BLOCKED' } })

      const resumeRequest = {
        schemaVersion: 1 as const,
        assessmentId: started.value.assessmentId,
        expectedAssessmentRevision: interrupted.value.assessmentRevision,
        idempotencyKey: 'resume-assessment-command-1',
        reason: {
          code: 'HOST_RESTART_RECONCILIATION',
          summary: 'Resume the interrupted deterministic assessment for Provider reconciliation.',
        },
      }
      const resumed = await restartedContext.securityAssurance.resumeAssessment(invocation, resumeRequest)
      expect(resumed).toMatchObject({
        ok: true,
        value: {
          operation: 'resume_assessment',
          assessmentId: started.value.assessmentId,
          assessmentRevision: interrupted.value.assessmentRevision + 1,
          state: 'CREATED',
          idempotencyKey: resumeRequest.idempotencyKey,
        },
      })
      await waitUntilSealed(restartedContext.securityAssurance, invocation, started.value.assessmentId)
      const sealed = await restartedContext.securityAssurance.getAssessment(invocation, {
        schemaVersion: 1,
        assessmentId: started.value.assessmentId,
      })
      expect(sealed).toMatchObject({
        ok: true,
        value: {
          state: 'SEALED',
          assessmentRevision: interrupted.value.assessmentRevision + 3,
          verdict: expect.any(String),
          seal: expect.objectContaining({
            assessmentRevision: interrupted.value.assessmentRevision + 3,
          }),
        },
      })
      await expect(
        restartedContext.securityAssurance.resumeAssessment(invocation, resumeRequest),
      ).resolves.toEqual(resumed)
    } finally {
      await restartedFiber.dispose()
    }
  })

  it('persists an explicit cancellation request before quiescing and committing CANCELED', async () => {
    const repository = await repositoryFixture()
    await Promise.all(Array.from({ length: 250 }, async (_value, index) => {
      const directory = join(repository, 'fixtures', `cancel-package-${index}`)
      await mkdir(directory, { recursive: true })
      await writeFile(join(directory, 'package.json'), JSON.stringify({
        name: `cancel-fixture-${index}`,
        version: '1.0.0',
      }), 'utf8')
    }))
    const dshHome = await mkdtemp(join(tmpdir(), 'dsh-security-cancel-home-'))
    temporaryRoots.push(dshHome)
    const platform = process.platform
    if (platform !== 'win32' && platform !== 'linux' && platform !== 'darwin') {
      throw new Error(`unsupported test platform: ${platform}`)
    }
    const ctx = new Context()
    const fiber = await ctx.plugin(SecurityAssuranceService, { dshHome })
    try {
      const invocation = referenceHostInvocation(ctx.securityAssurance)
      const registered = await ctx.securityAssurance.registerRepository(invocation, {
        schemaVersion: 1,
        idempotencyKey: 'cancel-repository-register-1',
        root: repository,
        displayName: 'Cancellation fixture',
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
      const started = await ctx.securityAssurance.startAssessment(invocation, {
        schemaVersion: 1,
        idempotencyKey: 'cancel-assessment-start-1',
        repositoryId: registered.value.repositoryId,
        subject: { kind: 'workspace_snapshot' },
        assessmentMode: 'REPOSITORY',
        assessmentProfileId: 'security/standard',
        target: { kind: 'repository' },
        requestedStrongerControlIds: [],
      })
      if (!started.ok) throw new Error(`start failed: ${started.error.code}`)
      const running = await ctx.securityAssurance.getAssessment(invocation, {
        schemaVersion: 1,
        assessmentId: started.value.assessmentId,
      })
      expect(running).toMatchObject({ ok: true, value: { state: 'RUNNING' } })
      if (!running.ok) throw new Error(`assessment query failed: ${running.error.code}`)

      const cancelRequest = {
        schemaVersion: 1 as const,
        assessmentId: started.value.assessmentId,
        expectedAssessmentRevision: running.value.assessmentRevision,
        idempotencyKey: 'cancel-assessment-command-1',
        reason: {
          code: 'OPERATOR_REQUEST',
          summary: 'Stop this Assessment because its owning operation was explicitly canceled.',
        },
      }
      const canceled = await ctx.securityAssurance.cancelAssessment(invocation, cancelRequest)
      expect(canceled).toMatchObject({
        ok: true,
        value: {
          operation: 'cancel_assessment',
          assessmentId: started.value.assessmentId,
          assessmentRevision: running.value.assessmentRevision + 1,
          acceptedState: 'RUNNING',
          idempotencyKey: cancelRequest.idempotencyKey,
        },
      })
      const terminal = await ctx.securityAssurance.getAssessment(invocation, {
        schemaVersion: 1,
        assessmentId: started.value.assessmentId,
      })
      expect(terminal).toMatchObject({
        ok: true,
        value: {
          state: 'CANCELED',
          assessmentRevision: running.value.assessmentRevision + 2,
          verdict: null,
          seal: null,
        },
      })
      await expect(ctx.securityAssurance.cancelAssessment(invocation, cancelRequest)).resolves.toEqual(canceled)
      await expect(ctx.securityAssurance.cancelAssessment(invocation, {
        ...cancelRequest,
        idempotencyKey: 'cancel-assessment-command-stale',
      })).resolves.toMatchObject({ ok: false, error: { code: 'CONFLICT' } })
    } finally {
      await fiber.dispose()
    }
  })

  it('replays the same sealed value after restart and fails closed if private publication bytes change', async () => {
    const repository = await repositoryFixture()
    const dshHome = await mkdtemp(join(tmpdir(), 'dsh-security-restart-home-'))
    temporaryRoots.push(dshHome)
    const platform = process.platform
    if (platform !== 'win32' && platform !== 'linux' && platform !== 'darwin') {
      throw new Error(`unsupported test platform: ${platform}`)
    }
    const startRequest = {
      schemaVersion: 1 as const,
      idempotencyKey: 'restart-assessment-start-1',
      subject: { kind: 'workspace_snapshot' as const },
      assessmentMode: 'REPOSITORY' as const,
      assessmentProfileId: 'security/standard',
      target: { kind: 'repository' as const },
      requestedStrongerControlIds: [],
    }

    const firstContext = new Context()
    const firstFiber = await firstContext.plugin(SecurityAssuranceService, { dshHome })
    let assessmentId: AssessmentId
    let repositoryId: RepositoryId
    let originalSubmission: unknown
    try {
      const invocation = referenceHostInvocation(firstContext.securityAssurance)
      const registered = await firstContext.securityAssurance.registerRepository(invocation, {
        schemaVersion: 1,
        idempotencyKey: 'restart-repository-register-1',
        root: repository,
        displayName: 'Restart fixture',
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
      repositoryId = registered.value.repositoryId
      const started = await firstContext.securityAssurance.startAssessment(invocation, {
        ...startRequest,
        repositoryId,
      })
      if (!started.ok) throw new Error(`start failed: ${started.error.code}`)
      assessmentId = started.value.assessmentId
      await waitUntilSealed(firstContext.securityAssurance, invocation, assessmentId)
      originalSubmission = await firstContext.securityAssurance.getAssuranceSubmission(invocation, {
        schemaVersion: 1,
        assessmentId,
      })
      expect(originalSubmission).toMatchObject({ ok: true })
    } finally {
      await firstFiber.dispose()
    }

    const restartedContext = new Context()
    const restartedFiber = await restartedContext.plugin(SecurityAssuranceService, { dshHome })
    try {
      const invocation = referenceHostInvocation(restartedContext.securityAssurance)
      await restartedContext.securityAssurance.whenReady()
      const replayed = await restartedContext.securityAssurance.startAssessment(invocation, {
        ...startRequest,
        repositoryId,
      })
      expect(replayed).toMatchObject({
        ok: true,
        value: { assessmentId, assessmentRevision: 1, state: 'CREATED' },
      })
      const replayedSubmission = await restartedContext.securityAssurance.getAssuranceSubmission(invocation, {
        schemaVersion: 1,
        assessmentId,
      })
      expect(replayedSubmission).toEqual(originalSubmission)

      const publicationRoot = join(dshHome, 'security-assurance', 'bundles', assessmentId)
      const publications = (await readdir(publicationRoot, { withFileTypes: true }))
        .filter(entry => entry.isDirectory() && /^[0-9a-f]{64}$/u.test(entry.name))
      expect(publications).toHaveLength(1)
      const publication = publications[0]
      if (publication === undefined) throw new Error('sealed publication is missing')
      await writeFile(join(publicationRoot, publication.name, 'assurance-submission.json'), '{}', 'utf8')

      const rejected = await restartedContext.securityAssurance.getAssuranceSubmission(invocation, {
        schemaVersion: 1,
        assessmentId,
      })
      expect(rejected).toMatchObject({
        ok: false,
        error: { code: 'UNAVAILABLE', retryable: true },
      })
    } finally {
      await restartedFiber.dispose()
    }
  })
})
