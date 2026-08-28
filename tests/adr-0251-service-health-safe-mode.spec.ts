import { execFile } from 'node:child_process'
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { DatabaseSync } from 'node:sqlite'
import { promisify } from 'node:util'
import { Context } from '@deepseek-ai/cordis'
import { afterEach, describe, expect, it } from 'vitest'
import SecurityAssuranceService from '../src/index.ts'
import type { AssessmentId, RepositoryId, SecurityInvocation } from '../src/index.ts'
import {
  referenceHostInvocation,
  referenceHostInvocationWithPermissions,
} from './support/reference-host.ts'

const run = promisify(execFile)
const temporaryRoots: string[] = []

afterEach(async () => {
  await Promise.all(temporaryRoots.splice(0).map(path => rm(path, { recursive: true, force: true })))
})

async function cleanRepository(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), 'dsh-security-adr-0251-repository-'))
  temporaryRoots.push(root)
  await run('git', ['init', '-b', 'main'], { cwd: root })
  await run('git', ['config', 'user.email', 'fixture@example.invalid'], { cwd: root })
  await run('git', ['config', 'user.name', 'Fixture'], { cwd: root })
  await writeFile(join(root, 'README.md'), '# ADR 0251 fixture\n', 'utf8')
  await run('git', ['add', 'README.md'], { cwd: root })
  await run('git', ['commit', '-m', 'fixture baseline'], { cwd: root })
  return root
}

async function waitUntilSealed(
  service: SecurityAssuranceService,
  invocation: SecurityInvocation,
  assessmentId: AssessmentId,
): Promise<void> {
  for (let attempt = 0; attempt < 100; attempt += 1) {
    const assessment = await service.getAssessment(invocation, { schemaVersion: 1, assessmentId })
    if (!assessment.ok) throw new Error(`assessment query failed: ${assessment.error.code}`)
    if (assessment.value.state === 'SEALED') return
    await new Promise(resolve => setTimeout(resolve, 10))
  }
  throw new Error('Assessment did not seal')
}

describe('ADR 0251: Service health is explicit and Safe Mode remains queryable', () => {
  it('keeps the bounded Runtime Health Snapshot behind health:read authority', async () => {
    const dshHome = await mkdtemp(join(tmpdir(), 'dsh-security-adr-0251-home-'))
    temporaryRoots.push(dshHome)
    const ctx = new Context()
    const fiber = await ctx.plugin(SecurityAssuranceService, { dshHome })

    try {
      const invocation = referenceHostInvocationWithPermissions(
        ctx.securityAssurance,
        ['repository:read'],
        'diagnosis-without-health-authority',
      )
      const result = await ctx.securityAssurance.getHealth(invocation, { schemaVersion: 1 })
      expect(result).toMatchObject({ ok: false, error: { code: 'UNAUTHORIZED', retryable: false } })
      expect(JSON.stringify(result)).not.toContain('diagnosis-without-health-authority')
      expect(JSON.stringify(result)).not.toContain(dshHome)
    } finally {
      await fiber.dispose()
    }
  })

  it('reports STOPPED with every admission class closed after Service teardown', async () => {
    const dshHome = await mkdtemp(join(tmpdir(), 'dsh-security-adr-0251-home-'))
    temporaryRoots.push(dshHome)
    const ctx = new Context()
    const fiber = await ctx.plugin(SecurityAssuranceService, { dshHome })
    const service = ctx.securityAssurance
    const invocation = referenceHostInvocation(service)

    await fiber.dispose()

    await expect(service.getHealth(invocation, { schemaVersion: 1 })).resolves.toMatchObject({
      ok: true,
      value: {
        state: 'STOPPED',
        admission: {
          queries: false,
          mutations: false,
          sealedExports: false,
        },
      },
    })
  })

  it('reports QUIESCING while teardown waits for owned Analyzer disposal', async () => {
    const repository = await cleanRepository()
    const dshHome = await mkdtemp(join(tmpdir(), 'dsh-security-adr-0251-home-'))
    temporaryRoots.push(dshHome)
    const platform = process.platform
    if (platform !== 'win32' && platform !== 'linux' && platform !== 'darwin') {
      throw new Error(`unsupported test platform: ${platform}`)
    }
    const ctx = new Context()
    const fiber = await ctx.plugin(SecurityAssuranceService, { dshHome })
    const service = ctx.securityAssurance
    const invocation = referenceHostInvocation(service)
    let markAnalyzerStarted = () => {}
    const analyzerStarted = new Promise<void>(resolve => { markAnalyzerStarted = resolve })
    let releaseAnalyzerDispose = () => {}
    const analyzerDisposeBarrier = new Promise<void>(resolve => { releaseAnalyzerDispose = resolve })
    const unregister = service.registerAnalyzer({
      schemaVersion: 1,
      analyzerId: 'fixture/quiescing-health',
      analyzerVersion: '1.0.0',
      descriptorSchemaVersion: 1,
      buildDigest: {
        schemaVersion: 1,
        algorithm: 'sha256',
        mediaType: 'application/vnd.fixture.quiescing-health+json',
        byteLength: 1,
        canonicalization: 'dsh-canonical-json-v1',
        value: '7'.repeat(64),
      },
      executionClass: 'PURE',
      supportedAssessmentModes: ['REPOSITORY'],
      supportedPolicyIds: ['security/quiescing-health'],
      coverageObligationIds: ['application-security-analysis'],
      evidenceSchemaIds: ['fixture/quiescing-health-evidence'],
      egress: 'NONE',
    }, descriptor => ({
      descriptor,
      analyze(_input, options) {
        markAnalyzerStarted()
        return new Promise<never>((_resolve, reject) => {
          const signal = options?.signal
          if (signal === undefined) return
          const rejectAbort = () => reject(signal.reason ?? new Error('Analyzer invocation aborted'))
          if (signal.aborted) rejectAbort()
          else signal.addEventListener('abort', rejectAbort, { once: true })
        })
      },
      async dispose() {
        await analyzerDisposeBarrier
      },
    }))

    try {
      const registered = await service.registerRepository(invocation, {
        schemaVersion: 1,
        contractVersion: 1 as const,
        idempotencyKey: 'quiescing-health-register-1',
        root: repository,
        displayName: 'Quiescing health fixture',
        bindings: {
          policyId: 'security/quiescing-health',
          assessmentProfileId: 'security/standard',
          evidenceProtectionId: 'evidence/local-protected',
          dataEgressPolicyId: 'egress/deny-by-default',
          platform,
          deliveryDestinationIds: [],
        },
      })
      if (!registered.ok) throw new Error(`registration failed: ${registered.error.code}`)
      const started = await service.startAssessment(invocation, {
        schemaVersion: 1,
        contractVersion: 1 as const,
        idempotencyKey: 'quiescing-health-start-1',
        repositoryId: registered.value.repositoryId,
        subject: { kind: 'workspace_snapshot' },
        assessmentMode: 'REPOSITORY',
        assessmentProfileId: 'security/standard',
        target: { kind: 'repository' },
        requestedStrongerControlIds: [],
      })
      if (!started.ok) throw new Error(`start failed: ${started.error.code}`)
      await Promise.race([
        analyzerStarted,
        new Promise<never>((_resolve, reject) => {
          setTimeout(() => reject(new Error('Analyzer did not start before teardown')), 5_000)
        }),
      ])

      const disposal = fiber.dispose()
      let quiescing = await service.getHealth(invocation, { schemaVersion: 1 })
      for (let attempt = 0; attempt < 50 && (quiescing.ok && quiescing.value.state !== 'QUIESCING'); attempt += 1) {
        await new Promise(resolve => setTimeout(resolve, 0))
        quiescing = await service.getHealth(invocation, { schemaVersion: 1 })
      }
      expect(quiescing).toMatchObject({
        ok: true,
        value: {
          state: 'QUIESCING',
          admission: { queries: true, mutations: false, sealedExports: false },
        },
      })
      await expect(service.listRepositories(invocation, {
        schemaVersion: 1,
        limit: 10,
      })).resolves.toMatchObject({
        ok: true,
        value: {
          repositories: [expect.objectContaining({ repositoryId: registered.value.repositoryId, state: 'ENABLED' })],
        },
      })
      await expect(service.disableRepository(invocation, {
        schemaVersion: 1,
        contractVersion: 1 as const,
        idempotencyKey: 'quiescing-health-disable-1',
        repositoryId: registered.value.repositoryId,
        expectedRepositoryRevision: 1,
      })).resolves.toMatchObject({ ok: false, error: { code: 'UNAVAILABLE', retryable: true } })

      releaseAnalyzerDispose()
      await disposal
      await expect(service.getHealth(invocation, { schemaVersion: 1 })).resolves.toMatchObject({
        ok: true,
        value: { state: 'STOPPED' },
      })
    } finally {
      releaseAnalyzerDispose()
      unregister()
      await fiber.dispose()
    }
  })

  it('keeps bounded catalog diagnosis available while Store-backed operations fail closed', async () => {
    const dshHome = await mkdtemp(join(tmpdir(), 'dsh-security-adr-0251-home-'))
    temporaryRoots.push(dshHome)
    const stateRoot = join(dshHome, 'security-assurance')
    await mkdir(stateRoot, { recursive: true })
    const foreign = new DatabaseSync(join(stateRoot, 'security-assurance.sqlite'))
    foreign.exec('CREATE TABLE foreign_owner (id INTEGER PRIMARY KEY)')
    foreign.close()
    const ctx = new Context()
    const fiber = await ctx.plugin(SecurityAssuranceService, { dshHome })

    try {
      const invocation = referenceHostInvocation(ctx.securityAssurance)
      const health = await ctx.securityAssurance.getHealth(invocation, {
        schemaVersion: 1,
      })
      expect(health).toMatchObject({
        ok: true,
        value: {
          state: 'READ_ONLY_SAFE',
          admission: { queries: true, mutations: false, sealedExports: false },
          checks: expect.arrayContaining([
            expect.objectContaining({ id: 'persistence.sqlite', status: 'FAIL', required: true }),
            expect.objectContaining({ id: 'runtime.node', status: 'PASS', required: true }),
          ]),
        },
      })
      const serializedHealth = JSON.stringify(health)
      expect(serializedHealth).not.toContain(dshHome)
      expect(serializedHealth).not.toContain('security-assurance.sqlite')
      expect(serializedHealth).not.toContain('foreign_owner')

      await expect(ctx.securityAssurance.getCatalog(invocation, {
        schemaVersion: 1,
      })).resolves.toMatchObject({
        ok: true,
        value: {
          schemaVersion: 1,
          repository: null,
        },
      })
      await expect(ctx.securityAssurance.listRepositories(invocation, {
        schemaVersion: 1,
        limit: 10,
      })).resolves.toMatchObject({ ok: false, error: { code: 'UNAVAILABLE', retryable: true } })
      await expect(ctx.securityAssurance.registerRepository(invocation, {
        schemaVersion: 1,
        contractVersion: 1 as const,
        idempotencyKey: 'read-only-safe-register-1',
        root: 'D:/must-not-be-resolved-in-safe-mode',
        displayName: 'Must not register',
        bindings: {
          policyId: 'security/default',
          assessmentProfileId: 'security/standard',
          evidenceProtectionId: 'evidence/local-protected',
          dataEgressPolicyId: 'egress/deny-by-default',
          platform: process.platform === 'win32' || process.platform === 'linux' || process.platform === 'darwin'
            ? process.platform
            : 'linux',
          deliveryDestinationIds: [],
        },
      })).resolves.toMatchObject({ ok: false, error: { code: 'UNAVAILABLE', retryable: true } })
    } finally {
      await fiber.dispose()
    }
  })

  it('fails mutations closed when the running Node version is incompatible', async () => {
    const repository = await cleanRepository()
    const dshHome = await mkdtemp(join(tmpdir(), 'dsh-security-adr-0251-home-'))
    temporaryRoots.push(dshHome)
    const nodeVersionDescriptor = Object.getOwnPropertyDescriptor(process.versions, 'node')
    if (nodeVersionDescriptor === undefined) throw new Error('process.versions.node descriptor is unavailable')
    Object.defineProperty(process.versions, 'node', {
      ...nodeVersionDescriptor,
      value: '23.0.0',
    })
    const ctx = new Context()
    const fiber = await ctx.plugin(SecurityAssuranceService, { dshHome })

    try {
      const invocation = referenceHostInvocation(ctx.securityAssurance)
      await expect(ctx.securityAssurance.getHealth(invocation, {
        schemaVersion: 1,
      })).resolves.toMatchObject({
        ok: true,
        value: {
          state: 'READ_ONLY_SAFE',
          compatibility: { actualNodeVersion: '23.0.0' },
          admission: { queries: true, mutations: false, sealedExports: true },
          checks: expect.arrayContaining([
            expect.objectContaining({ id: 'persistence.sqlite', status: 'PASS', required: true }),
            expect.objectContaining({ id: 'runtime.node', status: 'FAIL', required: true }),
          ]),
        },
      })

      await expect(ctx.securityAssurance.registerRepository(invocation, {
        schemaVersion: 1,
        contractVersion: 1 as const,
        idempotencyKey: 'incompatible-runtime-register-1',
        root: repository,
        displayName: 'Must not register on an incompatible runtime',
        bindings: {
          policyId: 'security/default',
          assessmentProfileId: 'security/standard',
          evidenceProtectionId: 'evidence/local-protected',
          dataEgressPolicyId: 'egress/deny-by-default',
          platform: process.platform === 'win32' || process.platform === 'linux' || process.platform === 'darwin'
            ? process.platform
            : 'linux',
          deliveryDestinationIds: [],
        },
      })).resolves.toMatchObject({ ok: false, error: { code: 'UNAVAILABLE', retryable: true } })

      const repositoryId = 'repo-00000000-0000-4000-8000-000000000001' as RepositoryId
      const assessmentId = 'asm-00000000-0000-4000-8000-000000000001' as AssessmentId
      const remainingMutationResults = await Promise.all([
        ctx.securityAssurance.updateRepository(invocation, {
          schemaVersion: 1,
          contractVersion: 1 as const,
          idempotencyKey: 'incompatible-runtime-update-1',
          repositoryId,
          expectedRepositoryRevision: 1,
          displayName: 'Must not update',
        }),
        ctx.securityAssurance.disableRepository(invocation, {
          schemaVersion: 1,
          contractVersion: 1 as const,
          idempotencyKey: 'incompatible-runtime-disable-1',
          repositoryId,
          expectedRepositoryRevision: 1,
        }),
        ctx.securityAssurance.startAssessment(invocation, {
          schemaVersion: 1,
          contractVersion: 1 as const,
          idempotencyKey: 'incompatible-runtime-start-1',
          repositoryId,
          subject: { kind: 'workspace_snapshot' },
          assessmentMode: 'REPOSITORY',
          assessmentProfileId: 'security/standard',
          target: { kind: 'repository' },
          requestedStrongerControlIds: [],
        }),
        ctx.securityAssurance.resumeAssessment(invocation, {
          schemaVersion: 1,
          contractVersion: 1 as const,
          idempotencyKey: 'incompatible-runtime-resume-1',
          assessmentId,
          expectedAssessmentRevision: 1,
          reason: { code: 'SAFE_MODE_TEST', summary: 'Must not resume in read-only-safe mode.' },
        }),
        ctx.securityAssurance.cancelAssessment(invocation, {
          schemaVersion: 1,
          contractVersion: 1 as const,
          idempotencyKey: 'incompatible-runtime-cancel-1',
          assessmentId,
          expectedAssessmentRevision: 1,
          reason: { code: 'SAFE_MODE_TEST', summary: 'Must not cancel in read-only-safe mode.' },
        }),
        ctx.securityAssurance.recordRiskDecision(invocation, {
          schemaVersion: 1,
          contractVersion: 1 as const,
          idempotencyKey: 'incompatible-runtime-risk-1',
          assessmentId,
          expectedAssessmentRevision: 1,
          finding: { recordId: `finding-${'0'.repeat(64)}`, recordRevision: 1 },
          decision: 'DENY',
          rationale: 'This valid request must fail closed before any lookup or write occurs.',
          compensatingControls: [],
          expiresAt: null,
        }),
        ctx.securityAssurance.requestExport(invocation, {
          schemaVersion: 1,
          contractVersion: 1 as const,
          idempotencyKey: 'incompatible-runtime-export-1',
          assessmentId,
          expectedAssessmentRevision: 1,
          exportProfileId: 'security/export/internal-json-v1',
          deliveryDestinationId: 'delivery/local-audit',
        }),
      ])
      for (const result of remainingMutationResults) {
        expect(result).toMatchObject({ ok: false, error: { code: 'UNAVAILABLE', retryable: true } })
      }
      await expect(ctx.securityAssurance.listRepositories(invocation, {
        schemaVersion: 1,
        limit: 10,
      })).resolves.toMatchObject({ ok: true, value: { repositories: [] } })
    } finally {
      await fiber.dispose()
      Object.defineProperty(process.versions, 'node', nodeVersionDescriptor)
    }
  })

  it('keeps verified sealed records queryable on an incompatible runtime restart', async () => {
    const repository = await cleanRepository()
    const dshHome = await mkdtemp(join(tmpdir(), 'dsh-security-adr-0251-home-'))
    temporaryRoots.push(dshHome)
    const platform = process.platform
    if (platform !== 'win32' && platform !== 'linux' && platform !== 'darwin') {
      throw new Error(`unsupported test platform: ${platform}`)
    }
    const initialContext = new Context()
    const initialFiber = await initialContext.plugin(SecurityAssuranceService, { dshHome })
    let assessmentId: AssessmentId

    try {
      const invocation = referenceHostInvocation(initialContext.securityAssurance)
      const registered = await initialContext.securityAssurance.registerRepository(invocation, {
        schemaVersion: 1,
        contractVersion: 1 as const,
        idempotencyKey: 'sealed-safe-mode-register-1',
        root: repository,
        displayName: 'Sealed Safe Mode fixture',
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
      const started = await initialContext.securityAssurance.startAssessment(invocation, {
        schemaVersion: 1,
        contractVersion: 1 as const,
        idempotencyKey: 'sealed-safe-mode-start-1',
        repositoryId: registered.value.repositoryId,
        subject: { kind: 'workspace_snapshot' },
        assessmentMode: 'REPOSITORY',
        assessmentProfileId: 'security/standard',
        target: { kind: 'repository' },
        requestedStrongerControlIds: [],
      })
      if (!started.ok) throw new Error(`start failed: ${started.error.code}`)
      assessmentId = started.value.assessmentId
      await waitUntilSealed(initialContext.securityAssurance, invocation, assessmentId)
    } finally {
      await initialFiber.dispose()
    }

    const nodeVersionDescriptor = Object.getOwnPropertyDescriptor(process.versions, 'node')
    if (nodeVersionDescriptor === undefined) throw new Error('process.versions.node descriptor is unavailable')
    Object.defineProperty(process.versions, 'node', {
      ...nodeVersionDescriptor,
      value: '23.0.0',
    })
    const restartedContext = new Context()
    const restartedFiber = await restartedContext.plugin(SecurityAssuranceService, { dshHome })

    try {
      const invocation = referenceHostInvocation(restartedContext.securityAssurance)
      await expect(restartedContext.securityAssurance.getHealth(invocation, {
        schemaVersion: 1,
      })).resolves.toMatchObject({
        ok: true,
        value: {
          state: 'READ_ONLY_SAFE',
          admission: { queries: true, mutations: false, sealedExports: true },
        },
      })
      await expect(restartedContext.securityAssurance.getAssuranceSubmission(invocation, {
        schemaVersion: 1,
        assessmentId,
      })).resolves.toMatchObject({
        ok: true,
        value: { payload: { assessment: { assessmentId, state: 'SEALED' } } },
      })
      await expect(restartedContext.securityAssurance.getExport(invocation, {
        schemaVersion: 1,
        kind: 'PREVIEW',
        assessmentId,
        exportProfileId: 'security/export/internal-json-v1',
        deliveryDestinationId: 'delivery/local-audit',
      })).resolves.toMatchObject({ ok: true, value: { kind: 'PREVIEW', assessmentId } })
      await expect(restartedContext.securityAssurance.requestExport(invocation, {
        schemaVersion: 1,
        contractVersion: 1 as const,
        idempotencyKey: 'sealed-safe-mode-export-1',
        assessmentId,
        expectedAssessmentRevision: 3,
        exportProfileId: 'security/export/internal-json-v1',
        deliveryDestinationId: 'delivery/local-audit',
      })).resolves.toMatchObject({ ok: false, error: { code: 'UNAVAILABLE', retryable: true } })
    } finally {
      await restartedFiber.dispose()
      Object.defineProperty(process.versions, 'node', nodeVersionDescriptor)
    }
  })
})
