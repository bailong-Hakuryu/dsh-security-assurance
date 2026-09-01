import { SecurityAssuranceTestComposition } from './support/security-assurance-test-composition.ts'
import { removeTemporaryRoots } from './support/remove-temporary-root.ts'
import { execFile } from 'node:child_process'
import { mkdir, mkdtemp, readFile, readdir, realpath, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { promisify } from 'node:util'
import { Context } from '@deepseek-ai/cordis'
import { afterEach, describe, expect, it } from 'vitest'
import SecurityAssuranceService, { EXPORT_DELIVERY_MAX_ATTEMPTS } from '../src/index.ts'
import type {
  AssessmentId,
  ExportId,
  ExportStatusV1,
  RepositoryId,
  SecurityInvocation,
} from '../src/index.ts'
import { ExportDeliveryModule } from '../src/internal/export-delivery.ts'
import { referenceHostInvocation, referenceHostInvocationWithPermissions } from './support/reference-host.ts'

const run = promisify(execFile)
const temporaryRoots: string[] = []

afterEach(async () => {
  await removeTemporaryRoots(temporaryRoots)
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

async function securityHomeFixture(prefix: string): Promise<string> {
  const root = await realpath(await mkdtemp(join(tmpdir(), prefix)))
  temporaryRoots.push(root)
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

async function waitForExportStatus(
  service: SecurityAssuranceService,
  invocation: SecurityInvocation,
  exportId: ExportId,
  predicate: (status: ExportStatusV1) => boolean,
): Promise<ExportStatusV1> {
  for (let attempt = 0; attempt < 320; attempt += 1) {
    const result = await service.getExport(invocation, { schemaVersion: 1, kind: 'STATUS', exportId })
    if (result.ok && result.value.kind === 'STATUS' && predicate(result.value)) return result.value
    await new Promise(resolve => setTimeout(resolve, 25))
  }
  throw new Error(`Export ${exportId} did not reach the expected status`)
}

async function waitForPersistedExportPurge(recordFile: string): Promise<void> {
  for (let attempt = 0; attempt < 320; attempt += 1) {
    const value = JSON.parse(await readFile(recordFile, 'utf8')) as {
      readonly view?: { readonly retention?: { readonly status?: string } }
    }
    if (value.view?.retention?.status === 'PURGED') return
    await new Promise(resolve => setTimeout(resolve, 25))
  }
  throw new Error(`Export record ${recordFile} did not persist PURGED retention`)
}

describe('SecurityAssuranceService deterministic Assessment path', () => {
  it('seals an honest INDETERMINATE result and performs an idempotent registered Export delivery', async () => {
    const repository = await repositoryFixture()
    const dshHome = await securityHomeFixture('dsh-security-deterministic-home-')
    const ctx = new Context()
    let fiber = await ctx.plugin(SecurityAssuranceTestComposition, { dshHome })
    const platform = process.platform
    if (platform !== 'win32' && platform !== 'linux' && platform !== 'darwin') {
      throw new Error(`unsupported test platform: ${platform}`)
    }

    try {
      const invocation = referenceHostInvocation(ctx.securityAssurance)
      const registered = await ctx.securityAssurance.registerRepository(invocation, {
        schemaVersion: 1,
        contractVersion: 1 as const,
        idempotencyKey: 'deterministic-repository-register-1',
        root: repository,
        displayName: 'Deterministic fixture',
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

      const started = await ctx.securityAssurance.startAssessment(invocation, {
        schemaVersion: 1,
        contractVersion: 1 as const,
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
          roleCards: [],
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

      const preview = await ctx.securityAssurance.getExport(invocation, {
        schemaVersion: 1,
        kind: 'PREVIEW',
        assessmentId: started.value.assessmentId,
        exportProfileId: 'security/export/internal-json-v1',
        deliveryDestinationId: 'delivery/local-audit',
      })
      expect(preview).toMatchObject({
        ok: true,
        value: {
          schemaVersion: 1,
          kind: 'PREVIEW',
          assessmentId: started.value.assessmentId,
          assessmentRevision: 3,
          profile: {
            exportProfileId: 'security/export/internal-json-v1',
            audience: 'INTERNAL',
            artifactFormat: 'JSON',
            redactions: expect.arrayContaining(['ORIGINAL_CREDENTIAL_VALUES', 'PRIVATE_STORE_PATHS']),
          },
          destination: {
            deliveryDestinationId: 'delivery/local-audit',
            kind: 'HOST_REGISTERED_LOCAL_AUDIT',
          },
        },
      })
      expect(JSON.stringify(preview)).not.toContain(dshHome)
      expect(JSON.stringify(preview)).not.toContain(repository)
      if (!submission.ok || !preview.ok || preview.value.kind !== 'PREVIEW') {
        throw new Error('sealed Export fixture values were unavailable')
      }

      const exportRequest = {
        schemaVersion: 1 as const,
        contractVersion: 1 as const,
        idempotencyKey: 'deterministic-export-request-1',
        assessmentId: started.value.assessmentId,
        expectedAssessmentRevision: 3,
        exportProfileId: 'security/export/internal-json-v1' as const,
        deliveryDestinationId: 'delivery/local-audit',
      }
      const requested = await ctx.securityAssurance.requestExport(invocation, exportRequest)
      expect(requested).toMatchObject({
        ok: true,
        value: {
          operation: 'request_export',
          assessmentId: started.value.assessmentId,
          assessmentRevision: 3,
          acceptedState: 'PENDING',
          idempotencyKey: exportRequest.idempotencyKey,
          exportId: expect.stringMatching(/^export-[0-9a-f]{64}$/u),
        },
      })
      const replayed = await ctx.securityAssurance.requestExport(invocation, exportRequest)
      expect(replayed).toEqual(requested)
      if (!requested.ok) throw new Error(`export request failed: ${requested.error.code}`)

      const delivered = {
        ok: true as const,
        value: await waitForExportStatus(
          ctx.securityAssurance,
          invocation,
          requested.value.exportId,
          status => status.status === 'DELIVERED',
        ),
      }
      expect(delivered).toMatchObject({
        ok: true,
        value: {
          kind: 'STATUS',
          exportId: requested.value.exportId,
          assessmentId: started.value.assessmentId,
          status: 'DELIVERED',
          artifact: {
            artifactId: `${requested.value.exportId}/artifact`,
            digest: {
              algorithm: 'sha256',
              mediaType: 'application/vnd.dsh.security.export+json',
              canonicalization: 'raw-bytes',
              value: expect.stringMatching(/^[0-9a-f]{64}$/u),
            },
          },
          accessAction: { kind: 'ONE_USE_DOWNLOAD', action: 'REQUEST_ONE_USE_DOWNLOAD' },
          failure: null,
        },
      })
      expect(JSON.stringify(delivered)).not.toContain(dshHome)
      expect(JSON.stringify(delivered)).not.toContain(repository)
      if (!delivered.ok || delivered.value.kind !== 'STATUS' || delivered.value.artifact === null) {
        throw new Error('delivered Export did not expose artifact metadata')
      }

      const restrictedInvocation = referenceHostInvocationWithPermissions(
        ctx.securityAssurance,
        ['export:read'],
      )
      expect(await ctx.securityAssurance.getExport(restrictedInvocation, {
        schemaVersion: 1,
        kind: 'STATUS',
        exportId: requested.value.exportId,
      })).toMatchObject({
        ok: true,
        value: { accessAction: { kind: 'HOST_MANAGED', action: 'DELIVERED_TO_REGISTERED_DESTINATION' } },
      })

      const downloadRequest = {
        schemaVersion: 1 as const,
        kind: 'DOWNLOAD' as const,
        exportId: requested.value.exportId,
        artifactId: delivered.value.artifact.artifactId,
        expectedDigest: delivered.value.artifact.digest,
      }
      expect(await ctx.securityAssurance.getExport(restrictedInvocation, downloadRequest)).toMatchObject({
        ok: false,
        error: { code: 'UNAUTHORIZED' },
      })
      expect(await ctx.securityAssurance.getExport(invocation, {
        ...downloadRequest,
        expectedDigest: { ...downloadRequest.expectedDigest, value: '0'.repeat(64) },
      })).toMatchObject({ ok: false, error: { code: 'CONFLICT' } })

      const otherPrincipal = referenceHostInvocation(ctx.securityAssurance, 'other-reference-host-operator')
      expect(await ctx.securityAssurance.getExport(otherPrincipal, {
        schemaVersion: 1,
        kind: 'STATUS',
        exportId: requested.value.exportId,
      })).toMatchObject({ ok: false, error: { code: 'NOT_FOUND' } })

      const deliveredArtifact = join(
        dshHome,
        'security-assurance',
        'delivery',
        'destinations',
        'local-audit',
        `${requested.value.exportId}.json`,
      )
      const deliveredBytes = await readFile(deliveredArtifact, 'utf8')
      expect(JSON.parse(deliveredBytes)).toMatchObject({
        schemaVersion: 1,
        exportProfileId: 'security/export/internal-json-v1',
        source: { assessmentId: started.value.assessmentId, assessmentRevision: 3 },
        submission: { schemaVersion: 1 },
      })
      expect(deliveredBytes).not.toContain(repository)

      const downloaded = await ctx.securityAssurance.getExport(invocation, downloadRequest)
      expect(downloaded).toMatchObject({
        ok: true,
        value: {
          kind: 'DOWNLOAD',
          exportId: requested.value.exportId,
          artifactId: delivered.value.artifact.artifactId,
          mediaType: 'application/vnd.dsh.security.export+json',
          byteLength: Buffer.byteLength(deliveredBytes),
          digest: delivered.value.artifact.digest,
          capability: { kind: 'CONSUMED_ONE_USE' },
          content: { encoding: 'base64' },
        },
      })
      if (!downloaded.ok || downloaded.value.kind !== 'DOWNLOAD') {
        throw new Error('one-use Export download failed')
      }
      expect(Buffer.from(downloaded.value.content.value, 'base64').toString('utf8')).toBe(deliveredBytes)
      expect(JSON.stringify(downloaded)).not.toContain(dshHome)
      expect(JSON.stringify(downloaded)).not.toContain(repository)
      expect(JSON.stringify(downloaded)).not.toMatch(/capability(Id|Token)|privatePath/iu)

      const deliveryModule = new ExportDeliveryModule(join(dshHome, 'security-assurance'))
      const deliveryAuthority = {
        principalId: 'reference-host-operator',
        authorityKind: 'host-operator' as const,
      }
      const ownerBoundCapability = await deliveryModule.authorizeDownload(deliveryAuthority, downloadRequest)
      expect(JSON.stringify(ownerBoundCapability)).toBe('{}')
      await expect(deliveryModule.consumeDownload({
        ...deliveryAuthority,
        principalId: 'other-reference-host-operator',
      }, ownerBoundCapability)).rejects.toMatchObject({ code: 'NOT_FOUND' })
      await deliveryModule.consumeDownload(deliveryAuthority, ownerBoundCapability)

      const oneUseCapability = await deliveryModule.authorizeDownload(deliveryAuthority, downloadRequest)
      await deliveryModule.consumeDownload(deliveryAuthority, oneUseCapability)
      await expect(deliveryModule.consumeDownload(deliveryAuthority, oneUseCapability)).rejects.toMatchObject({
        code: 'CAPABILITY_CONSUMED',
      })

      let downloadClock = new Date().toISOString()
      const expiringModule = new ExportDeliveryModule(
        join(dshHome, 'security-assurance'),
        () => downloadClock,
      )
      const expiringCapability = await expiringModule.authorizeDownload(deliveryAuthority, downloadRequest)
      downloadClock = new Date(Date.parse(downloadClock) + 61_000).toISOString()
      await expect(expiringModule.consumeDownload(deliveryAuthority, expiringCapability)).rejects.toMatchObject({
        code: 'CAPABILITY_EXPIRED',
      })

      const failedDeliveryHome = await securityHomeFixture('dsh-security-failed-delivery-home-')
      let failureClock = new Date().toISOString()
      const failureModule = new ExportDeliveryModule(
        join(failedDeliveryHome, 'security-assurance'),
        () => failureClock,
      )
      const failedBegin = await failureModule.begin(deliveryAuthority, {
        ...exportRequest,
        idempotencyKey: 'deterministic-export-terminal-failure-1',
      }, preview.value)
      await mkdir(join(
        failedDeliveryHome,
        'security-assurance',
        'delivery',
        'destinations',
        'local-audit',
        `${failedBegin.record.receipt.exportId}.json`,
      ), { recursive: true })
      let failedStatus: ExportStatusV1 | undefined
      for (let attempt = 1; attempt <= EXPORT_DELIVERY_MAX_ATTEMPTS; attempt += 1) {
        failedStatus = await failureModule.deliver(failedBegin, submission.value)
        expect(failedStatus.delivery.attemptCount).toBe(attempt)
        expect(failedStatus.delivery.lastFailureCode).toBe('ARTIFACT_IO_ERROR')
        if (failedStatus.status === 'PENDING') {
          if (failedStatus.delivery.nextRetryAt === null) throw new Error('pending delivery lost retry schedule')
          failureClock = failedStatus.delivery.nextRetryAt
        }
      }
      expect(failedStatus).toMatchObject({
        status: 'FAILED',
        delivery: {
          attemptCount: EXPORT_DELIVERY_MAX_ATTEMPTS,
          lastFailureCode: 'ARTIFACT_IO_ERROR',
          nextRetryAt: null,
        },
        accessAction: { kind: 'NONE', reason: 'DELIVERY_FAILED' },
        failure: { code: 'ARTIFACT_DELIVERY_FAILED' },
      })

      const conflictingBegin = await failureModule.begin(deliveryAuthority, {
        ...exportRequest,
        idempotencyKey: 'deterministic-export-integrity-conflict-1',
      }, preview.value)
      await writeFile(join(
        failedDeliveryHome,
        'security-assurance',
        'delivery',
        'destinations',
        'local-audit',
        `${conflictingBegin.record.receipt.exportId}.json`,
      ), '{"different":"canonical bytes"}', 'utf8')
      expect(await failureModule.deliver(conflictingBegin, submission.value)).toMatchObject({
        status: 'FAILED',
        delivery: {
          attemptCount: 1,
          lastFailureCode: 'ARTIFACT_INTEGRITY_CONFLICT',
          nextRetryAt: null,
        },
        failure: { code: 'ARTIFACT_DELIVERY_FAILED' },
      })

      const retentionHome = await securityHomeFixture('dsh-security-export-retention-home-')
      let retentionClock = new Date().toISOString()
      const retentionModule = new ExportDeliveryModule(
        join(retentionHome, 'security-assurance'),
        () => retentionClock,
      )
      const retentionBegin = await retentionModule.begin(deliveryAuthority, {
        ...exportRequest,
        idempotencyKey: 'deterministic-export-retention-1',
      }, preview.value)
      const retained = await retentionModule.deliver(retentionBegin, submission.value)
      expect(retained).toMatchObject({ status: 'DELIVERED', retention: { status: 'RETAINED' } })
      if (retained.expiresAt === null || retained.artifact === null) {
        throw new Error('retained Export lost expiry or artifact metadata')
      }
      retentionClock = retained.expiresAt
      const retentionArtifact = join(
        retentionHome,
        'security-assurance',
        'delivery',
        'destinations',
        'local-audit',
        `${retentionBegin.record.receipt.exportId}.json`,
      )
      await rm(retentionArtifact)
      await mkdir(retentionArtifact)
      await writeFile(join(retentionArtifact, 'sentinel.txt'), 'must not be recursively deleted', 'utf8')
      const purgePending = await retentionModule.get(retentionBegin.record.receipt.exportId, deliveryAuthority)
      expect(purgePending).toMatchObject({
        status: 'EXPIRED',
        artifact: null,
        retention: {
          status: 'PURGE_PENDING',
          tombstone: {
            artifactId: retained.artifact.artifactId,
            digest: retained.artifact.digest,
            deletionAuthority: 'SECURITY_SERVICE_RETENTION',
            reason: 'ARTIFACT_EXPIRED',
          },
          purgedAt: null,
        },
        accessAction: { kind: 'NONE', reason: 'ARTIFACT_EXPIRED' },
      })
      await expect(readFile(join(retentionArtifact, 'sentinel.txt'), 'utf8')).resolves.toBe(
        'must not be recursively deleted',
      )
      await expect(retentionModule.authorizeDownload(deliveryAuthority, {
        ...downloadRequest,
        exportId: retentionBegin.record.receipt.exportId,
        artifactId: retained.artifact.artifactId,
        expectedDigest: retained.artifact.digest,
      })).rejects.toMatchObject({ code: 'CONFLICT' })
      if (purgePending?.retention.status !== 'PURGE_PENDING') {
        throw new Error('expired Export lost its pending purge audit')
      }
      const purgeRequestedAt = purgePending.retention.purgeRequestedAt
      await rm(retentionArtifact, { recursive: true })
      retentionClock = new Date(Date.parse(retentionClock) - 1_000).toISOString()
      const purged = await retentionModule.get(retentionBegin.record.receipt.exportId, deliveryAuthority)
      expect(purged).toMatchObject({
        status: 'EXPIRED',
        retention: {
          status: 'PURGED',
          tombstone: { digest: retained.artifact.digest },
          purgedAt: purgeRequestedAt,
        },
      })
      await expect(readFile(retentionArtifact)).rejects.toMatchObject({ code: 'ENOENT' })

      await fiber.dispose()
      const deliveredRecord = join(
        dshHome,
        'security-assurance',
        'delivery',
        'exports',
        requested.value.exportId,
        'record.json',
      )
      const offlineExpiry = JSON.parse(await readFile(deliveredRecord, 'utf8')) as {
        view: Record<string, unknown> & { createdAt: string; expiresAt: string }
      }
      delete offlineExpiry.view.retention
      offlineExpiry.view.expiresAt = new Date(Date.parse(offlineExpiry.view.createdAt) + 1).toISOString()
      await writeFile(deliveredRecord, JSON.stringify(offlineExpiry), 'utf8')
      const recoveryBegin = await deliveryModule.begin(deliveryAuthority, {
        ...exportRequest,
        idempotencyKey: 'deterministic-export-crash-recovery-1',
      }, preview.value)
      const recoveryArtifact = join(
        dshHome,
        'security-assurance',
        'delivery',
        'destinations',
        'local-audit',
        `${recoveryBegin.record.receipt.exportId}.json`,
      )
      await mkdir(recoveryArtifact, { recursive: true })
      const restartedContext = new Context()
      fiber = await restartedContext.plugin(SecurityAssuranceTestComposition, { dshHome })
      const restartedInvocation = referenceHostInvocation(restartedContext.securityAssurance)
      await waitForPersistedExportPurge(deliveredRecord)
      await expect(readFile(deliveredArtifact)).rejects.toMatchObject({ code: 'ENOENT' })
      const retrying = await waitForExportStatus(
        restartedContext.securityAssurance,
        restartedInvocation,
        recoveryBegin.record.receipt.exportId,
        status => status.status === 'PENDING'
          && status.delivery.attemptCount >= 1
          && status.delivery.nextRetryAt !== null,
      )
      expect(retrying.delivery.lastFailureCode).toBe('ARTIFACT_IO_ERROR')
      await rm(recoveryArtifact, { recursive: true })
      const recovered = await waitForExportStatus(
        restartedContext.securityAssurance,
        restartedInvocation,
        recoveryBegin.record.receipt.exportId,
        status => status.status === 'DELIVERED',
      )
      expect(recovered).toMatchObject({
        status: 'DELIVERED',
        delivery: {
          attemptCount: expect.any(Number),
          lastFailureCode: 'ARTIFACT_IO_ERROR',
          nextRetryAt: null,
        },
        failure: null,
      })
      expect(recovered.delivery.attemptCount).toBeGreaterThanOrEqual(2)
      const expired = await restartedContext.securityAssurance.getExport(restartedInvocation, {
        schemaVersion: 1,
        kind: 'STATUS',
        exportId: requested.value.exportId,
      })
      expect(expired).toMatchObject({
        ok: true,
        value: {
          status: 'EXPIRED',
          artifact: null,
          retention: {
            status: 'PURGED',
            tombstone: {
              artifactId: delivered.value.artifact.artifactId,
              digest: delivered.value.artifact.digest,
              deletionAuthority: 'SECURITY_SERVICE_RETENTION',
              reason: 'ARTIFACT_EXPIRED',
            },
          },
          accessAction: { kind: 'NONE', reason: 'ARTIFACT_EXPIRED' },
        },
      })
      expect(await restartedContext.securityAssurance.getExport(restartedInvocation, downloadRequest)).toMatchObject({
        ok: false,
        error: { code: 'CONFLICT' },
      })
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
    const dshHome = await securityHomeFixture('dsh-security-resume-home-')
    const platform = process.platform
    if (platform !== 'win32' && platform !== 'linux' && platform !== 'darwin') {
      throw new Error(`unsupported test platform: ${platform}`)
    }

    const firstContext = new Context()
    const firstFiber = await firstContext.plugin(SecurityAssuranceTestComposition, { dshHome })
    const firstInvocation = referenceHostInvocation(firstContext.securityAssurance)
    const registered = await firstContext.securityAssurance.registerRepository(firstInvocation, {
      schemaVersion: 1,
      contractVersion: 1 as const,
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
      contractVersion: 1 as const,
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
    const restartedFiber = await restartedContext.plugin(SecurityAssuranceTestComposition, { dshHome })
    try {
      const invocation = referenceHostInvocation(restartedContext.securityAssurance)
      await restartedContext.securityAssurance.whenReady()
      const interrupted = await restartedContext.securityAssurance.getAssessment(invocation, {
        schemaVersion: 1,
        assessmentId: started.value.assessmentId,
      })
      expect(interrupted).toMatchObject({
        ok: true,
        value: {
          state: 'BLOCKED',
          verdict: null,
          seal: null,
          availableActions: [
            { kind: 'CANCEL_ASSESSMENT', expectedAssessmentRevision: 3 },
            { kind: 'RESUME_ASSESSMENT', expectedAssessmentRevision: 3 },
          ],
        },
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
        contractVersion: 1 as const,
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
    const dshHome = await securityHomeFixture('dsh-security-cancel-home-')
    const platform = process.platform
    if (platform !== 'win32' && platform !== 'linux' && platform !== 'darwin') {
      throw new Error(`unsupported test platform: ${platform}`)
    }
    const ctx = new Context()
    const fiber = await ctx.plugin(SecurityAssuranceTestComposition, { dshHome })
    try {
      const invocation = referenceHostInvocation(ctx.securityAssurance)
      const registered = await ctx.securityAssurance.registerRepository(invocation, {
        schemaVersion: 1,
        contractVersion: 1 as const,
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
        contractVersion: 1 as const,
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
        contractVersion: 1 as const,
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
    const dshHome = await securityHomeFixture('dsh-security-restart-home-')
    const platform = process.platform
    if (platform !== 'win32' && platform !== 'linux' && platform !== 'darwin') {
      throw new Error(`unsupported test platform: ${platform}`)
    }
    const startRequest = {
      schemaVersion: 1 as const,
      contractVersion: 1 as const,
      idempotencyKey: 'restart-assessment-start-1',
      subject: { kind: 'workspace_snapshot' as const },
      assessmentMode: 'REPOSITORY' as const,
      assessmentProfileId: 'security/standard',
      target: { kind: 'repository' as const },
      requestedStrongerControlIds: [],
    }

    const firstContext = new Context()
    const firstFiber = await firstContext.plugin(SecurityAssuranceTestComposition, { dshHome })
    let assessmentId: AssessmentId
    let repositoryId: RepositoryId
    let originalSubmission: unknown
    try {
      const invocation = referenceHostInvocation(firstContext.securityAssurance)
      const registered = await firstContext.securityAssurance.registerRepository(invocation, {
        schemaVersion: 1,
        contractVersion: 1 as const,
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
    const restartedFiber = await restartedContext.plugin(SecurityAssuranceTestComposition, { dshHome })
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
