import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, describe, expect, it } from 'vitest'
import { removeTemporaryRoots } from './support/remove-temporary-root.ts'
import { exportStatusV1Schema } from '../src/contracts.ts'
import { binaryDigest } from '../src/internal/canonical.ts'
import { buildExportPreview, ExportDeliveryModule } from '../src/internal/export-delivery.ts'

const temporaryRoots: string[] = []

afterEach(async () => {
  await removeTemporaryRoots(temporaryRoots)
})

describe('ADR 0304 Export expiry uses two-phase exact-target reaping', () => {
  it('denies access before deletion and retains an exact tombstone through purge recovery', async () => {
    const root = await mkdtemp(join(tmpdir(), 'dsh-security-adr-0304-'))
    temporaryRoots.push(root)
    let clock = '2026-08-29T03:04:00.000Z'
    const module = new ExportDeliveryModule(root, () => clock)
    const assessmentId = 'asm-00000000-0000-0000-0000-000000000304'
    const authority = { principalId: 'adr-0304-owner', authorityKind: 'host-operator' as const }
    const preview = buildExportPreview({
      assessmentId,
      assessmentRevision: 4,
      sealId: 'seal-adr-0304',
      deliveryDestinationId: 'delivery/local-audit',
    })
    if (preview === undefined) throw new Error('ADR 0304 Export Preview fixture is unavailable')
    const begin = await module.begin(authority, {
      schemaVersion: 1,
      contractVersion: 1,
      idempotencyKey: 'adr-0304-export-expiry',
      assessmentId,
      expectedAssessmentRevision: 4,
      exportProfileId: 'security/export/internal-json-v1',
      deliveryDestinationId: 'delivery/local-audit',
    }, preview)
    const exportId = begin.record.receipt.exportId
    const artifactId = `${exportId}/artifact`
    const artifactBytes = Buffer.from('{"adr":304}', 'utf8')
    const digest = binaryDigest('application/vnd.dsh.security.export+json', artifactBytes)
    const expiresAt = '2026-08-29T03:04:01.000Z'
    const delivered = exportStatusV1Schema.parse({
      ...begin.record.view,
      status: 'DELIVERED',
      artifact: { artifactId, digest },
      expiresAt,
      retention: { status: 'RETAINED' },
      delivery: {
        attemptCount: 1,
        lastAttemptAt: clock,
        lastFailureAt: null,
        lastFailureCode: null,
        nextRetryAt: null,
      },
      accessAction: { kind: 'HOST_MANAGED', action: 'DELIVERED_TO_REGISTERED_DESTINATION' },
      failure: null,
      updatedAt: clock,
    })
    const recordPath = join(root, 'delivery', 'exports', exportId, 'record.json')
    const destination = join(root, 'delivery', 'destinations', 'local-audit')
    const artifactPath = join(destination, `${exportId}.json`)
    const neighborPath = join(destination, 'neighbor-must-remain.json')
    await mkdir(destination, { recursive: true })
    await writeFile(recordPath, JSON.stringify({ ...begin.record, view: delivered }), 'utf8')
    await mkdir(artifactPath)
    await writeFile(join(artifactPath, 'sentinel.txt'), 'not recursively deletable', 'utf8')
    await writeFile(neighborPath, 'neighbor', 'utf8')

    clock = expiresAt
    const pending = await module.reconcileExpiry(exportId)
    expect(pending).toMatchObject({
      status: 'EXPIRED',
      artifact: null,
      retention: {
        status: 'PURGE_PENDING',
        tombstone: {
          artifactId,
          digest,
          expiredAt: expiresAt,
          deletionAuthority: 'SECURITY_SERVICE_RETENTION',
          reason: 'ARTIFACT_EXPIRED',
        },
        purgeRequestedAt: expiresAt,
        purgedAt: null,
      },
      accessAction: { kind: 'NONE', reason: 'ARTIFACT_EXPIRED' },
    })
    await expect(readFile(join(artifactPath, 'sentinel.txt'), 'utf8')).resolves.toBe(
      'not recursively deletable',
    )
    await expect(module.authorizeDownload(authority, {
      schemaVersion: 1,
      kind: 'DOWNLOAD',
      exportId,
      artifactId,
      expectedDigest: digest,
    })).rejects.toMatchObject({ code: 'CONFLICT' })

    await rm(artifactPath, { recursive: true })
    const purged = await module.reconcileExpiry(exportId)
    expect(purged).toMatchObject({
      status: 'EXPIRED',
      retention: { status: 'PURGED', tombstone: { artifactId, digest }, purgedAt: expiresAt },
    })
    await expect(readFile(recordPath, 'utf8')).resolves.toContain('PURGED')
    await expect(readFile(neighborPath, 'utf8')).resolves.toBe('neighbor')
  })

  it('derives one exact artifact target and never performs recursive or caller-directed deletion', async () => {
    const source = await readFile(
      join(import.meta.dirname, '..', 'src', 'internal', 'export-delivery.ts'),
      'utf8',
    )
    const start = source.indexOf('  async reconcileExpiry(')
    const end = source.indexOf('  private async writeArtifact(', start)
    const reconcile = source.slice(start, end)

    expect(reconcile).toContain('await replaceRecord(this.root, record)')
    expect(reconcile).toContain('await rm(artifactPath(this.root, exportId), { force: true })')
    expect(reconcile.indexOf('await replaceRecord(this.root, record)')).toBeLessThan(
      reconcile.indexOf('await rm(artifactPath(this.root, exportId), { force: true })'),
    )
    expect(reconcile).not.toMatch(/recursive\s*:\s*true|glob|request\.(?:path|file|directory)/u)
    expect(reconcile).toContain("status: 'PURGED'")
  })
})
