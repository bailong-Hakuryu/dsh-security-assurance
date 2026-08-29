import { mkdtemp, readFile, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, describe, expect, it } from 'vitest'
import { EXPORT_DELIVERY_MAX_ATTEMPTS, exportStatusV1Schema } from '../src/contracts.ts'
import { buildExportPreview, ExportDeliveryModule } from '../src/internal/export-delivery.ts'

const temporaryRoots: string[] = []

afterEach(async () => {
  await Promise.all(temporaryRoots.splice(0).map(root => rm(root, { recursive: true, force: true })))
})

describe('ADR 0303 Export Delivery recovery is Service-owned and bounded', () => {
  it('durably records PENDING before attempts and stops after five safe source failures', async () => {
    const root = await mkdtemp(join(tmpdir(), 'dsh-security-adr-0303-'))
    temporaryRoots.push(root)
    let clock = '2026-08-29T03:03:00.000Z'
    const module = new ExportDeliveryModule(root, () => clock)
    const assessmentId = 'asm-00000000-0000-0000-0000-000000000303'
    const preview = buildExportPreview({
      assessmentId,
      assessmentRevision: 3,
      sealId: 'seal-adr-0303',
      deliveryDestinationId: 'delivery/local-audit',
    })
    if (preview === undefined) throw new Error('ADR 0303 Export Preview fixture is unavailable')
    const begin = await module.begin({
      principalId: 'adr-0303-owner',
      authorityKind: 'host-operator',
    }, {
      schemaVersion: 1,
      contractVersion: 1,
      idempotencyKey: 'adr-0303-export-recovery',
      assessmentId,
      expectedAssessmentRevision: 3,
      exportProfileId: 'security/export/internal-json-v1',
      deliveryDestinationId: 'delivery/local-audit',
    }, preview)
    const recordPath = join(root, 'delivery', 'exports', begin.record.receipt.exportId, 'record.json')
    const committed = JSON.parse(await readFile(recordPath, 'utf8')) as { readonly view: unknown }

    expect(committed.view).toMatchObject({
      status: 'PENDING',
      delivery: { attemptCount: 0, nextRetryAt: null },
    })
    let status = begin.record.view
    for (let attempt = 1; attempt <= EXPORT_DELIVERY_MAX_ATTEMPTS; attempt += 1) {
      status = await module.recordSourceUnavailable(begin.record.receipt.exportId)
      expect(status.delivery.attemptCount).toBe(attempt)
      expect(status.delivery.lastFailureCode).toBe('SOURCE_SUBMISSION_UNAVAILABLE')
      if (status.delivery.nextRetryAt !== null) clock = status.delivery.nextRetryAt
    }
    expect(status).toMatchObject({
      status: 'FAILED',
      artifact: null,
      delivery: {
        attemptCount: EXPORT_DELIVERY_MAX_ATTEMPTS,
        nextRetryAt: null,
      },
      accessAction: { kind: 'NONE', reason: 'DELIVERY_FAILED' },
      failure: { code: 'ARTIFACT_DELIVERY_FAILED' },
    })
    expect(exportStatusV1Schema.safeParse({ ...status, privatePath: `${root}/artifact.json` }).success).toBe(false)
    expect(JSON.stringify(status)).not.toContain(root)
  })

  it('owns startup scanning, wakeups, conflict classification, and teardown in the Service', async () => {
    const service = await readFile(join(import.meta.dirname, '..', 'src', 'index.ts'), 'utf8')
    const delivery = await readFile(
      join(import.meta.dirname, '..', 'src', 'internal', 'export-delivery.ts'),
      'utf8',
    )
    const requestStart = service.indexOf('  async requestExport(')
    const requestEnd = service.indexOf('  /** Preview one authorized Export', requestStart)
    const request = service.slice(requestStart, requestEnd)

    expect(request.indexOf('await this.exportDelivery.begin(')).toBeLessThan(
      request.indexOf('await this.exportDelivery.deliver('),
    )
    expect(request).toContain('this.wakeExportDeliveryWorker()')
    expect(service).toContain('this.startExportDeliveryWorker()')
    expect(service).toContain('await this.exportDelivery.listRecoverable()')
    expect(service).toContain('this.exportDeliveryWorkerController.abort()')
    expect(service).toContain('[this.exportDeliveryWorkerTask]')
    expect(delivery).toContain('EXPORT_DELIVERY_RETRY_DELAYS_MS = [1_000, 5_000, 30_000, 120_000]')
    expect(delivery).toContain("this.failAttempt(record, 'ARTIFACT_INTEGRITY_CONFLICT', false)")
  })
})
