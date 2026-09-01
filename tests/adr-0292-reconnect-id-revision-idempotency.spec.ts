import { mkdtemp, readFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, describe, expect, it } from 'vitest'
import { removeTemporaryRoots } from './support/remove-temporary-root.ts'
import {
  INTERNAL_JSON_EXPORT_PROFILE_ID,
  LOCAL_AUDIT_DELIVERY_DESTINATION_ID,
  type RequestExportRequest,
} from '../src/index.ts'
import {
  buildExportPreview,
  ExportDeliveryModule,
} from '../src/internal/export-delivery.ts'

const temporaryRoots: string[] = []
const assessmentId = 'asm-00000000-0000-0000-0000-000000000292'

afterEach(async () => {
  await removeTemporaryRoots(temporaryRoots)
})

describe('ADR 0292 reconnect recovery by ID, revision, and idempotency', () => {
  it('reopens an Assessment by opaque ID and fetches current Service truth without starting work', async () => {
    const source = await readFile(join(import.meta.dirname, '..', 'src', 'client', 'index.ts'), 'utf8')
    const start = source.indexOf('  async openAssessment(\n')
    const end = source.indexOf('  /** Resume exactly', start)
    expect(start).toBeGreaterThan(-1)
    expect(end).toBeGreaterThan(start)
    const recoveryFlow = source.slice(start, end)

    expect(recoveryFlow).toContain('this.eraseSession()')
    expect(recoveryFlow).toContain('request.assessmentId')
    expect(recoveryFlow).toContain('remote.securityAssuranceWorkbench.getAssessment(')
    expect(recoveryFlow).toContain('snapshot.assessmentRevision')
    expect(recoveryFlow).not.toContain('.startAssessment(')
    expect(recoveryFlow).not.toMatch(/localStorage|sessionStorage|indexedDB/u)
  })

  it('returns the original durable Receipt for the original key and conflicts on changed replay input', async () => {
    const root = await mkdtemp(join(tmpdir(), 'dsh-adr-0292-'))
    temporaryRoots.push(root)
    const delivery = new ExportDeliveryModule(root)
    const authority = { principalId: 'operator-0292', authorityKind: 'host-operator' as const }
    const preview = buildExportPreview({
      assessmentId,
      assessmentRevision: 7,
      sealId: 'seal-00000000-0000-0000-0000-000000000292',
      deliveryDestinationId: LOCAL_AUDIT_DELIVERY_DESTINATION_ID,
    })
    if (preview === undefined) throw new Error('Export Preview fixture was not resolved')
    const request: RequestExportRequest = {
      schemaVersion: 1,
      contractVersion: 1,
      idempotencyKey: 'adr-0292-unconfirmed-export-v1',
      assessmentId,
      expectedAssessmentRevision: 7,
      exportProfileId: INTERNAL_JSON_EXPORT_PROFILE_ID,
      deliveryDestinationId: LOCAL_AUDIT_DELIVERY_DESTINATION_ID,
    }

    const accepted = await delivery.begin(authority, request, preview)
    const replayed = await delivery.begin(authority, request, preview)
    expect(replayed.replayed).toBe(true)
    expect(replayed.record.receipt).toEqual(accepted.record.receipt)
    await expect(delivery.begin(authority, {
      ...request,
      expectedAssessmentRevision: 8,
    }, preview)).rejects.toMatchObject({ code: 'IDEMPOTENCY_CONFLICT' })
  })
})
