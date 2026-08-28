import { describe, expect, it } from 'vitest'
import {
  assessmentCancellationReceiptV1Schema,
  cancelAssessmentRequestSchema,
  resumeAssessmentRequestSchema,
} from '../src/index.ts'

const assessmentId = 'asm-00000000-0000-0000-0000-000000000267'
const reason = { code: 'OPERATOR_RETRY', summary: 'Retry after the external dependency recovered.' }

describe('ADR 0267 resume and cancel mutation contracts', () => {
  it('requires exact revision, idempotency key, and bounded structured reason', () => {
    const resume = {
      schemaVersion: 1,
      assessmentId,
      expectedAssessmentRevision: 7,
      idempotencyKey: 'adr-0267-resume',
      reason,
    }
    const cancel = { ...resume, idempotencyKey: 'adr-0267-cancel' }
    expect(resumeAssessmentRequestSchema.safeParse(resume).success).toBe(true)
    expect(cancelAssessmentRequestSchema.safeParse(cancel).success).toBe(true)

    for (const invalid of [
      { ...resume, expectedAssessmentRevision: undefined },
      { ...resume, idempotencyKey: undefined },
      { ...resume, reason: undefined },
      { ...resume, reason: { code: 'free form', summary: 'invalid code' } },
      { ...resume, reason: { code: 'OPERATOR_RETRY', summary: 'x'.repeat(513) } },
      { ...resume, subject: { kind: 'workspace_snapshot' } },
      { ...resume, state: 'RUNNING' },
    ]) {
      expect(resumeAssessmentRequestSchema.safeParse(invalid).success).toBe(false)
    }
    for (const forbidden of [
      { ...cancel, forceComplete: true },
      { ...cancel, skipCleanup: true },
      { ...cancel, deleteEvidence: true },
      { ...cancel, verdict: 'SATISFIED' },
    ]) {
      expect(cancelAssessmentRequestSchema.safeParse(forbidden).success).toBe(false)
    }
  })

  it('models cancellation acceptance without claiming terminal CANCELED state', () => {
    const receipt = {
      schemaVersion: 1,
      operation: 'cancel_assessment',
      assessmentId,
      assessmentRevision: 8,
      acceptedState: 'RUNNING',
      idempotencyKey: 'adr-0267-cancel',
      acceptedAt: '2026-08-28T00:00:00.000Z',
      correlationId: 'sec-00000000-0000-0000-0000-000000000267',
    }
    expect(assessmentCancellationReceiptV1Schema.safeParse(receipt).success).toBe(true)
    expect(assessmentCancellationReceiptV1Schema.safeParse({
      ...receipt,
      state: 'CANCELED',
    }).success).toBe(false)
  })
})
