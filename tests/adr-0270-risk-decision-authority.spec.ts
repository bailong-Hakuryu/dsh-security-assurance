import { describe, expect, it } from 'vitest'
import { recordRiskDecisionRequestSchema } from '../src/index.ts'

const request = {
  schemaVersion: 1,
  contractVersion: 1,
  idempotencyKey: 'adr-0270-risk-decision',
  assessmentId: 'asm-00000000-0000-0000-0000-000000000270',
  expectedAssessmentRevision: 7,
  finding: {
    recordId: `finding-${'7'.repeat(64)}`,
    recordRevision: 1,
  },
  decision: 'ACCEPT',
  rationale: 'The bounded recovery window is approved with compensating controls.',
  compensatingControls: ['isolate affected service'],
  expiresAt: '2026-08-29T00:00:00.000Z',
}

describe('ADR 0270 invocation-derived Risk Decision authority', () => {
  it('requires the exact Risk Decision contract version', () => {
    expect(recordRiskDecisionRequestSchema.safeParse(request).success).toBe(true)
    const { contractVersion: _omitted, ...withoutContractVersion } = request
    expect(recordRiskDecisionRequestSchema.safeParse(withoutContractVersion).success).toBe(false)
    expect(recordRiskDecisionRequestSchema.safeParse({ ...request, contractVersion: 2 }).success).toBe(false)
  })

  it('rejects every caller-supplied decision-maker or authority assertion', () => {
    for (const forbidden of [
      { decisionMaker: { kind: 'host-operator', principalId: 'forged' } },
      { authority: { permission: 'risk:break-glass' } },
      { attestations: [{ principalId: 'forged' }] },
      { authorizationMode: 'CRITICAL_DUAL_AUTHORITY' },
    ]) {
      expect(recordRiskDecisionRequestSchema.safeParse({ ...request, ...forbidden }).success).toBe(false)
    }
  })
})
