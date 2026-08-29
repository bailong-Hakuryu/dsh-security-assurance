import { describe, expect, it } from 'vitest'
import {
  recordRiskDecisionRequestSchema,
  type FindingDetailViewV1,
  type RecordRiskDecisionRequest,
} from '../src/index.ts'
import { RiskDecisionModule } from '../src/internal/risk-decision.ts'

const findingId = `finding-${'9'.repeat(64)}`

function finding(severity: 'HIGH' | 'CRITICAL'): FindingDetailViewV1 {
  return {
    recordKind: 'FINDING',
    recordId: findingId,
    recordRevision: 1,
    validation: { state: 'VALIDATED' },
    riskDecision: { state: 'NOT_RECORDED' },
    technicalSeverity: { value: severity },
  } as FindingDetailViewV1
}

function request(expiresAt: string): RecordRiskDecisionRequest {
  return {
    schemaVersion: 1,
    contractVersion: 1,
    idempotencyKey: 'risk-0289-1',
    assessmentId: 'asm-00000000-0000-0000-0000-000000000289',
    expectedAssessmentRevision: 5,
    finding: { recordId: findingId, recordRevision: 1 },
    decision: 'ACCEPT',
    rationale: 'A bounded operational exception is required for this deployment.',
    compensatingControls: ['Continuous detection and immediate rollback'],
    expiresAt,
  }
}

describe('ADR 0289 governed immutable Risk Decision form', () => {
  it('does not admit caller-entered decision-maker or consequence fields', () => {
    const governed = request('2026-08-30T00:00:00.000Z')
    expect(recordRiskDecisionRequestSchema.safeParse(governed).success).toBe(true)
    expect(recordRiskDecisionRequestSchema.safeParse({
      ...governed,
      decisionMaker: { kind: 'host-operator', principalId: 'forged' },
    }).success).toBe(false)
    expect(recordRiskDecisionRequestSchema.safeParse({
      ...governed,
      consequence: 'CALLER_SELECTED',
    }).success).toBe(false)
  })

  it('enforces the Service-owned severity ceiling and compensating controls', () => {
    const module = new RiskDecisionModule()
    expect(module.admit(
      finding('HIGH'),
      request('2026-09-05T00:00:00.000Z'),
      '2026-08-29T00:00:00.000Z',
      { criticalBreakGlassEnabled: false, criticalBreakGlassAuthorized: false },
    )).toBe('SINGLE_AUTHORITY')
    expect(() => module.admit(
      finding('HIGH'),
      request('2026-09-05T00:00:00.001Z'),
      '2026-08-29T00:00:00.000Z',
      { criticalBreakGlassEnabled: false, criticalBreakGlassAuthorized: false },
    )).toThrow('severity ceiling')
  })
})
