import { describe, expect, it } from 'vitest'
import {
  riskDecisionRecordV1Schema,
  type DigestEnvelopeV1,
  type FindingDetailViewV1,
} from '../src/index.ts'
import { RiskDecisionModule } from '../src/internal/risk-decision.ts'

const assessmentId = 'asm-00000000-0000-0000-0000-000000000290'
const findingId = `finding-${'0'.repeat(64)}`
const digest: DigestEnvelopeV1 = {
  schemaVersion: 1,
  algorithm: 'sha256',
  mediaType: 'application/vnd.dsh.canonical-json',
  byteLength: 1,
  canonicalization: 'dsh-canonical-json-v1',
  value: '0'.repeat(64),
}

function authority(principalId: string) {
  return {
    kind: 'host-operator' as const,
    principalId,
    permissions: new Set(['risk:decide', 'risk:break-glass']),
  }
}

function assessment(revision: number) {
  return {
    state: 'BLOCKED',
    assessmentRevision: revision,
    subject: { digest },
    contract: {
      policy: { digest },
      requestedStrongerControlIds: ['security/critical-break-glass-v1'],
    },
    riskDecisionWindow: { state: 'OPEN', findingRecordIds: [findingId] },
  }
}

function criticalFinding(riskDecision: FindingDetailViewV1['riskDecision']): FindingDetailViewV1 {
  return {
    recordKind: 'FINDING',
    recordId: findingId,
    recordRevision: 1,
    validation: { state: 'VALIDATED' },
    technicalSeverity: { value: 'CRITICAL' },
    riskDecision,
  } as FindingDetailViewV1
}

describe('ADR 0290 Critical break-glass requires two independent Invocations', () => {
  it('projects a pending first decision and only a distinct second authority may complete it', () => {
    const module = new RiskDecisionModule()
    const first = module.projectAvailableAction(
      assessment(7) as Parameters<RiskDecisionModule['projectAvailableAction']>[0],
      criticalFinding({ state: 'NOT_RECORDED' }),
      authority('operator-a') as Parameters<RiskDecisionModule['projectAvailableAction']>[2],
      '2026-08-29T00:00:00.000Z',
    )
    expect(first?.kind).toBe('RECORD_RISK_DECISION')
    if (first?.kind !== 'RECORD_RISK_DECISION') throw new Error('Critical action was not projected')
    expect(first.options).toContainEqual(expect.objectContaining({
      decision: 'ACCEPT',
      consequence: 'REQUIRES_SECOND_AUTHORITY',
      requiredAttestations: 2,
      completedAttestations: 0,
    }))

    const pending = criticalFinding({
      state: 'PENDING_DUAL_AUTHORITY',
      decisionId: 'risk-decision-00000000-0000-0000-0000-000000000290',
      authorizationMode: 'CRITICAL_DUAL_AUTHORITY',
      rationale: 'Critical exception requires two independent operator attestations.',
      compensatingControls: ['Continuous monitoring', 'Immediate rollback'],
      expiresAt: '2026-08-29T12:00:00.000Z',
      decisionMaker: { kind: 'host-operator', principalId: 'operator-a' },
      scope: { subjectDigest: digest, policyDigest: digest },
      attestations: [{
        sequence: 1,
        decisionMaker: { kind: 'host-operator', principalId: 'operator-a' },
        authorizationEvidence: {
          permission: 'risk:break-glass',
          invocationClass: 'independently-authenticated',
        },
        attestedAt: '2026-08-29T00:00:00.000Z',
      }],
      recordedAt: '2026-08-29T00:00:00.000Z',
    })
    expect(module.projectAvailableAction(
      assessment(8) as Parameters<RiskDecisionModule['projectAvailableAction']>[0],
      pending,
      authority('operator-a') as Parameters<RiskDecisionModule['projectAvailableAction']>[2],
      '2026-08-29T01:00:00.000Z',
    )).toBeUndefined()
    const second = module.projectAvailableAction(
      assessment(8) as Parameters<RiskDecisionModule['projectAvailableAction']>[0],
      pending,
      authority('operator-b') as Parameters<RiskDecisionModule['projectAvailableAction']>[2],
      '2026-08-29T01:00:00.000Z',
    )
    expect(second?.kind).toBe('RECORD_RISK_DECISION')
    if (second?.kind !== 'RECORD_RISK_DECISION') throw new Error('Second authority action was not projected')
    expect(second.options).toEqual([expect.objectContaining({
      exactMatchRequired: true,
      completedAttestations: 1,
      consequence: 'MAKES_FINDING_NON_BLOCKING',
    })])
  })

  it('rejects two attestations from the same principal', () => {
    const attestation = {
      decisionMaker: { kind: 'host-operator' as const, principalId: 'operator-a' },
      authorizationEvidence: {
        permission: 'risk:break-glass' as const,
        invocationClass: 'independently-authenticated' as const,
      },
      attestedAt: '2026-08-29T00:00:00.000Z',
    }
    expect(riskDecisionRecordV1Schema.safeParse({
      schemaVersion: 1,
      decisionId: 'risk-decision-00000000-0000-0000-0000-000000000290',
      assessmentId,
      finding: { recordId: findingId, recordRevision: 1 },
      decision: 'ACCEPT',
      resolution: 'ACCEPTED',
      authorizationMode: 'CRITICAL_DUAL_AUTHORITY',
      rationale: 'Critical exception requires two independent operator attestations.',
      compensatingControls: ['Continuous monitoring', 'Immediate rollback'],
      expiresAt: '2026-08-29T12:00:00.000Z',
      decisionMaker: attestation.decisionMaker,
      scope: { subjectDigest: digest, policyDigest: digest },
      attestations: [
        { ...attestation, sequence: 1 },
        { ...attestation, sequence: 2, attestedAt: '2026-08-29T01:00:00.000Z' },
      ],
      recordedAt: '2026-08-29T00:00:00.000Z',
    }).success).toBe(false)
  })
})
