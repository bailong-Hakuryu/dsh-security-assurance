import { describe, expect, it } from 'vitest'

import type { InternalAssessmentRecordV1 } from '../src/internal/assessment-record.ts'
import { structuredDigest } from '../src/internal/canonical.ts'
import { RiskDecisionModule } from '../src/internal/risk-decision.ts'

const digest = structuredDigest('application/vnd.dsh.security.fixture+json', {
  fixture: 'risk-finalization',
})

function record(): InternalAssessmentRecordV1 {
  return {
    state: 'BLOCKED',
    coverage: {
      status: 'COMPLETE',
      mandatoryObligations: 1,
      satisfiedObligations: 1,
      gapObligations: 0,
      resolutions: [],
      digest,
    },
    contract: { policy: { digest } },
    evaluationTrace: { schemaVersion: 1 },
    findings: [{
      findingId: 'finding-acceptance-expiry',
      policySignificance: 'BLOCKING',
    }],
    riskDecisions: [{
      decisionId: 'risk-decision-expiry',
      decision: 'ACCEPT',
      expiresAt: '2026-08-30T00:00:02.000Z',
      finding: { recordId: 'finding-acceptance-expiry' },
    }],
    riskDecisionWindow: {
      state: 'RESOLVED',
      findingRecordIds: ['finding-acceptance-expiry'],
      providerComposition: { schemaVersion: 1 },
      proposedVerdict: 'FAILED',
      evaluationInstant: '2026-08-30T00:00:00.000Z',
      resolvedAt: '2026-08-30T00:00:01.000Z',
    },
  } as unknown as InternalAssessmentRecordV1
}

describe('Risk Decision finalization expiry', () => {
  it('uses the seal finalization instant rather than the earlier resolution instant', () => {
    const module = new RiskDecisionModule()
    const beforeExpiry = module.finalizedOutcome(
      record(),
      [],
      '2026-08-30T00:00:01.500Z',
    )
    expect(beforeExpiry.verdict).toBe('SATISFIED')
    expect(beforeExpiry.findings[0]).toMatchObject({ policySignificance: 'NON_BLOCKING' })

    const afterExpiry = module.finalizedOutcome(
      record(),
      [],
      '2026-08-30T00:00:02.001Z',
    )
    expect(afterExpiry.verdict).toBe('FAILED')
    expect(afterExpiry.findings[0]).toMatchObject({ policySignificance: 'BLOCKING' })
  })
})
