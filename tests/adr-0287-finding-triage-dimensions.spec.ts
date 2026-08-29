import { describe, expect, it } from 'vitest'
import {
  findingSummaryV1Schema,
  type FindingSummaryV1,
} from '../src/index.ts'
import {
  FINDING_TRIAGE_DIMENSIONS,
  findingTriageValues,
} from '../src/client/workbench/finding-triage.ts'

const summary: FindingSummaryV1 = {
  schemaVersion: 1,
  assessmentId: 'asm-00000000-0000-0000-0000-000000000287',
  assessmentRevision: 9,
  recordKind: 'FINDING',
  recordId: `finding-${'2'.repeat(64)}`,
  candidateId: `candidate-${'7'.repeat(64)}`,
  recordRevision: 3,
  validationState: 'VALIDATED',
  validationContractId: 'security/validation/reference-v1',
  weaknessClassification: { primary: 'cwe/79', secondary: ['owasp/a03'] },
  technicalSeverity: 'HIGH',
  evidenceConfidence: 'MEDIUM',
  policySignificance: 'BLOCKING',
  component: 'src',
  sensitivity: 'PROTECTED_DETAIL',
  coverageRelations: [{ obligationId: 'security/output-encoding', state: 'GAP' }],
  hasProtectedDetail: true,
}

describe('ADR 0287 Finding triage keeps domain dimensions separate', () => {
  it('projects all eight named dimensions without an aggregate risk score', () => {
    expect(FINDING_TRIAGE_DIMENSIONS).toEqual([
      'policySignificance',
      'technicalSeverity',
      'validationOutcome',
      'evidenceConfidence',
      'weakness',
      'component',
      'sensitivity',
      'coverageRelation',
    ])
    expect(Object.fromEntries(FINDING_TRIAGE_DIMENSIONS.map(dimension => [
      dimension,
      findingTriageValues(summary, dimension),
    ]))).toEqual({
      policySignificance: ['BLOCKING'],
      technicalSeverity: ['HIGH'],
      validationOutcome: ['VALIDATED'],
      evidenceConfidence: ['MEDIUM'],
      weakness: ['cwe/79', 'owasp/a03'],
      component: ['src'],
      sensitivity: ['PROTECTED_DETAIL'],
      coverageRelation: ['GAP:security/output-encoding'],
    })
    expect(findingSummaryV1Schema.safeParse({ ...summary, riskScore: 9.8 }).success).toBe(false)
  })

  it('preserves Candidate and Finding identities instead of merging lineage', () => {
    expect(findingSummaryV1Schema.parse(summary)).toMatchObject({
      recordKind: 'FINDING',
      recordId: summary.recordId,
      candidateId: summary.candidateId,
      recordRevision: 3,
    })
    expect(summary.recordId).not.toBe(summary.candidateId)
  })
})
