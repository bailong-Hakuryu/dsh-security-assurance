import { describe, expect, it } from 'vitest'
import {
  findingDetailViewV1Schema,
  findingSummaryV1Schema,
} from '../src/index.ts'

const assessmentId = 'asm-00000000-0000-0000-0000-000000000268'
const candidateId = `candidate-${'2'.repeat(64)}`
const recordId = `finding-${'8'.repeat(64)}`
const digest = {
  schemaVersion: 1 as const,
  algorithm: 'sha256' as const,
  mediaType: 'application/vnd.dsh.canonical-json',
  byteLength: 1,
  canonicalization: 'dsh-canonical-json-v1' as const,
  value: '8'.repeat(64),
}

describe('ADR 0268 Finding query projections', () => {
  it('keeps list Summaries redacted and revision-bound', () => {
    const summary = {
      schemaVersion: 1,
      assessmentId,
      assessmentRevision: 7,
      recordKind: 'FINDING',
      recordId,
      candidateId,
      recordRevision: 1,
      validationState: 'VALIDATED',
      validationContractId: 'security/validation-v1',
      weaknessClassification: { primary: 'CWE-20', secondary: [] },
      technicalSeverity: 'HIGH',
      evidenceConfidence: 'HIGH',
      policySignificance: 'BLOCKING',
      component: 'src',
      sensitivity: 'PROTECTED_DETAIL',
      coverageRelations: [{ obligationId: 'application-security-analysis', state: 'SATISFIED' }],
      hasProtectedDetail: true,
    }
    expect(findingSummaryV1Schema.safeParse(summary).success).toBe(true)
    for (const forbidden of [
      { sourceAnchor: { path: 'src/index.ts' } },
      { evidenceLinks: [{ value: { secret: true } }] },
      { markdown: '# derived report' },
    ]) {
      expect(findingSummaryV1Schema.safeParse({ ...summary, ...forbidden }).success).toBe(false)
    }
  })

  it('requires exact revision detail with bounded Evidence metadata but no payload', () => {
    const detail = {
      schemaVersion: 1,
      assessmentId,
      assessmentRevision: 7,
      recordKind: 'FINDING',
      recordId,
      candidateId,
      recordRevision: 1,
      revisionChain: [{ recordRevision: 1, supersedesRecordRevision: null, isCurrent: true }],
      weaknessClassification: { primary: 'CWE-20', secondary: [] },
      affectedControlId: 'security/input-validation',
      sourceAnchor: {
        path: 'src/index.ts',
        fileDigest: digest,
        locator: { kind: 'JSON_POINTER', value: '/scripts/install' },
      },
      validation: {
        state: 'VALIDATED',
        contractId: 'security/validation-v1',
        contractVersion: 1,
        outcomeArtifactId: 'validation-outcome',
        rejectionCondition: null,
        proofGaps: [],
        negativeControls: ['exact-source-anchor'],
      },
      technicalSeverity: {
        value: 'HIGH',
        methodVersion: 'security/severity-v1',
        inputs: [{ dimension: 'impact', value: 'HIGH' }],
      },
      evidenceConfidence: {
        value: 'HIGH',
        methodVersion: 'security/confidence-v1',
        rubric: [{ dimension: 'reproducible', value: true }],
      },
      policySignificance: 'BLOCKING',
      coverageRelations: [{
        obligationId: 'application-security-analysis',
        state: 'SATISFIED',
        reason: 'ELIGIBLE_EVIDENCE',
      }],
      riskDecision: { state: 'NOT_RECORDED' },
      evidenceLinks: [{
        artifactId: 'validation-evidence',
        schemaId: 'security/validation-evidence',
        digest,
        purpose: 'VALIDATION_EVIDENCE',
        eligibilityDecision: 'ELIGIBLE',
        eligibilityDecisionArtifactId: 'eligibility-decision',
      }],
      attackPath: { state: 'NOT_AVAILABLE' },
    }
    expect(findingDetailViewV1Schema.safeParse(detail).success).toBe(true)
    expect(findingDetailViewV1Schema.safeParse({
      ...detail,
      evidenceLinks: [{ ...detail.evidenceLinks[0], value: { secret: true } }],
    }).success).toBe(false)
  })
})
