import { describe, expect, it } from 'vitest'
import {
  calculateEffectivenessMetricsV1,
  EFFECTIVENESS_METRICS_ENGINE_ID,
  effectivenessMetricsRequestV1Schema,
  effectivenessMetricsV1Schema,
  EvaluationMetricsInputError,
} from '../src/evaluation.ts'

const severityWeights = {
  CRITICAL: 8,
  HIGH: 5,
  MEDIUM: 3,
  LOW: 2,
  INFORMATIONAL: 1,
} as const

function request(cases: readonly unknown[]) {
  return {
    schemaVersion: 1 as const,
    engineId: EFFECTIVENESS_METRICS_ENGINE_ID,
    severityWeights,
    cases,
  }
}

describe('Effectiveness Metrics Engine v1', () => {
  it('calculates the five primary metrics from one-to-one adjudicated evidence', () => {
    const result = calculateEffectivenessMetricsV1(request([
      {
        caseId: 'case-supported-unsafe',
        disposition: 'INCLUDED',
        expectedCoverage: 'COMPLETE',
        groundTruthDefects: [
          { defectId: 'defect-critical', severity: 'CRITICAL', policyBlocking: true },
          { defectId: 'defect-low', severity: 'LOW', policyBlocking: false },
        ],
        result: {
          kind: 'COMPLETED',
          verdict: 'SATISFIED',
          coverageStatus: 'COMPLETE',
          findings: [
            {
              findingId: 'finding-low',
              adjudication: { status: 'MATCHED', defectId: 'defect-low' },
            },
            {
              findingId: 'finding-false-positive',
              adjudication: { status: 'NOT_MATCHED' },
            },
          ],
        },
      },
      {
        caseId: 'case-honest-gap',
        disposition: 'INCLUDED',
        expectedCoverage: 'INCOMPLETE_OR_UNSUPPORTED',
        groundTruthDefects: [
          { defectId: 'defect-high', severity: 'HIGH', policyBlocking: true },
        ],
        result: {
          kind: 'COMPLETED',
          verdict: 'INDETERMINATE',
          coverageStatus: 'GAP',
          findings: [],
        },
      },
      {
        caseId: 'case-invalid-benchmark',
        disposition: 'BENCHMARK_INVALID',
        expectedCoverage: 'COMPLETE',
        groundTruthDefects: [
          { defectId: 'defect-excluded', severity: 'CRITICAL', policyBlocking: true },
        ],
        result: {
          kind: 'COMPLETED',
          verdict: 'FAILED',
          coverageStatus: 'COMPLETE',
          findings: [
            {
              findingId: 'finding-excluded',
              adjudication: { status: 'MATCHED', defectId: 'defect-excluded' },
            },
          ],
        },
      },
    ]))

    expect(effectivenessMetricsV1Schema.parse(result)).toEqual(result)
    expect(result).toEqual({
      schemaVersion: 1,
      engineId: 'security/effectiveness-metrics/v1',
      conclusion: 'MEASURED',
      reasonCodes: [],
      counts: {
        includedCases: 2,
        benchmarkInvalidCases: 1,
        groundTruthDefects: 3,
        validatedFindings: 2,
        unadjudicatedFindings: 0,
        productFailures: 0,
      },
      metrics: {
        criticalHighValidatedRecall: {
          status: 'MEASURED', numerator: 0, denominator: 2, value: 0,
        },
        severityWeightedValidatedRecall: {
          status: 'MEASURED', numerator: 2, denominator: 15, value: 2 / 15,
        },
        validatedPrecision: {
          status: 'MEASURED', numerator: 1, denominator: 2, value: 0.5,
        },
        unsafeSatisfactionRate: {
          status: 'MEASURED', numerator: 1, denominator: 2, value: 0.5,
        },
        coverageHonestyRate: {
          status: 'MEASURED', numerator: 1, denominator: 1, value: 1,
        },
      },
    })
    expect(Object.isFrozen(result)).toBe(true)
    expect(Object.isFrozen(result.counts)).toBe(true)
    expect(Object.isFrozen(result.metrics)).toBe(true)
    expect(Object.isFrozen(result.metrics.validatedPrecision)).toBe(true)
  })

  it('counts preclassified product failures as misses without treating them as benchmark exclusions', () => {
    const result = calculateEffectivenessMetricsV1(request([{
      caseId: 'case-product-crash',
      disposition: 'INCLUDED',
      expectedCoverage: 'INCOMPLETE_OR_UNSUPPORTED',
      groundTruthDefects: [
        { defectId: 'defect-high', severity: 'HIGH', policyBlocking: true },
      ],
      result: { kind: 'PRODUCT_FAILURE', failure: 'CRASH' },
    }]))

    expect(result.counts).toEqual({
      includedCases: 1,
      benchmarkInvalidCases: 0,
      groundTruthDefects: 1,
      validatedFindings: 0,
      unadjudicatedFindings: 0,
      productFailures: 1,
    })
    expect(result.metrics).toMatchObject({
      criticalHighValidatedRecall: { numerator: 0, denominator: 1, value: 0 },
      severityWeightedValidatedRecall: { numerator: 0, denominator: 5, value: 0 },
      unsafeSatisfactionRate: { numerator: 0, denominator: 1, value: 0 },
      coverageHonestyRate: { numerator: 0, denominator: 1, value: 0 },
      validatedPrecision: { status: 'INCONCLUSIVE', numerator: 0, denominator: 0, value: null },
    })
    expect(result.conclusion).toBe('INCONCLUSIVE')
    expect(result.reasonCodes).toEqual(['NO_VALIDATED_FINDINGS'])
  })

  it('keeps zero-denominator and unadjudicated evidence visibly inconclusive', () => {
    const result = calculateEffectivenessMetricsV1(request([{
      caseId: 'case-unadjudicated',
      disposition: 'INCLUDED',
      expectedCoverage: 'COMPLETE',
      groundTruthDefects: [],
      result: {
        kind: 'COMPLETED',
        verdict: 'SATISFIED',
        coverageStatus: 'COMPLETE',
        findings: [{
          findingId: 'finding-unadjudicated',
          adjudication: { status: 'UNADJUDICATED' },
        }],
      },
    }]))

    expect(result.conclusion).toBe('INCONCLUSIVE')
    expect(result.reasonCodes).toEqual([
      'NO_BLOCKING_GROUND_TRUTH_CASES',
      'NO_CRITICAL_HIGH_GROUND_TRUTH',
      'NO_INCOMPLETE_COVERAGE_CASES',
      'NO_WEIGHTED_GROUND_TRUTH',
      'UNADJUDICATED_FINDINGS',
    ])
    expect(result.metrics.validatedPrecision).toEqual({
      status: 'MEASURED', numerator: 0, denominator: 1, value: 0,
    })
  })

  it('rejects evidence that violates identity or one-to-one matching invariants', () => {
    const validCase = {
      caseId: 'case-valid',
      disposition: 'INCLUDED',
      expectedCoverage: 'COMPLETE',
      groundTruthDefects: [
        { defectId: 'defect-one', severity: 'HIGH', policyBlocking: true },
      ],
      result: {
        kind: 'COMPLETED',
        verdict: 'FAILED',
        coverageStatus: 'COMPLETE',
        findings: [{
          findingId: 'finding-one',
          adjudication: { status: 'MATCHED', defectId: 'defect-one' },
        }],
      },
    }
    const invalid = [
      request([validCase, { ...validCase }]),
      request([{
        ...validCase,
        groundTruthDefects: [validCase.groundTruthDefects[0], validCase.groundTruthDefects[0]],
      }]),
      request([{
        ...validCase,
        result: {
          ...validCase.result,
          findings: [validCase.result.findings[0], validCase.result.findings[0]],
        },
      }]),
      request([{
        ...validCase,
        result: {
          ...validCase.result,
          findings: [
            validCase.result.findings[0],
            {
              findingId: 'finding-two',
              adjudication: { status: 'MATCHED', defectId: 'defect-one' },
            },
          ],
        },
      }]),
      request([{
        ...validCase,
        result: {
          ...validCase.result,
          findings: [{
            findingId: 'finding-unknown-match',
            adjudication: { status: 'MATCHED', defectId: 'defect-unknown' },
          }],
        },
      }]),
      {
        ...request([validCase]),
        severityWeights: { ...severityWeights, CRITICAL: 1 },
      },
    ]

    for (const candidate of invalid) {
      expect(() => calculateEffectivenessMetricsV1(candidate)).toThrow(EvaluationMetricsInputError)
    }
  })

  it('uses strict schemas and rejects authority, path, and post-hoc threshold fields', () => {
    const candidate = request([])
    expect(effectivenessMetricsRequestV1Schema.parse(candidate)).toEqual(candidate)
    for (const extra of [
      { principalId: 'self-declared-evaluator' },
      { repositoryPath: 'C:\\private\\benchmark' },
      { releaseThreshold: 0.5 },
    ]) {
      expect(effectivenessMetricsRequestV1Schema.safeParse({ ...candidate, ...extra }).success).toBe(false)
    }
  })
})
