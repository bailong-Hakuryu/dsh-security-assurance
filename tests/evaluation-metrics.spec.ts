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

const sufficientStratumDefinitions = [
  {
    stratumId: 'severity-high',
    selector: { dimension: 'SEVERITY', value: 'HIGH' },
    minimumSamples: 1,
  },
  {
    stratumId: 'weakness-cwe-79',
    selector: { dimension: 'WEAKNESS_FAMILY', value: 'cwe-79' },
    minimumSamples: 1,
  },
  {
    stratumId: 'mode-change',
    selector: { dimension: 'ASSESSMENT_MODE', value: 'CHANGE' },
    minimumSamples: 1,
  },
  {
    stratumId: 'ecosystem-node',
    selector: { dimension: 'SUPPORTED_ECOSYSTEM', value: 'node' },
    minimumSamples: 1,
  },
] as const

function request(
  cases: readonly unknown[],
  stratumDefinitions: readonly unknown[] = sufficientStratumDefinitions,
) {
  return {
    schemaVersion: 1 as const,
    engineId: EFFECTIVENESS_METRICS_ENGINE_ID,
    severityWeights,
    stratumDefinitions,
    cases,
  }
}

describe('Effectiveness Metrics Engine v1', () => {
  it('calculates the five primary metrics from one-to-one adjudicated evidence', () => {
    const result = calculateEffectivenessMetricsV1(request([
      {
        caseId: 'case-supported-unsafe',
        disposition: 'INCLUDED',
        assessmentMode: 'CHANGE',
        supportedEcosystem: 'node',
        expectedCoverage: 'COMPLETE',
        groundTruthDefects: [
          {
            defectId: 'defect-critical',
            severity: 'CRITICAL',
            weaknessFamily: 'cwe-89',
            policyBlocking: true,
          },
          {
            defectId: 'defect-low',
            severity: 'LOW',
            weaknessFamily: 'cwe-79',
            policyBlocking: false,
          },
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
        assessmentMode: 'CHANGE',
        supportedEcosystem: 'node',
        expectedCoverage: 'INCOMPLETE_OR_UNSUPPORTED',
        groundTruthDefects: [
          {
            defectId: 'defect-high',
            severity: 'HIGH',
            weaknessFamily: 'cwe-79',
            policyBlocking: true,
          },
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
        assessmentMode: 'CHANGE',
        supportedEcosystem: 'node',
        expectedCoverage: 'COMPLETE',
        groundTruthDefects: [
          {
            defectId: 'defect-excluded',
            severity: 'CRITICAL',
            weaknessFamily: 'cwe-79',
            policyBlocking: true,
          },
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
        sufficientStrata: 4,
        inconclusiveStrata: 0,
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
      strata: [
        {
          stratumId: 'ecosystem-node',
          selector: { dimension: 'SUPPORTED_ECOSYSTEM', value: 'node' },
          sampleUnit: 'CASE',
          minimumSamples: 1,
          observedSamples: 2,
          status: 'SUFFICIENT',
          reasonCodes: [],
        },
        {
          stratumId: 'mode-change',
          selector: { dimension: 'ASSESSMENT_MODE', value: 'CHANGE' },
          sampleUnit: 'CASE',
          minimumSamples: 1,
          observedSamples: 2,
          status: 'SUFFICIENT',
          reasonCodes: [],
        },
        {
          stratumId: 'severity-high',
          selector: { dimension: 'SEVERITY', value: 'HIGH' },
          sampleUnit: 'GROUND_TRUTH_DEFECT',
          minimumSamples: 1,
          observedSamples: 1,
          status: 'SUFFICIENT',
          reasonCodes: [],
        },
        {
          stratumId: 'weakness-cwe-79',
          selector: { dimension: 'WEAKNESS_FAMILY', value: 'cwe-79' },
          sampleUnit: 'GROUND_TRUTH_DEFECT',
          minimumSamples: 1,
          observedSamples: 2,
          status: 'SUFFICIENT',
          reasonCodes: [],
        },
      ],
    })
    expect(Object.isFrozen(result)).toBe(true)
    expect(Object.isFrozen(result.counts)).toBe(true)
    expect(Object.isFrozen(result.metrics)).toBe(true)
    expect(Object.isFrozen(result.metrics.validatedPrecision)).toBe(true)
    expect(Object.isFrozen(result.strata)).toBe(true)
    expect(Object.isFrozen(result.strata[0])).toBe(true)
    expect(Object.isFrozen(result.strata[0]?.selector)).toBe(true)
  })

  it('counts preclassified product failures as misses without treating them as benchmark exclusions', () => {
    const result = calculateEffectivenessMetricsV1(request([{
      caseId: 'case-product-crash',
      disposition: 'INCLUDED',
      assessmentMode: 'CHANGE',
      supportedEcosystem: 'node',
      expectedCoverage: 'INCOMPLETE_OR_UNSUPPORTED',
      groundTruthDefects: [
        {
          defectId: 'defect-high',
          severity: 'HIGH',
          weaknessFamily: 'cwe-79',
          policyBlocking: true,
        },
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
      sufficientStrata: 4,
      inconclusiveStrata: 0,
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
      assessmentMode: 'CHANGE',
      supportedEcosystem: 'node',
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
      'INSUFFICIENT_BENCHMARK_STRATA',
    ])
    expect(result.metrics.validatedPrecision).toEqual({
      status: 'MEASURED', numerator: 0, denominator: 1, value: 0,
    })
  })

  it('rejects evidence that violates identity or one-to-one matching invariants', () => {
    const validCase = {
      caseId: 'case-valid',
      disposition: 'INCLUDED',
      assessmentMode: 'CHANGE',
      supportedEcosystem: 'node',
      expectedCoverage: 'COMPLETE',
      groundTruthDefects: [
        {
          defectId: 'defect-one',
          severity: 'HIGH',
          weaknessFamily: 'cwe-79',
          policyBlocking: true,
        },
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
      request([validCase], [
        ...sufficientStratumDefinitions.slice(1),
        {
          stratumId: 'weakness-cwe-89',
          selector: { dimension: 'WEAKNESS_FAMILY', value: 'cwe-89' },
          minimumSamples: 1,
        },
      ]),
      request([validCase], [
        ...sufficientStratumDefinitions,
        { ...sufficientStratumDefinitions[0], stratumId: 'severity-high-copy' },
      ]),
      request([validCase], [
        ...sufficientStratumDefinitions,
        {
          stratumId: 'severity-high',
          selector: { dimension: 'SEVERITY', value: 'CRITICAL' },
          minimumSamples: 1,
        },
      ]),
    ]

    for (const candidate of invalid) {
      expect(() => calculateEffectivenessMetricsV1(candidate)).toThrow(EvaluationMetricsInputError)
    }
  })

  it('evaluates predeclared sample sufficiency separately in every mandatory stratum', () => {
    const result = calculateEffectivenessMetricsV1(request([
      {
        caseId: 'case-measured',
        disposition: 'INCLUDED',
        assessmentMode: 'CHANGE',
        supportedEcosystem: 'node',
        expectedCoverage: 'COMPLETE',
        groundTruthDefects: [
          {
            defectId: 'defect-high-one',
            severity: 'HIGH',
            weaknessFamily: 'cwe-79',
            policyBlocking: true,
          },
        ],
        result: { kind: 'PRODUCT_FAILURE', failure: 'CRASH' },
      },
      {
        caseId: 'case-measured-two',
        disposition: 'INCLUDED',
        assessmentMode: 'CHANGE',
        supportedEcosystem: 'node',
        expectedCoverage: 'COMPLETE',
        groundTruthDefects: [
          {
            defectId: 'defect-high-two',
            severity: 'HIGH',
            weaknessFamily: 'cwe-79',
            policyBlocking: true,
          },
        ],
        result: { kind: 'PRODUCT_FAILURE', failure: 'TIMEOUT' },
      },
      {
        caseId: 'case-excluded',
        disposition: 'BENCHMARK_INVALID',
        assessmentMode: 'CHANGE',
        supportedEcosystem: 'node',
        expectedCoverage: 'COMPLETE',
        groundTruthDefects: [
          {
            defectId: 'defect-excluded',
            severity: 'HIGH',
            weaknessFamily: 'cwe-79',
            policyBlocking: true,
          },
        ],
        result: { kind: 'PRODUCT_FAILURE', failure: 'INCORRECT_OUTCOME' },
      },
    ], [
      {
        stratumId: 'weakness-cwe-79',
        selector: { dimension: 'WEAKNESS_FAMILY', value: 'cwe-79' },
        minimumSamples: 3,
      },
      {
        stratumId: 'severity-high',
        selector: { dimension: 'SEVERITY', value: 'HIGH' },
        minimumSamples: 2,
      },
      {
        stratumId: 'mode-change',
        selector: { dimension: 'ASSESSMENT_MODE', value: 'CHANGE' },
        minimumSamples: 2,
      },
      {
        stratumId: 'ecosystem-node',
        selector: { dimension: 'SUPPORTED_ECOSYSTEM', value: 'node' },
        minimumSamples: 3,
      },
    ]))

    expect(result.conclusion).toBe('INCONCLUSIVE')
    expect(result.reasonCodes).toEqual([
      'NO_INCOMPLETE_COVERAGE_CASES',
      'NO_VALIDATED_FINDINGS',
      'INSUFFICIENT_BENCHMARK_STRATA',
    ])
    expect(result.counts).toMatchObject({
      includedCases: 2,
      benchmarkInvalidCases: 1,
      productFailures: 2,
      sufficientStrata: 2,
      inconclusiveStrata: 2,
    })
    expect(result.strata).toEqual([
      {
        stratumId: 'ecosystem-node',
        selector: { dimension: 'SUPPORTED_ECOSYSTEM', value: 'node' },
        sampleUnit: 'CASE',
        minimumSamples: 3,
        observedSamples: 2,
        status: 'INCONCLUSIVE',
        reasonCodes: ['INSUFFICIENT_SAMPLE_COUNT'],
      },
      {
        stratumId: 'mode-change',
        selector: { dimension: 'ASSESSMENT_MODE', value: 'CHANGE' },
        sampleUnit: 'CASE',
        minimumSamples: 2,
        observedSamples: 2,
        status: 'SUFFICIENT',
        reasonCodes: [],
      },
      {
        stratumId: 'severity-high',
        selector: { dimension: 'SEVERITY', value: 'HIGH' },
        sampleUnit: 'GROUND_TRUTH_DEFECT',
        minimumSamples: 2,
        observedSamples: 2,
        status: 'SUFFICIENT',
        reasonCodes: [],
      },
      {
        stratumId: 'weakness-cwe-79',
        selector: { dimension: 'WEAKNESS_FAMILY', value: 'cwe-79' },
        sampleUnit: 'GROUND_TRUTH_DEFECT',
        minimumSamples: 3,
        observedSamples: 2,
        status: 'INCONCLUSIVE',
        reasonCodes: ['INSUFFICIENT_SAMPLE_COUNT'],
      },
    ])
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
