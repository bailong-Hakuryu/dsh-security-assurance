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

const repetitionStratumDefinitions = sufficientStratumDefinitions.map(definition => ({
  ...definition,
  maximumValidatedRecallIntervalWidth: 1,
}))

function request(
  cases: readonly unknown[],
  stratumDefinitions: readonly unknown[] = sufficientStratumDefinitions,
  repetitionPlan?: unknown,
) {
  return {
    schemaVersion: 1 as const,
    engineId: EFFECTIVENESS_METRICS_ENGINE_ID,
    severityWeights,
    stratumDefinitions,
    ...(repetitionPlan === undefined ? {} : { repetitionPlan }),
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
      repetitionAnalysis: null,
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
    const repetitionPlan = {
      method: 'HOEFFDING_TWO_SIDED_V1',
      repetitionIds: ['rep-a', 'rep-b'],
      benchmarkCaseIds: ['case-valid'],
      confidenceLevel: 0.95,
      maximumConfidenceIntervalWidth: 1,
    }
    const repeatedValidCase = { ...validCase, repetitionId: 'rep-a' }
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
      request([{ ...validCase, repetitionId: 'rep-a' }]),
      request([repeatedValidCase, repeatedValidCase], repetitionStratumDefinitions, repetitionPlan),
      request(
        [{ ...repeatedValidCase, repetitionId: 'rep-unknown' }],
        repetitionStratumDefinitions,
        repetitionPlan,
      ),
      request([repeatedValidCase], repetitionStratumDefinitions, {
        ...repetitionPlan,
        repetitionIds: ['rep-a', 'rep-a'],
      }),
      request([
        repeatedValidCase,
        { ...repeatedValidCase, repetitionId: 'rep-b', assessmentMode: 'TARGETED' },
      ], repetitionStratumDefinitions, repetitionPlan),
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

  it('reports the complete independent-repetition distribution and frozen uncertainty method', () => {
    const repeatedCases = [
      {
        caseId: 'case-shared',
        repetitionId: 'rep-a',
        disposition: 'INCLUDED',
        assessmentMode: 'CHANGE',
        supportedEcosystem: 'node',
        expectedCoverage: 'INCOMPLETE_OR_UNSUPPORTED',
        groundTruthDefects: [{
          defectId: 'defect-high',
          severity: 'HIGH',
          weaknessFamily: 'cwe-79',
          policyBlocking: true,
        }],
        result: {
          kind: 'COMPLETED',
          verdict: 'FAILED',
          coverageStatus: 'GAP',
          findings: [{
            findingId: 'finding-match',
            adjudication: { status: 'MATCHED', defectId: 'defect-high' },
          }],
        },
      },
      {
        caseId: 'case-shared',
        repetitionId: 'rep-b',
        disposition: 'INCLUDED',
        assessmentMode: 'CHANGE',
        supportedEcosystem: 'node',
        expectedCoverage: 'INCOMPLETE_OR_UNSUPPORTED',
        groundTruthDefects: [{
          defectId: 'defect-high',
          severity: 'HIGH',
          weaknessFamily: 'cwe-79',
          policyBlocking: true,
        }],
        result: {
          kind: 'COMPLETED',
          verdict: 'SATISFIED',
          coverageStatus: 'COMPLETE',
          findings: [{
            findingId: 'finding-false-positive',
            adjudication: { status: 'NOT_MATCHED' },
          }],
        },
      },
    ]
    const repetitionPlan = {
      method: 'HOEFFDING_TWO_SIDED_V1',
      repetitionIds: ['rep-a', 'rep-b'],
      benchmarkCaseIds: ['case-shared'],
      confidenceLevel: 0.95,
      maximumConfidenceIntervalWidth: 1,
    }
    const result = calculateEffectivenessMetricsV1(request(
      repeatedCases,
      repetitionStratumDefinitions,
      repetitionPlan,
    ))

    const measuredMinimumDistribution = {
      status: 'MEASURED',
      sampleSize: 2,
      mean: 0.5,
      sampleStandardDeviation: Math.sqrt(0.5),
      worst: 0,
      worstDirection: 'MINIMUM',
      confidenceInterval: {
        method: 'HOEFFDING_TWO_SIDED_V1',
        confidenceLevel: 0.95,
        lower: 0,
        upper: 1,
        width: 1,
      },
      uncertaintyStatus: 'SUFFICIENT',
      reasonCodes: [],
    }
    expect(effectivenessMetricsV1Schema.parse(result)).toEqual(result)
    expect(result.conclusion).toBe('MEASURED')
    expect(result.counts).toMatchObject({
      includedCases: 2,
      sufficientStrata: 4,
      inconclusiveStrata: 0,
    })
    expect(result.strata.map(item => item.observedSamples)).toEqual([1, 1, 1, 1])
    expect(result.repetitionAnalysis).toEqual({
      method: 'HOEFFDING_TWO_SIDED_V1',
      confidenceLevel: 0.95,
      maximumConfidenceIntervalWidth: 1,
      plannedIndependentRepetitions: 2,
      observedIndependentRepetitions: 2,
      status: 'SUFFICIENT',
      reasonCodes: [],
      metrics: {
        criticalHighValidatedRecall: measuredMinimumDistribution,
        severityWeightedValidatedRecall: measuredMinimumDistribution,
        validatedPrecision: measuredMinimumDistribution,
        unsafeSatisfactionRate: {
          ...measuredMinimumDistribution,
          worst: 1,
          worstDirection: 'MAXIMUM',
        },
        coverageHonestyRate: measuredMinimumDistribution,
      },
    })
    expect(Object.isFrozen(result.repetitionAnalysis)).toBe(true)
    expect(Object.isFrozen(result.repetitionAnalysis?.metrics)).toBe(true)
  })

  it('makes missing repetitions and excessive uncertainty explicitly inconclusive', () => {
    const caseFor = (repetitionId: string) => ({
      caseId: 'case-shared',
      repetitionId,
      disposition: 'INCLUDED',
      assessmentMode: 'CHANGE',
      supportedEcosystem: 'node',
      expectedCoverage: 'INCOMPLETE_OR_UNSUPPORTED',
      groundTruthDefects: [{
        defectId: 'defect-high',
        severity: 'HIGH',
        weaknessFamily: 'cwe-79',
        policyBlocking: true,
      }],
      result: {
        kind: 'COMPLETED',
        verdict: repetitionId === 'rep-a' ? 'FAILED' : 'SATISFIED',
        coverageStatus: repetitionId === 'rep-a' ? 'GAP' : 'COMPLETE',
        findings: [{
          findingId: `finding-${repetitionId}`,
          adjudication: repetitionId === 'rep-a'
            ? { status: 'MATCHED', defectId: 'defect-high' }
            : { status: 'NOT_MATCHED' },
        }],
      },
    })
    const tightPlan = {
      method: 'HOEFFDING_TWO_SIDED_V1',
      repetitionIds: ['rep-a', 'rep-b'],
      benchmarkCaseIds: ['case-shared'],
      confidenceLevel: 0.95,
      maximumConfidenceIntervalWidth: 0.5,
    }
    const excessive = calculateEffectivenessMetricsV1(request(
      [caseFor('rep-a'), caseFor('rep-b')],
      repetitionStratumDefinitions,
      tightPlan,
    ))
    expect(excessive.conclusion).toBe('INCONCLUSIVE')
    expect(excessive.reasonCodes).toContain('EXCESSIVE_REPETITION_UNCERTAINTY')
    expect(excessive.repetitionAnalysis).toMatchObject({
      status: 'INCONCLUSIVE',
      reasonCodes: ['EXCESSIVE_CONFIDENCE_INTERVAL_WIDTH'],
      metrics: {
        criticalHighValidatedRecall: {
          status: 'MEASURED',
          uncertaintyStatus: 'INCONCLUSIVE',
          reasonCodes: ['CONFIDENCE_INTERVAL_TOO_WIDE'],
        },
      },
    })

    const missing = calculateEffectivenessMetricsV1(request(
      [caseFor('rep-a')],
      repetitionStratumDefinitions,
      tightPlan,
    ))
    expect(missing.conclusion).toBe('INCONCLUSIVE')
    expect(missing.reasonCodes).toContain('INCOMPLETE_REPETITION_EVIDENCE')
    expect(missing.repetitionAnalysis).toMatchObject({
      plannedIndependentRepetitions: 2,
      observedIndependentRepetitions: 1,
      status: 'INCONCLUSIVE',
      reasonCodes: ['INCOMPLETE_REPETITION_CASE_MATRIX'],
      metrics: {
        criticalHighValidatedRecall: {
          status: 'INCONCLUSIVE',
          sampleSize: 0,
          reasonCodes: ['INCOMPLETE_REPETITION_CASE_MATRIX'],
        },
      },
    })
  })

  it('enforces predeclared validated-recall uncertainty within each Stratum', () => {
    const caseFor = (repetitionId: string, matched: boolean) => ({
      caseId: 'case-shared',
      repetitionId,
      disposition: 'INCLUDED',
      assessmentMode: 'CHANGE',
      supportedEcosystem: 'node',
      expectedCoverage: 'INCOMPLETE_OR_UNSUPPORTED',
      groundTruthDefects: [{
        defectId: 'defect-high',
        severity: 'HIGH',
        weaknessFamily: 'cwe-79',
        policyBlocking: true,
      }],
      result: {
        kind: 'COMPLETED',
        verdict: matched ? 'FAILED' : 'SATISFIED',
        coverageStatus: matched ? 'GAP' : 'COMPLETE',
        findings: [{
          findingId: `finding-${repetitionId}`,
          adjudication: matched
            ? { status: 'MATCHED', defectId: 'defect-high' }
            : { status: 'NOT_MATCHED' },
        }],
      },
    })
    const result = calculateEffectivenessMetricsV1(request(
      [caseFor('rep-a', true), caseFor('rep-b', false)],
      repetitionStratumDefinitions.map(definition => definition.stratumId === 'severity-high'
        ? { ...definition, maximumValidatedRecallIntervalWidth: 0.5 }
        : definition),
      {
        method: 'HOEFFDING_TWO_SIDED_V1',
        repetitionIds: ['rep-a', 'rep-b'],
        benchmarkCaseIds: ['case-shared'],
        confidenceLevel: 0.95,
        maximumConfidenceIntervalWidth: 1,
      },
    ))

    expect(result.conclusion).toBe('INCONCLUSIVE')
    expect(result.reasonCodes).toEqual(['INSUFFICIENT_BENCHMARK_STRATA'])
    expect(result.repetitionAnalysis?.status).toBe('SUFFICIENT')
    expect(result.counts).toMatchObject({ sufficientStrata: 3, inconclusiveStrata: 1 })
    expect(result.strata.find(item => item.stratumId === 'severity-high')).toMatchObject({
      status: 'INCONCLUSIVE',
      reasonCodes: ['EXCESSIVE_CONFIDENCE_INTERVAL_WIDTH'],
      uncertainty: {
        method: 'HOEFFDING_TWO_SIDED_V1',
        confidenceLevel: 0.95,
        maximumValidatedRecallIntervalWidth: 0.5,
        status: 'INCONCLUSIVE',
        reasonCodes: ['EXCESSIVE_CONFIDENCE_INTERVAL_WIDTH'],
        metrics: {
          validatedRecall: {
            status: 'MEASURED',
            sampleSize: 2,
            mean: 0.5,
            sampleStandardDeviation: Math.sqrt(0.5),
            worst: 0,
            worstDirection: 'MINIMUM',
            confidenceInterval: {
              method: 'HOEFFDING_TWO_SIDED_V1',
              confidenceLevel: 0.95,
              lower: 0,
              upper: 1,
              width: 1,
            },
            uncertaintyStatus: 'INCONCLUSIVE',
            reasonCodes: ['CONFIDENCE_INTERVAL_TOO_WIDE'],
          },
          severityWeightedValidatedRecall: {
            status: 'MEASURED',
            uncertaintyStatus: 'INCONCLUSIVE',
            reasonCodes: ['CONFIDENCE_INTERVAL_TOO_WIDE'],
          },
        },
      },
    })
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
