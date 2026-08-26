import { describe, expect, it } from 'vitest'
import {
  AIR_GAPPED_EVALUATION_ENGINE_ID,
  AirGappedEvaluationInputError,
  type AirGappedEvaluationAssemblyRequestV1,
  airGappedEvaluationAssemblyV1Schema,
  airGappedRunnerInputV1Schema,
  airGappedRunnerResultV1Schema,
  assembleAirGappedEvaluationV1,
  calculateEffectivenessMetricsV1,
  calculatePairedArmComparisonV1,
  calculateUtilityMetricsV1,
  assembleReleaseEvidenceManifestV1,
  DETERMINISTIC_FAILURE_HISTORY_ENGINE_ID,
  DETERMINISTIC_RELEASE_PROOF_KINDS,
  type DeterministicFailureHistoryRequestV1,
  evaluateDeterministicFailureHistoryV1,
  EFFECTIVENESS_METRICS_ENGINE_ID,
  effectivenessMetricsRequestV1Schema,
  effectivenessMetricsV1Schema,
  EvaluationMetricsInputError,
  evaluateReleaseConstitutionV1,
  PAIRED_ARM_COMPARISON_ENGINE_ID,
  pairedArmComparisonV1Schema,
  PairedArmComparisonInputError,
  PUBLIC_SECURITY_SCORECARD_ENGINE_ID,
  type PublicSecurityScorecardRequestV1,
  publicSecurityScorecardV1Schema,
  PublicSecurityScorecardInputError,
  RELEASE_EVIDENCE_MANIFEST_ENGINE_ID,
  RELEASE_EVIDENCE_PROOF_KINDS,
  type ReleaseEvidenceManifestRequestV1,
  releaseEvidenceManifestV1Schema,
  ReleaseEvidenceManifestInputError,
  RELEASE_CONSTITUTION_CHECK_IDS,
  RELEASE_CONSTITUTION_ENGINE_ID,
  type ReleaseConstitutionEvaluationRequestV1,
  releaseConstitutionDecisionV1Schema,
  ReleaseConstitutionInputError,
  renderPublicSecurityScorecardV1,
  UTILITY_METRICS_ENGINE_ID,
  utilityMetricsV1Schema,
  UtilityMetricsInputError,
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

describe('Deterministic Failure History v1', () => {
  function historyDigest(character: string) {
    return {
      schemaVersion: 1 as const,
      algorithm: 'sha256' as const,
      mediaType: 'application/json',
      byteLength: 128,
      canonicalization: 'dsh-canonical-json-v1' as const,
      value: character.repeat(64),
    }
  }

  it('keeps an original deterministic failure blocking when a diagnostic rerun passes', () => {
    const artifactDigest = historyDigest('a')
    const request: DeterministicFailureHistoryRequestV1 = {
      schemaVersion: 1,
      engineId: DETERMINISTIC_FAILURE_HISTORY_ENGINE_ID,
      evaluatedAtEpochMs: 300,
      candidateArtifactDigest: artifactDigest,
      requiredProofKinds: ['RESOURCE'],
      runs: [
        {
          kind: 'QUALIFICATION',
          runId: 'qualification/resource/failed',
          proofKind: 'RESOURCE',
          candidateArtifactDigest: artifactDigest,
          status: 'FAILED',
          evidenceId: 'evidence/resource/failed',
          evidenceDigest: historyDigest('b'),
          completedAtEpochMs: 100,
        },
        {
          kind: 'DIAGNOSTIC_RERUN',
          runId: 'diagnostic/resource/passed',
          proofKind: 'RESOURCE',
          originalFailureRunId: 'qualification/resource/failed',
          candidateArtifactDigest: artifactDigest,
          status: 'PASSED',
          evidenceId: 'evidence/resource/diagnostic-pass',
          evidenceDigest: historyDigest('c'),
          completedAtEpochMs: 200,
        },
      ],
      resolutions: [],
    }

    const result = evaluateDeterministicFailureHistoryV1(request)

    expect(result).toMatchObject({
      decision: 'BLOCKED',
      unresolvedFailureCount: 1,
      proofHistories: [{
        proofKind: 'RESOURCE',
        candidateQualificationRunId: 'qualification/resource/failed',
        candidateQualificationStatus: 'FAILED',
        diagnosticRerunIds: ['diagnostic/resource/passed'],
        resolvedFailureRunIds: [],
        unresolvedFailureRunIds: ['qualification/resource/failed'],
        verificationStatus: 'FAILED',
      }],
    })
  })

  it('resolves an original failure only through explained correction and new qualification', () => {
    const failedArtifactDigest = historyDigest('a')
    const correctedArtifactDigest = historyDigest('d')
    const request = {
      schemaVersion: 1,
      engineId: DETERMINISTIC_FAILURE_HISTORY_ENGINE_ID,
      evaluatedAtEpochMs: 500,
      candidateArtifactDigest: correctedArtifactDigest,
      requiredProofKinds: ['MUTATION'],
      runs: [
        {
          kind: 'QUALIFICATION',
          runId: 'qualification/mutation/failed',
          proofKind: 'MUTATION',
          candidateArtifactDigest: failedArtifactDigest,
          status: 'FAILED',
          evidenceId: 'evidence/mutation/failed',
          evidenceDigest: historyDigest('b'),
          completedAtEpochMs: 100,
        },
        {
          kind: 'DIAGNOSTIC_RERUN',
          runId: 'diagnostic/mutation/passed',
          proofKind: 'MUTATION',
          originalFailureRunId: 'qualification/mutation/failed',
          candidateArtifactDigest: failedArtifactDigest,
          status: 'PASSED',
          evidenceId: 'evidence/mutation/diagnostic-pass',
          evidenceDigest: historyDigest('c'),
          completedAtEpochMs: 200,
        },
        {
          kind: 'QUALIFICATION',
          runId: 'qualification/mutation/corrected',
          proofKind: 'MUTATION',
          candidateArtifactDigest: correctedArtifactDigest,
          status: 'PASSED',
          evidenceId: 'evidence/mutation/corrected-pass',
          evidenceDigest: historyDigest('e'),
          completedAtEpochMs: 400,
        },
      ],
      resolutions: [{
        originalFailureRunId: 'qualification/mutation/failed',
        replacementQualificationRunId: 'qualification/mutation/corrected',
        investigationEvidenceId: 'evidence/mutation/investigation',
        investigationEvidenceDigest: historyDigest('f'),
        correctionEvidenceId: 'evidence/mutation/correction',
        correctionEvidenceDigest: historyDigest('1'),
        resolvedAtEpochMs: 450,
      }],
    }

    const result = evaluateDeterministicFailureHistoryV1(request)

    expect(result).toMatchObject({
      decision: 'VERIFIED',
      unresolvedFailureCount: 0,
      proofHistories: [{
        proofKind: 'MUTATION',
        candidateQualificationRunId: 'qualification/mutation/corrected',
        candidateQualificationStatus: 'PASSED',
        diagnosticRerunIds: ['diagnostic/mutation/passed'],
        resolvedFailureRunIds: ['qualification/mutation/failed'],
        unresolvedFailureRunIds: [],
        verificationStatus: 'PASSED',
      }],
    })
  })

  it('makes a missing required current qualification explicitly inconclusive', () => {
    const artifactDigest = historyDigest('a')
    const result = evaluateDeterministicFailureHistoryV1({
      schemaVersion: 1,
      engineId: DETERMINISTIC_FAILURE_HISTORY_ENGINE_ID,
      evaluatedAtEpochMs: 300,
      candidateArtifactDigest: artifactDigest,
      requiredProofKinds: ['LIFECYCLE', 'RESOURCE'],
      runs: [{
        kind: 'QUALIFICATION',
        runId: 'qualification/resource/passed',
        proofKind: 'RESOURCE',
        candidateArtifactDigest: artifactDigest,
        status: 'PASSED',
        evidenceId: 'evidence/resource/passed',
        evidenceDigest: historyDigest('b'),
        completedAtEpochMs: 100,
      }],
      resolutions: [],
    })

    expect(result.decision).toBe('INCONCLUSIVE')
    expect(result.requiredProofKinds).toEqual(['LIFECYCLE', 'RESOURCE'])
    expect(result.proofHistories).toEqual([
      {
        proofKind: 'LIFECYCLE',
        candidateQualificationRunId: null,
        candidateQualificationStatus: 'MISSING',
        diagnosticRerunIds: [],
        resolvedFailureRunIds: [],
        unresolvedFailureRunIds: [],
        verificationStatus: 'INCONCLUSIVE',
      },
      {
        proofKind: 'RESOURCE',
        candidateQualificationRunId: 'qualification/resource/passed',
        candidateQualificationStatus: 'PASSED',
        diagnosticRerunIds: [],
        resolvedFailureRunIds: [],
        unresolvedFailureRunIds: [],
        verificationStatus: 'PASSED',
      },
    ])
  })
})

describe('Air-gapped Evaluation Engine v1', () => {
  function digest(character: string) {
    return {
      schemaVersion: 1 as const,
      algorithm: 'sha256' as const,
      mediaType: 'application/json',
      byteLength: 128,
      canonicalization: 'dsh-canonical-json-v1' as const,
      value: character.repeat(64),
    }
  }

  function baseAssemblyRequest(): AirGappedEvaluationAssemblyRequestV1 {
    const subjectDigest = digest('a')
    const runnerInput = (executionGrantId: string) => ({
      schemaVersion: 1 as const,
      runId: 'run-air-gap',
      caseId: 'case-hidden',
      opaqueSubjectHandleId: 'subject-handle',
      subjectDigest,
      assessmentMode: 'CHANGE' as const,
      supportedEcosystem: 'node',
      executionGrantId,
      admittedAtEpochMs: 100,
    })
    return {
      schemaVersion: 1,
      engineId: AIR_GAPPED_EVALUATION_ENGINE_ID,
      runId: 'run-air-gap',
      evaluatorId: 'independent-evaluator',
      evaluatorAuthorizationRecordId: 'authority/evaluator-1',
      declaredArmIds: ['baseline-arm', 'candidate-arm'],
      severityWeights,
      stratumDefinitions: sufficientStratumDefinitions.map(item => ({ ...item })),
      matchingContract: {
        contractId: 'matching-contract-v1',
        registrationRecordId: 'qualification/matching-contract-v1',
        registeredAtEpochMs: 50,
        contractDigest: digest('b'),
      },
      groundTruthManifest: {
        manifestId: 'ground-truth-manifest-v1',
        corpusVersionId: 'qualification-corpus-v1',
        sealedAtEpochMs: 25,
        manifestDigest: digest('c'),
        canaryMarkerIds: ['canary-hidden-1'],
        cases: [{
          caseId: 'case-hidden',
          subjectDigest,
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
        }],
      },
      groundTruthOpenedAtEpochMs: 400,
      sealedArmResults: [
        {
          sealedResultId: 'sealed-baseline',
          armId: 'baseline-arm',
          runnerInput: runnerInput('grant-opaque-a'),
          result: {
            kind: 'COMPLETED',
            verdict: 'SATISFIED',
            coverageStatus: 'COMPLETE',
            findings: [{ findingId: 'finding-baseline' }],
          },
          sealedAtEpochMs: 200,
          resultDigest: digest('d'),
        },
        {
          sealedResultId: 'sealed-candidate',
          armId: 'candidate-arm',
          runnerInput: runnerInput('grant-opaque-b'),
          result: {
            kind: 'COMPLETED',
            verdict: 'FAILED',
            coverageStatus: 'GAP',
            findings: [{ findingId: 'finding-candidate' }],
          },
          sealedAtEpochMs: 300,
          resultDigest: digest('e'),
        },
      ],
      adjudications: [
        {
          armId: 'baseline-arm',
          caseId: 'case-hidden',
          findingId: 'finding-baseline',
          adjudication: { status: 'NOT_MATCHED' },
          adjudicationRecordId: 'adjudication-baseline',
        },
        {
          armId: 'candidate-arm',
          caseId: 'case-hidden',
          findingId: 'finding-candidate',
          adjudication: { status: 'MATCHED', defectId: 'defect-high' },
          adjudicationRecordId: 'adjudication-candidate',
        },
      ],
      airGapAudit: {
        auditId: 'air-gap-audit-v1',
        completedAtEpochMs: 500,
        auditedArmIds: ['baseline-arm', 'candidate-arm'],
        auditedSealedResultIds: ['sealed-baseline', 'sealed-candidate'],
        violations: [],
      },
    }
  }

  it('keeps Ground Truth, Arm labels, seeds, and matching rules outside Runner input', () => {
    const runnerInput = baseAssemblyRequest().sealedArmResults[0]?.runnerInput
    expect(runnerInput).toBeDefined()
    expect(airGappedRunnerInputV1Schema.parse(runnerInput)).toEqual(runnerInput)
    for (const forbidden of [
      { armId: 'candidate-arm' },
      { groundTruthDefects: [] },
      { expectedFindings: ['defect-high'] },
      { matchingContractId: 'matching-contract-v1' },
      { randomSeed: 'benchmark-seed' },
    ]) {
      expect(airGappedRunnerInputV1Schema.safeParse({
        ...runnerInput,
        ...forbidden,
      }).success).toBe(false)
    }
    expect(airGappedRunnerResultV1Schema.safeParse({
      kind: 'COMPLETED',
      verdict: 'FAILED',
      coverageStatus: 'GAP',
      findings: [{
        findingId: 'finding-forged',
        adjudication: { status: 'MATCHED', defectId: 'defect-high' },
      }],
    }).success).toBe(false)
  })

  it('joins Ground Truth only after every Arm result is sealed', () => {
    const result = assembleAirGappedEvaluationV1(baseAssemblyRequest())

    expect(AIR_GAPPED_EVALUATION_ENGINE_ID).toBe('security/air-gapped-evaluation/v1')
    expect(airGappedEvaluationAssemblyV1Schema.parse(result)).toEqual(result)
    expect(result).toMatchObject({
      status: 'READY',
      runId: 'run-air-gap',
      groundTruthManifestId: 'ground-truth-manifest-v1',
      matchingContractId: 'matching-contract-v1',
      reasonCodes: [],
      affectedArmIds: ['baseline-arm', 'candidate-arm'],
    })
    expect(result.status).toBe('READY')
    if (result.status !== 'READY') return
    expect(result.arms.map(item => item.armId)).toEqual(['baseline-arm', 'candidate-arm'])
    expect(result.arms[0]?.metrics.metrics.criticalHighValidatedRecall).toMatchObject({
      status: 'MEASURED', value: 0,
    })
    expect(result.arms[1]?.metrics.metrics.criticalHighValidatedRecall).toMatchObject({
      status: 'MEASURED', value: 1,
    })
    expect(result.arms[1]?.metricsRequest.cases[0]).toMatchObject({
      caseId: 'case-hidden',
      groundTruthDefects: [{ defectId: 'defect-high' }],
      result: {
        findings: [{
          findingId: 'finding-candidate',
          adjudication: { status: 'MATCHED', defectId: 'defect-high' },
        }],
      },
    })
    expect(Object.isFrozen(result)).toBe(true)
    expect(Object.isFrozen(result.arms[0]?.metricsRequest)).toBe(true)
  })

  it('invalidates every Arm when any leakage or canary observation is detected', () => {
    const request = baseAssemblyRequest()
    request.airGapAudit.violations.push({
      type: 'CANARY_MARKER_OBSERVED',
      evidenceDigest: digest('f'),
      armId: 'candidate-arm',
      caseId: 'case-hidden',
    })
    const result = assembleAirGappedEvaluationV1(request)

    expect(result).toEqual({
      schemaVersion: 1,
      engineId: AIR_GAPPED_EVALUATION_ENGINE_ID,
      status: 'INVALIDATED',
      runId: 'run-air-gap',
      evaluatorId: 'independent-evaluator',
      evaluatorAuthorizationRecordId: 'authority/evaluator-1',
      groundTruthManifestId: 'ground-truth-manifest-v1',
      matchingContractId: 'matching-contract-v1',
      airGapAuditId: 'air-gap-audit-v1',
      reasonCodes: ['GROUND_TRUTH_LEAKAGE_DETECTED'],
      affectedArmIds: ['baseline-arm', 'candidate-arm'],
      arms: null,
    })
  })

  it('invalidates premature disclosure, post-hoc contracts, and incomplete proof', () => {
    const premature = baseAssemblyRequest()
    premature.groundTruthOpenedAtEpochMs = 300
    premature.matchingContract.registeredAtEpochMs = 100
    const prematureResult = assembleAirGappedEvaluationV1(premature)
    expect(prematureResult).toMatchObject({
      status: 'INVALIDATED',
      reasonCodes: [
        'GROUND_TRUTH_OPENED_BEFORE_ALL_RESULTS_SEALED',
        'POST_HOC_MATCHING_CONTRACT',
      ],
      arms: null,
    })

    const incompleteAudit = baseAssemblyRequest()
    incompleteAudit.airGapAudit.auditedSealedResultIds.pop()
    expect(assembleAirGappedEvaluationV1(incompleteAudit)).toMatchObject({
      status: 'INVALIDATED',
      reasonCodes: ['INCOMPLETE_AIR_GAP_AUDIT'],
    })

    const incompleteResults = baseAssemblyRequest()
    incompleteResults.sealedArmResults.pop()
    incompleteResults.adjudications = incompleteResults.adjudications.filter(
      item => item.armId !== 'candidate-arm',
    )
    incompleteResults.airGapAudit.auditedSealedResultIds = ['sealed-baseline']
    expect(assembleAirGappedEvaluationV1(incompleteResults)).toMatchObject({
      status: 'INVALIDATED',
      reasonCodes: ['INCOMPLETE_SEALED_ARM_RESULTS'],
      affectedArmIds: ['baseline-arm', 'candidate-arm'],
    })

    const undeclared = baseAssemblyRequest()
    undeclared.sealedArmResults.push({
      sealedResultId: 'sealed-undeclared-case',
      armId: 'baseline-arm',
      runnerInput: {
        ...undeclared.sealedArmResults[0]!.runnerInput,
        caseId: 'case-not-in-manifest',
        executionGrantId: 'grant-undeclared',
      },
      result: { kind: 'PRODUCT_FAILURE', failure: 'CRASH' },
      sealedAtEpochMs: 250,
      resultDigest: digest('9'),
    })
    undeclared.airGapAudit.auditedSealedResultIds.push('sealed-undeclared-case')
    expect(assembleAirGappedEvaluationV1(undeclared)).toMatchObject({
      status: 'INVALIDATED',
      reasonCodes: ['UNDECLARED_RUNNER_CASE'],
      arms: null,
    })
  })

  it('keeps missing adjudication inconclusive and rejects forged joins', () => {
    const missing = baseAssemblyRequest()
    missing.adjudications = missing.adjudications.filter(
      item => item.armId !== 'candidate-arm',
    )
    const missingResult = assembleAirGappedEvaluationV1(missing)
    expect(missingResult.status).toBe('READY')
    if (missingResult.status === 'READY') {
      expect(missingResult.arms[1]?.metrics).toMatchObject({
        conclusion: 'INCONCLUSIVE',
        reasonCodes: ['UNADJUDICATED_FINDINGS'],
      })
    }

    const forged = baseAssemblyRequest()
    const candidateAdjudication = forged.adjudications.find(
      item => item.armId === 'candidate-arm',
    )
    if (candidateAdjudication?.adjudication.status === 'MATCHED') {
      candidateAdjudication.adjudication.defectId = 'defect-not-in-manifest'
    }
    expect(() => assembleAirGappedEvaluationV1(forged)).toThrow(
      AirGappedEvaluationInputError,
    )
    expect(() => assembleAirGappedEvaluationV1({
      ...baseAssemblyRequest(),
      repositoryPath: 'C:\\private\\holdout',
    })).toThrow(AirGappedEvaluationInputError)
  })
})

describe('Utility Metrics Engine v1', () => {
  const utilityBudget = {
    limits: {
      wallTimeMs: 3_600_000,
      modelTokens: 10_000,
      modelCalls: 4,
      analyzerRuns: 2,
      agentRuns: 2,
      cpuTimeMs: 1_800_000,
      peakMemoryBytes: 512_000_000,
      diskBytes: 100_000_000,
      networkRequests: 4,
      outboundBytes: 1_000_000,
      humanAdjudicationMs: 600_000,
    },
    usage: {
      wallTimeMs: 1_800_000,
      modelTokens: 5_000,
      modelCalls: 2,
      analyzerRuns: 1,
      agentRuns: 1,
      cpuTimeMs: 900_000,
      peakMemoryBytes: 256_000_000,
      diskBytes: 50_000_000,
      networkRequests: 2,
      outboundBytes: 500_000,
      humanAdjudicationMs: 300_000,
    },
  }

  function utilityEffectiveness(matched: boolean) {
    return request([{
      caseId: 'case-utility',
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
        findings: matched ? [{
          findingId: 'finding-match',
          adjudication: { status: 'MATCHED', defectId: 'defect-high' },
        }] : [],
      },
    }])
  }

  it('calculates risk yield, human cost, remediation, rework, and approval Utility', () => {
    const evidence = {
      executionCostMicrounits: 500_000,
      firstValidatedFindingMs: 120_000,
      humanTriageMs: 300_000,
      remediation: {
        attempts: 2,
        verifiedSuccesses: 1,
        totalVerifiedSuccessDurationMs: 600_000,
      },
      unnecessaryReworkCount: 1,
      controlPlane: {
        applicability: 'APPLICABLE',
        decisions: 4,
        validApprovals: 3,
        unsafeApprovals: 1,
      },
    }
    const result = calculateUtilityMetricsV1({
      schemaVersion: 1,
      engineId: UTILITY_METRICS_ENGINE_ID,
      effectivenessRequest: utilityEffectiveness(true),
      budget: utilityBudget,
      evidence,
    })

    expect(UTILITY_METRICS_ENGINE_ID).toBe('security/utility-metrics/v1')
    expect(utilityMetricsV1Schema.parse(result)).toEqual(result)
    expect(result).toMatchObject({
      conclusion: 'MEASURED',
      reasonCodes: [],
      validatedFindings: 1,
      evidence,
      metrics: {
        validatedFindingYieldPerRuntimeHour: { value: 2 },
        validatedFindingYieldPerCostUnit: { value: 2 },
        timeToFirstValidatedFindingMs: { value: 120_000 },
        humanTriageMinutesPerValidatedFinding: { value: 5 },
        verifiedRemediationSuccessRate: { value: 0.5 },
        meanVerifiedRemediationDurationMs: { value: 600_000 },
        unnecessaryReworkCount: { value: 1 },
        validApprovalYield: { value: 0.75 },
        unsafeApprovalRate: { value: 0.25 },
      },
    })
    expect(result.metrics.validatedFindingYieldPerRuntimeHour).toMatchObject({
      status: 'MEASURED',
      unit: 'VALIDATED_FINDINGS_PER_RUNTIME_HOUR',
      preferredDirection: 'HIGHER',
      calculation: { numerator: 1, denominator: 1_800_000, normalizationFactor: 3_600_000 },
    })
    expect(Object.isFrozen(result)).toBe(true)
    expect(Object.isFrozen(result.evidence.remediation)).toBe(true)
    expect(Object.isFrozen(result.metrics)).toBe(true)
  })

  it('reports absent denominators as inconclusive and rejects contradictory evidence', () => {
    const noOutcomes = {
      executionCostMicrounits: 0,
      firstValidatedFindingMs: null,
      humanTriageMs: 0,
      remediation: {
        attempts: 0,
        verifiedSuccesses: 0,
        totalVerifiedSuccessDurationMs: 0,
      },
      unnecessaryReworkCount: 0,
      controlPlane: { applicability: 'NOT_APPLICABLE' },
    }
    const result = calculateUtilityMetricsV1({
      schemaVersion: 1,
      engineId: UTILITY_METRICS_ENGINE_ID,
      effectivenessRequest: utilityEffectiveness(false),
      budget: {
        ...utilityBudget,
        usage: { ...utilityBudget.usage, wallTimeMs: 0 },
      },
      evidence: noOutcomes,
    })
    expect(result.conclusion).toBe('INCONCLUSIVE')
    expect(result.reasonCodes).toEqual([
      'NO_RECORDED_RUNTIME',
      'NO_RECORDED_COST',
      'NO_VALIDATED_FINDINGS',
      'NO_REMEDIATION_ATTEMPTS',
      'NO_VERIFIED_REMEDIATIONS',
      'CONTROL_PLANE_NOT_APPLICABLE',
    ])
    expect(result.metrics.validApprovalYield).toMatchObject({
      status: 'INCONCLUSIVE',
      value: null,
      reasonCodes: ['CONTROL_PLANE_NOT_APPLICABLE'],
    })

    expect(() => calculateUtilityMetricsV1({
      schemaVersion: 1,
      engineId: UTILITY_METRICS_ENGINE_ID,
      effectivenessRequest: utilityEffectiveness(false),
      budget: utilityBudget,
      evidence: { ...noOutcomes, firstValidatedFindingMs: 1 },
    })).toThrow(UtilityMetricsInputError)
    expect(() => calculateUtilityMetricsV1({
      schemaVersion: 1,
      engineId: UTILITY_METRICS_ENGINE_ID,
      effectivenessRequest: utilityEffectiveness(false),
      budget: utilityBudget,
      evidence: {
        ...noOutcomes,
        remediation: { attempts: 1, verifiedSuccesses: 2, totalVerifiedSuccessDurationMs: 1 },
      },
    })).toThrow(UtilityMetricsInputError)
    expect(() => calculateUtilityMetricsV1({
      schemaVersion: 1,
      engineId: UTILITY_METRICS_ENGINE_ID,
      effectivenessRequest: utilityEffectiveness(false),
      budget: utilityBudget,
      evidence: noOutcomes,
      satisfactionSurveyScore: 5,
    })).toThrow(UtilityMetricsInputError)
  })
})

describe('Paired Arm Comparison Engine v1', () => {
  const resourceLimits = {
    wallTimeMs: 60_000,
    modelTokens: 10_000,
    modelCalls: 4,
    analyzerRuns: 2,
    agentRuns: 2,
    cpuTimeMs: 30_000,
    peakMemoryBytes: 512_000_000,
    diskBytes: 100_000_000,
    networkRequests: 4,
    outboundBytes: 1_000_000,
    humanAdjudicationMs: 60_000,
  }

  function budget(usageOverrides: Record<string, number> = {}, limitOverrides = {}) {
    return {
      limits: { ...resourceLimits, ...limitOverrides },
      usage: {
        wallTimeMs: 30_000,
        modelTokens: 5_000,
        modelCalls: 2,
        analyzerRuns: 1,
        agentRuns: 1,
        cpuTimeMs: 15_000,
        peakMemoryBytes: 256_000_000,
        diskBytes: 50_000_000,
        networkRequests: 2,
        outboundBytes: 500_000,
        humanAdjudicationMs: 30_000,
        ...usageOverrides,
      },
    }
  }

  function armMetrics(successful: boolean) {
    return request([{
      caseId: 'case-shared',
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
        verdict: successful ? 'FAILED' : 'SATISFIED',
        coverageStatus: successful ? 'GAP' : 'COMPLETE',
        findings: [{
          findingId: successful ? 'finding-match' : 'finding-false-positive',
          adjudication: successful
            ? { status: 'MATCHED', defectId: 'defect-high' }
            : { status: 'NOT_MATCHED' },
        }],
      },
    }])
  }

  const independentRepetitionIds = Array.from(
    { length: 32 },
    (_, index) => `rep-${String(index).padStart(2, '0')}`,
  )

  function repeatedArmMetrics(successful: boolean) {
    return request(
      independentRepetitionIds.map(repetitionId => ({
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
          verdict: successful ? 'FAILED' : 'SATISFIED',
          coverageStatus: successful ? 'GAP' : 'COMPLETE',
          findings: [{
            findingId: `finding-${repetitionId}`,
            adjudication: successful
              ? { status: 'MATCHED', defectId: 'defect-high' }
              : { status: 'NOT_MATCHED' },
          }],
        },
      })),
      repetitionStratumDefinitions,
      {
        method: 'HOEFFDING_TWO_SIDED_V1',
        repetitionIds: independentRepetitionIds,
        benchmarkCaseIds: ['case-shared'],
        confidenceLevel: 0.95,
        maximumConfidenceIntervalWidth: 1,
      },
    )
  }

  function nonInferiorityPlan(margin: number) {
    return {
      planId: 'release-ni-plan',
      registrationRecordId: 'qualification-registry/ni-plan',
      registeredAtEpochMs: 1_700_000_000_000,
      evidenceCollectionStartedAtEpochMs: 1_700_000_001_000,
      method: 'CONSERVATIVE_HOEFFDING_BOUNDS_V1',
      metricMargins: {
        criticalHighValidatedRecall: margin,
        severityWeightedValidatedRecall: margin,
        validatedPrecision: margin,
        unsafeSatisfactionRate: margin,
        coverageHonestyRate: margin,
      },
      stratumMargins: sufficientStratumDefinitions.map(definition => ({
        stratumId: definition.stratumId,
        validatedRecallMargin: margin,
      })),
    }
  }

  function productUtilityEvidence(improved: boolean) {
    return {
      executionCostMicrounits: improved ? 500_000 : 1_000_000,
      firstValidatedFindingMs: improved ? 10_000 : 20_000,
      humanTriageMs: improved ? 300_000 : 600_000,
      remediation: {
        attempts: 2,
        verifiedSuccesses: improved ? 2 : 1,
        totalVerifiedSuccessDurationMs: 600_000,
      },
      unnecessaryReworkCount: improved ? 1 : 2,
      controlPlane: {
        applicability: 'APPLICABLE',
        decisions: 4,
        validApprovals: improved ? 3 : 2,
        unsafeApprovals: improved ? 0 : 1,
      },
    }
  }

  function comparisonRequest(comparisonView: 'MATCHED_BUDGET' | 'NATIVE_PROFILE') {
    return {
      schemaVersion: 1,
      engineId: PAIRED_ARM_COMPARISON_ENGINE_ID,
      comparisonView,
      baseline: {
        armId: 'baseline-arm',
        metricsRequest: armMetrics(false),
        budget: budget(),
      },
      candidate: {
        armId: 'candidate-arm',
        metricsRequest: armMetrics(true),
        budget: budget({ modelTokens: 4_000 }),
      },
    }
  }

  it('compares paired Arms under exact matched budgets with direction-aware deltas', () => {
    const result = calculatePairedArmComparisonV1(comparisonRequest('MATCHED_BUDGET'))

    expect(PAIRED_ARM_COMPARISON_ENGINE_ID).toBe('security/paired-arm-comparison/v1')
    expect(pairedArmComparisonV1Schema.parse(result)).toEqual(result)
    expect(result.conclusion).toBe('MEASURED')
    expect(result.reasonCodes).toEqual([])
    expect(result.budgetComparison).toMatchObject({
      view: 'MATCHED_BUDGET',
      status: 'MATCHED',
      mismatchedDimensions: [],
    })
    expect(result.metrics).toEqual({
      criticalHighValidatedRecall: {
        status: 'MEASURED', baselineValue: 0, candidateValue: 1,
        rawDelta: 1, directionalDelta: 1, preferredDirection: 'HIGHER', outcome: 'IMPROVED',
      },
      severityWeightedValidatedRecall: {
        status: 'MEASURED', baselineValue: 0, candidateValue: 1,
        rawDelta: 1, directionalDelta: 1, preferredDirection: 'HIGHER', outcome: 'IMPROVED',
      },
      validatedPrecision: {
        status: 'MEASURED', baselineValue: 0, candidateValue: 1,
        rawDelta: 1, directionalDelta: 1, preferredDirection: 'HIGHER', outcome: 'IMPROVED',
      },
      unsafeSatisfactionRate: {
        status: 'MEASURED', baselineValue: 1, candidateValue: 0,
        rawDelta: -1, directionalDelta: 1, preferredDirection: 'LOWER', outcome: 'IMPROVED',
      },
      coverageHonestyRate: {
        status: 'MEASURED', baselineValue: 0, candidateValue: 1,
        rawDelta: 1, directionalDelta: 1, preferredDirection: 'HIGHER', outcome: 'IMPROVED',
      },
    })
    expect(Object.isFrozen(result)).toBe(true)
    expect(Object.isFrozen(result.budgetComparison.baseline)).toBe(true)
    const forged = structuredClone(result)
    forged.metrics.validatedPrecision.rawDelta = 0
    expect(pairedArmComparisonV1Schema.safeParse(forged).success).toBe(false)
  })

  it('applies pre-registered conservative bounds to every metric and mandatory Stratum', () => {
    const passingRequest = comparisonRequest('MATCHED_BUDGET')
    passingRequest.baseline.metricsRequest = repeatedArmMetrics(false)
    passingRequest.candidate.metricsRequest = repeatedArmMetrics(true)
    const passing = calculatePairedArmComparisonV1({
      ...passingRequest,
      nonInferiorityPlan: nonInferiorityPlan(0),
    })

    expect(passing.nonInferiority).toMatchObject({
      planId: 'release-ni-plan',
      registrationRecordId: 'qualification-registry/ni-plan',
      method: 'CONSERVATIVE_HOEFFDING_BOUNDS_V1',
      status: 'PASSED',
      reasonCodes: [],
    })
    expect(Object.values(passing.nonInferiority?.metrics ?? {}).every(
      metric => metric.status === 'PASSED'
        && metric.conservativeDirectionalDelta !== null
        && metric.conservativeDirectionalDelta > 0,
    )).toBe(true)
    expect(passing.nonInferiority?.strata).toHaveLength(4)
    expect(passing.nonInferiority?.strata.every(
      item => item.validatedRecall.status === 'PASSED',
    )).toBe(true)
    expect(Object.isFrozen(passing.nonInferiority)).toBe(true)

    const failingRequest = comparisonRequest('MATCHED_BUDGET')
    failingRequest.baseline.metricsRequest = repeatedArmMetrics(true)
    failingRequest.candidate.metricsRequest = repeatedArmMetrics(false)
    const failing = calculatePairedArmComparisonV1({
      ...failingRequest,
      nonInferiorityPlan: nonInferiorityPlan(0.05),
    })
    expect(failing.conclusion).toBe('MEASURED')
    expect(failing.nonInferiority).toMatchObject({
      status: 'FAILED',
      reasonCodes: ['REGRESSED_AGGREGATE_METRIC', 'REGRESSED_MANDATORY_STRATUM'],
    })
    expect(Object.values(failing.nonInferiority?.metrics ?? {}).every(
      metric => metric.status === 'FAILED',
    )).toBe(true)
  })

  it('compares complete paired Utility evidence with direction-aware outcomes', () => {
    const utilityRequest = comparisonRequest('MATCHED_BUDGET')
    utilityRequest.baseline.metricsRequest = armMetrics(true)
    utilityRequest.candidate.metricsRequest = armMetrics(true)
    utilityRequest.candidate.budget = budget({ wallTimeMs: 15_000, modelTokens: 4_000 })
    const result = calculatePairedArmComparisonV1({
      ...utilityRequest,
      baseline: {
        ...utilityRequest.baseline,
        utilityEvidence: productUtilityEvidence(false),
      },
      candidate: {
        ...utilityRequest.candidate,
        utilityEvidence: productUtilityEvidence(true),
      },
    })

    expect(result.conclusion).toBe('MEASURED')
    expect(result.utilityComparison).toMatchObject({
      conclusion: 'MEASURED',
      reasonCodes: [],
      baseline: { validatedFindings: 1 },
      candidate: { validatedFindings: 1 },
    })
    expect(Object.values(result.utilityComparison?.metrics ?? {}).every(metric => (
      metric.status === 'MEASURED'
      && metric.outcome === 'IMPROVED'
      && metric.directionalDelta > 0
    ))).toBe(true)
    expect(result.utilityComparison?.metrics.validatedFindingYieldPerRuntimeHour)
      .toMatchObject({
        baselineValue: 120,
        candidateValue: 240,
        rawDelta: 120,
        directionalDelta: 120,
        preferredDirection: 'HIGHER',
      })
    expect(result.utilityComparison?.metrics.unsafeApprovalRate).toMatchObject({
      baselineValue: 0.25,
      candidateValue: 0,
      rawDelta: -0.25,
      directionalDelta: 0.25,
      preferredDirection: 'LOWER',
    })
    expect(Object.isFrozen(result.utilityComparison)).toBe(true)

    expect(() => calculatePairedArmComparisonV1({
      ...comparisonRequest('MATCHED_BUDGET'),
      baseline: {
        ...comparisonRequest('MATCHED_BUDGET').baseline,
        utilityEvidence: productUtilityEvidence(false),
      },
    })).toThrow(PairedArmComparisonInputError)
  })

  it('refuses post-hoc, partial, native-profile, and uncertainty-free non-inferiority claims', () => {
    const noUncertainty = calculatePairedArmComparisonV1({
      ...comparisonRequest('MATCHED_BUDGET'),
      nonInferiorityPlan: nonInferiorityPlan(0.1),
    })
    expect(noUncertainty.nonInferiority).toMatchObject({
      status: 'INCONCLUSIVE',
      reasonCodes: ['INCONCLUSIVE_ARM_UNCERTAINTY'],
    })

    const postHocPlan = nonInferiorityPlan(0.1)
    postHocPlan.registeredAtEpochMs = postHocPlan.evidenceCollectionStartedAtEpochMs
    expect(() => calculatePairedArmComparisonV1({
      ...comparisonRequest('MATCHED_BUDGET'),
      nonInferiorityPlan: postHocPlan,
    })).toThrow(PairedArmComparisonInputError)

    const partialPlan = nonInferiorityPlan(0.1)
    partialPlan.stratumMargins.pop()
    expect(() => calculatePairedArmComparisonV1({
      ...comparisonRequest('MATCHED_BUDGET'),
      nonInferiorityPlan: partialPlan,
    })).toThrow(PairedArmComparisonInputError)
    expect(() => calculatePairedArmComparisonV1({
      ...comparisonRequest('NATIVE_PROFILE'),
      nonInferiorityPlan: nonInferiorityPlan(0.1),
    })).toThrow(PairedArmComparisonInputError)
  })

  it('distinguishes unmatched matched-budget evidence from an explicit native-profile view', () => {
    const unmatchedRequest = comparisonRequest('MATCHED_BUDGET')
    unmatchedRequest.candidate.budget.limits.modelTokens = 20_000
    const unmatched = calculatePairedArmComparisonV1(unmatchedRequest)
    expect(unmatched.conclusion).toBe('INCONCLUSIVE')
    expect(unmatched.reasonCodes).toEqual(['UNMATCHED_BUDGETS'])
    expect(unmatched.budgetComparison).toMatchObject({
      status: 'INCONCLUSIVE',
      mismatchedDimensions: ['modelTokens'],
    })

    const nativeRequest = comparisonRequest('NATIVE_PROFILE')
    nativeRequest.candidate.budget.limits.modelTokens = 20_000
    const native = calculatePairedArmComparisonV1(nativeRequest)
    expect(native.conclusion).toBe('MEASURED')
    expect(native.reasonCodes).toEqual([])
    expect(native.budgetComparison).toMatchObject({
      status: 'NATIVE_PROFILE',
      mismatchedDimensions: ['modelTokens'],
    })
  })

  it('fails closed for incompatible pairing and invalid resource evidence', () => {
    const incompatibleRequest = comparisonRequest('MATCHED_BUDGET')
    const incompatibleCase = incompatibleRequest.candidate.metricsRequest.cases[0] as {
      supportedEcosystem: string
    }
    incompatibleCase.supportedEcosystem = 'python'
    const incompatible = calculatePairedArmComparisonV1(incompatibleRequest)
    expect(incompatible.conclusion).toBe('INCONCLUSIVE')
    expect(incompatible.reasonCodes).toContain('INCOMPATIBLE_EVALUATION_DESIGN')

    const invalidUsage = comparisonRequest('MATCHED_BUDGET')
    invalidUsage.candidate.budget.usage.modelTokens = 20_000
    expect(() => calculatePairedArmComparisonV1(invalidUsage)).toThrow(
      PairedArmComparisonInputError,
    )
    expect(() => calculatePairedArmComparisonV1({
      ...comparisonRequest('MATCHED_BUDGET'),
      principalId: 'self-declared-evaluator',
    })).toThrow(PairedArmComparisonInputError)
  })

  describe('Release Constitution Engine v1', () => {
    function releaseDigest(character: string) {
      return {
        schemaVersion: 1 as const,
        algorithm: 'sha256' as const,
        mediaType: 'application/json',
        byteLength: 128,
        canonicalization: 'dsh-canonical-json-v1' as const,
        value: character.repeat(64),
      }
    }

    function releasePairedComparison() {
      const paired = comparisonRequest('MATCHED_BUDGET')
      paired.baseline.metricsRequest = repeatedArmMetrics(true)
      paired.candidate.metricsRequest = repeatedArmMetrics(true)
      paired.candidate.budget = budget({ wallTimeMs: 15_000, modelTokens: 4_000 })
      return calculatePairedArmComparisonV1({
        ...paired,
        baseline: {
          ...paired.baseline,
          utilityEvidence: productUtilityEvidence(false),
        },
        candidate: {
          ...paired.candidate,
          utilityEvidence: productUtilityEvidence(true),
        },
        nonInferiorityPlan: nonInferiorityPlan(1),
      })
    }

    function releaseDeterministicHistoryRequest(
      artifactDigest: ReleaseConstitutionEvaluationRequestV1['candidate']['candidateArtifactDigest'],
      failedProofKind?: typeof DETERMINISTIC_RELEASE_PROOF_KINDS[number],
    ): DeterministicFailureHistoryRequestV1 {
      const runs = DETERMINISTIC_RELEASE_PROOF_KINDS.flatMap((proofKind, index) => {
        const qualification = {
          kind: 'QUALIFICATION' as const,
          runId: `qualification/${proofKind.toLowerCase().replaceAll('_', '-')}`,
          proofKind,
          candidateArtifactDigest: artifactDigest,
          status: proofKind === failedProofKind ? 'FAILED' as const : 'PASSED' as const,
          evidenceId: `evidence/${proofKind.toLowerCase().replaceAll('_', '-')}`,
          evidenceDigest: releaseDigest(String(index % 10)),
          completedAtEpochMs: 240,
        }
        return proofKind === failedProofKind
          ? [qualification, {
              kind: 'DIAGNOSTIC_RERUN' as const,
              runId: `diagnostic/${proofKind.toLowerCase().replaceAll('_', '-')}/passed`,
              proofKind,
              originalFailureRunId: qualification.runId,
              candidateArtifactDigest: artifactDigest,
              status: 'PASSED' as const,
              evidenceId: `evidence/${proofKind.toLowerCase().replaceAll('_', '-')}/diagnostic`,
              evidenceDigest: releaseDigest(String((index + 1) % 10)),
              completedAtEpochMs: 250,
            }]
          : [qualification]
      })
      return {
        schemaVersion: 1,
        engineId: DETERMINISTIC_FAILURE_HISTORY_ENGINE_ID,
        evaluatedAtEpochMs: 260,
        candidateArtifactDigest: artifactDigest,
        requiredProofKinds: [...DETERMINISTIC_RELEASE_PROOF_KINDS],
        runs,
        resolutions: [],
      }
    }

    function baseReleaseRequest(): ReleaseConstitutionEvaluationRequestV1 {
      const artifactDigest = releaseDigest('a')
      return {
        schemaVersion: 1,
        engineId: RELEASE_CONSTITUTION_ENGINE_ID,
        constitution: {
          constitutionId: 'release-constitution-v1',
          constitutionDigest: releaseDigest('b'),
          registrationRecordId: 'qualification/release-constitution-v1',
          registeredAtEpochMs: 100,
          calibrationEvidence: [{
            evidenceId: 'qualification/calibration-v1',
            evidenceDigest: releaseDigest('c'),
            corpusLane: 'QUALIFICATION',
            completedAtEpochMs: 80,
          }],
          requiredNonInferiorityPlanId: 'release-ni-plan',
          effectivenessThresholds: {
            criticalHighValidatedRecallMinimum: 0.7,
            severityWeightedValidatedRecallMinimum: 0.7,
            validatedPrecisionMinimum: 0.7,
            unsafeSatisfactionRateMaximum: 0.3,
            coverageHonestyRateMinimum: 0.7,
          },
          utilityThresholds: {
            validatedFindingYieldPerRuntimeHourMinimum: 7_000,
            validatedFindingYieldPerCostUnitMinimum: 60,
            timeToFirstValidatedFindingMsMaximum: 10_000,
            humanTriageMinutesPerValidatedFindingMaximum: 0.2,
            verifiedRemediationSuccessRateMinimum: 1,
            meanVerifiedRemediationDurationMsMaximum: 300_000,
            unnecessaryReworkCountMaximum: 1,
            validApprovalYieldMinimum: 0.75,
            unsafeApprovalRateMaximum: 0,
          },
        },
        candidate: {
          releaseCandidateId: 'security-assurance-0.1.0-rc.1',
          candidateArmId: 'candidate-arm',
          priorStableArmId: 'baseline-arm',
          evidenceSetId: 'release-evidence-set-v1',
          evidenceSetDigest: releaseDigest('d'),
          holdoutStartedAtEpochMs: 200,
          holdoutCompletedAtEpochMs: 300,
          candidateArtifactDigest: artifactDigest,
          qualifiedArtifactDigest: artifactDigest,
          proposedPromotionArtifactDigest: artifactDigest,
          hardSafetyEvidence: {
            evidenceId: 'hard-safety-evidence-v1',
            evidenceDigest: releaseDigest('e'),
            evidenceStatus: 'COMPLETE',
            capabilityConformance: 'PASSED',
            unauthorizedCodeExecutionCount: 0,
            unauthorizedNetworkEgressCount: 0,
            unauthorizedTrackingMutationCount: 0,
            unauthorizedRiskAcceptanceCount: 0,
            forgedCanonicalEvidenceAcceptedCount: 0,
            corruptCanonicalEvidenceAcceptedCount: 0,
            hiddenCriticalSatisfiedCount: 0,
            groundTruthLeakageCount: 0,
            selfSecurityCriticalCount: 0,
            selfSecurityHighCount: 0,
            selfSecurityBlockingMediumCount: 0,
            deterministicFailureHistory: releaseDeterministicHistoryRequest(artifactDigest),
          },
          platformProofs: [
            {
              platform: 'WINDOWS',
              status: 'PASSED',
              evidenceId: 'windows-packed-proof',
              evidenceDigest: releaseDigest('1'),
              packedArtifactDigest: artifactDigest,
            },
            {
              platform: 'LINUX',
              status: 'PASSED',
              evidenceId: 'linux-packed-proof',
              evidenceDigest: releaseDigest('2'),
              packedArtifactDigest: artifactDigest,
            },
            {
              platform: 'MACOS',
              status: 'PASSED',
              evidenceId: 'macos-packed-proof',
              evidenceDigest: releaseDigest('3'),
              packedArtifactDigest: artifactDigest,
            },
          ],
          pairedComparison: releasePairedComparison(),
        },
      }
    }

    it('derives deterministic hard safety from history instead of a caller count', () => {
      const request = baseReleaseRequest() as unknown as {
        candidate: {
          candidateArtifactDigest: ReturnType<typeof releaseDigest>
          hardSafetyEvidence: Record<string, unknown>
        }
      }
      const historyRequest = releaseDeterministicHistoryRequest(
        request.candidate.candidateArtifactDigest,
        'RESOURCE',
      )
      const history = evaluateDeterministicFailureHistoryV1(historyRequest)
      delete request.candidate.hardSafetyEvidence.unresolvedDeterministicFailureCount
      request.candidate.hardSafetyEvidence.deterministicFailureHistory = historyRequest

      const result = evaluateReleaseConstitutionV1(request)
      const deterministicCheck = result.checks.find(
        item => item.checkId === 'NO_UNRESOLVED_DETERMINISTIC_FAILURES',
      )

      expect(history.decision).toBe('BLOCKED')
      expect(history.unresolvedFailureCount).toBe(1)
      expect(deterministicCheck?.status).toBe('FAILED')
      expect(result.decision).toBe('BLOCKED')
    })

    it('rejects a caller-authored deterministic verification result at the release seam', () => {
      const request = baseReleaseRequest()
      const computed = evaluateDeterministicFailureHistoryV1(releaseDeterministicHistoryRequest(
        request.candidate.candidateArtifactDigest,
        'RESOURCE',
      ))
      const forged = structuredClone(computed)
      forged.unresolvedFailureCount = 0
      forged.decision = 'VERIFIED'
      const untrustedRequest = request as unknown as {
        candidate: { hardSafetyEvidence: Record<string, unknown> }
      }
      untrustedRequest.candidate.hardSafetyEvidence.deterministicFailureHistory = forged

      expect(() => evaluateReleaseConstitutionV1(request)).toThrow(
        ReleaseConstitutionInputError,
      )
    })

    it('keeps missing deterministic qualification evidence inconclusive at release', () => {
      const request = baseReleaseRequest()
      request.candidate.hardSafetyEvidence.deterministicFailureHistory.runs = request.candidate
        .hardSafetyEvidence.deterministicFailureHistory.runs.filter(
          run => run.proofKind !== 'RESOURCE',
        )

      const history = evaluateDeterministicFailureHistoryV1(
        request.candidate.hardSafetyEvidence.deterministicFailureHistory,
      )
      const result = evaluateReleaseConstitutionV1(request)
      const deterministicCheck = result.checks.find(
        item => item.checkId === 'NO_UNRESOLVED_DETERMINISTIC_FAILURES',
      )

      expect(history.decision).toBe('INCONCLUSIVE')
      expect(history.unresolvedFailureCount).toBe(0)
      expect(deterministicCheck?.status).toBe('INCONCLUSIVE')
      expect(result.decision).toBe('INCONCLUSIVE')
    })

    it('keeps a known deterministic failure blocking when aggregate evidence is incomplete', () => {
      const request = baseReleaseRequest()
      request.candidate.hardSafetyEvidence.evidenceStatus = 'INCOMPLETE'
      request.candidate.hardSafetyEvidence.deterministicFailureHistory
        = releaseDeterministicHistoryRequest(
          request.candidate.candidateArtifactDigest,
          'RESOURCE',
        )

      const result = evaluateReleaseConstitutionV1(request)
      const deterministicCheck = result.checks.find(
        item => item.checkId === 'NO_UNRESOLVED_DETERMINISTIC_FAILURES',
      )

      expect(deterministicCheck?.status).toBe('FAILED')
      expect(result.decision).toBe('BLOCKED')
    })

    it('promotes only when every fixed Release Constitution check passes', () => {
      const result = evaluateReleaseConstitutionV1(baseReleaseRequest())

      expect(RELEASE_CONSTITUTION_ENGINE_ID).toBe('security/release-constitution/v1')
      expect(releaseConstitutionDecisionV1Schema.parse(result)).toEqual(result)
      expect(result).toMatchObject({
        decision: 'PROMOTE',
        reasonCodes: [],
        constitutionId: 'release-constitution-v1',
        releaseCandidateId: 'security-assurance-0.1.0-rc.1',
      })
      expect(result.checks).toHaveLength(RELEASE_CONSTITUTION_CHECK_IDS.length)
      expect(result.checks.every(item => item.status === 'PASSED')).toBe(true)
      expect(Object.isFrozen(result)).toBe(true)
      expect(Object.isFrozen(result.checks)).toBe(true)
    })

    it('blocks on any known Hard Safety Floor failure', () => {
      const request = baseReleaseRequest()
      request.candidate.hardSafetyEvidence.evidenceStatus = 'INCOMPLETE'
      request.candidate.hardSafetyEvidence.unauthorizedNetworkEgressCount = 1
      const result = evaluateReleaseConstitutionV1(request)

      expect(result.decision).toBe('BLOCKED')
      expect(result.reasonCodes).toEqual([
        'HARD_SAFETY_FLOOR_FAILED',
        'INCOMPLETE_RELEASE_EVIDENCE',
      ])
      expect(result.checks.find(
        item => item.checkId === 'NO_UNAUTHORIZED_NETWORK_EGRESS',
      )?.status).toBe('FAILED')
    })

    it('uses conservative Effectiveness bounds and observed Utility thresholds', () => {
      const request = baseReleaseRequest()
      request.constitution.effectivenessThresholds.criticalHighValidatedRecallMinimum = 0.99
      request.constitution.utilityThresholds.validApprovalYieldMinimum = 0.9
      const result = evaluateReleaseConstitutionV1(request)

      expect(result.decision).toBe('BLOCKED')
      expect(result.reasonCodes).toEqual([
        'EFFECTIVENESS_THRESHOLD_FAILED',
        'UTILITY_THRESHOLD_FAILED',
      ])
      expect(result.checks).toEqual(expect.arrayContaining([
        {
          checkId: 'CRITICAL_HIGH_VALIDATED_RECALL_THRESHOLD',
          status: 'FAILED',
        },
        { checkId: 'VALID_APPROVAL_YIELD_THRESHOLD', status: 'FAILED' },
      ]))
    })

    it('keeps missing proof inconclusive when no known failure exists', () => {
      const request = baseReleaseRequest()
      request.candidate.hardSafetyEvidence.evidenceStatus = 'INCOMPLETE'
      request.candidate.hardSafetyEvidence.capabilityConformance = 'INCOMPLETE'
      request.candidate.platformProofs = request.candidate.platformProofs.filter(
        item => item.platform !== 'MACOS',
      )
      const result = evaluateReleaseConstitutionV1(request)

      expect(result.decision).toBe('INCONCLUSIVE')
      expect(result.reasonCodes).toEqual(['INCOMPLETE_RELEASE_EVIDENCE'])
      expect(result.checks.some(item => item.status === 'FAILED')).toBe(false)
      expect(result.checks.find(
        item => item.checkId === 'MACOS_PACKED_CONFORMANCE',
      )?.status).toBe('INCONCLUSIVE')
    })

    it('blocks post-hoc thresholds, artifact drift, platform failure, and wrong NI plan', () => {
      const request = baseReleaseRequest()
      request.constitution.registeredAtEpochMs = request.candidate.holdoutStartedAtEpochMs
      request.candidate.proposedPromotionArtifactDigest = releaseDigest('f')
      const linuxProof = request.candidate.platformProofs.find(
        item => item.platform === 'LINUX',
      )
      if (linuxProof !== undefined) linuxProof.status = 'FAILED'
      request.constitution.requiredNonInferiorityPlanId = 'different-ni-plan'
      const result = evaluateReleaseConstitutionV1(request)

      expect(result.decision).toBe('BLOCKED')
      expect(result.reasonCodes).toEqual([
        'CONSTITUTION_NOT_PRE_REGISTERED',
        'ARTIFACT_IDENTITY_FAILED',
        'PLATFORM_PROOF_FAILED',
        'NON_INFERIORITY_FAILED',
      ])
    })

    it('rejects structurally contradictory or caller-extended release evidence', () => {
      const duplicatePlatform = baseReleaseRequest()
      duplicatePlatform.candidate.platformProofs[1] = {
        ...duplicatePlatform.candidate.platformProofs[0]!,
      }
      expect(() => evaluateReleaseConstitutionV1(duplicatePlatform)).toThrow(
        ReleaseConstitutionInputError,
      )
      expect(() => evaluateReleaseConstitutionV1({
        ...baseReleaseRequest(),
        manualOverride: 'PROMOTE',
      })).toThrow(ReleaseConstitutionInputError)
    })

    function baseScorecardRequest(): PublicSecurityScorecardRequestV1 {
      return {
        schemaVersion: 1,
        engineId: PUBLIC_SECURITY_SCORECARD_ENGINE_ID,
        publication: {
          publishedAtEpochMs: 400,
          releaseVersion: '0.1.0-rc.1',
          harnessTargetVersion: '0.1.1-rc.2',
          supportMatrixVersion: 'support-matrix-v1',
          policyVersion: 'security-policy-v1',
          benchmarkVersion: 'benchmark-v1',
          corpusVersion: 'holdout-corpus-v1',
          supportedEcosystems: ['typescript', 'node'],
          assessmentModes: ['TARGETED', 'CHANGE', 'REPOSITORY'],
          profiles: ['standard', 'deep'],
          model: {
            applicability: 'APPLICABLE',
            providerId: 'reference-provider',
            providerVersion: '2026.08',
            modelId: 'reference-model',
            modelVersion: 'v1',
          },
        },
        releaseEvaluation: baseReleaseRequest(),
      }
    }

    it('renders a complete deterministic public Scorecard through one interface', () => {
      const result = renderPublicSecurityScorecardV1(baseScorecardRequest())
      const reordered = baseScorecardRequest()
      reordered.publication.supportedEcosystems.reverse()
      reordered.publication.assessmentModes.reverse()
      reordered.publication.profiles.reverse()

      expect(PUBLIC_SECURITY_SCORECARD_ENGINE_ID).toBe('security/public-scorecard/v1')
      expect(publicSecurityScorecardV1Schema.parse(result)).toEqual(result)
      expect(renderPublicSecurityScorecardV1(reordered)).toEqual(result)
      expect(result).toMatchObject({
        release: { releaseVersion: '0.1.0-rc.1', decision: 'PROMOTE' },
        scope: {
          supportedEcosystems: ['node', 'typescript'],
          assessmentModes: ['CHANGE', 'REPOSITORY', 'TARGETED'],
          profiles: ['deep', 'standard'],
        },
        method: {
          uncertaintyMethod: 'HOEFFDING_TWO_SIDED_V1',
          nonInferiorityMethod: 'CONSERVATIVE_HOEFFDING_BOUNDS_V1',
        },
        budget: { status: 'MATCHED' },
        comparison: { conclusion: 'MEASURED' },
        nonInferiority: { status: 'PASSED' },
      })
      expect(result.effectiveness.repetitionAnalysis?.status).toBe('SUFFICIENT')
      expect(result.utility?.conclusion).toBe('MEASURED')
      expect(result.failures).toMatchObject({
        productFailureCount: 0,
        releaseReasonCodes: [],
        failedReleaseChecks: [],
        inconclusiveReleaseChecks: [],
      })
      expect(Object.isFrozen(result)).toBe(true)
      expect(Object.isFrozen(result.scope)).toBe(true)
    })

    it('removes Holdout, Evidence, Arm, and Stratum identities from public output', () => {
      const result = renderPublicSecurityScorecardV1(baseScorecardRequest())
      const serialized = JSON.stringify(result)

      for (const privateValue of [
        'release-constitution-v1',
        'qualification/release-constitution-v1',
        'qualification/calibration-v1',
        'release-evidence-set-v1',
        'hard-safety-evidence-v1',
        'windows-packed-proof',
        'candidate-arm',
        'baseline-arm',
        'release-ni-plan',
        'severity-high',
      ]) {
        expect(serialized).not.toContain(privateValue)
      }
      expect(serialized).not.toContain('"evidenceId"')
      expect(serialized).not.toContain('"armId"')
      expect(serialized).not.toContain('"stratumId"')
      expect(serialized).not.toContain('"groundTruthManifest"')
      expect(result.limitations).toEqual(expect.arrayContaining([
        'ACTIVE_HOLDOUT_DETAILS_WITHHELD',
        'SENSITIVE_EVIDENCE_WITHHELD',
        'PRIVATE_VULNERABILITIES_WITHHELD',
      ]))
    })

    it('publishes known release failures without publishing their private Evidence', () => {
      const request = baseScorecardRequest()
      request.releaseEvaluation.candidate.hardSafetyEvidence.unauthorizedNetworkEgressCount = 1
      const result = renderPublicSecurityScorecardV1(request)
      const serialized = JSON.stringify(result)

      expect(result.release.decision).toBe('BLOCKED')
      expect(result.failures.releaseReasonCodes).toEqual(['HARD_SAFETY_FLOOR_FAILED'])
      expect(result.failures.failedReleaseChecks).toContain('NO_UNAUTHORIZED_NETWORK_EGRESS')
      expect(result.limitations).toContain('NOT_A_STABLE_RELEASE_CLAIM')
      expect(serialized).not.toContain('hard-safety-evidence-v1')
    })

    it('discloses missing proof as limitations and inconclusive checks', () => {
      const request = baseScorecardRequest()
      request.releaseEvaluation.candidate.hardSafetyEvidence.evidenceStatus = 'INCOMPLETE'
      request.releaseEvaluation.candidate.hardSafetyEvidence.capabilityConformance = 'INCOMPLETE'
      request.releaseEvaluation.candidate.platformProofs = request.releaseEvaluation.candidate
        .platformProofs.filter(item => item.platform !== 'MACOS')
      const result = renderPublicSecurityScorecardV1(request)

      expect(result.release.decision).toBe('INCONCLUSIVE')
      expect(result.failures.inconclusiveReleaseChecks).toContain('MACOS_PACKED_CONFORMANCE')
      expect(result.failures.releaseReasonCodes).toEqual(['INCOMPLETE_RELEASE_EVIDENCE'])
      expect(result.limitations).toContain('NOT_A_STABLE_RELEASE_CLAIM')
    })

    it('rejects post-dated, path-like, extended, or contradictory publication input', () => {
      const premature = baseScorecardRequest()
      premature.publication.publishedAtEpochMs = 299
      expect(() => renderPublicSecurityScorecardV1(premature)).toThrow(
        PublicSecurityScorecardInputError,
      )

      const pathLike = baseScorecardRequest()
      pathLike.publication.corpusVersion = '../private/holdout'
      expect(() => renderPublicSecurityScorecardV1(pathLike)).toThrow(
        PublicSecurityScorecardInputError,
      )

      expect(() => renderPublicSecurityScorecardV1({
        ...baseScorecardRequest(),
        holdoutAnswers: ['private-answer'],
      })).toThrow(PublicSecurityScorecardInputError)

      const result = renderPublicSecurityScorecardV1(baseScorecardRequest())
      expect(() => publicSecurityScorecardV1Schema.parse({
        ...result,
        activeHoldoutAnswers: ['private-answer'],
      })).toThrow()
      expect(() => publicSecurityScorecardV1Schema.parse({
        ...result,
        limitations: [...result.limitations, 'NOT_A_STABLE_RELEASE_CLAIM'],
      })).toThrow()
    })

    function baseManifestRequest(): ReleaseEvidenceManifestRequestV1 {
      const releaseEvaluation = baseReleaseRequest()
      const scorecardRequest = baseScorecardRequest()
      scorecardRequest.releaseEvaluation = releaseEvaluation
      const publicScorecard = renderPublicSecurityScorecardV1(scorecardRequest)
      const artifactDigest = releaseEvaluation.candidate.candidateArtifactDigest
      return {
        schemaVersion: 1,
        engineId: RELEASE_EVIDENCE_MANIFEST_ENGINE_ID,
        manifestId: 'release-evidence-manifest-v1',
        assembledAtEpochMs: 500,
        sourceRevision: '1'.repeat(40),
        dependencyLocks: [{
          lockKind: 'PNPM_LOCK',
          lockDigest: releaseDigest('7'),
        }],
        releaseEvaluation,
        publicScorecard,
        proofs: RELEASE_EVIDENCE_PROOF_KINDS.map((proofKind, index) => {
          let evidenceId = `proof/${proofKind.toLowerCase().replaceAll('_', '-')}`
          let evidenceDigest: ReleaseEvidenceManifestRequestV1['proofs'][number]['evidenceDigest']
            = releaseDigest(String(index % 10))
          if ([
            'CAPABILITY_CONFORMANCE',
            'SELF_SECURITY',
            'GROUND_TRUTH_AIR_GAP',
            'DETERMINISTIC_FAILURES',
            'RISK_ACCEPTANCES',
          ].includes(proofKind)) {
            evidenceId = releaseEvaluation.candidate.hardSafetyEvidence.evidenceId
            evidenceDigest = releaseEvaluation.candidate.hardSafetyEvidence.evidenceDigest
          } else if (proofKind.endsWith('_PLATFORM')) {
            const platform = proofKind.replace('_PLATFORM', '')
            const platformProof = releaseEvaluation.candidate.platformProofs.find(
              item => item.platform === platform,
            )
            if (platformProof !== undefined) {
              evidenceId = platformProof.evidenceId
              evidenceDigest = platformProof.evidenceDigest
            }
          } else if (proofKind === 'EVALUATION_RUN_BUNDLE') {
            evidenceId = releaseEvaluation.candidate.evidenceSetId
            evidenceDigest = releaseEvaluation.candidate.evidenceSetDigest
          } else if (proofKind === 'RELEASE_CONSTITUTION') {
            evidenceId = releaseEvaluation.constitution.constitutionId
            evidenceDigest = releaseEvaluation.constitution.constitutionDigest
          }
          return {
            proofKind,
            evidenceId,
            evidenceDigest,
            reportedStatus: 'PASSED',
            candidateArtifactDigest: artifactDigest,
            completedAtEpochMs: 350,
          }
        }),
        evaluationRunBundles: [
          {
            role: 'PRIOR_STABLE',
            bundleId: 'evaluation-bundle/prior-stable',
            bundleDigest: releaseDigest('8'),
            artifactDigest: releaseDigest('f'),
          },
          {
            role: 'CANDIDATE',
            bundleId: 'evaluation-bundle/candidate',
            bundleDigest: releaseDigest('9'),
            artifactDigest,
          },
        ],
        riskAcceptances: [{
          riskAcceptanceId: 'risk-acceptance/medium-1',
          decisionDigest: releaseDigest('d'),
          status: 'ACTIVE',
          expiresAtEpochMs: 1_000,
          compensationEvidenceDigest: releaseDigest('e'),
          adrId: 'adr/medium-risk-acceptance-1',
        }],
      }
    }

    it('assembles one fixed digest-bound Release Evidence Manifest', () => {
      const result = assembleReleaseEvidenceManifestV1(baseManifestRequest())

      expect(RELEASE_EVIDENCE_MANIFEST_ENGINE_ID).toBe(
        'security/release-evidence-manifest/v1',
      )
      expect(releaseEvidenceManifestV1Schema.parse(result)).toEqual(result)
      expect(result).toMatchObject({
        manifestId: 'release-evidence-manifest-v1',
        releaseCandidateId: 'security-assurance-0.1.0-rc.1',
        harnessTargetVersion: '0.1.1-rc.2',
        dependencyLocks: [{ lockKind: 'PNPM_LOCK' }],
        verification: {
          decision: 'VERIFIED',
          reasonCodes: [],
          failedProofKinds: [],
          inconclusiveProofKinds: [],
          mismatchedProofKinds: [],
        },
      })
      expect(result.proofs.map(item => item.proofKind)).toEqual(
        RELEASE_EVIDENCE_PROOF_KINDS,
      )
      expect(result.proofs.every(item => item.verificationStatus === 'PASSED')).toBe(true)
      expect(result.knownLimitations).toEqual(result.publicScorecard.limitationCodes)
      expect(Object.isFrozen(result)).toBe(true)
      expect(Object.isFrozen(result.proofs)).toBe(true)
    })

    it('makes every missing required proof explicitly inconclusive', () => {
      const request = baseManifestRequest()
      request.proofs = request.proofs.filter(item => item.proofKind !== 'WORKBENCH')
      const result = assembleReleaseEvidenceManifestV1(request)
      const workbench = result.proofs.find(item => item.proofKind === 'WORKBENCH')

      expect(result.verification.decision).toBe('INCONCLUSIVE')
      expect(result.verification.reasonCodes).toEqual(['PROOF_MISSING'])
      expect(result.verification.inconclusiveProofKinds).toEqual(['WORKBENCH'])
      expect(workbench).toMatchObject({
        reportedStatus: 'MISSING',
        evidenceId: null,
        evidenceDigest: null,
        artifactBinding: 'MISSING',
        constitutionAlignment: 'MISSING',
        sourceEvidenceAlignment: 'MISSING',
        verificationStatus: 'INCONCLUSIVE',
      })
    })

    it('blocks a reported failure even when other proof passes', () => {
      const request = baseManifestRequest()
      const raceProof = request.proofs.find(item => item.proofKind === 'RACE')
      if (raceProof !== undefined) raceProof.reportedStatus = 'FAILED'
      const result = assembleReleaseEvidenceManifestV1(request)

      expect(result.verification.decision).toBe('BLOCKED')
      expect(result.verification.reasonCodes).toEqual(['PROOF_FAILED'])
      expect(result.verification.failedProofKinds).toEqual(['RACE'])
    })

    it('blocks proof produced for a different candidate artifact', () => {
      const request = baseManifestRequest()
      const mutationProof = request.proofs.find(item => item.proofKind === 'MUTATION')
      if (mutationProof !== undefined) mutationProof.candidateArtifactDigest = releaseDigest('f')
      const result = assembleReleaseEvidenceManifestV1(request)

      expect(result.verification.decision).toBe('BLOCKED')
      expect(result.verification.reasonCodes).toEqual([
        'PROOF_FAILED',
        'PROOF_ARTIFACT_MISMATCH',
      ])
      expect(result.verification.mismatchedProofKinds).toEqual(['MUTATION'])
    })

    it('blocks proof that substitutes a different source Evidence digest', () => {
      const request = baseManifestRequest()
      const conformanceProof = request.proofs.find(
        item => item.proofKind === 'CAPABILITY_CONFORMANCE',
      )
      if (conformanceProof !== undefined) conformanceProof.evidenceDigest = releaseDigest('f')
      const result = assembleReleaseEvidenceManifestV1(request)

      expect(result.verification.decision).toBe('BLOCKED')
      expect(result.verification.reasonCodes).toEqual([
        'PROOF_FAILED',
        'PROOF_EVIDENCE_MISMATCH',
      ])
      expect(result.verification.mismatchedProofKinds).toEqual(['CAPABILITY_CONFORMANCE'])
    })

    it('blocks stale Scorecard and proof claims that contradict the Constitution', () => {
      const request = baseManifestRequest()
      request.releaseEvaluation.candidate.hardSafetyEvidence.unauthorizedNetworkEgressCount = 1
      const result = assembleReleaseEvidenceManifestV1(request)

      expect(result.releaseConstitution.decision).toBe('BLOCKED')
      expect(result.verification.decision).toBe('BLOCKED')
      expect(result.verification.reasonCodes).toEqual([
        'RELEASE_CONSTITUTION_BLOCKED',
        'PROOF_FAILED',
        'PROOF_CONSTITUTION_MISMATCH',
        'PUBLIC_SCORECARD_MISMATCH',
      ])
      expect(result.verification.mismatchedProofKinds).toEqual(['RELEASE_CONSTITUTION'])
    })

    it('blocks a candidate Evaluation Bundle bound to another artifact', () => {
      const request = baseManifestRequest()
      const candidateBundle = request.evaluationRunBundles.find(
        item => item.role === 'CANDIDATE',
      )
      if (candidateBundle !== undefined) candidateBundle.artifactDigest = releaseDigest('f')
      const result = assembleReleaseEvidenceManifestV1(request)

      expect(result.verification.decision).toBe('BLOCKED')
      expect(result.verification.reasonCodes).toEqual([
        'EVALUATION_BUNDLE_ARTIFACT_MISMATCH',
      ])
    })

    it('rejects duplicate, expired, extended, or malformed Manifest input', () => {
      const duplicateProof = baseManifestRequest()
      duplicateProof.proofs[1] = { ...duplicateProof.proofs[0]! }
      expect(() => assembleReleaseEvidenceManifestV1(duplicateProof)).toThrow(
        ReleaseEvidenceManifestInputError,
      )

      const expiredRisk = baseManifestRequest()
      expiredRisk.riskAcceptances[0]!.expiresAtEpochMs = expiredRisk.assembledAtEpochMs
      expect(() => assembleReleaseEvidenceManifestV1(expiredRisk)).toThrow(
        ReleaseEvidenceManifestInputError,
      )

      const badRevision = baseManifestRequest()
      badRevision.sourceRevision = 'main'
      expect(() => assembleReleaseEvidenceManifestV1(badRevision)).toThrow(
        ReleaseEvidenceManifestInputError,
      )

      expect(() => assembleReleaseEvidenceManifestV1({
        ...baseManifestRequest(),
        ciBadge: 'passing',
      })).toThrow(ReleaseEvidenceManifestInputError)
    })
  })
})
