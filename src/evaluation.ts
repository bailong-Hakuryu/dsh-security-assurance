import { z } from 'zod'

export const EFFECTIVENESS_METRICS_ENGINE_ID = 'security/effectiveness-metrics/v1' as const

const boundedEvaluationIdSchema = z.string()
  .regex(/^[a-z0-9][a-z0-9._:/-]{0,127}$/i)

export const evaluationSeveritySchema = z.enum([
  'CRITICAL',
  'HIGH',
  'MEDIUM',
  'LOW',
  'INFORMATIONAL',
])

export type EvaluationSeverity = z.infer<typeof evaluationSeveritySchema>

export const evaluationAssessmentModeSchema = z.enum([
  'REPOSITORY',
  'CHANGE',
  'TARGETED',
])

export type EvaluationAssessmentMode = z.infer<typeof evaluationAssessmentModeSchema>

export const evaluationGroundTruthDefectV1Schema = z.strictObject({
  defectId: boundedEvaluationIdSchema,
  severity: evaluationSeveritySchema,
  weaknessFamily: boundedEvaluationIdSchema,
  policyBlocking: z.boolean(),
})

export type EvaluationGroundTruthDefectV1 = z.infer<
  typeof evaluationGroundTruthDefectV1Schema
>

export const findingAdjudicationV1Schema = z.discriminatedUnion('status', [
  z.strictObject({
    status: z.literal('MATCHED'),
    defectId: boundedEvaluationIdSchema,
  }),
  z.strictObject({ status: z.literal('NOT_MATCHED') }),
  z.strictObject({ status: z.literal('UNADJUDICATED') }),
])

export type FindingAdjudicationV1 = z.infer<typeof findingAdjudicationV1Schema>

export const evaluatedFindingV1Schema = z.strictObject({
  findingId: boundedEvaluationIdSchema,
  adjudication: findingAdjudicationV1Schema,
})

export type EvaluatedFindingV1 = z.infer<typeof evaluatedFindingV1Schema>

export const evaluationCompletedResultV1Schema = z.strictObject({
  kind: z.literal('COMPLETED'),
  verdict: z.enum(['SATISFIED', 'FAILED', 'INDETERMINATE']),
  coverageStatus: z.enum(['COMPLETE', 'GAP']),
  findings: z.array(evaluatedFindingV1Schema).max(10_000),
})

export const evaluationProductFailureV1Schema = z.strictObject({
  kind: z.literal('PRODUCT_FAILURE'),
  failure: z.enum(['TIMEOUT', 'BUDGET_EXHAUSTED', 'CRASH', 'INCORRECT_OUTCOME']),
})

export const evaluationCaseV1Schema = z.strictObject({
  caseId: boundedEvaluationIdSchema,
  disposition: z.enum(['INCLUDED', 'BENCHMARK_INVALID']),
  assessmentMode: evaluationAssessmentModeSchema,
  supportedEcosystem: boundedEvaluationIdSchema,
  expectedCoverage: z.enum(['COMPLETE', 'INCOMPLETE_OR_UNSUPPORTED']),
  groundTruthDefects: z.array(evaluationGroundTruthDefectV1Schema).max(10_000),
  result: z.discriminatedUnion('kind', [
    evaluationCompletedResultV1Schema,
    evaluationProductFailureV1Schema,
  ]),
})

export type EvaluationCaseV1 = z.infer<typeof evaluationCaseV1Schema>

export const benchmarkStratumSelectorV1Schema = z.discriminatedUnion('dimension', [
  z.strictObject({
    dimension: z.literal('SEVERITY'),
    value: evaluationSeveritySchema,
  }),
  z.strictObject({
    dimension: z.literal('WEAKNESS_FAMILY'),
    value: boundedEvaluationIdSchema,
  }),
  z.strictObject({
    dimension: z.literal('ASSESSMENT_MODE'),
    value: evaluationAssessmentModeSchema,
  }),
  z.strictObject({
    dimension: z.literal('SUPPORTED_ECOSYSTEM'),
    value: boundedEvaluationIdSchema,
  }),
])

export type BenchmarkStratumSelectorV1 = z.infer<
  typeof benchmarkStratumSelectorV1Schema
>

export const benchmarkStratumDefinitionV1Schema = z.strictObject({
  stratumId: boundedEvaluationIdSchema,
  selector: benchmarkStratumSelectorV1Schema,
  minimumSamples: z.number().int().positive().max(1_000_000),
})

export type BenchmarkStratumDefinitionV1 = z.infer<
  typeof benchmarkStratumDefinitionV1Schema
>

export const effectivenessMetricsRequestV1Schema = z.strictObject({
  schemaVersion: z.literal(1),
  engineId: z.literal(EFFECTIVENESS_METRICS_ENGINE_ID),
  severityWeights: z.strictObject({
    CRITICAL: z.number().int().positive().max(1_000_000),
    HIGH: z.number().int().positive().max(1_000_000),
    MEDIUM: z.number().int().positive().max(1_000_000),
    LOW: z.number().int().positive().max(1_000_000),
    INFORMATIONAL: z.number().int().positive().max(1_000_000),
  }),
  stratumDefinitions: z.array(benchmarkStratumDefinitionV1Schema).min(4).max(10_000),
  cases: z.array(evaluationCaseV1Schema).max(10_000),
})

export type EffectivenessMetricsRequestV1 = z.infer<
  typeof effectivenessMetricsRequestV1Schema
>

export const effectivenessRatioMetricV1Schema = z.discriminatedUnion('status', [
  z.strictObject({
    status: z.literal('MEASURED'),
    numerator: z.number().int().nonnegative(),
    denominator: z.number().int().positive(),
    value: z.number().min(0).max(1),
  }),
  z.strictObject({
    status: z.literal('INCONCLUSIVE'),
    numerator: z.literal(0),
    denominator: z.literal(0),
    value: z.null(),
  }),
])

export type EffectivenessRatioMetricV1 = z.infer<
  typeof effectivenessRatioMetricV1Schema
>

export const effectivenessInconclusiveReasonV1Schema = z.enum([
  'NO_BLOCKING_GROUND_TRUTH_CASES',
  'NO_CRITICAL_HIGH_GROUND_TRUTH',
  'NO_INCOMPLETE_COVERAGE_CASES',
  'NO_VALIDATED_FINDINGS',
  'NO_WEIGHTED_GROUND_TRUTH',
  'UNADJUDICATED_FINDINGS',
  'INSUFFICIENT_BENCHMARK_STRATA',
])

export type EffectivenessInconclusiveReasonV1 = z.infer<
  typeof effectivenessInconclusiveReasonV1Schema
>

export const benchmarkStratumResultV1Schema = z.strictObject({
  stratumId: boundedEvaluationIdSchema,
  selector: benchmarkStratumSelectorV1Schema,
  sampleUnit: z.enum(['CASE', 'GROUND_TRUTH_DEFECT']),
  minimumSamples: z.number().int().positive(),
  observedSamples: z.number().int().nonnegative(),
  status: z.enum(['SUFFICIENT', 'INCONCLUSIVE']),
  reasonCodes: z.array(z.literal('INSUFFICIENT_SAMPLE_COUNT')).max(1),
}).superRefine((value, context) => {
  const expectedUnit = value.selector.dimension === 'SEVERITY'
    || value.selector.dimension === 'WEAKNESS_FAMILY'
    ? 'GROUND_TRUTH_DEFECT'
    : 'CASE'
  const sufficient = value.observedSamples >= value.minimumSamples
  if (
    value.sampleUnit !== expectedUnit
    || (sufficient && (value.status !== 'SUFFICIENT' || value.reasonCodes.length !== 0))
    || (!sufficient && (
      value.status !== 'INCONCLUSIVE'
      || value.reasonCodes.length !== 1
      || value.reasonCodes[0] !== 'INSUFFICIENT_SAMPLE_COUNT'
    ))
  ) {
    context.addIssue({ code: 'custom', message: 'Inconsistent Benchmark Stratum result.' })
  }
})

export type BenchmarkStratumResultV1 = z.infer<
  typeof benchmarkStratumResultV1Schema
>

export const effectivenessMetricsV1Schema = z.strictObject({
  schemaVersion: z.literal(1),
  engineId: z.literal(EFFECTIVENESS_METRICS_ENGINE_ID),
  conclusion: z.enum(['MEASURED', 'INCONCLUSIVE']),
  reasonCodes: z.array(effectivenessInconclusiveReasonV1Schema).max(7),
  counts: z.strictObject({
    includedCases: z.number().int().nonnegative(),
    benchmarkInvalidCases: z.number().int().nonnegative(),
    groundTruthDefects: z.number().int().nonnegative(),
    validatedFindings: z.number().int().nonnegative(),
    unadjudicatedFindings: z.number().int().nonnegative(),
    productFailures: z.number().int().nonnegative(),
    sufficientStrata: z.number().int().nonnegative(),
    inconclusiveStrata: z.number().int().nonnegative(),
  }),
  metrics: z.strictObject({
    criticalHighValidatedRecall: effectivenessRatioMetricV1Schema,
    severityWeightedValidatedRecall: effectivenessRatioMetricV1Schema,
    validatedPrecision: effectivenessRatioMetricV1Schema,
    unsafeSatisfactionRate: effectivenessRatioMetricV1Schema,
    coverageHonestyRate: effectivenessRatioMetricV1Schema,
  }),
  strata: z.array(benchmarkStratumResultV1Schema).max(10_000),
})

export type EffectivenessMetricsV1 = z.infer<typeof effectivenessMetricsV1Schema>

/** Stable, detail-free rejection for malformed or internally inconsistent evaluation evidence. */
export class EvaluationMetricsInputError extends Error {
  readonly code = 'INVALID_EVALUATION_EVIDENCE' as const

  constructor() {
    super('Evaluation evidence does not match Effectiveness Metrics Engine v1.')
    this.name = 'EvaluationMetricsInputError'
  }
}

function invalidEvidence(): never {
  throw new EvaluationMetricsInputError()
}

function unique(values: readonly string[]): boolean {
  return new Set(values).size === values.length
}

function parseRequest(input: unknown): EffectivenessMetricsRequestV1 {
  const parsed = effectivenessMetricsRequestV1Schema.safeParse(input)
  if (
    !parsed.success
    || parsed.data.severityWeights.CRITICAL < parsed.data.severityWeights.HIGH
    || parsed.data.severityWeights.HIGH < parsed.data.severityWeights.MEDIUM
    || parsed.data.severityWeights.MEDIUM < parsed.data.severityWeights.LOW
    || parsed.data.severityWeights.LOW < parsed.data.severityWeights.INFORMATIONAL
    || !unique(parsed.data.cases.map(item => item.caseId))
  ) {
    return invalidEvidence()
  }

  const stratumIds = parsed.data.stratumDefinitions.map(item => item.stratumId)
  const stratumSelectors = parsed.data.stratumDefinitions.map(
    item => `${item.selector.dimension}\0${item.selector.value}`,
  )
  const stratumDimensions = new Set(
    parsed.data.stratumDefinitions.map(item => item.selector.dimension),
  )
  if (
    !unique(stratumIds)
    || !unique(stratumSelectors)
    || !stratumDimensions.has('SEVERITY')
    || !stratumDimensions.has('WEAKNESS_FAMILY')
    || !stratumDimensions.has('ASSESSMENT_MODE')
    || !stratumDimensions.has('SUPPORTED_ECOSYSTEM')
  ) {
    return invalidEvidence()
  }

  for (const item of parsed.data.cases) {
    const defects = item.groundTruthDefects.map(defect => defect.defectId)
    if (!unique(defects)) return invalidEvidence()
    if (item.result.kind !== 'COMPLETED') continue

    const findings = item.result.findings.map(finding => finding.findingId)
    if (!unique(findings)) return invalidEvidence()
    const defectSet = new Set(defects)
    const matchedDefects: string[] = []
    for (const finding of item.result.findings) {
      if (finding.adjudication.status !== 'MATCHED') continue
      if (!defectSet.has(finding.adjudication.defectId)) return invalidEvidence()
      matchedDefects.push(finding.adjudication.defectId)
    }
    if (!unique(matchedDefects)) return invalidEvidence()
  }
  return parsed.data
}

function ratio(numerator: number, denominator: number): EffectivenessRatioMetricV1 {
  if (denominator === 0) {
    if (numerator !== 0) throw new Error('Effectiveness metric numerator cannot exceed a zero denominator')
    return { status: 'INCONCLUSIVE', numerator: 0, denominator: 0, value: null }
  }
  return { status: 'MEASURED', numerator, denominator, value: numerator / denominator }
}

function incrementCount(counts: Map<string, number>, key: string): void {
  counts.set(key, (counts.get(key) ?? 0) + 1)
}

function deepFreeze<T>(value: T): T {
  if (typeof value !== 'object' || value === null || Object.isFrozen(value)) return value
  for (const nested of Object.values(value)) deepFreeze(nested)
  return Object.freeze(value)
}

/**
 * Calculate the five primary aggregate Effectiveness measures and predeclared
 * Stratum sample sufficiency from immutable, independently adjudicated
 * evidence. This pure module does not choose release thresholds, access Ground
 * Truth during scanning, or render a scorecard.
 */
export function calculateEffectivenessMetricsV1(input: unknown): EffectivenessMetricsV1 {
  const request = parseRequest(input)
  let benchmarkInvalidCases = 0
  let includedCases = 0
  let groundTruthDefects = 0
  let validatedFindings = 0
  let unadjudicatedFindings = 0
  let productFailures = 0
  let criticalHighDefects = 0
  let matchedCriticalHighDefects = 0
  let weightedDefects = 0
  let matchedWeightedDefects = 0
  let matchedFindings = 0
  let blockingGroundTruthCases = 0
  let unsafeSatisfiedCases = 0
  let incompleteCoverageCases = 0
  let honestIncompleteCoverageCases = 0
  const severitySamples = new Map<string, number>()
  const weaknessSamples = new Map<string, number>()
  const assessmentModeSamples = new Map<string, number>()
  const ecosystemSamples = new Map<string, number>()

  for (const item of request.cases) {
    if (item.disposition === 'BENCHMARK_INVALID') {
      benchmarkInvalidCases += 1
      continue
    }
    includedCases += 1
    incrementCount(assessmentModeSamples, item.assessmentMode)
    incrementCount(ecosystemSamples, item.supportedEcosystem)
    groundTruthDefects += item.groundTruthDefects.length
    const blocking = item.groundTruthDefects.some(defect => defect.policyBlocking)
    if (blocking) blockingGroundTruthCases += 1
    if (item.expectedCoverage === 'INCOMPLETE_OR_UNSUPPORTED') incompleteCoverageCases += 1

    const matchedDefects = new Set<string>()
    if (item.result.kind === 'PRODUCT_FAILURE') {
      productFailures += 1
    } else {
      validatedFindings += item.result.findings.length
      for (const finding of item.result.findings) {
        if (finding.adjudication.status === 'MATCHED') {
          matchedFindings += 1
          matchedDefects.add(finding.adjudication.defectId)
        } else if (finding.adjudication.status === 'UNADJUDICATED') {
          unadjudicatedFindings += 1
        }
      }
      if (blocking && item.result.verdict === 'SATISFIED') unsafeSatisfiedCases += 1
      if (
        item.expectedCoverage === 'INCOMPLETE_OR_UNSUPPORTED'
        && item.result.coverageStatus === 'GAP'
        && item.result.verdict !== 'SATISFIED'
      ) {
        honestIncompleteCoverageCases += 1
      }
    }

    for (const defect of item.groundTruthDefects) {
      incrementCount(severitySamples, defect.severity)
      incrementCount(weaknessSamples, defect.weaknessFamily)
      const weight = request.severityWeights[defect.severity]
      weightedDefects += weight
      if (matchedDefects.has(defect.defectId)) matchedWeightedDefects += weight
      if (defect.severity === 'CRITICAL' || defect.severity === 'HIGH') {
        criticalHighDefects += 1
        if (matchedDefects.has(defect.defectId)) matchedCriticalHighDefects += 1
      }
    }
  }

  const strata: BenchmarkStratumResultV1[] = request.stratumDefinitions
    .map((definition): BenchmarkStratumResultV1 => {
      let sampleUnit: BenchmarkStratumResultV1['sampleUnit']
      let observedSamples: number
      switch (definition.selector.dimension) {
        case 'SEVERITY':
          sampleUnit = 'GROUND_TRUTH_DEFECT'
          observedSamples = severitySamples.get(definition.selector.value) ?? 0
          break
        case 'WEAKNESS_FAMILY':
          sampleUnit = 'GROUND_TRUTH_DEFECT'
          observedSamples = weaknessSamples.get(definition.selector.value) ?? 0
          break
        case 'ASSESSMENT_MODE':
          sampleUnit = 'CASE'
          observedSamples = assessmentModeSamples.get(definition.selector.value) ?? 0
          break
        case 'SUPPORTED_ECOSYSTEM':
          sampleUnit = 'CASE'
          observedSamples = ecosystemSamples.get(definition.selector.value) ?? 0
          break
      }
      const sufficient = observedSamples >= definition.minimumSamples
      return {
        stratumId: definition.stratumId,
        selector: definition.selector,
        sampleUnit,
        minimumSamples: definition.minimumSamples,
        observedSamples,
        status: sufficient ? 'SUFFICIENT' : 'INCONCLUSIVE',
        reasonCodes: sufficient ? [] : ['INSUFFICIENT_SAMPLE_COUNT'],
      }
    })
    .sort((left, right) => left.stratumId < right.stratumId
      ? -1
      : left.stratumId > right.stratumId ? 1 : 0)
  const sufficientStrata = strata.filter(item => item.status === 'SUFFICIENT').length
  const inconclusiveStrata = strata.length - sufficientStrata

  const reasonCodes: EffectivenessInconclusiveReasonV1[] = []
  if (blockingGroundTruthCases === 0) reasonCodes.push('NO_BLOCKING_GROUND_TRUTH_CASES')
  if (criticalHighDefects === 0) reasonCodes.push('NO_CRITICAL_HIGH_GROUND_TRUTH')
  if (incompleteCoverageCases === 0) reasonCodes.push('NO_INCOMPLETE_COVERAGE_CASES')
  if (validatedFindings === 0) reasonCodes.push('NO_VALIDATED_FINDINGS')
  if (weightedDefects === 0) reasonCodes.push('NO_WEIGHTED_GROUND_TRUTH')
  if (unadjudicatedFindings > 0) reasonCodes.push('UNADJUDICATED_FINDINGS')
  if (inconclusiveStrata > 0) reasonCodes.push('INSUFFICIENT_BENCHMARK_STRATA')

  const result: EffectivenessMetricsV1 = {
    schemaVersion: 1,
    engineId: EFFECTIVENESS_METRICS_ENGINE_ID,
    conclusion: reasonCodes.length === 0 ? 'MEASURED' : 'INCONCLUSIVE',
    reasonCodes,
    counts: {
      includedCases,
      benchmarkInvalidCases,
      groundTruthDefects,
      validatedFindings,
      unadjudicatedFindings,
      productFailures,
      sufficientStrata,
      inconclusiveStrata,
    },
    metrics: {
      criticalHighValidatedRecall: ratio(matchedCriticalHighDefects, criticalHighDefects),
      severityWeightedValidatedRecall: ratio(matchedWeightedDefects, weightedDefects),
      validatedPrecision: ratio(matchedFindings, validatedFindings),
      unsafeSatisfactionRate: ratio(unsafeSatisfiedCases, blockingGroundTruthCases),
      coverageHonestyRate: ratio(honestIncompleteCoverageCases, incompleteCoverageCases),
    },
    strata,
  }
  return deepFreeze(effectivenessMetricsV1Schema.parse(result))
}
