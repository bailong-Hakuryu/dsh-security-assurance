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
  repetitionId: boundedEvaluationIdSchema.optional(),
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

export const benchmarkRepetitionPlanV1Schema = z.strictObject({
  method: z.literal('HOEFFDING_TWO_SIDED_V1'),
  repetitionIds: z.array(boundedEvaluationIdSchema).min(2).max(1_000),
  benchmarkCaseIds: z.array(boundedEvaluationIdSchema).min(1).max(10_000),
  confidenceLevel: z.number().gt(0.5).lt(1),
  maximumConfidenceIntervalWidth: z.number().positive().max(1),
})

export type BenchmarkRepetitionPlanV1 = z.infer<
  typeof benchmarkRepetitionPlanV1Schema
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
  repetitionPlan: benchmarkRepetitionPlanV1Schema.optional(),
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
  'INCOMPLETE_REPETITION_EVIDENCE',
  'EXCESSIVE_REPETITION_UNCERTAINTY',
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

export const repetitionConfidenceIntervalV1Schema = z.strictObject({
  method: z.literal('HOEFFDING_TWO_SIDED_V1'),
  confidenceLevel: z.number().gt(0.5).lt(1),
  lower: z.number().min(0).max(1),
  upper: z.number().min(0).max(1),
  width: z.number().min(0).max(1),
}).superRefine((value, context) => {
  if (
    value.lower > value.upper
    || Math.abs((value.upper - value.lower) - value.width) > Number.EPSILON * 4
  ) {
    context.addIssue({ code: 'custom', message: 'Inconsistent confidence interval.' })
  }
})

const incompleteRepetitionMetricReasonV1Schema = z.enum([
  'INCOMPLETE_REPETITION_CASE_MATRIX',
  'INCOMPLETE_REPETITION_METRICS',
])

export const repetitionMetricDistributionV1Schema = z.discriminatedUnion('status', [
  z.strictObject({
    status: z.literal('MEASURED'),
    sampleSize: z.number().int().min(2),
    mean: z.number().min(0).max(1),
    sampleStandardDeviation: z.number().nonnegative(),
    worst: z.number().min(0).max(1),
    worstDirection: z.enum(['MINIMUM', 'MAXIMUM']),
    confidenceInterval: repetitionConfidenceIntervalV1Schema,
    uncertaintyStatus: z.enum(['SUFFICIENT', 'INCONCLUSIVE']),
    reasonCodes: z.array(z.literal('CONFIDENCE_INTERVAL_TOO_WIDE')).max(1),
  }),
  z.strictObject({
    status: z.literal('INCONCLUSIVE'),
    sampleSize: z.literal(0),
    mean: z.null(),
    sampleStandardDeviation: z.null(),
    worst: z.null(),
    worstDirection: z.enum(['MINIMUM', 'MAXIMUM']),
    confidenceInterval: z.null(),
    uncertaintyStatus: z.literal('INCONCLUSIVE'),
    reasonCodes: z.array(incompleteRepetitionMetricReasonV1Schema).min(1).max(1),
  }),
]).superRefine((value, context) => {
  if (
    value.status === 'MEASURED'
    && (
      (value.uncertaintyStatus === 'SUFFICIENT' && value.reasonCodes.length !== 0)
      || (value.uncertaintyStatus === 'INCONCLUSIVE' && value.reasonCodes.length !== 1)
    )
  ) {
    context.addIssue({ code: 'custom', message: 'Inconsistent uncertainty result.' })
  }
})

export type RepetitionMetricDistributionV1 = z.infer<
  typeof repetitionMetricDistributionV1Schema
>

export const repetitionAnalysisV1Schema = z.strictObject({
  method: z.literal('HOEFFDING_TWO_SIDED_V1'),
  confidenceLevel: z.number().gt(0.5).lt(1),
  maximumConfidenceIntervalWidth: z.number().positive().max(1),
  plannedIndependentRepetitions: z.number().int().min(2),
  observedIndependentRepetitions: z.number().int().nonnegative(),
  status: z.enum(['SUFFICIENT', 'INCONCLUSIVE']),
  reasonCodes: z.array(z.enum([
    'INCOMPLETE_REPETITION_CASE_MATRIX',
    'INCOMPLETE_REPETITION_METRICS',
    'EXCESSIVE_CONFIDENCE_INTERVAL_WIDTH',
  ])).max(3),
  metrics: z.strictObject({
    criticalHighValidatedRecall: repetitionMetricDistributionV1Schema,
    severityWeightedValidatedRecall: repetitionMetricDistributionV1Schema,
    validatedPrecision: repetitionMetricDistributionV1Schema,
    unsafeSatisfactionRate: repetitionMetricDistributionV1Schema,
    coverageHonestyRate: repetitionMetricDistributionV1Schema,
  }),
}).superRefine((value, context) => {
  const metrics = Object.values(value.metrics)
  if (
    value.observedIndependentRepetitions > value.plannedIndependentRepetitions
    || (value.status === 'SUFFICIENT' && (
      value.reasonCodes.length !== 0
      || value.observedIndependentRepetitions !== value.plannedIndependentRepetitions
      || metrics.some(metric => (
        metric.status !== 'MEASURED'
        || metric.uncertaintyStatus !== 'SUFFICIENT'
      ))
    ))
    || (value.status === 'INCONCLUSIVE' && value.reasonCodes.length === 0)
  ) {
    context.addIssue({ code: 'custom', message: 'Inconsistent repetition analysis.' })
  }
})

export type RepetitionAnalysisV1 = z.infer<typeof repetitionAnalysisV1Schema>

export const effectivenessMetricsV1Schema = z.strictObject({
  schemaVersion: z.literal(1),
  engineId: z.literal(EFFECTIVENESS_METRICS_ENGINE_ID),
  conclusion: z.enum(['MEASURED', 'INCONCLUSIVE']),
  reasonCodes: z.array(effectivenessInconclusiveReasonV1Schema).max(9),
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
  repetitionAnalysis: repetitionAnalysisV1Schema.nullable(),
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

  const repetitionPlan = parsed.data.repetitionPlan
  if (repetitionPlan === undefined) {
    if (
      parsed.data.cases.some(item => item.repetitionId !== undefined)
      || !unique(parsed.data.cases.map(item => item.caseId))
    ) {
      return invalidEvidence()
    }
  } else {
    if (
      !unique(repetitionPlan.repetitionIds)
      || !unique(repetitionPlan.benchmarkCaseIds)
    ) {
      return invalidEvidence()
    }
    const repetitionIds = new Set(repetitionPlan.repetitionIds)
    const benchmarkCaseIds = new Set(repetitionPlan.benchmarkCaseIds)
    const observationIds: string[] = []
    const caseContracts = new Map<string, string>()
    for (const item of parsed.data.cases) {
      if (
        item.repetitionId === undefined
        || !repetitionIds.has(item.repetitionId)
        || !benchmarkCaseIds.has(item.caseId)
      ) {
        return invalidEvidence()
      }
      observationIds.push(`${item.repetitionId}\0${item.caseId}`)
      const caseContract = JSON.stringify({
        disposition: item.disposition,
        assessmentMode: item.assessmentMode,
        supportedEcosystem: item.supportedEcosystem,
        expectedCoverage: item.expectedCoverage,
        groundTruthDefects: item.groundTruthDefects,
      })
      const existingContract = caseContracts.get(item.caseId)
      if (existingContract !== undefined && existingContract !== caseContract) {
        return invalidEvidence()
      }
      caseContracts.set(item.caseId, caseContract)
    }
    if (!unique(observationIds)) return invalidEvidence()
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

type EffectivenessCaseSummary = {
  benchmarkInvalidCases: number
  includedCases: number
  groundTruthDefects: number
  validatedFindings: number
  unadjudicatedFindings: number
  productFailures: number
  metrics: EffectivenessMetricsV1['metrics']
  reasonCodes: EffectivenessInconclusiveReasonV1[]
  severitySamples: Map<string, number>
  weaknessSamples: Map<string, number>
  assessmentModeSamples: Map<string, number>
  ecosystemSamples: Map<string, number>
}

function summarizeCases(
  cases: readonly EvaluationCaseV1[],
  severityWeights: EffectivenessMetricsRequestV1['severityWeights'],
): EffectivenessCaseSummary {
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

  for (const item of cases) {
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
      const weight = severityWeights[defect.severity]
      weightedDefects += weight
      if (matchedDefects.has(defect.defectId)) matchedWeightedDefects += weight
      if (defect.severity === 'CRITICAL' || defect.severity === 'HIGH') {
        criticalHighDefects += 1
        if (matchedDefects.has(defect.defectId)) matchedCriticalHighDefects += 1
      }
    }
  }

  const reasonCodes: EffectivenessInconclusiveReasonV1[] = []
  if (blockingGroundTruthCases === 0) reasonCodes.push('NO_BLOCKING_GROUND_TRUTH_CASES')
  if (criticalHighDefects === 0) reasonCodes.push('NO_CRITICAL_HIGH_GROUND_TRUTH')
  if (incompleteCoverageCases === 0) reasonCodes.push('NO_INCOMPLETE_COVERAGE_CASES')
  if (validatedFindings === 0) reasonCodes.push('NO_VALIDATED_FINDINGS')
  if (weightedDefects === 0) reasonCodes.push('NO_WEIGHTED_GROUND_TRUTH')
  if (unadjudicatedFindings > 0) reasonCodes.push('UNADJUDICATED_FINDINGS')

  return {
    benchmarkInvalidCases,
    includedCases,
    groundTruthDefects,
    validatedFindings,
    unadjudicatedFindings,
    productFailures,
    metrics: {
      criticalHighValidatedRecall: ratio(matchedCriticalHighDefects, criticalHighDefects),
      severityWeightedValidatedRecall: ratio(matchedWeightedDefects, weightedDefects),
      validatedPrecision: ratio(matchedFindings, validatedFindings),
      unsafeSatisfactionRate: ratio(unsafeSatisfiedCases, blockingGroundTruthCases),
      coverageHonestyRate: ratio(honestIncompleteCoverageCases, incompleteCoverageCases),
    },
    reasonCodes,
    severitySamples,
    weaknessSamples,
    assessmentModeSamples,
    ecosystemSamples,
  }
}

function compareIds(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0
}

function inconclusiveDistribution(
  worstDirection: RepetitionMetricDistributionV1['worstDirection'],
  reason: 'INCOMPLETE_REPETITION_CASE_MATRIX' | 'INCOMPLETE_REPETITION_METRICS',
): RepetitionMetricDistributionV1 {
  return {
    status: 'INCONCLUSIVE',
    sampleSize: 0,
    mean: null,
    sampleStandardDeviation: null,
    worst: null,
    worstDirection,
    confidenceInterval: null,
    uncertaintyStatus: 'INCONCLUSIVE',
    reasonCodes: [reason],
  }
}

function calculateDistribution(
  values: readonly number[],
  worstDirection: 'MINIMUM' | 'MAXIMUM',
  plan: BenchmarkRepetitionPlanV1,
): RepetitionMetricDistributionV1 {
  const mean = values.reduce((sum, value) => sum + value, 0) / values.length
  const squaredDeviation = values.reduce(
    (sum, value) => sum + ((value - mean) ** 2),
    0,
  )
  const sampleStandardDeviation = Math.sqrt(squaredDeviation / (values.length - 1))
  const alpha = 1 - plan.confidenceLevel
  const radius = Math.sqrt(Math.log(2 / alpha) / (2 * values.length))
  const lower = Math.max(0, mean - radius)
  const upper = Math.min(1, mean + radius)
  const width = upper - lower
  const uncertaintySufficient = width <= plan.maximumConfidenceIntervalWidth
  return {
    status: 'MEASURED',
    sampleSize: values.length,
    mean,
    sampleStandardDeviation,
    worst: worstDirection === 'MINIMUM' ? Math.min(...values) : Math.max(...values),
    worstDirection,
    confidenceInterval: {
      method: plan.method,
      confidenceLevel: plan.confidenceLevel,
      lower,
      upper,
      width,
    },
    uncertaintyStatus: uncertaintySufficient ? 'SUFFICIENT' : 'INCONCLUSIVE',
    reasonCodes: uncertaintySufficient ? [] : ['CONFIDENCE_INTERVAL_TOO_WIDE'],
  }
}

function calculateRepetitionAnalysis(
  request: EffectivenessMetricsRequestV1,
): RepetitionAnalysisV1 | null {
  const plan = request.repetitionPlan
  if (plan === undefined) return null

  const casesByRepetition = new Map<string, EvaluationCaseV1[]>()
  for (const repetitionId of plan.repetitionIds) casesByRepetition.set(repetitionId, [])
  for (const item of request.cases) {
    casesByRepetition.get(item.repetitionId as string)?.push(item)
  }
  const expectedCaseIds = new Set(plan.benchmarkCaseIds)
  const completeRepetitionIds = plan.repetitionIds.filter((repetitionId) => {
    const cases = casesByRepetition.get(repetitionId) ?? []
    return cases.length === expectedCaseIds.size
      && cases.every(item => expectedCaseIds.has(item.caseId))
  })
  const matrixComplete = completeRepetitionIds.length === plan.repetitionIds.length
  const directions = {
    criticalHighValidatedRecall: 'MINIMUM',
    severityWeightedValidatedRecall: 'MINIMUM',
    validatedPrecision: 'MINIMUM',
    unsafeSatisfactionRate: 'MAXIMUM',
    coverageHonestyRate: 'MINIMUM',
  } as const
  const metricNames = Object.keys(directions) as Array<keyof typeof directions>
  const distributions = {} as RepetitionAnalysisV1['metrics']

  if (!matrixComplete) {
    for (const metricName of metricNames) {
      distributions[metricName] = inconclusiveDistribution(
        directions[metricName],
        'INCOMPLETE_REPETITION_CASE_MATRIX',
      )
    }
  } else {
    const summaries = [...plan.repetitionIds]
      .sort(compareIds)
      .map(repetitionId => summarizeCases(
        casesByRepetition.get(repetitionId) ?? [],
        request.severityWeights,
      ))
    for (const metricName of metricNames) {
      const ratios = summaries.map(summary => summary.metrics[metricName])
      if (ratios.some(metric => metric.status === 'INCONCLUSIVE')) {
        distributions[metricName] = inconclusiveDistribution(
          directions[metricName],
          'INCOMPLETE_REPETITION_METRICS',
        )
      } else {
        distributions[metricName] = calculateDistribution(
          ratios.map(metric => metric.value as number),
          directions[metricName],
          plan,
        )
      }
    }
  }

  const reasonCodes: RepetitionAnalysisV1['reasonCodes'] = []
  if (!matrixComplete) reasonCodes.push('INCOMPLETE_REPETITION_CASE_MATRIX')
  if (metricNames.some(name => distributions[name].status === 'INCONCLUSIVE')) {
    if (matrixComplete) reasonCodes.push('INCOMPLETE_REPETITION_METRICS')
  }
  if (metricNames.some(name => (
    distributions[name].status === 'MEASURED'
    && distributions[name].uncertaintyStatus === 'INCONCLUSIVE'
  ))) {
    reasonCodes.push('EXCESSIVE_CONFIDENCE_INTERVAL_WIDTH')
  }

  return {
    method: plan.method,
    confidenceLevel: plan.confidenceLevel,
    maximumConfidenceIntervalWidth: plan.maximumConfidenceIntervalWidth,
    plannedIndependentRepetitions: plan.repetitionIds.length,
    observedIndependentRepetitions: completeRepetitionIds.length,
    status: reasonCodes.length === 0 ? 'SUFFICIENT' : 'INCONCLUSIVE',
    reasonCodes,
    metrics: distributions,
  }
}

/**
 * Calculate aggregate Effectiveness, predeclared Stratum sample sufficiency,
 * and optional independent-repetition uncertainty from immutable evidence.
 * This pure module does not choose release thresholds, access Ground Truth
 * during scanning, or render a scorecard.
 */
export function calculateEffectivenessMetricsV1(input: unknown): EffectivenessMetricsV1 {
  const request = parseRequest(input)
  const summary = summarizeCases(request.cases, request.severityWeights)
  const stratumCases = request.repetitionPlan === undefined
    ? request.cases
    : [...request.cases.reduce((representatives, item) => {
        if (!representatives.has(item.caseId)) representatives.set(item.caseId, item)
        return representatives
      }, new Map<string, EvaluationCaseV1>()).values()]
  const stratumSummary = request.repetitionPlan === undefined
    ? summary
    : summarizeCases(stratumCases, request.severityWeights)

  const strata: BenchmarkStratumResultV1[] = request.stratumDefinitions
    .map((definition): BenchmarkStratumResultV1 => {
      let sampleUnit: BenchmarkStratumResultV1['sampleUnit']
      let observedSamples: number
      switch (definition.selector.dimension) {
        case 'SEVERITY':
          sampleUnit = 'GROUND_TRUTH_DEFECT'
          observedSamples = stratumSummary.severitySamples.get(definition.selector.value) ?? 0
          break
        case 'WEAKNESS_FAMILY':
          sampleUnit = 'GROUND_TRUTH_DEFECT'
          observedSamples = stratumSummary.weaknessSamples.get(definition.selector.value) ?? 0
          break
        case 'ASSESSMENT_MODE':
          sampleUnit = 'CASE'
          observedSamples = stratumSummary.assessmentModeSamples.get(definition.selector.value) ?? 0
          break
        case 'SUPPORTED_ECOSYSTEM':
          sampleUnit = 'CASE'
          observedSamples = stratumSummary.ecosystemSamples.get(definition.selector.value) ?? 0
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
    .sort((left, right) => compareIds(left.stratumId, right.stratumId))
  const sufficientStrata = strata.filter(item => item.status === 'SUFFICIENT').length
  const inconclusiveStrata = strata.length - sufficientStrata
  const repetitionAnalysis = calculateRepetitionAnalysis(request)

  const reasonCodes = [...summary.reasonCodes]
  if (inconclusiveStrata > 0) reasonCodes.push('INSUFFICIENT_BENCHMARK_STRATA')
  if (repetitionAnalysis?.reasonCodes.some(reason => (
    reason === 'INCOMPLETE_REPETITION_CASE_MATRIX'
    || reason === 'INCOMPLETE_REPETITION_METRICS'
  ))) {
    reasonCodes.push('INCOMPLETE_REPETITION_EVIDENCE')
  }
  if (repetitionAnalysis?.reasonCodes.includes('EXCESSIVE_CONFIDENCE_INTERVAL_WIDTH')) {
    reasonCodes.push('EXCESSIVE_REPETITION_UNCERTAINTY')
  }

  const result: EffectivenessMetricsV1 = {
    schemaVersion: 1,
    engineId: EFFECTIVENESS_METRICS_ENGINE_ID,
    conclusion: reasonCodes.length === 0 ? 'MEASURED' : 'INCONCLUSIVE',
    reasonCodes,
    counts: {
      includedCases: summary.includedCases,
      benchmarkInvalidCases: summary.benchmarkInvalidCases,
      groundTruthDefects: summary.groundTruthDefects,
      validatedFindings: summary.validatedFindings,
      unadjudicatedFindings: summary.unadjudicatedFindings,
      productFailures: summary.productFailures,
      sufficientStrata,
      inconclusiveStrata,
    },
    metrics: summary.metrics,
    strata,
    repetitionAnalysis,
  }
  return deepFreeze(effectivenessMetricsV1Schema.parse(result))
}
