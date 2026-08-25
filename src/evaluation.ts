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
  maximumValidatedRecallIntervalWidth: z.number().positive().max(1).optional(),
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

export const stratumUncertaintyAnalysisV1Schema = z.strictObject({
  method: z.literal('HOEFFDING_TWO_SIDED_V1'),
  confidenceLevel: z.number().gt(0.5).lt(1),
  maximumValidatedRecallIntervalWidth: z.number().positive().max(1),
  status: z.enum(['SUFFICIENT', 'INCONCLUSIVE']),
  reasonCodes: z.array(z.enum([
    'INCOMPLETE_REPETITION_METRICS',
    'EXCESSIVE_CONFIDENCE_INTERVAL_WIDTH',
  ])).max(2),
  metrics: z.strictObject({
    validatedRecall: repetitionMetricDistributionV1Schema,
    severityWeightedValidatedRecall: repetitionMetricDistributionV1Schema,
  }),
}).superRefine((value, context) => {
  const metrics = Object.values(value.metrics)
  if (
    (value.status === 'SUFFICIENT' && (
      value.reasonCodes.length !== 0
      || metrics.some(metric => (
        metric.status !== 'MEASURED'
        || metric.uncertaintyStatus !== 'SUFFICIENT'
      ))
    ))
    || (value.status === 'INCONCLUSIVE' && value.reasonCodes.length === 0)
  ) {
    context.addIssue({ code: 'custom', message: 'Inconsistent Stratum uncertainty.' })
  }
})

export type StratumUncertaintyAnalysisV1 = z.infer<
  typeof stratumUncertaintyAnalysisV1Schema
>

export const benchmarkStratumResultV1Schema = z.strictObject({
  stratumId: boundedEvaluationIdSchema,
  selector: benchmarkStratumSelectorV1Schema,
  sampleUnit: z.enum(['CASE', 'GROUND_TRUTH_DEFECT']),
  minimumSamples: z.number().int().positive(),
  observedSamples: z.number().int().nonnegative(),
  status: z.enum(['SUFFICIENT', 'INCONCLUSIVE']),
  reasonCodes: z.array(z.enum([
    'INSUFFICIENT_SAMPLE_COUNT',
    'INCOMPLETE_REPETITION_METRICS',
    'EXCESSIVE_CONFIDENCE_INTERVAL_WIDTH',
  ])).max(3),
  uncertainty: stratumUncertaintyAnalysisV1Schema.optional(),
}).superRefine((value, context) => {
  const expectedUnit = value.selector.dimension === 'SEVERITY'
    || value.selector.dimension === 'WEAKNESS_FAMILY'
    ? 'GROUND_TRUTH_DEFECT'
    : 'CASE'
  const sampleSufficient = value.observedSamples >= value.minimumSamples
  const uncertaintySufficient = value.uncertainty === undefined
    || value.uncertainty.status === 'SUFFICIENT'
  const sufficient = sampleSufficient && uncertaintySufficient
  if (
    value.sampleUnit !== expectedUnit
    || (sufficient && (value.status !== 'SUFFICIENT' || value.reasonCodes.length !== 0))
    || (!sufficient && (value.status !== 'INCONCLUSIVE' || value.reasonCodes.length === 0))
  ) {
    context.addIssue({ code: 'custom', message: 'Inconsistent Benchmark Stratum result.' })
  }
})

export type BenchmarkStratumResultV1 = z.infer<
  typeof benchmarkStratumResultV1Schema
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

export const PAIRED_ARM_COMPARISON_ENGINE_ID = 'security/paired-arm-comparison/v1' as const

export const EVALUATION_RESOURCE_DIMENSIONS = [
  'wallTimeMs',
  'modelTokens',
  'modelCalls',
  'analyzerRuns',
  'agentRuns',
  'cpuTimeMs',
  'peakMemoryBytes',
  'diskBytes',
  'networkRequests',
  'outboundBytes',
  'humanAdjudicationMs',
] as const

export type EvaluationResourceDimension = typeof EVALUATION_RESOURCE_DIMENSIONS[number]

const resourceQuantitySchema = z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER)

export const evaluationResourceBudgetV1Schema = z.strictObject({
  wallTimeMs: resourceQuantitySchema,
  modelTokens: resourceQuantitySchema,
  modelCalls: resourceQuantitySchema,
  analyzerRuns: resourceQuantitySchema,
  agentRuns: resourceQuantitySchema,
  cpuTimeMs: resourceQuantitySchema,
  peakMemoryBytes: resourceQuantitySchema,
  diskBytes: resourceQuantitySchema,
  networkRequests: resourceQuantitySchema,
  outboundBytes: resourceQuantitySchema,
  humanAdjudicationMs: resourceQuantitySchema,
})

export type EvaluationResourceBudgetV1 = z.infer<typeof evaluationResourceBudgetV1Schema>

export const evaluationArmBudgetV1Schema = z.strictObject({
  limits: evaluationResourceBudgetV1Schema,
  usage: evaluationResourceBudgetV1Schema,
}).superRefine((value, context) => {
  if (EVALUATION_RESOURCE_DIMENSIONS.some(
    dimension => value.usage[dimension] > value.limits[dimension],
  )) {
    context.addIssue({ code: 'custom', message: 'Resource usage exceeds its frozen limit.' })
  }
})

export type EvaluationArmBudgetV1 = z.infer<typeof evaluationArmBudgetV1Schema>

export const pairedArmEvidenceV1Schema = z.strictObject({
  armId: boundedEvaluationIdSchema,
  metricsRequest: effectivenessMetricsRequestV1Schema,
  budget: evaluationArmBudgetV1Schema,
})

export type PairedArmEvidenceV1 = z.infer<typeof pairedArmEvidenceV1Schema>

const nonInferiorityMarginV1Schema = z.number().min(0).max(1)

export const nonInferiorityPlanV1Schema = z.strictObject({
  planId: boundedEvaluationIdSchema,
  registrationRecordId: boundedEvaluationIdSchema,
  registeredAtEpochMs: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER),
  evidenceCollectionStartedAtEpochMs: z.number().int().nonnegative()
    .max(Number.MAX_SAFE_INTEGER),
  method: z.literal('CONSERVATIVE_HOEFFDING_BOUNDS_V1'),
  metricMargins: z.strictObject({
    criticalHighValidatedRecall: nonInferiorityMarginV1Schema,
    severityWeightedValidatedRecall: nonInferiorityMarginV1Schema,
    validatedPrecision: nonInferiorityMarginV1Schema,
    unsafeSatisfactionRate: nonInferiorityMarginV1Schema,
    coverageHonestyRate: nonInferiorityMarginV1Schema,
  }),
  stratumMargins: z.array(z.strictObject({
    stratumId: boundedEvaluationIdSchema,
    validatedRecallMargin: nonInferiorityMarginV1Schema,
  })).min(4).max(10_000),
}).superRefine((value, context) => {
  if (value.registeredAtEpochMs >= value.evidenceCollectionStartedAtEpochMs) {
    context.addIssue({
      code: 'custom',
      message: 'The non-inferiority plan must predate evidence collection.',
    })
  }
  if (new Set(value.stratumMargins.map(item => item.stratumId)).size
    !== value.stratumMargins.length) {
    context.addIssue({ code: 'custom', message: 'Duplicate Stratum margin.' })
  }
})

export type NonInferiorityPlanV1 = z.infer<typeof nonInferiorityPlanV1Schema>

export const pairedArmComparisonRequestV1Schema = z.strictObject({
  schemaVersion: z.literal(1),
  engineId: z.literal(PAIRED_ARM_COMPARISON_ENGINE_ID),
  comparisonView: z.enum(['MATCHED_BUDGET', 'NATIVE_PROFILE']),
  baseline: pairedArmEvidenceV1Schema,
  candidate: pairedArmEvidenceV1Schema,
  nonInferiorityPlan: nonInferiorityPlanV1Schema.optional(),
})

export type PairedArmComparisonRequestV1 = z.infer<
  typeof pairedArmComparisonRequestV1Schema
>

const pairedMetricInconclusiveReasonV1Schema = z.enum([
  'INCOMPATIBLE_EVALUATION_DESIGN',
  'UNMATCHED_BUDGETS',
  'INCONCLUSIVE_ARM_METRIC',
])

export const pairedMetricComparisonV1Schema = z.discriminatedUnion('status', [
  z.strictObject({
    status: z.literal('MEASURED'),
    baselineValue: z.number().min(0).max(1),
    candidateValue: z.number().min(0).max(1),
    rawDelta: z.number().min(-1).max(1),
    directionalDelta: z.number().min(-1).max(1),
    preferredDirection: z.enum(['HIGHER', 'LOWER']),
    outcome: z.enum(['IMPROVED', 'EQUIVALENT', 'REGRESSED']),
  }),
  z.strictObject({
    status: z.literal('INCONCLUSIVE'),
    baselineValue: z.number().min(0).max(1).nullable(),
    candidateValue: z.number().min(0).max(1).nullable(),
    rawDelta: z.null(),
    directionalDelta: z.null(),
    preferredDirection: z.enum(['HIGHER', 'LOWER']),
    outcome: z.null(),
    reasonCodes: z.array(pairedMetricInconclusiveReasonV1Schema).min(1).max(1),
  }),
]).superRefine((value, context) => {
  if (value.status !== 'MEASURED') return
  const rawDelta = value.candidateValue - value.baselineValue
  const directionalDelta = value.preferredDirection === 'HIGHER' ? rawDelta : -rawDelta
  const outcome = directionalDelta > 0
    ? 'IMPROVED'
    : directionalDelta < 0 ? 'REGRESSED' : 'EQUIVALENT'
  if (
    Math.abs(value.rawDelta - rawDelta) > Number.EPSILON * 4
    || Math.abs(value.directionalDelta - directionalDelta) > Number.EPSILON * 4
    || value.outcome !== outcome
  ) {
    context.addIssue({ code: 'custom', message: 'Inconsistent paired metric comparison.' })
  }
})

export type PairedMetricComparisonV1 = z.infer<typeof pairedMetricComparisonV1Schema>

export const pairedBudgetComparisonV1Schema = z.strictObject({
  view: z.enum(['MATCHED_BUDGET', 'NATIVE_PROFILE']),
  status: z.enum(['MATCHED', 'NATIVE_PROFILE', 'INCONCLUSIVE']),
  mismatchedDimensions: z.array(z.enum(EVALUATION_RESOURCE_DIMENSIONS)).max(
    EVALUATION_RESOURCE_DIMENSIONS.length,
  ),
  baseline: evaluationArmBudgetV1Schema,
  candidate: evaluationArmBudgetV1Schema,
}).superRefine((value, context) => {
  const expectedMismatches = EVALUATION_RESOURCE_DIMENSIONS.filter(dimension => (
    value.baseline.limits[dimension] !== value.candidate.limits[dimension]
  ))
  if (
    JSON.stringify(value.mismatchedDimensions) !== JSON.stringify(expectedMismatches)
    || (value.view === 'MATCHED_BUDGET' && value.mismatchedDimensions.length === 0
      && value.status !== 'MATCHED')
    || (value.view === 'MATCHED_BUDGET' && value.mismatchedDimensions.length > 0
      && value.status !== 'INCONCLUSIVE')
    || (value.view === 'NATIVE_PROFILE' && value.status !== 'NATIVE_PROFILE')
  ) {
    context.addIssue({ code: 'custom', message: 'Inconsistent budget comparison.' })
  }
})

export type PairedBudgetComparisonV1 = z.infer<typeof pairedBudgetComparisonV1Schema>

const nonInferiorityMeasureReasonV1Schema = z.enum([
  'INCOMPATIBLE_EVALUATION_DESIGN',
  'UNMATCHED_BUDGETS',
  'INCONCLUSIVE_ARM_UNCERTAINTY',
])

export const nonInferiorityMeasureV1Schema = z.discriminatedUnion('status', [
  z.strictObject({
    status: z.enum(['PASSED', 'FAILED']),
    margin: nonInferiorityMarginV1Schema,
    preferredDirection: z.enum(['HIGHER', 'LOWER']),
    baselineConfidenceInterval: repetitionConfidenceIntervalV1Schema,
    candidateConfidenceInterval: repetitionConfidenceIntervalV1Schema,
    conservativeDirectionalDelta: z.number().min(-1).max(1),
  }),
  z.strictObject({
    status: z.literal('INCONCLUSIVE'),
    margin: nonInferiorityMarginV1Schema,
    preferredDirection: z.enum(['HIGHER', 'LOWER']),
    baselineConfidenceInterval: z.null(),
    candidateConfidenceInterval: z.null(),
    conservativeDirectionalDelta: z.null(),
    reasonCodes: z.array(nonInferiorityMeasureReasonV1Schema).length(1),
  }),
]).superRefine((value, context) => {
  if (value.status === 'INCONCLUSIVE') return
  const expectedDelta = value.preferredDirection === 'HIGHER'
    ? value.candidateConfidenceInterval.lower - value.baselineConfidenceInterval.upper
    : value.baselineConfidenceInterval.lower - value.candidateConfidenceInterval.upper
  const expectedStatus = expectedDelta >= -value.margin ? 'PASSED' : 'FAILED'
  if (
    Math.abs(value.conservativeDirectionalDelta - expectedDelta) > Number.EPSILON * 4
    || value.status !== expectedStatus
  ) {
    context.addIssue({ code: 'custom', message: 'Inconsistent non-inferiority measure.' })
  }
})

export type NonInferiorityMeasureV1 = z.infer<typeof nonInferiorityMeasureV1Schema>

export const nonInferiorityComparisonV1Schema = z.strictObject({
  planId: boundedEvaluationIdSchema,
  registrationRecordId: boundedEvaluationIdSchema,
  registeredAtEpochMs: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER),
  evidenceCollectionStartedAtEpochMs: z.number().int().nonnegative()
    .max(Number.MAX_SAFE_INTEGER),
  method: z.literal('CONSERVATIVE_HOEFFDING_BOUNDS_V1'),
  status: z.enum(['PASSED', 'FAILED', 'INCONCLUSIVE']),
  reasonCodes: z.array(z.enum([
    'INCOMPATIBLE_EVALUATION_DESIGN',
    'UNMATCHED_BUDGETS',
    'INCONCLUSIVE_ARM_UNCERTAINTY',
    'REGRESSED_AGGREGATE_METRIC',
    'REGRESSED_MANDATORY_STRATUM',
  ])).max(5),
  metrics: z.strictObject({
    criticalHighValidatedRecall: nonInferiorityMeasureV1Schema,
    severityWeightedValidatedRecall: nonInferiorityMeasureV1Schema,
    validatedPrecision: nonInferiorityMeasureV1Schema,
    unsafeSatisfactionRate: nonInferiorityMeasureV1Schema,
    coverageHonestyRate: nonInferiorityMeasureV1Schema,
  }),
  strata: z.array(z.strictObject({
    stratumId: boundedEvaluationIdSchema,
    validatedRecall: nonInferiorityMeasureV1Schema,
  })).min(4).max(10_000),
}).superRefine((value, context) => {
  const measures = [
    ...Object.values(value.metrics),
    ...value.strata.map(item => item.validatedRecall),
  ]
  const expectedStatus = measures.some(item => item.status === 'FAILED')
    ? 'FAILED'
    : measures.some(item => item.status === 'INCONCLUSIVE') ? 'INCONCLUSIVE' : 'PASSED'
  if (
    value.registeredAtEpochMs >= value.evidenceCollectionStartedAtEpochMs
    || value.status !== expectedStatus
    || (value.status === 'PASSED' && value.reasonCodes.length !== 0)
    || (value.status !== 'PASSED' && value.reasonCodes.length === 0)
  ) {
    context.addIssue({ code: 'custom', message: 'Inconsistent non-inferiority comparison.' })
  }
})

export type NonInferiorityComparisonV1 = z.infer<
  typeof nonInferiorityComparisonV1Schema
>

export const pairedArmComparisonV1Schema = z.strictObject({
  schemaVersion: z.literal(1),
  engineId: z.literal(PAIRED_ARM_COMPARISON_ENGINE_ID),
  comparisonView: z.enum(['MATCHED_BUDGET', 'NATIVE_PROFILE']),
  conclusion: z.enum(['MEASURED', 'INCONCLUSIVE']),
  reasonCodes: z.array(z.enum([
    'INCOMPATIBLE_EVALUATION_DESIGN',
    'UNMATCHED_BUDGETS',
    'INCONCLUSIVE_ARM_METRICS',
  ])).max(3),
  baseline: z.strictObject({
    armId: boundedEvaluationIdSchema,
    metrics: effectivenessMetricsV1Schema,
  }),
  candidate: z.strictObject({
    armId: boundedEvaluationIdSchema,
    metrics: effectivenessMetricsV1Schema,
  }),
  budgetComparison: pairedBudgetComparisonV1Schema,
  metrics: z.strictObject({
    criticalHighValidatedRecall: pairedMetricComparisonV1Schema,
    severityWeightedValidatedRecall: pairedMetricComparisonV1Schema,
    validatedPrecision: pairedMetricComparisonV1Schema,
    unsafeSatisfactionRate: pairedMetricComparisonV1Schema,
    coverageHonestyRate: pairedMetricComparisonV1Schema,
  }),
  nonInferiority: nonInferiorityComparisonV1Schema.nullable(),
}).superRefine((value, context) => {
  const metrics = Object.values(value.metrics)
  if (
    (value.conclusion === 'MEASURED' && value.reasonCodes.length !== 0)
    || (value.conclusion === 'MEASURED' && (
      value.baseline.metrics.conclusion !== 'MEASURED'
      || value.candidate.metrics.conclusion !== 'MEASURED'
      || value.budgetComparison.status === 'INCONCLUSIVE'
      || metrics.some(metric => metric.status !== 'MEASURED')
    ))
    || (value.conclusion === 'INCONCLUSIVE' && value.reasonCodes.length === 0)
  ) {
    context.addIssue({ code: 'custom', message: 'Inconsistent paired Arm conclusion.' })
  }
})

export type PairedArmComparisonV1 = z.infer<typeof pairedArmComparisonV1Schema>

/** Stable, detail-free rejection for malformed or internally inconsistent evaluation evidence. */
export class EvaluationMetricsInputError extends Error {
  readonly code = 'INVALID_EVALUATION_EVIDENCE' as const

  constructor() {
    super('Evaluation evidence does not match Effectiveness Metrics Engine v1.')
    this.name = 'EvaluationMetricsInputError'
  }
}

/** Stable, detail-free rejection for malformed paired Arm or resource evidence. */
export class PairedArmComparisonInputError extends Error {
  readonly code = 'INVALID_PAIRED_ARM_EVIDENCE' as const

  constructor() {
    super('Paired Arm evidence does not match Comparison Engine v1.')
    this.name = 'PairedArmComparisonInputError'
  }
}

function invalidEvidence(): never {
  throw new EvaluationMetricsInputError()
}

function unique(values: readonly string[]): boolean {
  return new Set(values).size === values.length
}

function stratumSelectorKey(selector: BenchmarkStratumSelectorV1): string {
  return `${selector.dimension}\0${selector.value}`
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
  const stratumSelectors = parsed.data.stratumDefinitions.map(item => (
    stratumSelectorKey(item.selector)
  ))
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
      parsed.data.stratumDefinitions.some(
        item => item.maximumValidatedRecallIntervalWidth !== undefined,
      )
      || parsed.data.cases.some(item => item.repetitionId !== undefined)
      || !unique(parsed.data.cases.map(item => item.caseId))
    ) {
      return invalidEvidence()
    }
  } else {
    if (
      !unique(repetitionPlan.repetitionIds)
      || !unique(repetitionPlan.benchmarkCaseIds)
      || parsed.data.stratumDefinitions.some(
        item => item.maximumValidatedRecallIntervalWidth === undefined,
      )
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

const effectivenessMetricDirections = {
  criticalHighValidatedRecall: 'MINIMUM',
  severityWeightedValidatedRecall: 'MINIMUM',
  validatedPrecision: 'MINIMUM',
  unsafeSatisfactionRate: 'MAXIMUM',
  coverageHonestyRate: 'MINIMUM',
} as const

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
  const metricNames = Object.keys(effectivenessMetricDirections) as Array<
    keyof typeof effectivenessMetricDirections
  >
  const distributions = {} as RepetitionAnalysisV1['metrics']

  if (!matrixComplete) {
    for (const metricName of metricNames) {
      distributions[metricName] = inconclusiveDistribution(
        effectivenessMetricDirections[metricName],
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
          effectivenessMetricDirections[metricName],
          'INCOMPLETE_REPETITION_METRICS',
        )
      } else {
        distributions[metricName] = calculateDistribution(
          ratios.map(metric => metric.value as number),
          effectivenessMetricDirections[metricName],
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

type StratumRecallCounts = {
  matched: number
  total: number
  matchedWeighted: number
  totalWeighted: number
}

function calculateStratumUncertaintyAnalyses(
  request: EffectivenessMetricsRequestV1,
  repetitionAnalysis: RepetitionAnalysisV1 | null,
): Map<string, StratumUncertaintyAnalysisV1> {
  const plan = request.repetitionPlan
  if (plan === undefined || repetitionAnalysis === null) return new Map()

  const definitionsBySelector = new Map(
    request.stratumDefinitions.map(definition => [
      stratumSelectorKey(definition.selector),
      definition,
    ]),
  )
  const countsByRepetition = new Map<string, Map<string, StratumRecallCounts>>()
  for (const repetitionId of plan.repetitionIds) {
    countsByRepetition.set(repetitionId, new Map())
  }

  for (const item of request.cases) {
    if (item.disposition === 'BENCHMARK_INVALID') continue
    const repetitionCounts = countsByRepetition.get(item.repetitionId as string)
    if (repetitionCounts === undefined) continue
    const matchedDefects = new Set<string>()
    if (item.result.kind === 'COMPLETED') {
      for (const finding of item.result.findings) {
        if (finding.adjudication.status === 'MATCHED') {
          matchedDefects.add(finding.adjudication.defectId)
        }
      }
    }
    const caseDefinitions = [
      definitionsBySelector.get(`ASSESSMENT_MODE\0${item.assessmentMode}`),
      definitionsBySelector.get(`SUPPORTED_ECOSYSTEM\0${item.supportedEcosystem}`),
    ]
    for (const defect of item.groundTruthDefects) {
      const definitions = [
        definitionsBySelector.get(`SEVERITY\0${defect.severity}`),
        definitionsBySelector.get(`WEAKNESS_FAMILY\0${defect.weaknessFamily}`),
        ...caseDefinitions,
      ]
      for (const definition of definitions) {
        if (definition === undefined) continue
        const counts = repetitionCounts.get(definition.stratumId) ?? {
          matched: 0,
          total: 0,
          matchedWeighted: 0,
          totalWeighted: 0,
        }
        const weight = request.severityWeights[defect.severity]
        counts.total += 1
        counts.totalWeighted += weight
        if (matchedDefects.has(defect.defectId)) {
          counts.matched += 1
          counts.matchedWeighted += weight
        }
        repetitionCounts.set(definition.stratumId, counts)
      }
    }
  }

  const matrixIncomplete = repetitionAnalysis.reasonCodes.includes(
    'INCOMPLETE_REPETITION_CASE_MATRIX',
  )
  const analyses = new Map<string, StratumUncertaintyAnalysisV1>()
  for (const definition of request.stratumDefinitions) {
    const maximumWidth = definition.maximumValidatedRecallIntervalWidth as number
    let validatedRecall: RepetitionMetricDistributionV1
    let severityWeightedValidatedRecall: RepetitionMetricDistributionV1
    if (matrixIncomplete) {
      validatedRecall = inconclusiveDistribution('MINIMUM', 'INCOMPLETE_REPETITION_METRICS')
      severityWeightedValidatedRecall = inconclusiveDistribution(
        'MINIMUM',
        'INCOMPLETE_REPETITION_METRICS',
      )
    } else {
      const counts = [...plan.repetitionIds]
        .sort(compareIds)
        .map(repetitionId => countsByRepetition.get(repetitionId)?.get(definition.stratumId) ?? {
          matched: 0,
          total: 0,
          matchedWeighted: 0,
          totalWeighted: 0,
        })
      const recalls = counts.map(item => ratio(item.matched, item.total))
      const weightedRecalls = counts.map(item => ratio(
        item.matchedWeighted,
        item.totalWeighted,
      ))
      const distributionPlan = {
        ...plan,
        maximumConfidenceIntervalWidth: maximumWidth,
      }
      validatedRecall = recalls.some(metric => metric.status === 'INCONCLUSIVE')
        ? inconclusiveDistribution('MINIMUM', 'INCOMPLETE_REPETITION_METRICS')
        : calculateDistribution(
            recalls.map(metric => metric.value as number),
            'MINIMUM',
            distributionPlan,
          )
      severityWeightedValidatedRecall = weightedRecalls.some(
        metric => metric.status === 'INCONCLUSIVE',
      )
        ? inconclusiveDistribution('MINIMUM', 'INCOMPLETE_REPETITION_METRICS')
        : calculateDistribution(
            weightedRecalls.map(metric => metric.value as number),
            'MINIMUM',
            distributionPlan,
          )
    }

    const metrics = { validatedRecall, severityWeightedValidatedRecall }
    const reasonCodes: StratumUncertaintyAnalysisV1['reasonCodes'] = []
    if (Object.values(metrics).some(metric => metric.status === 'INCONCLUSIVE')) {
      reasonCodes.push('INCOMPLETE_REPETITION_METRICS')
    }
    if (Object.values(metrics).some(metric => (
      metric.status === 'MEASURED'
      && metric.uncertaintyStatus === 'INCONCLUSIVE'
    ))) {
      reasonCodes.push('EXCESSIVE_CONFIDENCE_INTERVAL_WIDTH')
    }
    analyses.set(definition.stratumId, {
      method: plan.method,
      confidenceLevel: plan.confidenceLevel,
      maximumValidatedRecallIntervalWidth: maximumWidth,
      status: reasonCodes.length === 0 ? 'SUFFICIENT' : 'INCONCLUSIVE',
      reasonCodes,
      metrics,
    })
  }
  return analyses
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
  const repetitionAnalysis = calculateRepetitionAnalysis(request)
  const stratumUncertaintyAnalyses = calculateStratumUncertaintyAnalyses(
    request,
    repetitionAnalysis,
  )

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
      const uncertainty = stratumUncertaintyAnalyses.get(definition.stratumId)
      const reasonCodes: BenchmarkStratumResultV1['reasonCodes'] = []
      if (observedSamples < definition.minimumSamples) {
        reasonCodes.push('INSUFFICIENT_SAMPLE_COUNT')
      }
      if (uncertainty?.reasonCodes.includes('INCOMPLETE_REPETITION_METRICS')) {
        reasonCodes.push('INCOMPLETE_REPETITION_METRICS')
      }
      if (uncertainty?.reasonCodes.includes('EXCESSIVE_CONFIDENCE_INTERVAL_WIDTH')) {
        reasonCodes.push('EXCESSIVE_CONFIDENCE_INTERVAL_WIDTH')
      }
      return {
        stratumId: definition.stratumId,
        selector: definition.selector,
        sampleUnit,
        minimumSamples: definition.minimumSamples,
        observedSamples,
        status: reasonCodes.length === 0 ? 'SUFFICIENT' : 'INCONCLUSIVE',
        reasonCodes,
        ...(uncertainty === undefined ? {} : { uncertainty }),
      }
    })
    .sort((left, right) => compareIds(left.stratumId, right.stratumId))
  const sufficientStrata = strata.filter(item => item.status === 'SUFFICIENT').length
  const inconclusiveStrata = strata.length - sufficientStrata

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

function invalidPairedArmEvidence(): never {
  throw new PairedArmComparisonInputError()
}

function parsePairedArmComparisonRequest(input: unknown): PairedArmComparisonRequestV1 {
  const parsed = pairedArmComparisonRequestV1Schema.safeParse(input)
  if (!parsed.success || parsed.data.baseline.armId === parsed.data.candidate.armId) {
    return invalidPairedArmEvidence()
  }
  const plan = parsed.data.nonInferiorityPlan
  if (plan !== undefined) {
    const expectedStratumIds = [...parsed.data.baseline.metricsRequest.stratumDefinitions]
      .map(item => item.stratumId)
      .sort(compareIds)
    const marginStratumIds = plan.stratumMargins
      .map(item => item.stratumId)
      .sort(compareIds)
    if (
      parsed.data.comparisonView !== 'MATCHED_BUDGET'
      || JSON.stringify(expectedStratumIds) !== JSON.stringify(marginStratumIds)
    ) {
      return invalidPairedArmEvidence()
    }
  }
  for (const arm of [parsed.data.baseline, parsed.data.candidate]) {
    for (const dimension of EVALUATION_RESOURCE_DIMENSIONS) {
      if (arm.budget.usage[dimension] > arm.budget.limits[dimension]) {
        return invalidPairedArmEvidence()
      }
    }
  }
  return parsed.data
}

function compareNonInferiorityDistribution(
  baseline: RepetitionMetricDistributionV1 | undefined,
  candidate: RepetitionMetricDistributionV1 | undefined,
  margin: number,
  worstDirection: 'MINIMUM' | 'MAXIMUM',
  blockedReason?: 'INCOMPATIBLE_EVALUATION_DESIGN' | 'UNMATCHED_BUDGETS',
): NonInferiorityMeasureV1 {
  const preferredDirection = worstDirection === 'MINIMUM' ? 'HIGHER' : 'LOWER'
  if (
    blockedReason !== undefined
    || baseline === undefined
    || candidate === undefined
    || baseline.status !== 'MEASURED'
    || candidate.status !== 'MEASURED'
    || baseline.uncertaintyStatus !== 'SUFFICIENT'
    || candidate.uncertaintyStatus !== 'SUFFICIENT'
  ) {
    return {
      status: 'INCONCLUSIVE',
      margin,
      preferredDirection,
      baselineConfidenceInterval: null,
      candidateConfidenceInterval: null,
      conservativeDirectionalDelta: null,
      reasonCodes: [blockedReason ?? 'INCONCLUSIVE_ARM_UNCERTAINTY'],
    }
  }
  const baselineConfidenceInterval = baseline.confidenceInterval
  const candidateConfidenceInterval = candidate.confidenceInterval
  const directed = preferredDirection === 'HIGHER'
    ? candidateConfidenceInterval.lower - baselineConfidenceInterval.upper
    : baselineConfidenceInterval.lower - candidateConfidenceInterval.upper
  const conservativeDirectionalDelta = directed === 0 ? 0 : directed
  return {
    status: conservativeDirectionalDelta >= -margin ? 'PASSED' : 'FAILED',
    margin,
    preferredDirection,
    baselineConfidenceInterval,
    candidateConfidenceInterval,
    conservativeDirectionalDelta,
  }
}

function calculateNonInferiorityComparison(
  request: PairedArmComparisonRequestV1,
  baselineMetrics: EffectivenessMetricsV1,
  candidateMetrics: EffectivenessMetricsV1,
  compatibleDesign: boolean,
  matchedBudgetBlocked: boolean,
): NonInferiorityComparisonV1 | null {
  const plan = request.nonInferiorityPlan
  if (plan === undefined) return null
  const blockedReason = !compatibleDesign
    ? 'INCOMPATIBLE_EVALUATION_DESIGN' as const
    : matchedBudgetBlocked ? 'UNMATCHED_BUDGETS' as const : undefined
  const metricNames = Object.keys(effectivenessMetricDirections) as Array<
    keyof typeof effectivenessMetricDirections
  >
  const metrics = {} as NonInferiorityComparisonV1['metrics']
  for (const metricName of metricNames) {
    metrics[metricName] = compareNonInferiorityDistribution(
      baselineMetrics.repetitionAnalysis?.metrics[metricName],
      candidateMetrics.repetitionAnalysis?.metrics[metricName],
      plan.metricMargins[metricName],
      effectivenessMetricDirections[metricName],
      blockedReason,
    )
  }
  const baselineStrata = new Map(baselineMetrics.strata.map(item => [item.stratumId, item]))
  const candidateStrata = new Map(candidateMetrics.strata.map(item => [item.stratumId, item]))
  const strata = [...plan.stratumMargins]
    .sort((left, right) => compareIds(left.stratumId, right.stratumId))
    .map(item => ({
      stratumId: item.stratumId,
      validatedRecall: compareNonInferiorityDistribution(
        baselineStrata.get(item.stratumId)?.uncertainty?.metrics.validatedRecall,
        candidateStrata.get(item.stratumId)?.uncertainty?.metrics.validatedRecall,
        item.validatedRecallMargin,
        'MINIMUM',
        blockedReason,
      ),
    }))
  const measures = [...Object.values(metrics), ...strata.map(item => item.validatedRecall)]
  const reasonCodes: NonInferiorityComparisonV1['reasonCodes'] = []
  if (blockedReason !== undefined) {
    reasonCodes.push(blockedReason)
  } else {
    if (Object.values(metrics).some(item => item.status === 'FAILED')) {
      reasonCodes.push('REGRESSED_AGGREGATE_METRIC')
    }
    if (strata.some(item => item.validatedRecall.status === 'FAILED')) {
      reasonCodes.push('REGRESSED_MANDATORY_STRATUM')
    }
    if (measures.some(item => item.status === 'INCONCLUSIVE')) {
      reasonCodes.push('INCONCLUSIVE_ARM_UNCERTAINTY')
    }
  }
  const status = measures.some(item => item.status === 'FAILED')
    ? 'FAILED'
    : measures.some(item => item.status === 'INCONCLUSIVE') ? 'INCONCLUSIVE' : 'PASSED'
  return {
    planId: plan.planId,
    registrationRecordId: plan.registrationRecordId,
    registeredAtEpochMs: plan.registeredAtEpochMs,
    evidenceCollectionStartedAtEpochMs: plan.evidenceCollectionStartedAtEpochMs,
    method: plan.method,
    status,
    reasonCodes,
    metrics,
    strata,
  }
}

function canonicalEvaluationDesign(request: EffectivenessMetricsRequestV1): string {
  const stratumDefinitions = [...request.stratumDefinitions]
    .sort((left, right) => compareIds(left.stratumId, right.stratumId))
  const repetitionPlan = request.repetitionPlan === undefined
    ? null
    : {
        ...request.repetitionPlan,
        repetitionIds: [...request.repetitionPlan.repetitionIds].sort(compareIds),
        benchmarkCaseIds: [...request.repetitionPlan.benchmarkCaseIds].sort(compareIds),
      }
  const cases = request.cases
    .map(item => ({
      caseId: item.caseId,
      repetitionId: item.repetitionId ?? null,
      disposition: item.disposition,
      assessmentMode: item.assessmentMode,
      supportedEcosystem: item.supportedEcosystem,
      expectedCoverage: item.expectedCoverage,
      groundTruthDefects: [...item.groundTruthDefects]
        .sort((left, right) => compareIds(left.defectId, right.defectId)),
    }))
    .sort((left, right) => compareIds(
      `${left.repetitionId ?? ''}\0${left.caseId}`,
      `${right.repetitionId ?? ''}\0${right.caseId}`,
    ))
  return JSON.stringify({
    schemaVersion: request.schemaVersion,
    engineId: request.engineId,
    severityWeights: request.severityWeights,
    stratumDefinitions,
    repetitionPlan,
    cases,
  })
}

function comparePairedMetric(
  baseline: EffectivenessRatioMetricV1,
  candidate: EffectivenessRatioMetricV1,
  worstDirection: 'MINIMUM' | 'MAXIMUM',
  blockedReason?: 'INCOMPATIBLE_EVALUATION_DESIGN' | 'UNMATCHED_BUDGETS',
): PairedMetricComparisonV1 {
  const preferredDirection = worstDirection === 'MINIMUM' ? 'HIGHER' : 'LOWER'
  if (
    blockedReason !== undefined
    || baseline.status === 'INCONCLUSIVE'
    || candidate.status === 'INCONCLUSIVE'
  ) {
    return {
      status: 'INCONCLUSIVE',
      baselineValue: baseline.value,
      candidateValue: candidate.value,
      rawDelta: null,
      directionalDelta: null,
      preferredDirection,
      outcome: null,
      reasonCodes: [blockedReason ?? 'INCONCLUSIVE_ARM_METRIC'],
    }
  }
  const rawDelta = candidate.value - baseline.value
  const directed = preferredDirection === 'HIGHER' ? rawDelta : -rawDelta
  const directionalDelta = directed === 0 ? 0 : directed
  return {
    status: 'MEASURED',
    baselineValue: baseline.value,
    candidateValue: candidate.value,
    rawDelta: rawDelta === 0 ? 0 : rawDelta,
    directionalDelta,
    preferredDirection,
    outcome: directionalDelta > 0
      ? 'IMPROVED'
      : directionalDelta < 0 ? 'REGRESSED' : 'EQUIVALENT',
  }
}

/**
 * Compare two complete Evaluation Arms against one frozen design. Matched-budget
 * comparisons require exact equality across every declared resource ceiling;
 * native-profile comparisons retain and disclose differences without treating
 * them as equivalent budgets.
 */
export function calculatePairedArmComparisonV1(input: unknown): PairedArmComparisonV1 {
  const request = parsePairedArmComparisonRequest(input)
  let baselineMetrics: EffectivenessMetricsV1
  let candidateMetrics: EffectivenessMetricsV1
  try {
    baselineMetrics = calculateEffectivenessMetricsV1(request.baseline.metricsRequest)
    candidateMetrics = calculateEffectivenessMetricsV1(request.candidate.metricsRequest)
  } catch (error) {
    if (error instanceof EvaluationMetricsInputError) return invalidPairedArmEvidence()
    throw error
  }

  const compatibleDesign = canonicalEvaluationDesign(request.baseline.metricsRequest)
    === canonicalEvaluationDesign(request.candidate.metricsRequest)
  const mismatchedDimensions = EVALUATION_RESOURCE_DIMENSIONS.filter(dimension => (
    request.baseline.budget.limits[dimension]
    !== request.candidate.budget.limits[dimension]
  ))
  const matchedBudgetBlocked = request.comparisonView === 'MATCHED_BUDGET'
    && mismatchedDimensions.length > 0
  const budgetComparison: PairedBudgetComparisonV1 = {
    view: request.comparisonView,
    status: request.comparisonView === 'NATIVE_PROFILE'
      ? 'NATIVE_PROFILE'
      : matchedBudgetBlocked ? 'INCONCLUSIVE' : 'MATCHED',
    mismatchedDimensions,
    baseline: request.baseline.budget,
    candidate: request.candidate.budget,
  }
  const blockedReason = !compatibleDesign
    ? 'INCOMPATIBLE_EVALUATION_DESIGN' as const
    : matchedBudgetBlocked ? 'UNMATCHED_BUDGETS' as const : undefined
  const metricNames = Object.keys(effectivenessMetricDirections) as Array<
    keyof typeof effectivenessMetricDirections
  >
  const metricComparisons = {} as PairedArmComparisonV1['metrics']
  for (const metricName of metricNames) {
    metricComparisons[metricName] = comparePairedMetric(
      baselineMetrics.metrics[metricName],
      candidateMetrics.metrics[metricName],
      effectivenessMetricDirections[metricName],
      blockedReason,
    )
  }

  const reasonCodes: PairedArmComparisonV1['reasonCodes'] = []
  if (!compatibleDesign) reasonCodes.push('INCOMPATIBLE_EVALUATION_DESIGN')
  if (matchedBudgetBlocked) reasonCodes.push('UNMATCHED_BUDGETS')
  if (
    baselineMetrics.conclusion === 'INCONCLUSIVE'
    || candidateMetrics.conclusion === 'INCONCLUSIVE'
  ) {
    reasonCodes.push('INCONCLUSIVE_ARM_METRICS')
  }
  const result: PairedArmComparisonV1 = {
    schemaVersion: 1,
    engineId: PAIRED_ARM_COMPARISON_ENGINE_ID,
    comparisonView: request.comparisonView,
    conclusion: reasonCodes.length === 0 ? 'MEASURED' : 'INCONCLUSIVE',
    reasonCodes,
    baseline: { armId: request.baseline.armId, metrics: baselineMetrics },
    candidate: { armId: request.candidate.armId, metrics: candidateMetrics },
    budgetComparison,
    metrics: metricComparisons,
    nonInferiority: calculateNonInferiorityComparison(
      request,
      baselineMetrics,
      candidateMetrics,
      compatibleDesign,
      matchedBudgetBlocked,
    ),
  }
  return deepFreeze(pairedArmComparisonV1Schema.parse(result))
}
