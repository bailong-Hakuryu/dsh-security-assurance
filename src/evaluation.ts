import { z } from 'zod'
import { digestEnvelopeV1Schema } from './digest-envelope.ts'

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

export const AIR_GAPPED_EVALUATION_ENGINE_ID = 'security/air-gapped-evaluation/v1' as const

const evaluationEpochMsSchema = z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER)

export const airGappedRunnerInputV1Schema = z.strictObject({
  schemaVersion: z.literal(1),
  runId: boundedEvaluationIdSchema,
  caseId: boundedEvaluationIdSchema,
  repetitionId: boundedEvaluationIdSchema.optional(),
  opaqueSubjectHandleId: boundedEvaluationIdSchema,
  subjectDigest: digestEnvelopeV1Schema,
  assessmentMode: evaluationAssessmentModeSchema,
  supportedEcosystem: boundedEvaluationIdSchema,
  executionGrantId: boundedEvaluationIdSchema,
  admittedAtEpochMs: evaluationEpochMsSchema,
})

export type AirGappedRunnerInputV1 = z.infer<typeof airGappedRunnerInputV1Schema>

export const airGappedRunnerResultV1Schema = z.discriminatedUnion('kind', [
  z.strictObject({
    kind: z.literal('COMPLETED'),
    verdict: z.enum(['SATISFIED', 'FAILED', 'INDETERMINATE']),
    coverageStatus: z.enum(['COMPLETE', 'GAP']),
    findings: z.array(z.strictObject({
      findingId: boundedEvaluationIdSchema,
    })).max(10_000),
  }),
  evaluationProductFailureV1Schema,
])

export type AirGappedRunnerResultV1 = z.infer<typeof airGappedRunnerResultV1Schema>

export const sealedAirGappedArmResultV1Schema = z.strictObject({
  sealedResultId: boundedEvaluationIdSchema,
  armId: boundedEvaluationIdSchema,
  runnerInput: airGappedRunnerInputV1Schema,
  result: airGappedRunnerResultV1Schema,
  sealedAtEpochMs: evaluationEpochMsSchema,
  resultDigest: digestEnvelopeV1Schema,
}).superRefine((value, context) => {
  if (value.sealedAtEpochMs < value.runnerInput.admittedAtEpochMs) {
    context.addIssue({ code: 'custom', message: 'Arm result was sealed before admission.' })
  }
  if (
    value.result.kind === 'COMPLETED'
    && new Set(value.result.findings.map(item => item.findingId)).size
      !== value.result.findings.length
  ) {
    context.addIssue({ code: 'custom', message: 'Duplicate sealed Finding identity.' })
  }
})

export type SealedAirGappedArmResultV1 = z.infer<
  typeof sealedAirGappedArmResultV1Schema
>

export const sealedGroundTruthManifestV1Schema = z.strictObject({
  manifestId: boundedEvaluationIdSchema,
  corpusVersionId: boundedEvaluationIdSchema,
  sealedAtEpochMs: evaluationEpochMsSchema,
  manifestDigest: digestEnvelopeV1Schema,
  canaryMarkerIds: z.array(boundedEvaluationIdSchema).min(1).max(1_000),
  cases: z.array(z.strictObject({
    caseId: boundedEvaluationIdSchema,
    repetitionId: boundedEvaluationIdSchema.optional(),
    subjectDigest: digestEnvelopeV1Schema,
    disposition: z.enum(['INCLUDED', 'BENCHMARK_INVALID']),
    assessmentMode: evaluationAssessmentModeSchema,
    supportedEcosystem: boundedEvaluationIdSchema,
    expectedCoverage: z.enum(['COMPLETE', 'INCOMPLETE_OR_UNSUPPORTED']),
    groundTruthDefects: z.array(evaluationGroundTruthDefectV1Schema).max(10_000),
  })).min(1).max(10_000),
}).superRefine((value, context) => {
  const caseKeys = value.cases.map(item => (
    `${item.repetitionId ?? ''}\0${item.caseId}`
  ))
  if (new Set(caseKeys).size !== caseKeys.length) {
    context.addIssue({ code: 'custom', message: 'Duplicate Ground Truth Case identity.' })
  }
  if (new Set(value.canaryMarkerIds).size !== value.canaryMarkerIds.length) {
    context.addIssue({ code: 'custom', message: 'Duplicate Ground Truth canary identity.' })
  }
})

export type SealedGroundTruthManifestV1 = z.infer<
  typeof sealedGroundTruthManifestV1Schema
>

export const preRegisteredMatchingContractV1Schema = z.strictObject({
  contractId: boundedEvaluationIdSchema,
  registrationRecordId: boundedEvaluationIdSchema,
  registeredAtEpochMs: evaluationEpochMsSchema,
  contractDigest: digestEnvelopeV1Schema,
})

export type PreRegisteredMatchingContractV1 = z.infer<
  typeof preRegisteredMatchingContractV1Schema
>

export const airGappedFindingAdjudicationV1Schema = z.strictObject({
  armId: boundedEvaluationIdSchema,
  caseId: boundedEvaluationIdSchema,
  repetitionId: boundedEvaluationIdSchema.optional(),
  findingId: boundedEvaluationIdSchema,
  adjudication: findingAdjudicationV1Schema,
  adjudicationRecordId: boundedEvaluationIdSchema,
})

export type AirGappedFindingAdjudicationV1 = z.infer<
  typeof airGappedFindingAdjudicationV1Schema
>

const airGapViolationTypeV1Schema = z.enum([
  'GROUND_TRUTH_ACCESS',
  'EXPECTED_FINDING_ACCESS',
  'SEED_METADATA_ACCESS',
  'MATCHING_RULE_ACCESS',
  'ARM_LABEL_ACCESS',
  'CANARY_MARKER_OBSERVED',
  'BENCHMARK_HINT_DETECTED',
])

export const airGapAccessAuditV1Schema = z.strictObject({
  auditId: boundedEvaluationIdSchema,
  completedAtEpochMs: evaluationEpochMsSchema,
  auditedArmIds: z.array(boundedEvaluationIdSchema).min(1).max(1_000),
  auditedSealedResultIds: z.array(boundedEvaluationIdSchema).min(1).max(10_000),
  violations: z.array(z.strictObject({
    type: airGapViolationTypeV1Schema,
    evidenceDigest: digestEnvelopeV1Schema,
    armId: boundedEvaluationIdSchema.optional(),
    caseId: boundedEvaluationIdSchema.optional(),
  })).max(10_000),
}).superRefine((value, context) => {
  if (
    new Set(value.auditedArmIds).size !== value.auditedArmIds.length
    || new Set(value.auditedSealedResultIds).size !== value.auditedSealedResultIds.length
  ) {
    context.addIssue({ code: 'custom', message: 'Duplicate air-gap audit coverage.' })
  }
})

export type AirGapAccessAuditV1 = z.infer<typeof airGapAccessAuditV1Schema>

export const airGappedEvaluationAssemblyRequestV1Schema = z.strictObject({
  schemaVersion: z.literal(1),
  engineId: z.literal(AIR_GAPPED_EVALUATION_ENGINE_ID),
  runId: boundedEvaluationIdSchema,
  evaluatorId: boundedEvaluationIdSchema,
  evaluatorAuthorizationRecordId: boundedEvaluationIdSchema,
  declaredArmIds: z.array(boundedEvaluationIdSchema).min(1).max(1_000),
  severityWeights: effectivenessMetricsRequestV1Schema.shape.severityWeights,
  stratumDefinitions: z.array(benchmarkStratumDefinitionV1Schema).min(4).max(10_000),
  repetitionPlan: benchmarkRepetitionPlanV1Schema.optional(),
  matchingContract: preRegisteredMatchingContractV1Schema,
  groundTruthManifest: sealedGroundTruthManifestV1Schema,
  groundTruthOpenedAtEpochMs: evaluationEpochMsSchema,
  sealedArmResults: z.array(sealedAirGappedArmResultV1Schema).min(1).max(100_000),
  adjudications: z.array(airGappedFindingAdjudicationV1Schema).max(100_000),
  airGapAudit: airGapAccessAuditV1Schema,
})

export type AirGappedEvaluationAssemblyRequestV1 = z.infer<
  typeof airGappedEvaluationAssemblyRequestV1Schema
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

const airGappedInvalidationReasonV1Schema = z.enum([
  'GROUND_TRUTH_LEAKAGE_DETECTED',
  'GROUND_TRUTH_OPENED_BEFORE_ALL_RESULTS_SEALED',
  'POST_HOC_MATCHING_CONTRACT',
  'INCOMPLETE_AIR_GAP_AUDIT',
  'INCOMPLETE_SEALED_ARM_RESULTS',
  'UNDECLARED_RUNNER_CASE',
])

export const airGappedEvaluationAssemblyV1Schema = z.discriminatedUnion('status', [
  z.strictObject({
    schemaVersion: z.literal(1),
    engineId: z.literal(AIR_GAPPED_EVALUATION_ENGINE_ID),
    status: z.literal('READY'),
    runId: boundedEvaluationIdSchema,
    evaluatorId: boundedEvaluationIdSchema,
    evaluatorAuthorizationRecordId: boundedEvaluationIdSchema,
    groundTruthManifestId: boundedEvaluationIdSchema,
    matchingContractId: boundedEvaluationIdSchema,
    airGapAuditId: boundedEvaluationIdSchema,
    reasonCodes: z.array(airGappedInvalidationReasonV1Schema).length(0),
    affectedArmIds: z.array(boundedEvaluationIdSchema).min(1).max(1_000),
    arms: z.array(z.strictObject({
      armId: boundedEvaluationIdSchema,
      metricsRequest: effectivenessMetricsRequestV1Schema,
      metrics: effectivenessMetricsV1Schema,
    })).min(1).max(1_000),
  }).superRefine((value, context) => {
    const armIds = value.arms.map(item => item.armId)
    if (
      new Set(armIds).size !== armIds.length
      || JSON.stringify(armIds) !== JSON.stringify(value.affectedArmIds)
    ) {
      context.addIssue({ code: 'custom', message: 'Inconsistent assembled Arm identities.' })
    }
  }),
  z.strictObject({
    schemaVersion: z.literal(1),
    engineId: z.literal(AIR_GAPPED_EVALUATION_ENGINE_ID),
    status: z.literal('INVALIDATED'),
    runId: boundedEvaluationIdSchema,
    evaluatorId: boundedEvaluationIdSchema,
    evaluatorAuthorizationRecordId: boundedEvaluationIdSchema,
    groundTruthManifestId: boundedEvaluationIdSchema,
    matchingContractId: boundedEvaluationIdSchema,
    airGapAuditId: boundedEvaluationIdSchema,
    reasonCodes: z.array(airGappedInvalidationReasonV1Schema).min(1).max(6),
    affectedArmIds: z.array(boundedEvaluationIdSchema).min(1).max(1_000),
    arms: z.null(),
  }),
])

export type AirGappedEvaluationAssemblyV1 = z.infer<
  typeof airGappedEvaluationAssemblyV1Schema
>

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

export const UTILITY_METRICS_ENGINE_ID = 'security/utility-metrics/v1' as const

const controlPlaneUtilityEvidenceV1Schema = z.discriminatedUnion('applicability', [
  z.strictObject({ applicability: z.literal('NOT_APPLICABLE') }),
  z.strictObject({
    applicability: z.literal('APPLICABLE'),
    decisions: resourceQuantitySchema,
    validApprovals: resourceQuantitySchema,
    unsafeApprovals: resourceQuantitySchema,
  }).superRefine((value, context) => {
    if (
      value.validApprovals > value.decisions
      || value.unsafeApprovals > value.decisions
      || value.validApprovals + value.unsafeApprovals > value.decisions
    ) {
      context.addIssue({ code: 'custom', message: 'Inconsistent Control Plane utility counts.' })
    }
  }),
])

export const utilityEvidenceV1Schema = z.strictObject({
  executionCostMicrounits: resourceQuantitySchema,
  firstValidatedFindingMs: resourceQuantitySchema.nullable(),
  humanTriageMs: resourceQuantitySchema,
  remediation: z.strictObject({
    attempts: resourceQuantitySchema,
    verifiedSuccesses: resourceQuantitySchema,
    totalVerifiedSuccessDurationMs: resourceQuantitySchema,
  }),
  unnecessaryReworkCount: resourceQuantitySchema,
  controlPlane: controlPlaneUtilityEvidenceV1Schema,
}).superRefine((value, context) => {
  if (
    value.remediation.verifiedSuccesses > value.remediation.attempts
    || (value.remediation.verifiedSuccesses === 0
      && value.remediation.totalVerifiedSuccessDurationMs !== 0)
  ) {
    context.addIssue({ code: 'custom', message: 'Inconsistent verified remediation evidence.' })
  }
})

export type UtilityEvidenceV1 = z.infer<typeof utilityEvidenceV1Schema>

export const utilityMetricsRequestV1Schema = z.strictObject({
  schemaVersion: z.literal(1),
  engineId: z.literal(UTILITY_METRICS_ENGINE_ID),
  effectivenessRequest: effectivenessMetricsRequestV1Schema,
  budget: evaluationArmBudgetV1Schema,
  evidence: utilityEvidenceV1Schema,
})

export type UtilityMetricsRequestV1 = z.infer<typeof utilityMetricsRequestV1Schema>

const utilityMetricUnitV1Schema = z.enum([
  'VALIDATED_FINDINGS_PER_RUNTIME_HOUR',
  'VALIDATED_FINDINGS_PER_COST_UNIT',
  'MILLISECONDS',
  'MINUTES_PER_VALIDATED_FINDING',
  'RATIO',
  'COUNT',
])

const utilityMetricReasonV1Schema = z.enum([
  'INCOMPLETE_FINDING_ADJUDICATION',
  'NO_VALIDATED_FINDINGS',
  'NO_RECORDED_RUNTIME',
  'NO_RECORDED_COST',
  'NO_REMEDIATION_ATTEMPTS',
  'NO_VERIFIED_REMEDIATIONS',
  'CONTROL_PLANE_NOT_APPLICABLE',
  'NO_CONTROL_PLANE_DECISIONS',
])

const utilityMetricCalculationV1Schema = z.strictObject({
  numerator: resourceQuantitySchema,
  denominator: z.number().int().positive().max(Number.MAX_SAFE_INTEGER),
  normalizationFactor: z.number().positive().max(Number.MAX_SAFE_INTEGER),
})

export const utilityMetricV1Schema = z.discriminatedUnion('status', [
  z.strictObject({
    status: z.literal('MEASURED'),
    value: z.number().nonnegative(),
    unit: utilityMetricUnitV1Schema,
    preferredDirection: z.enum(['HIGHER', 'LOWER']),
    calculation: utilityMetricCalculationV1Schema,
  }),
  z.strictObject({
    status: z.literal('INCONCLUSIVE'),
    value: z.null(),
    unit: utilityMetricUnitV1Schema,
    preferredDirection: z.enum(['HIGHER', 'LOWER']),
    calculation: z.strictObject({
      numerator: resourceQuantitySchema,
      denominator: z.literal(0),
      normalizationFactor: z.number().positive().max(Number.MAX_SAFE_INTEGER),
    }),
    reasonCodes: z.array(utilityMetricReasonV1Schema).length(1),
  }),
]).superRefine((value, context) => {
  if (value.status !== 'MEASURED') return
  const expected = value.calculation.numerator
    * value.calculation.normalizationFactor
    / value.calculation.denominator
  if (Math.abs(value.value - expected) > Number.EPSILON * Math.max(4, expected * 4)) {
    context.addIssue({ code: 'custom', message: 'Inconsistent Utility metric calculation.' })
  }
})

export type UtilityMetricV1 = z.infer<typeof utilityMetricV1Schema>

export const UTILITY_METRIC_DIRECTIONS = {
  validatedFindingYieldPerRuntimeHour: 'HIGHER',
  validatedFindingYieldPerCostUnit: 'HIGHER',
  timeToFirstValidatedFindingMs: 'LOWER',
  humanTriageMinutesPerValidatedFinding: 'LOWER',
  verifiedRemediationSuccessRate: 'HIGHER',
  meanVerifiedRemediationDurationMs: 'LOWER',
  unnecessaryReworkCount: 'LOWER',
  validApprovalYield: 'HIGHER',
  unsafeApprovalRate: 'LOWER',
} as const

export const utilityMetricsV1Schema = z.strictObject({
  schemaVersion: z.literal(1),
  engineId: z.literal(UTILITY_METRICS_ENGINE_ID),
  conclusion: z.enum(['MEASURED', 'INCONCLUSIVE']),
  reasonCodes: z.array(utilityMetricReasonV1Schema).max(8),
  validatedFindings: resourceQuantitySchema,
  evidence: utilityEvidenceV1Schema,
  metrics: z.strictObject({
    validatedFindingYieldPerRuntimeHour: utilityMetricV1Schema,
    validatedFindingYieldPerCostUnit: utilityMetricV1Schema,
    timeToFirstValidatedFindingMs: utilityMetricV1Schema,
    humanTriageMinutesPerValidatedFinding: utilityMetricV1Schema,
    verifiedRemediationSuccessRate: utilityMetricV1Schema,
    meanVerifiedRemediationDurationMs: utilityMetricV1Schema,
    unnecessaryReworkCount: utilityMetricV1Schema,
    validApprovalYield: utilityMetricV1Schema,
    unsafeApprovalRate: utilityMetricV1Schema,
  }),
}).superRefine((value, context) => {
  const metricNames = Object.keys(UTILITY_METRIC_DIRECTIONS) as Array<
    keyof typeof UTILITY_METRIC_DIRECTIONS
  >
  const metrics = metricNames.map(name => value.metrics[name])
  const expectedReasons = [...new Set(metrics.flatMap(metric => (
    metric.status === 'INCONCLUSIVE' ? metric.reasonCodes : []
  )))]
  if (
    metricNames.some(name => (
      value.metrics[name].preferredDirection !== UTILITY_METRIC_DIRECTIONS[name]
    ))
    || (value.conclusion === 'MEASURED' && metrics.some(metric => metric.status !== 'MEASURED'))
    || (value.conclusion === 'INCONCLUSIVE' && metrics.every(metric => metric.status === 'MEASURED'))
    || JSON.stringify(value.reasonCodes) !== JSON.stringify(expectedReasons)
  ) {
    context.addIssue({ code: 'custom', message: 'Inconsistent Utility conclusion.' })
  }
})

export type UtilityMetricsV1 = z.infer<typeof utilityMetricsV1Schema>

export const pairedArmEvidenceV1Schema = z.strictObject({
  armId: boundedEvaluationIdSchema,
  metricsRequest: effectivenessMetricsRequestV1Schema,
  budget: evaluationArmBudgetV1Schema,
  utilityEvidence: utilityEvidenceV1Schema.optional(),
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

const pairedUtilityMetricReasonV1Schema = z.enum([
  'INCOMPATIBLE_EVALUATION_DESIGN',
  'UNMATCHED_BUDGETS',
  'INCONCLUSIVE_ARM_UTILITY',
])

export const pairedUtilityMetricComparisonV1Schema = z.discriminatedUnion('status', [
  z.strictObject({
    status: z.literal('MEASURED'),
    baselineValue: z.number().nonnegative(),
    candidateValue: z.number().nonnegative(),
    rawDelta: z.number(),
    directionalDelta: z.number(),
    preferredDirection: z.enum(['HIGHER', 'LOWER']),
    outcome: z.enum(['IMPROVED', 'EQUIVALENT', 'REGRESSED']),
  }),
  z.strictObject({
    status: z.literal('INCONCLUSIVE'),
    baselineValue: z.number().nonnegative().nullable(),
    candidateValue: z.number().nonnegative().nullable(),
    rawDelta: z.null(),
    directionalDelta: z.null(),
    preferredDirection: z.enum(['HIGHER', 'LOWER']),
    outcome: z.null(),
    reasonCodes: z.array(pairedUtilityMetricReasonV1Schema).length(1),
  }),
]).superRefine((value, context) => {
  if (value.status !== 'MEASURED') return
  const rawDelta = value.candidateValue - value.baselineValue
  const directionalDelta = value.preferredDirection === 'HIGHER' ? rawDelta : -rawDelta
  const outcome = directionalDelta > 0
    ? 'IMPROVED'
    : directionalDelta < 0 ? 'REGRESSED' : 'EQUIVALENT'
  if (
    Math.abs(value.rawDelta - rawDelta) > Number.EPSILON * Math.max(4, Math.abs(rawDelta) * 4)
    || Math.abs(value.directionalDelta - directionalDelta)
      > Number.EPSILON * Math.max(4, Math.abs(directionalDelta) * 4)
    || value.outcome !== outcome
  ) {
    context.addIssue({ code: 'custom', message: 'Inconsistent paired Utility metric.' })
  }
})

export type PairedUtilityMetricComparisonV1 = z.infer<
  typeof pairedUtilityMetricComparisonV1Schema
>

export const pairedUtilityComparisonV1Schema = z.strictObject({
  conclusion: z.enum(['MEASURED', 'INCONCLUSIVE']),
  reasonCodes: z.array(pairedUtilityMetricReasonV1Schema).max(3),
  baseline: utilityMetricsV1Schema,
  candidate: utilityMetricsV1Schema,
  metrics: z.strictObject({
    validatedFindingYieldPerRuntimeHour: pairedUtilityMetricComparisonV1Schema,
    validatedFindingYieldPerCostUnit: pairedUtilityMetricComparisonV1Schema,
    timeToFirstValidatedFindingMs: pairedUtilityMetricComparisonV1Schema,
    humanTriageMinutesPerValidatedFinding: pairedUtilityMetricComparisonV1Schema,
    verifiedRemediationSuccessRate: pairedUtilityMetricComparisonV1Schema,
    meanVerifiedRemediationDurationMs: pairedUtilityMetricComparisonV1Schema,
    unnecessaryReworkCount: pairedUtilityMetricComparisonV1Schema,
    validApprovalYield: pairedUtilityMetricComparisonV1Schema,
    unsafeApprovalRate: pairedUtilityMetricComparisonV1Schema,
  }),
}).superRefine((value, context) => {
  const metrics = Object.values(value.metrics)
  if (
    (value.conclusion === 'MEASURED' && value.reasonCodes.length !== 0)
    || (value.conclusion === 'MEASURED' && (
      value.baseline.conclusion !== 'MEASURED'
      || value.candidate.conclusion !== 'MEASURED'
      || metrics.some(metric => metric.status !== 'MEASURED')
    ))
    || (value.conclusion === 'INCONCLUSIVE' && value.reasonCodes.length === 0)
  ) {
    context.addIssue({ code: 'custom', message: 'Inconsistent paired Utility conclusion.' })
  }
})

export type PairedUtilityComparisonV1 = z.infer<typeof pairedUtilityComparisonV1Schema>

export const pairedArmComparisonV1Schema = z.strictObject({
  schemaVersion: z.literal(1),
  engineId: z.literal(PAIRED_ARM_COMPARISON_ENGINE_ID),
  comparisonView: z.enum(['MATCHED_BUDGET', 'NATIVE_PROFILE']),
  conclusion: z.enum(['MEASURED', 'INCONCLUSIVE']),
  reasonCodes: z.array(z.enum([
    'INCOMPATIBLE_EVALUATION_DESIGN',
    'UNMATCHED_BUDGETS',
    'INCONCLUSIVE_ARM_METRICS',
    'INCONCLUSIVE_ARM_UTILITY',
  ])).max(4),
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
  utilityComparison: pairedUtilityComparisonV1Schema.nullable(),
}).superRefine((value, context) => {
  const metrics = Object.values(value.metrics)
  if (
    (value.conclusion === 'MEASURED' && value.reasonCodes.length !== 0)
    || (value.conclusion === 'MEASURED' && (
      value.baseline.metrics.conclusion !== 'MEASURED'
      || value.candidate.metrics.conclusion !== 'MEASURED'
      || value.budgetComparison.status === 'INCONCLUSIVE'
      || metrics.some(metric => metric.status !== 'MEASURED')
      || value.utilityComparison?.conclusion === 'INCONCLUSIVE'
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

/** Stable, detail-free rejection for malformed air-gapped Evaluation evidence. */
export class AirGappedEvaluationInputError extends Error {
  readonly code = 'INVALID_AIR_GAPPED_EVALUATION_EVIDENCE' as const

  constructor() {
    super('Evidence does not match Air-gapped Evaluation Engine v1.')
    this.name = 'AirGappedEvaluationInputError'
  }
}

/** Stable, detail-free rejection for malformed or contradictory Utility evidence. */
export class UtilityMetricsInputError extends Error {
  readonly code = 'INVALID_UTILITY_EVIDENCE' as const

  constructor() {
    super('Utility evidence does not match Utility Metrics Engine v1.')
    this.name = 'UtilityMetricsInputError'
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

function invalidAirGappedEvaluationEvidence(): never {
  throw new AirGappedEvaluationInputError()
}

function airGapCaseKey(value: { caseId: string, repetitionId?: string | undefined }): string {
  return `${value.repetitionId ?? ''}\0${value.caseId}`
}

function sameDigest(
  left: z.infer<typeof digestEnvelopeV1Schema>,
  right: z.infer<typeof digestEnvelopeV1Schema>,
): boolean {
  return JSON.stringify(left) === JSON.stringify(right)
}

/**
 * Join already-sealed Arm outputs with Ground Truth only after scanning has
 * ended. Any detected leakage invalidates every declared Arm in the Run.
 */
export function assembleAirGappedEvaluationV1(
  input: unknown,
): AirGappedEvaluationAssemblyV1 {
  const parsed = airGappedEvaluationAssemblyRequestV1Schema.safeParse(input)
  if (!parsed.success) return invalidAirGappedEvaluationEvidence()
  const request = parsed.data
  const affectedArmIds = [...request.declaredArmIds].sort(compareIds)
  if (
    new Set(affectedArmIds).size !== affectedArmIds.length
    || new Set(request.sealedArmResults.map(item => item.sealedResultId)).size
      !== request.sealedArmResults.length
  ) {
    return invalidAirGappedEvaluationEvidence()
  }
  const declaredArmIds = new Set(affectedArmIds)
  const manifestCases = new Map(
    request.groundTruthManifest.cases.map(item => [airGapCaseKey(item), item]),
  )
  if (
    request.groundTruthManifest.sealedAtEpochMs > request.groundTruthOpenedAtEpochMs
    || request.sealedArmResults.some(item => (
      item.runnerInput.runId !== request.runId
      || !declaredArmIds.has(item.armId)
    ))
  ) {
    return invalidAirGappedEvaluationEvidence()
  }

  let undeclaredRunnerCase = false
  const resultsByArm = new Map<string, Map<string, SealedAirGappedArmResultV1>>()
  for (const armId of affectedArmIds) resultsByArm.set(armId, new Map())
  for (const sealedResult of request.sealedArmResults) {
    const key = airGapCaseKey(sealedResult.runnerInput)
    const manifestCase = manifestCases.get(key)
    if (manifestCase === undefined) {
      undeclaredRunnerCase = true
      continue
    }
    if (
      manifestCase.assessmentMode !== sealedResult.runnerInput.assessmentMode
      || manifestCase.supportedEcosystem !== sealedResult.runnerInput.supportedEcosystem
      || !sameDigest(manifestCase.subjectDigest, sealedResult.runnerInput.subjectDigest)
    ) {
      return invalidAirGappedEvaluationEvidence()
    }
    const armResults = resultsByArm.get(sealedResult.armId) as Map<
      string,
      SealedAirGappedArmResultV1
    >
    if (armResults.has(key)) return invalidAirGappedEvaluationEvidence()
    armResults.set(key, sealedResult)
  }

  const adjudications = new Map<string, AirGappedFindingAdjudicationV1>()
  for (const adjudication of request.adjudications) {
    if (!declaredArmIds.has(adjudication.armId)) return invalidAirGappedEvaluationEvidence()
    const caseKey = airGapCaseKey(adjudication)
    const sealedResult = resultsByArm.get(adjudication.armId)?.get(caseKey)
    const manifestCase = manifestCases.get(caseKey)
    const matchedDefectId = adjudication.adjudication.status === 'MATCHED'
      ? adjudication.adjudication.defectId
      : null
    if (
      sealedResult?.result.kind !== 'COMPLETED'
      || manifestCase === undefined
      || !sealedResult.result.findings.some(item => item.findingId === adjudication.findingId)
      || (matchedDefectId !== null
        && !manifestCase.groundTruthDefects.some(
          item => item.defectId === matchedDefectId,
        ))
    ) {
      return invalidAirGappedEvaluationEvidence()
    }
    const key = `${adjudication.armId}\0${caseKey}\0${adjudication.findingId}`
    if (adjudications.has(key)) return invalidAirGappedEvaluationEvidence()
    adjudications.set(key, adjudication)
  }

  const expectedCaseKeys = [...manifestCases.keys()].sort(compareIds)
  const incompleteResults = affectedArmIds.some((armId) => {
    const observedKeys = [...(resultsByArm.get(armId)?.keys() ?? [])].sort(compareIds)
    return JSON.stringify(observedKeys) !== JSON.stringify(expectedCaseKeys)
  })
  const expectedResultIds = request.sealedArmResults
    .map(item => item.sealedResultId)
    .sort(compareIds)
  const auditedResultIds = [...request.airGapAudit.auditedSealedResultIds].sort(compareIds)
  const auditedArmIds = [...request.airGapAudit.auditedArmIds].sort(compareIds)
  const incompleteAudit = (
    JSON.stringify(auditedArmIds) !== JSON.stringify(affectedArmIds)
    || JSON.stringify(auditedResultIds) !== JSON.stringify(expectedResultIds)
    || request.airGapAudit.completedAtEpochMs < request.groundTruthOpenedAtEpochMs
  )
  const sealedTimes = request.sealedArmResults.map(item => item.sealedAtEpochMs)
  const admittedTimes = request.sealedArmResults.map(item => item.runnerInput.admittedAtEpochMs)
  const latestSeal = sealedTimes.length === 0 ? 0 : Math.max(...sealedTimes)
  const earliestAdmission = admittedTimes.length === 0
    ? Number.MAX_SAFE_INTEGER
    : Math.min(...admittedTimes)
  const reasonCodes: Array<z.infer<typeof airGappedInvalidationReasonV1Schema>> = []
  if (request.airGapAudit.violations.length > 0) {
    reasonCodes.push('GROUND_TRUTH_LEAKAGE_DETECTED')
  }
  if (request.groundTruthOpenedAtEpochMs <= latestSeal) {
    reasonCodes.push('GROUND_TRUTH_OPENED_BEFORE_ALL_RESULTS_SEALED')
  }
  if (request.matchingContract.registeredAtEpochMs >= earliestAdmission) {
    reasonCodes.push('POST_HOC_MATCHING_CONTRACT')
  }
  if (incompleteAudit) reasonCodes.push('INCOMPLETE_AIR_GAP_AUDIT')
  if (incompleteResults) reasonCodes.push('INCOMPLETE_SEALED_ARM_RESULTS')
  if (undeclaredRunnerCase) reasonCodes.push('UNDECLARED_RUNNER_CASE')

  const provenance = {
    schemaVersion: 1 as const,
    engineId: AIR_GAPPED_EVALUATION_ENGINE_ID,
    runId: request.runId,
    evaluatorId: request.evaluatorId,
    evaluatorAuthorizationRecordId: request.evaluatorAuthorizationRecordId,
    groundTruthManifestId: request.groundTruthManifest.manifestId,
    matchingContractId: request.matchingContract.contractId,
    airGapAuditId: request.airGapAudit.auditId,
    affectedArmIds,
  }
  if (reasonCodes.length > 0) {
    return deepFreeze(airGappedEvaluationAssemblyV1Schema.parse({
      ...provenance,
      status: 'INVALIDATED',
      reasonCodes,
      arms: null,
    }))
  }

  const arms: Extract<AirGappedEvaluationAssemblyV1, { status: 'READY' }>['arms'] = []
  for (const armId of affectedArmIds) {
    const armResults = resultsByArm.get(armId) as Map<string, SealedAirGappedArmResultV1>
    const cases: EvaluationCaseV1[] = expectedCaseKeys.map((caseKey) => {
      const manifestCase = manifestCases.get(caseKey) as SealedGroundTruthManifestV1['cases'][number]
      const sealedResult = armResults.get(caseKey) as SealedAirGappedArmResultV1
      const result: EvaluationCaseV1['result'] = sealedResult.result.kind === 'PRODUCT_FAILURE'
        ? sealedResult.result
        : {
            kind: 'COMPLETED',
            verdict: sealedResult.result.verdict,
            coverageStatus: sealedResult.result.coverageStatus,
            findings: sealedResult.result.findings.map((finding) => {
              const adjudicationKey = `${armId}\0${caseKey}\0${finding.findingId}`
              return {
                findingId: finding.findingId,
                adjudication: adjudications.get(adjudicationKey)?.adjudication
                  ?? { status: 'UNADJUDICATED' },
              }
            }),
          }
      return {
        caseId: manifestCase.caseId,
        ...(manifestCase.repetitionId === undefined
          ? {}
          : { repetitionId: manifestCase.repetitionId }),
        disposition: manifestCase.disposition,
        assessmentMode: manifestCase.assessmentMode,
        supportedEcosystem: manifestCase.supportedEcosystem,
        expectedCoverage: manifestCase.expectedCoverage,
        groundTruthDefects: manifestCase.groundTruthDefects,
        result,
      }
    })
    const metricsRequest: EffectivenessMetricsRequestV1 = {
      schemaVersion: 1,
      engineId: EFFECTIVENESS_METRICS_ENGINE_ID,
      severityWeights: request.severityWeights,
      stratumDefinitions: request.stratumDefinitions,
      ...(request.repetitionPlan === undefined
        ? {}
        : { repetitionPlan: request.repetitionPlan }),
      cases,
    }
    let metrics: EffectivenessMetricsV1
    try {
      metrics = calculateEffectivenessMetricsV1(metricsRequest)
    } catch (error) {
      if (error instanceof EvaluationMetricsInputError) {
        return invalidAirGappedEvaluationEvidence()
      }
      throw error
    }
    arms.push({ armId, metricsRequest, metrics })
  }
  return deepFreeze(airGappedEvaluationAssemblyV1Schema.parse({
    ...provenance,
    status: 'READY',
    reasonCodes: [],
    arms,
  }))
}

type UtilityMetricReasonV1 = z.infer<typeof utilityMetricReasonV1Schema>
type UtilityMetricUnitV1 = z.infer<typeof utilityMetricUnitV1Schema>

function measuredUtilityMetric(
  numerator: number,
  denominator: number,
  normalizationFactor: number,
  unit: UtilityMetricUnitV1,
  preferredDirection: 'HIGHER' | 'LOWER',
): UtilityMetricV1 {
  if (denominator <= 0) throw new UtilityMetricsInputError()
  return {
    status: 'MEASURED',
    value: numerator * normalizationFactor / denominator,
    unit,
    preferredDirection,
    calculation: { numerator, denominator, normalizationFactor },
  }
}

function inconclusiveUtilityMetric(
  numerator: number,
  normalizationFactor: number,
  unit: UtilityMetricUnitV1,
  preferredDirection: 'HIGHER' | 'LOWER',
  reason: UtilityMetricReasonV1,
): UtilityMetricV1 {
  return {
    status: 'INCONCLUSIVE',
    value: null,
    unit,
    preferredDirection,
    calculation: { numerator, denominator: 0, normalizationFactor },
    reasonCodes: [reason],
  }
}

function calculateUtilityMetricsFromEvidence(
  effectiveness: EffectivenessMetricsV1,
  budget: EvaluationArmBudgetV1,
  evidence: UtilityEvidenceV1,
): UtilityMetricsV1 {
  const validatedFindings = effectiveness.metrics.validatedPrecision.numerator
  if (
    (validatedFindings === 0 && evidence.firstValidatedFindingMs !== null)
    || (validatedFindings > 0 && evidence.firstValidatedFindingMs === null)
    || (evidence.firstValidatedFindingMs !== null
      && evidence.firstValidatedFindingMs > budget.usage.wallTimeMs)
  ) {
    throw new UtilityMetricsInputError()
  }
  const incompleteAdjudication = effectiveness.counts.unadjudicatedFindings > 0
  const runtimeYield = incompleteAdjudication
    ? inconclusiveUtilityMetric(
        validatedFindings,
        3_600_000,
        'VALIDATED_FINDINGS_PER_RUNTIME_HOUR',
        'HIGHER',
        'INCOMPLETE_FINDING_ADJUDICATION',
      )
    : budget.usage.wallTimeMs === 0
      ? inconclusiveUtilityMetric(
          validatedFindings,
          3_600_000,
          'VALIDATED_FINDINGS_PER_RUNTIME_HOUR',
          'HIGHER',
          'NO_RECORDED_RUNTIME',
        )
      : measuredUtilityMetric(
          validatedFindings,
          budget.usage.wallTimeMs,
          3_600_000,
          'VALIDATED_FINDINGS_PER_RUNTIME_HOUR',
          'HIGHER',
        )
  const costYield = incompleteAdjudication
    ? inconclusiveUtilityMetric(
        validatedFindings,
        1_000_000,
        'VALIDATED_FINDINGS_PER_COST_UNIT',
        'HIGHER',
        'INCOMPLETE_FINDING_ADJUDICATION',
      )
    : evidence.executionCostMicrounits === 0
      ? inconclusiveUtilityMetric(
          validatedFindings,
          1_000_000,
          'VALIDATED_FINDINGS_PER_COST_UNIT',
          'HIGHER',
          'NO_RECORDED_COST',
        )
      : measuredUtilityMetric(
          validatedFindings,
          evidence.executionCostMicrounits,
          1_000_000,
          'VALIDATED_FINDINGS_PER_COST_UNIT',
          'HIGHER',
        )
  const timeToFirst = evidence.firstValidatedFindingMs === null
    ? inconclusiveUtilityMetric(
        validatedFindings,
        1,
        'MILLISECONDS',
        'LOWER',
        'NO_VALIDATED_FINDINGS',
      )
    : measuredUtilityMetric(
        evidence.firstValidatedFindingMs,
        1,
        1,
        'MILLISECONDS',
        'LOWER',
      )
  const triage = incompleteAdjudication
    ? inconclusiveUtilityMetric(
        evidence.humanTriageMs,
        1 / 60_000,
        'MINUTES_PER_VALIDATED_FINDING',
        'LOWER',
        'INCOMPLETE_FINDING_ADJUDICATION',
      )
    : validatedFindings === 0
      ? inconclusiveUtilityMetric(
          evidence.humanTriageMs,
          1 / 60_000,
          'MINUTES_PER_VALIDATED_FINDING',
          'LOWER',
          'NO_VALIDATED_FINDINGS',
        )
      : measuredUtilityMetric(
          evidence.humanTriageMs,
          validatedFindings,
          1 / 60_000,
          'MINUTES_PER_VALIDATED_FINDING',
          'LOWER',
        )
  const remediationSuccess = evidence.remediation.attempts === 0
    ? inconclusiveUtilityMetric(
        evidence.remediation.verifiedSuccesses,
        1,
        'RATIO',
        'HIGHER',
        'NO_REMEDIATION_ATTEMPTS',
      )
    : measuredUtilityMetric(
        evidence.remediation.verifiedSuccesses,
        evidence.remediation.attempts,
        1,
        'RATIO',
        'HIGHER',
      )
  const remediationDuration = evidence.remediation.verifiedSuccesses === 0
    ? inconclusiveUtilityMetric(
        evidence.remediation.totalVerifiedSuccessDurationMs,
        1,
        'MILLISECONDS',
        'LOWER',
        'NO_VERIFIED_REMEDIATIONS',
      )
    : measuredUtilityMetric(
        evidence.remediation.totalVerifiedSuccessDurationMs,
        evidence.remediation.verifiedSuccesses,
        1,
        'MILLISECONDS',
        'LOWER',
      )
  const rework = measuredUtilityMetric(
    evidence.unnecessaryReworkCount,
    1,
    1,
    'COUNT',
    'LOWER',
  )
  const controlPlane = evidence.controlPlane
  const validApprovalYield = controlPlane.applicability === 'NOT_APPLICABLE'
    ? inconclusiveUtilityMetric(
        0,
        1,
        'RATIO',
        'HIGHER',
        'CONTROL_PLANE_NOT_APPLICABLE',
      )
    : controlPlane.decisions === 0
      ? inconclusiveUtilityMetric(
          controlPlane.validApprovals,
          1,
          'RATIO',
          'HIGHER',
          'NO_CONTROL_PLANE_DECISIONS',
        )
      : measuredUtilityMetric(
          controlPlane.validApprovals,
          controlPlane.decisions,
          1,
          'RATIO',
          'HIGHER',
        )
  const unsafeApprovalRate = controlPlane.applicability === 'NOT_APPLICABLE'
    ? inconclusiveUtilityMetric(
        0,
        1,
        'RATIO',
        'LOWER',
        'CONTROL_PLANE_NOT_APPLICABLE',
      )
    : controlPlane.decisions === 0
      ? inconclusiveUtilityMetric(
          controlPlane.unsafeApprovals,
          1,
          'RATIO',
          'LOWER',
          'NO_CONTROL_PLANE_DECISIONS',
        )
      : measuredUtilityMetric(
          controlPlane.unsafeApprovals,
          controlPlane.decisions,
          1,
          'RATIO',
          'LOWER',
        )
  const metrics: UtilityMetricsV1['metrics'] = {
    validatedFindingYieldPerRuntimeHour: runtimeYield,
    validatedFindingYieldPerCostUnit: costYield,
    timeToFirstValidatedFindingMs: timeToFirst,
    humanTriageMinutesPerValidatedFinding: triage,
    verifiedRemediationSuccessRate: remediationSuccess,
    meanVerifiedRemediationDurationMs: remediationDuration,
    unnecessaryReworkCount: rework,
    validApprovalYield,
    unsafeApprovalRate,
  }
  const reasonCodes = [...new Set(Object.values(metrics).flatMap(metric => (
    metric.status === 'INCONCLUSIVE' ? metric.reasonCodes : []
  )))]
  const result: UtilityMetricsV1 = {
    schemaVersion: 1,
    engineId: UTILITY_METRICS_ENGINE_ID,
    conclusion: reasonCodes.length === 0 ? 'MEASURED' : 'INCONCLUSIVE',
    reasonCodes,
    validatedFindings,
    evidence,
    metrics,
  }
  return deepFreeze(utilityMetricsV1Schema.parse(result))
}

/** Calculate auditable Product Utility from the same frozen Effectiveness evidence. */
export function calculateUtilityMetricsV1(input: unknown): UtilityMetricsV1 {
  const parsed = utilityMetricsRequestV1Schema.safeParse(input)
  if (!parsed.success) throw new UtilityMetricsInputError()
  let effectiveness: EffectivenessMetricsV1
  try {
    effectiveness = calculateEffectivenessMetricsV1(parsed.data.effectivenessRequest)
  } catch (error) {
    if (error instanceof EvaluationMetricsInputError) throw new UtilityMetricsInputError()
    throw error
  }
  return calculateUtilityMetricsFromEvidence(
    effectiveness,
    parsed.data.budget,
    parsed.data.evidence,
  )
}

function invalidPairedArmEvidence(): never {
  throw new PairedArmComparisonInputError()
}

function parsePairedArmComparisonRequest(input: unknown): PairedArmComparisonRequestV1 {
  const parsed = pairedArmComparisonRequestV1Schema.safeParse(input)
  if (!parsed.success || parsed.data.baseline.armId === parsed.data.candidate.armId) {
    return invalidPairedArmEvidence()
  }
  if ((parsed.data.baseline.utilityEvidence === undefined)
    !== (parsed.data.candidate.utilityEvidence === undefined)) {
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

function comparePairedUtilityMetric(
  baseline: UtilityMetricV1,
  candidate: UtilityMetricV1,
  preferredDirection: 'HIGHER' | 'LOWER',
  blockedReason?: 'INCOMPATIBLE_EVALUATION_DESIGN' | 'UNMATCHED_BUDGETS',
): PairedUtilityMetricComparisonV1 {
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
      reasonCodes: [blockedReason ?? 'INCONCLUSIVE_ARM_UTILITY'],
    }
  }
  const raw = candidate.value - baseline.value
  const directed = preferredDirection === 'HIGHER' ? raw : -raw
  const rawDelta = raw === 0 ? 0 : raw
  const directionalDelta = directed === 0 ? 0 : directed
  return {
    status: 'MEASURED',
    baselineValue: baseline.value,
    candidateValue: candidate.value,
    rawDelta,
    directionalDelta,
    preferredDirection,
    outcome: directionalDelta > 0
      ? 'IMPROVED'
      : directionalDelta < 0 ? 'REGRESSED' : 'EQUIVALENT',
  }
}

function calculatePairedUtilityComparison(
  request: PairedArmComparisonRequestV1,
  baselineEffectiveness: EffectivenessMetricsV1,
  candidateEffectiveness: EffectivenessMetricsV1,
  compatibleDesign: boolean,
  matchedBudgetBlocked: boolean,
): PairedUtilityComparisonV1 | null {
  const baselineEvidence = request.baseline.utilityEvidence
  const candidateEvidence = request.candidate.utilityEvidence
  if (baselineEvidence === undefined || candidateEvidence === undefined) return null
  const baseline = calculateUtilityMetricsFromEvidence(
    baselineEffectiveness,
    request.baseline.budget,
    baselineEvidence,
  )
  const candidate = calculateUtilityMetricsFromEvidence(
    candidateEffectiveness,
    request.candidate.budget,
    candidateEvidence,
  )
  const blockedReason = !compatibleDesign
    ? 'INCOMPATIBLE_EVALUATION_DESIGN' as const
    : matchedBudgetBlocked ? 'UNMATCHED_BUDGETS' as const : undefined
  const metricNames = Object.keys(UTILITY_METRIC_DIRECTIONS) as Array<
    keyof typeof UTILITY_METRIC_DIRECTIONS
  >
  const metrics = {} as PairedUtilityComparisonV1['metrics']
  for (const metricName of metricNames) {
    metrics[metricName] = comparePairedUtilityMetric(
      baseline.metrics[metricName],
      candidate.metrics[metricName],
      UTILITY_METRIC_DIRECTIONS[metricName],
      blockedReason,
    )
  }
  const reasonCodes: PairedUtilityComparisonV1['reasonCodes'] = []
  if (blockedReason !== undefined) {
    reasonCodes.push(blockedReason)
  } else if (
    baseline.conclusion === 'INCONCLUSIVE'
    || candidate.conclusion === 'INCONCLUSIVE'
  ) {
    reasonCodes.push('INCONCLUSIVE_ARM_UTILITY')
  }
  return {
    conclusion: reasonCodes.length === 0 ? 'MEASURED' : 'INCONCLUSIVE',
    reasonCodes,
    baseline,
    candidate,
    metrics,
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
  let utilityComparison: PairedUtilityComparisonV1 | null
  try {
    utilityComparison = calculatePairedUtilityComparison(
      request,
      baselineMetrics,
      candidateMetrics,
      compatibleDesign,
      matchedBudgetBlocked,
    )
  } catch (error) {
    if (error instanceof UtilityMetricsInputError) return invalidPairedArmEvidence()
    throw error
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
  if (
    utilityComparison?.conclusion === 'INCONCLUSIVE'
    && compatibleDesign
    && !matchedBudgetBlocked
  ) {
    reasonCodes.push('INCONCLUSIVE_ARM_UTILITY')
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
    utilityComparison,
  }
  return deepFreeze(pairedArmComparisonV1Schema.parse(result))
}

export const RELEASE_CONSTITUTION_ENGINE_ID = 'security/release-constitution/v1' as const

const releaseThresholdNumberSchema = z.number().nonnegative()

export const releaseConstitutionV1Schema = z.strictObject({
  constitutionId: boundedEvaluationIdSchema,
  constitutionDigest: digestEnvelopeV1Schema,
  registrationRecordId: boundedEvaluationIdSchema,
  registeredAtEpochMs: evaluationEpochMsSchema,
  calibrationEvidence: z.array(z.strictObject({
    evidenceId: boundedEvaluationIdSchema,
    evidenceDigest: digestEnvelopeV1Schema,
    corpusLane: z.enum(['DEVELOPMENT', 'QUALIFICATION']),
    completedAtEpochMs: evaluationEpochMsSchema,
  })).min(1).max(1_000),
  requiredNonInferiorityPlanId: boundedEvaluationIdSchema,
  effectivenessThresholds: z.strictObject({
    criticalHighValidatedRecallMinimum: z.number().min(0).max(1),
    severityWeightedValidatedRecallMinimum: z.number().min(0).max(1),
    validatedPrecisionMinimum: z.number().min(0).max(1),
    unsafeSatisfactionRateMaximum: z.number().min(0).max(1),
    coverageHonestyRateMinimum: z.number().min(0).max(1),
  }),
  utilityThresholds: z.strictObject({
    validatedFindingYieldPerRuntimeHourMinimum: releaseThresholdNumberSchema,
    validatedFindingYieldPerCostUnitMinimum: releaseThresholdNumberSchema,
    timeToFirstValidatedFindingMsMaximum: releaseThresholdNumberSchema,
    humanTriageMinutesPerValidatedFindingMaximum: releaseThresholdNumberSchema,
    verifiedRemediationSuccessRateMinimum: z.number().min(0).max(1),
    meanVerifiedRemediationDurationMsMaximum: releaseThresholdNumberSchema,
    unnecessaryReworkCountMaximum: releaseThresholdNumberSchema,
    validApprovalYieldMinimum: z.number().min(0).max(1),
    unsafeApprovalRateMaximum: z.number().min(0).max(1),
  }),
}).superRefine((value, context) => {
  if (new Set(value.calibrationEvidence.map(item => item.evidenceId)).size
    !== value.calibrationEvidence.length) {
    context.addIssue({ code: 'custom', message: 'Duplicate calibration Evidence identity.' })
  }
})

export type ReleaseConstitutionV1 = z.infer<typeof releaseConstitutionV1Schema>

export const releaseHardSafetyEvidenceV1Schema = z.strictObject({
  evidenceId: boundedEvaluationIdSchema,
  evidenceDigest: digestEnvelopeV1Schema,
  evidenceStatus: z.enum(['COMPLETE', 'INCOMPLETE']),
  capabilityConformance: z.enum(['PASSED', 'FAILED', 'INCOMPLETE']),
  unauthorizedCodeExecutionCount: resourceQuantitySchema,
  unauthorizedNetworkEgressCount: resourceQuantitySchema,
  unauthorizedTrackingMutationCount: resourceQuantitySchema,
  unauthorizedRiskAcceptanceCount: resourceQuantitySchema,
  forgedCanonicalEvidenceAcceptedCount: resourceQuantitySchema,
  corruptCanonicalEvidenceAcceptedCount: resourceQuantitySchema,
  hiddenCriticalSatisfiedCount: resourceQuantitySchema,
  groundTruthLeakageCount: resourceQuantitySchema,
  selfSecurityCriticalCount: resourceQuantitySchema,
  selfSecurityHighCount: resourceQuantitySchema,
  selfSecurityBlockingMediumCount: resourceQuantitySchema,
  unresolvedDeterministicFailureCount: resourceQuantitySchema,
})

export type ReleaseHardSafetyEvidenceV1 = z.infer<
  typeof releaseHardSafetyEvidenceV1Schema
>

export const releasePlatformProofV1Schema = z.strictObject({
  platform: z.enum(['WINDOWS', 'LINUX', 'MACOS']),
  status: z.enum(['PASSED', 'FAILED', 'INCOMPLETE']),
  evidenceId: boundedEvaluationIdSchema,
  evidenceDigest: digestEnvelopeV1Schema,
  packedArtifactDigest: digestEnvelopeV1Schema,
})

export type ReleasePlatformProofV1 = z.infer<typeof releasePlatformProofV1Schema>

export const releaseConstitutionEvaluationRequestV1Schema = z.strictObject({
  schemaVersion: z.literal(1),
  engineId: z.literal(RELEASE_CONSTITUTION_ENGINE_ID),
  constitution: releaseConstitutionV1Schema,
  candidate: z.strictObject({
    releaseCandidateId: boundedEvaluationIdSchema,
    candidateArmId: boundedEvaluationIdSchema,
    priorStableArmId: boundedEvaluationIdSchema,
    evidenceSetId: boundedEvaluationIdSchema,
    evidenceSetDigest: digestEnvelopeV1Schema,
    holdoutStartedAtEpochMs: evaluationEpochMsSchema,
    holdoutCompletedAtEpochMs: evaluationEpochMsSchema,
    candidateArtifactDigest: digestEnvelopeV1Schema,
    qualifiedArtifactDigest: digestEnvelopeV1Schema,
    proposedPromotionArtifactDigest: digestEnvelopeV1Schema,
    hardSafetyEvidence: releaseHardSafetyEvidenceV1Schema,
    platformProofs: z.array(releasePlatformProofV1Schema).max(3),
    pairedComparison: pairedArmComparisonV1Schema,
  }),
}).superRefine((value, context) => {
  const candidate = value.candidate
  if (
    candidate.candidateArmId === candidate.priorStableArmId
    || candidate.holdoutCompletedAtEpochMs < candidate.holdoutStartedAtEpochMs
    || candidate.pairedComparison.candidate.armId !== candidate.candidateArmId
    || candidate.pairedComparison.baseline.armId !== candidate.priorStableArmId
    || new Set(candidate.platformProofs.map(item => item.platform)).size
      !== candidate.platformProofs.length
  ) {
    context.addIssue({ code: 'custom', message: 'Inconsistent Release Candidate Evidence.' })
  }
})

export type ReleaseConstitutionEvaluationRequestV1 = z.infer<
  typeof releaseConstitutionEvaluationRequestV1Schema
>

export const RELEASE_CONSTITUTION_CHECK_IDS = [
  'CONSTITUTION_PRE_REGISTERED',
  'CALIBRATION_EVIDENCE_PRE_REGISTRATION',
  'COMPLETE_CAPABILITY_CONFORMANCE',
  'NO_UNAUTHORIZED_CODE_EXECUTION',
  'NO_UNAUTHORIZED_NETWORK_EGRESS',
  'NO_UNAUTHORIZED_TRACKING_MUTATION',
  'NO_UNAUTHORIZED_RISK_ACCEPTANCE',
  'NO_FORGED_CANONICAL_EVIDENCE_ACCEPTANCE',
  'NO_CORRUPT_CANONICAL_EVIDENCE_ACCEPTANCE',
  'NO_HIDDEN_CRITICAL_SATISFACTION',
  'NO_GROUND_TRUTH_LEAKAGE',
  'SELF_SECURITY_CRITICAL_HIGH_CLEAR',
  'SELF_SECURITY_BLOCKING_MEDIUM_CLEAR',
  'NO_UNRESOLVED_DETERMINISTIC_FAILURES',
  'EXACT_QUALIFIED_ARTIFACT',
  'WINDOWS_PACKED_CONFORMANCE',
  'LINUX_PACKED_CONFORMANCE',
  'MACOS_PACKED_CONFORMANCE',
  'PAIRED_EVIDENCE_CONCLUSIVE',
  'MANDATORY_STRATA_NON_INFERIOR',
  'CRITICAL_HIGH_VALIDATED_RECALL_THRESHOLD',
  'SEVERITY_WEIGHTED_VALIDATED_RECALL_THRESHOLD',
  'VALIDATED_PRECISION_THRESHOLD',
  'UNSAFE_SATISFACTION_RATE_THRESHOLD',
  'COVERAGE_HONESTY_RATE_THRESHOLD',
  'VALIDATED_FINDING_RUNTIME_YIELD_THRESHOLD',
  'VALIDATED_FINDING_COST_YIELD_THRESHOLD',
  'TIME_TO_FIRST_VALIDATED_FINDING_THRESHOLD',
  'HUMAN_TRIAGE_THRESHOLD',
  'VERIFIED_REMEDIATION_SUCCESS_THRESHOLD',
  'VERIFIED_REMEDIATION_DURATION_THRESHOLD',
  'UNNECESSARY_REWORK_THRESHOLD',
  'VALID_APPROVAL_YIELD_THRESHOLD',
  'UNSAFE_APPROVAL_RATE_THRESHOLD',
] as const

export type ReleaseConstitutionCheckId = typeof RELEASE_CONSTITUTION_CHECK_IDS[number]

export const releaseConstitutionCheckV1Schema = z.strictObject({
  checkId: z.enum(RELEASE_CONSTITUTION_CHECK_IDS),
  status: z.enum(['PASSED', 'FAILED', 'INCONCLUSIVE']),
})

export type ReleaseConstitutionCheckV1 = z.infer<typeof releaseConstitutionCheckV1Schema>

export const releaseConstitutionDecisionV1Schema = z.strictObject({
  schemaVersion: z.literal(1),
  engineId: z.literal(RELEASE_CONSTITUTION_ENGINE_ID),
  constitutionId: boundedEvaluationIdSchema,
  constitutionDigest: digestEnvelopeV1Schema,
  releaseCandidateId: boundedEvaluationIdSchema,
  evidenceSetId: boundedEvaluationIdSchema,
  evidenceSetDigest: digestEnvelopeV1Schema,
  candidateArtifactDigest: digestEnvelopeV1Schema,
  qualifiedArtifactDigest: digestEnvelopeV1Schema,
  proposedPromotionArtifactDigest: digestEnvelopeV1Schema,
  decision: z.enum(['PROMOTE', 'BLOCKED', 'INCONCLUSIVE']),
  reasonCodes: z.array(z.enum([
    'CONSTITUTION_NOT_PRE_REGISTERED',
    'HARD_SAFETY_FLOOR_FAILED',
    'ARTIFACT_IDENTITY_FAILED',
    'PLATFORM_PROOF_FAILED',
    'PAIRED_EVIDENCE_FAILED',
    'NON_INFERIORITY_FAILED',
    'EFFECTIVENESS_THRESHOLD_FAILED',
    'UTILITY_THRESHOLD_FAILED',
    'INCOMPLETE_RELEASE_EVIDENCE',
  ])).max(9),
  checks: z.array(releaseConstitutionCheckV1Schema)
    .length(RELEASE_CONSTITUTION_CHECK_IDS.length),
}).superRefine((value, context) => {
  const expectedIds = [...RELEASE_CONSTITUTION_CHECK_IDS]
  const actualIds = value.checks.map(item => item.checkId)
  const expectedDecision = value.checks.some(item => item.status === 'FAILED')
    ? 'BLOCKED'
    : value.checks.some(item => item.status === 'INCONCLUSIVE')
      ? 'INCONCLUSIVE'
      : 'PROMOTE'
  if (
    JSON.stringify(actualIds) !== JSON.stringify(expectedIds)
    || value.decision !== expectedDecision
    || (value.decision === 'PROMOTE' && value.reasonCodes.length !== 0)
    || (value.decision !== 'PROMOTE' && value.reasonCodes.length === 0)
  ) {
    context.addIssue({ code: 'custom', message: 'Inconsistent Release Constitution decision.' })
  }
})

export type ReleaseConstitutionDecisionV1 = z.infer<
  typeof releaseConstitutionDecisionV1Schema
>

/** Stable, detail-free rejection for malformed Release Constitution evidence. */
export class ReleaseConstitutionInputError extends Error {
  readonly code = 'INVALID_RELEASE_CONSTITUTION_EVIDENCE' as const

  constructor() {
    super('Evidence does not match Release Constitution Engine v1.')
    this.name = 'ReleaseConstitutionInputError'
  }
}

type ReleaseCheckStatusV1 = ReleaseConstitutionCheckV1['status']

function releaseCountCheckStatus(
  count: number,
  evidenceComplete: boolean,
): ReleaseCheckStatusV1 {
  if (count > 0) return 'FAILED'
  return evidenceComplete ? 'PASSED' : 'INCONCLUSIVE'
}

function releaseEffectivenessThresholdStatus(
  distribution: RepetitionMetricDistributionV1 | undefined,
  preferredDirection: 'HIGHER' | 'LOWER',
  threshold: number,
): ReleaseCheckStatusV1 {
  if (
    distribution?.status !== 'MEASURED'
    || distribution.uncertaintyStatus !== 'SUFFICIENT'
  ) {
    return 'INCONCLUSIVE'
  }
  const conservativeValue = preferredDirection === 'HIGHER'
    ? distribution.confidenceInterval.lower
    : distribution.confidenceInterval.upper
  return preferredDirection === 'HIGHER'
    ? conservativeValue >= threshold ? 'PASSED' : 'FAILED'
    : conservativeValue <= threshold ? 'PASSED' : 'FAILED'
}

function releaseUtilityThresholdStatus(
  metric: UtilityMetricV1 | undefined,
  preferredDirection: 'HIGHER' | 'LOWER',
  threshold: number,
): ReleaseCheckStatusV1 {
  if (metric?.status !== 'MEASURED') return 'INCONCLUSIVE'
  return preferredDirection === 'HIGHER'
    ? metric.value >= threshold ? 'PASSED' : 'FAILED'
    : metric.value <= threshold ? 'PASSED' : 'FAILED'
}

/** Evaluate the complete, pre-registered stable-release Constitution in one place. */
export function evaluateReleaseConstitutionV1(
  input: unknown,
): ReleaseConstitutionDecisionV1 {
  const parsed = releaseConstitutionEvaluationRequestV1Schema.safeParse(input)
  if (!parsed.success) throw new ReleaseConstitutionInputError()
  const request = parsed.data
  const { constitution, candidate } = request
  const statuses = new Map<ReleaseConstitutionCheckId, ReleaseCheckStatusV1>(
    RELEASE_CONSTITUTION_CHECK_IDS.map(checkId => [checkId, 'INCONCLUSIVE']),
  )
  const set = (checkId: ReleaseConstitutionCheckId, status: ReleaseCheckStatusV1): void => {
    statuses.set(checkId, status)
  }

  set(
    'CONSTITUTION_PRE_REGISTERED',
    constitution.registeredAtEpochMs < candidate.holdoutStartedAtEpochMs
      ? 'PASSED'
      : 'FAILED',
  )
  set(
    'CALIBRATION_EVIDENCE_PRE_REGISTRATION',
    constitution.calibrationEvidence.every(
      item => item.completedAtEpochMs <= constitution.registeredAtEpochMs,
    ) ? 'PASSED' : 'FAILED',
  )

  const hardSafety = candidate.hardSafetyEvidence
  const hardEvidenceComplete = hardSafety.evidenceStatus === 'COMPLETE'
  set(
    'COMPLETE_CAPABILITY_CONFORMANCE',
    hardSafety.capabilityConformance === 'FAILED'
      ? 'FAILED'
      : hardSafety.capabilityConformance === 'PASSED' && hardEvidenceComplete
        ? 'PASSED'
        : 'INCONCLUSIVE',
  )
  set('NO_UNAUTHORIZED_CODE_EXECUTION', releaseCountCheckStatus(
    hardSafety.unauthorizedCodeExecutionCount,
    hardEvidenceComplete,
  ))
  set('NO_UNAUTHORIZED_NETWORK_EGRESS', releaseCountCheckStatus(
    hardSafety.unauthorizedNetworkEgressCount,
    hardEvidenceComplete,
  ))
  set('NO_UNAUTHORIZED_TRACKING_MUTATION', releaseCountCheckStatus(
    hardSafety.unauthorizedTrackingMutationCount,
    hardEvidenceComplete,
  ))
  set('NO_UNAUTHORIZED_RISK_ACCEPTANCE', releaseCountCheckStatus(
    hardSafety.unauthorizedRiskAcceptanceCount,
    hardEvidenceComplete,
  ))
  set('NO_FORGED_CANONICAL_EVIDENCE_ACCEPTANCE', releaseCountCheckStatus(
    hardSafety.forgedCanonicalEvidenceAcceptedCount,
    hardEvidenceComplete,
  ))
  set('NO_CORRUPT_CANONICAL_EVIDENCE_ACCEPTANCE', releaseCountCheckStatus(
    hardSafety.corruptCanonicalEvidenceAcceptedCount,
    hardEvidenceComplete,
  ))
  set('NO_HIDDEN_CRITICAL_SATISFACTION', releaseCountCheckStatus(
    hardSafety.hiddenCriticalSatisfiedCount,
    hardEvidenceComplete,
  ))
  set('NO_GROUND_TRUTH_LEAKAGE', releaseCountCheckStatus(
    hardSafety.groundTruthLeakageCount,
    hardEvidenceComplete,
  ))
  set('SELF_SECURITY_CRITICAL_HIGH_CLEAR', releaseCountCheckStatus(
    hardSafety.selfSecurityCriticalCount + hardSafety.selfSecurityHighCount,
    hardEvidenceComplete,
  ))
  set('SELF_SECURITY_BLOCKING_MEDIUM_CLEAR', releaseCountCheckStatus(
    hardSafety.selfSecurityBlockingMediumCount,
    hardEvidenceComplete,
  ))
  set('NO_UNRESOLVED_DETERMINISTIC_FAILURES', releaseCountCheckStatus(
    hardSafety.unresolvedDeterministicFailureCount,
    hardEvidenceComplete,
  ))

  const exactArtifact = sameDigest(
    candidate.candidateArtifactDigest,
    candidate.qualifiedArtifactDigest,
  ) && sameDigest(
    candidate.candidateArtifactDigest,
    candidate.proposedPromotionArtifactDigest,
  )
  set('EXACT_QUALIFIED_ARTIFACT', exactArtifact ? 'PASSED' : 'FAILED')

  const platformChecks = [
    ['WINDOWS', 'WINDOWS_PACKED_CONFORMANCE'],
    ['LINUX', 'LINUX_PACKED_CONFORMANCE'],
    ['MACOS', 'MACOS_PACKED_CONFORMANCE'],
  ] as const
  for (const [platform, checkId] of platformChecks) {
    const proof = candidate.platformProofs.find(item => item.platform === platform)
    if (proof === undefined) {
      set(checkId, 'INCONCLUSIVE')
    } else if (!sameDigest(proof.packedArtifactDigest, candidate.candidateArtifactDigest)) {
      set(checkId, 'FAILED')
    } else {
      set(
        checkId,
        proof.status === 'PASSED'
          ? 'PASSED'
          : proof.status === 'FAILED' ? 'FAILED' : 'INCONCLUSIVE',
      )
    }
  }

  const paired = candidate.pairedComparison
  const matchedPair = paired.comparisonView === 'MATCHED_BUDGET'
    && paired.budgetComparison.status === 'MATCHED'
  set(
    'PAIRED_EVIDENCE_CONCLUSIVE',
    !matchedPair
      ? 'FAILED'
      : paired.conclusion === 'MEASURED'
        && paired.utilityComparison?.conclusion === 'MEASURED'
        ? 'PASSED'
        : 'INCONCLUSIVE',
  )
  const nonInferiority = paired.nonInferiority
  set(
    'MANDATORY_STRATA_NON_INFERIOR',
    nonInferiority === null || nonInferiority.status === 'INCONCLUSIVE'
      ? 'INCONCLUSIVE'
      : nonInferiority.planId !== constitution.requiredNonInferiorityPlanId
        || nonInferiority.status === 'FAILED'
        ? 'FAILED'
        : 'PASSED',
  )

  const distributions = paired.candidate.metrics.repetitionAnalysis?.metrics
  const effectivenessThresholds = constitution.effectivenessThresholds
  set('CRITICAL_HIGH_VALIDATED_RECALL_THRESHOLD', releaseEffectivenessThresholdStatus(
    distributions?.criticalHighValidatedRecall,
    'HIGHER',
    effectivenessThresholds.criticalHighValidatedRecallMinimum,
  ))
  set('SEVERITY_WEIGHTED_VALIDATED_RECALL_THRESHOLD', releaseEffectivenessThresholdStatus(
    distributions?.severityWeightedValidatedRecall,
    'HIGHER',
    effectivenessThresholds.severityWeightedValidatedRecallMinimum,
  ))
  set('VALIDATED_PRECISION_THRESHOLD', releaseEffectivenessThresholdStatus(
    distributions?.validatedPrecision,
    'HIGHER',
    effectivenessThresholds.validatedPrecisionMinimum,
  ))
  set('UNSAFE_SATISFACTION_RATE_THRESHOLD', releaseEffectivenessThresholdStatus(
    distributions?.unsafeSatisfactionRate,
    'LOWER',
    effectivenessThresholds.unsafeSatisfactionRateMaximum,
  ))
  set('COVERAGE_HONESTY_RATE_THRESHOLD', releaseEffectivenessThresholdStatus(
    distributions?.coverageHonestyRate,
    'HIGHER',
    effectivenessThresholds.coverageHonestyRateMinimum,
  ))

  const utility = paired.utilityComparison?.candidate.metrics
  const utilityThresholds = constitution.utilityThresholds
  set('VALIDATED_FINDING_RUNTIME_YIELD_THRESHOLD', releaseUtilityThresholdStatus(
    utility?.validatedFindingYieldPerRuntimeHour,
    'HIGHER',
    utilityThresholds.validatedFindingYieldPerRuntimeHourMinimum,
  ))
  set('VALIDATED_FINDING_COST_YIELD_THRESHOLD', releaseUtilityThresholdStatus(
    utility?.validatedFindingYieldPerCostUnit,
    'HIGHER',
    utilityThresholds.validatedFindingYieldPerCostUnitMinimum,
  ))
  set('TIME_TO_FIRST_VALIDATED_FINDING_THRESHOLD', releaseUtilityThresholdStatus(
    utility?.timeToFirstValidatedFindingMs,
    'LOWER',
    utilityThresholds.timeToFirstValidatedFindingMsMaximum,
  ))
  set('HUMAN_TRIAGE_THRESHOLD', releaseUtilityThresholdStatus(
    utility?.humanTriageMinutesPerValidatedFinding,
    'LOWER',
    utilityThresholds.humanTriageMinutesPerValidatedFindingMaximum,
  ))
  set('VERIFIED_REMEDIATION_SUCCESS_THRESHOLD', releaseUtilityThresholdStatus(
    utility?.verifiedRemediationSuccessRate,
    'HIGHER',
    utilityThresholds.verifiedRemediationSuccessRateMinimum,
  ))
  set('VERIFIED_REMEDIATION_DURATION_THRESHOLD', releaseUtilityThresholdStatus(
    utility?.meanVerifiedRemediationDurationMs,
    'LOWER',
    utilityThresholds.meanVerifiedRemediationDurationMsMaximum,
  ))
  set('UNNECESSARY_REWORK_THRESHOLD', releaseUtilityThresholdStatus(
    utility?.unnecessaryReworkCount,
    'LOWER',
    utilityThresholds.unnecessaryReworkCountMaximum,
  ))
  set('VALID_APPROVAL_YIELD_THRESHOLD', releaseUtilityThresholdStatus(
    utility?.validApprovalYield,
    'HIGHER',
    utilityThresholds.validApprovalYieldMinimum,
  ))
  set('UNSAFE_APPROVAL_RATE_THRESHOLD', releaseUtilityThresholdStatus(
    utility?.unsafeApprovalRate,
    'LOWER',
    utilityThresholds.unsafeApprovalRateMaximum,
  ))

  const checks: ReleaseConstitutionCheckV1[] = RELEASE_CONSTITUTION_CHECK_IDS.map(
    checkId => ({ checkId, status: statuses.get(checkId) as ReleaseCheckStatusV1 }),
  )
  const failed = new Set(checks.filter(item => item.status === 'FAILED').map(item => item.checkId))
  const inconclusive = checks.some(item => item.status === 'INCONCLUSIVE')
  const reasonCodes: ReleaseConstitutionDecisionV1['reasonCodes'] = []
  if (
    failed.has('CONSTITUTION_PRE_REGISTERED')
    || failed.has('CALIBRATION_EVIDENCE_PRE_REGISTRATION')
  ) reasonCodes.push('CONSTITUTION_NOT_PRE_REGISTERED')
  const hardSafetyCheckIds = RELEASE_CONSTITUTION_CHECK_IDS.slice(2, 14)
  if (hardSafetyCheckIds.some(checkId => failed.has(checkId))) {
    reasonCodes.push('HARD_SAFETY_FLOOR_FAILED')
  }
  if (failed.has('EXACT_QUALIFIED_ARTIFACT')) {
    reasonCodes.push('ARTIFACT_IDENTITY_FAILED')
  }
  if (platformChecks.some(([, checkId]) => failed.has(checkId))) {
    reasonCodes.push('PLATFORM_PROOF_FAILED')
  }
  if (failed.has('PAIRED_EVIDENCE_CONCLUSIVE')) {
    reasonCodes.push('PAIRED_EVIDENCE_FAILED')
  }
  if (failed.has('MANDATORY_STRATA_NON_INFERIOR')) {
    reasonCodes.push('NON_INFERIORITY_FAILED')
  }
  if (RELEASE_CONSTITUTION_CHECK_IDS.slice(20, 25).some(checkId => failed.has(checkId))) {
    reasonCodes.push('EFFECTIVENESS_THRESHOLD_FAILED')
  }
  if (RELEASE_CONSTITUTION_CHECK_IDS.slice(25).some(checkId => failed.has(checkId))) {
    reasonCodes.push('UTILITY_THRESHOLD_FAILED')
  }
  if (inconclusive) reasonCodes.push('INCOMPLETE_RELEASE_EVIDENCE')
  const decision = failed.size > 0
    ? 'BLOCKED'
    : inconclusive ? 'INCONCLUSIVE' : 'PROMOTE'
  const result: ReleaseConstitutionDecisionV1 = {
    schemaVersion: 1,
    engineId: RELEASE_CONSTITUTION_ENGINE_ID,
    constitutionId: constitution.constitutionId,
    constitutionDigest: constitution.constitutionDigest,
    releaseCandidateId: candidate.releaseCandidateId,
    evidenceSetId: candidate.evidenceSetId,
    evidenceSetDigest: candidate.evidenceSetDigest,
    candidateArtifactDigest: candidate.candidateArtifactDigest,
    qualifiedArtifactDigest: candidate.qualifiedArtifactDigest,
    proposedPromotionArtifactDigest: candidate.proposedPromotionArtifactDigest,
    decision,
    reasonCodes,
    checks,
  }
  return deepFreeze(releaseConstitutionDecisionV1Schema.parse(result))
}

export const PUBLIC_SECURITY_SCORECARD_ENGINE_ID = 'security/public-scorecard/v1' as const

const publicSemanticVersionSchema = z.string()
  .regex(/^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/)
  .max(128)

const publicVersionTokenSchema = z.string()
  .regex(/^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$/)

const publicModelDisclosureV1Schema = z.discriminatedUnion('applicability', [
  z.strictObject({
    applicability: z.literal('NOT_APPLICABLE'),
    reason: z.literal('NO_MODEL_ASSISTED_EVALUATION'),
  }),
  z.strictObject({
    applicability: z.literal('APPLICABLE'),
    providerId: publicVersionTokenSchema,
    providerVersion: publicVersionTokenSchema,
    modelId: publicVersionTokenSchema,
    modelVersion: publicVersionTokenSchema,
  }),
])

export const publicSecurityScorecardRequestV1Schema = z.strictObject({
  schemaVersion: z.literal(1),
  engineId: z.literal(PUBLIC_SECURITY_SCORECARD_ENGINE_ID),
  publication: z.strictObject({
    publishedAtEpochMs: evaluationEpochMsSchema,
    releaseVersion: publicSemanticVersionSchema,
    harnessTargetVersion: publicSemanticVersionSchema,
    supportMatrixVersion: publicVersionTokenSchema,
    policyVersion: publicVersionTokenSchema,
    benchmarkVersion: publicVersionTokenSchema,
    corpusVersion: publicVersionTokenSchema,
    supportedEcosystems: z.array(publicVersionTokenSchema).min(1).max(64),
    assessmentModes: z.array(evaluationAssessmentModeSchema).min(1).max(3),
    profiles: z.array(publicVersionTokenSchema).min(1).max(16),
    model: publicModelDisclosureV1Schema,
  }),
  releaseEvaluation: releaseConstitutionEvaluationRequestV1Schema,
}).superRefine((value, context) => {
  const publication = value.publication
  if (
    publication.publishedAtEpochMs < value.releaseEvaluation.candidate.holdoutCompletedAtEpochMs
    || new Set(publication.supportedEcosystems).size !== publication.supportedEcosystems.length
    || new Set(publication.assessmentModes).size !== publication.assessmentModes.length
    || new Set(publication.profiles).size !== publication.profiles.length
  ) {
    context.addIssue({ code: 'custom', message: 'Inconsistent public Scorecard publication.' })
  }
})

export type PublicSecurityScorecardRequestV1 = z.infer<
  typeof publicSecurityScorecardRequestV1Schema
>

export const PUBLIC_SECURITY_SCORECARD_LIMITATION_CODES = [
  'NO_SECURITY_GUARANTEE',
  'NO_COMPLETE_VULNERABILITY_DISCOVERY_CLAIM',
  'OUTSIDE_DECLARED_SCOPE_UNSUPPORTED',
  'ACTIVE_HOLDOUT_DETAILS_WITHHELD',
  'SENSITIVE_EVIDENCE_WITHHELD',
  'PRIVATE_VULNERABILITIES_WITHHELD',
  'INCONCLUSIVE_BENCHMARK_STRATA',
  'INCONCLUSIVE_EFFECTIVENESS',
  'INCONCLUSIVE_PAIRED_COMPARISON',
  'INCONCLUSIVE_UTILITY',
  'NON_INFERIORITY_NOT_PROVEN',
  'NOT_A_STABLE_RELEASE_CLAIM',
] as const

export type PublicSecurityScorecardLimitationCode =
  typeof PUBLIC_SECURITY_SCORECARD_LIMITATION_CODES[number]

const publicSecurityScorecardLimitationCodeSchema = z.enum(
  PUBLIC_SECURITY_SCORECARD_LIMITATION_CODES,
)

const publicReleaseDecisionV1Schema = z.strictObject({
  releaseVersion: publicSemanticVersionSchema,
  candidateArtifactDigest: digestEnvelopeV1Schema,
  decision: releaseConstitutionDecisionV1Schema.shape.decision,
  reasonCodes: releaseConstitutionDecisionV1Schema.shape.reasonCodes,
  checks: releaseConstitutionDecisionV1Schema.shape.checks,
}).superRefine((value, context) => {
  const expectedIds = [...RELEASE_CONSTITUTION_CHECK_IDS]
  const actualIds = value.checks.map(item => item.checkId)
  const expectedDecision = value.checks.some(item => item.status === 'FAILED')
    ? 'BLOCKED'
    : value.checks.some(item => item.status === 'INCONCLUSIVE')
      ? 'INCONCLUSIVE'
      : 'PROMOTE'
  if (
    JSON.stringify(actualIds) !== JSON.stringify(expectedIds)
    || value.decision !== expectedDecision
    || (value.decision === 'PROMOTE' && value.reasonCodes.length !== 0)
    || (value.decision !== 'PROMOTE' && value.reasonCodes.length === 0)
  ) {
    context.addIssue({ code: 'custom', message: 'Inconsistent public Release decision.' })
  }
})

const publicEffectivenessMetricsV1Schema = z.strictObject({
  conclusion: effectivenessMetricsV1Schema.shape.conclusion,
  reasonCodes: effectivenessMetricsV1Schema.shape.reasonCodes,
  counts: effectivenessMetricsV1Schema.shape.counts,
  metrics: effectivenessMetricsV1Schema.shape.metrics,
  repetitionAnalysis: effectivenessMetricsV1Schema.shape.repetitionAnalysis,
})

const publicUtilityMetricsV1Schema = z.strictObject({
  conclusion: utilityMetricsV1Schema.shape.conclusion,
  reasonCodes: utilityMetricsV1Schema.shape.reasonCodes,
  validatedFindings: utilityMetricsV1Schema.shape.validatedFindings,
  executionCostMicrounits: resourceQuantitySchema,
  metrics: utilityMetricsV1Schema.shape.metrics,
})

const publicNonInferiorityV1Schema = z.strictObject({
  method: nonInferiorityComparisonV1Schema.shape.method,
  status: nonInferiorityComparisonV1Schema.shape.status,
  reasonCodes: nonInferiorityComparisonV1Schema.shape.reasonCodes,
  metrics: nonInferiorityComparisonV1Schema.shape.metrics,
  mandatoryStrata: z.strictObject({
    total: resourceQuantitySchema,
    passed: resourceQuantitySchema,
    failed: resourceQuantitySchema,
    inconclusive: resourceQuantitySchema,
  }),
}).superRefine((value, context) => {
  if (
    value.mandatoryStrata.total !== value.mandatoryStrata.passed
      + value.mandatoryStrata.failed
      + value.mandatoryStrata.inconclusive
  ) {
    context.addIssue({ code: 'custom', message: 'Inconsistent public Stratum summary.' })
  }
})

const publicScorecardFailuresV1Schema = z.strictObject({
  productFailureCount: resourceQuantitySchema,
  releaseReasonCodes: releaseConstitutionDecisionV1Schema.shape.reasonCodes,
  failedReleaseChecks: z.array(z.enum(RELEASE_CONSTITUTION_CHECK_IDS))
    .max(RELEASE_CONSTITUTION_CHECK_IDS.length),
  inconclusiveReleaseChecks: z.array(z.enum(RELEASE_CONSTITUTION_CHECK_IDS))
    .max(RELEASE_CONSTITUTION_CHECK_IDS.length),
  effectivenessReasonCodes: effectivenessMetricsV1Schema.shape.reasonCodes,
  comparisonReasonCodes: pairedArmComparisonV1Schema.shape.reasonCodes,
  utilityReasonCodes: utilityMetricsV1Schema.shape.reasonCodes,
  nonInferiorityReasonCodes: nonInferiorityComparisonV1Schema.shape.reasonCodes,
})

export const publicSecurityScorecardV1Schema = z.strictObject({
  schemaVersion: z.literal(1),
  engineId: z.literal(PUBLIC_SECURITY_SCORECARD_ENGINE_ID),
  publishedAtEpochMs: evaluationEpochMsSchema,
  release: publicReleaseDecisionV1Schema,
  scope: z.strictObject({
    harnessTargetVersion: publicSemanticVersionSchema,
    supportMatrixVersion: publicVersionTokenSchema,
    policyVersion: publicVersionTokenSchema,
    benchmarkVersion: publicVersionTokenSchema,
    corpusVersion: publicVersionTokenSchema,
    supportedEcosystems: z.array(publicVersionTokenSchema).min(1).max(64),
    assessmentModes: z.array(evaluationAssessmentModeSchema).min(1).max(3),
    profiles: z.array(publicVersionTokenSchema).min(1).max(16),
    model: publicModelDisclosureV1Schema,
  }),
  method: z.strictObject({
    releaseConstitutionEngineId: z.literal(RELEASE_CONSTITUTION_ENGINE_ID),
    comparisonEngineId: z.literal(PAIRED_ARM_COMPARISON_ENGINE_ID),
    effectivenessEngineId: z.literal(EFFECTIVENESS_METRICS_ENGINE_ID),
    utilityEngineId: z.literal(UTILITY_METRICS_ENGINE_ID),
    uncertaintyMethod: z.literal('HOEFFDING_TWO_SIDED_V1').nullable(),
    nonInferiorityMethod: z.literal('CONSERVATIVE_HOEFFDING_BOUNDS_V1').nullable(),
  }),
  corpus: effectivenessMetricsV1Schema.shape.counts,
  budget: pairedBudgetComparisonV1Schema,
  effectiveness: publicEffectivenessMetricsV1Schema,
  utility: publicUtilityMetricsV1Schema.nullable(),
  comparison: z.strictObject({
    view: pairedArmComparisonV1Schema.shape.comparisonView,
    conclusion: pairedArmComparisonV1Schema.shape.conclusion,
    reasonCodes: pairedArmComparisonV1Schema.shape.reasonCodes,
    effectiveness: pairedArmComparisonV1Schema.shape.metrics,
    utility: pairedUtilityComparisonV1Schema.shape.metrics.nullable(),
  }),
  nonInferiority: publicNonInferiorityV1Schema.nullable(),
  limitations: z.array(publicSecurityScorecardLimitationCodeSchema)
    .min(6)
    .max(PUBLIC_SECURITY_SCORECARD_LIMITATION_CODES.length),
  failures: publicScorecardFailuresV1Schema,
}).superRefine((value, context) => {
  const failedChecks = value.release.checks
    .filter(item => item.status === 'FAILED')
    .map(item => item.checkId)
  const inconclusiveChecks = value.release.checks
    .filter(item => item.status === 'INCONCLUSIVE')
    .map(item => item.checkId)
  const expectedLimitations = publicScorecardLimitations({
    decision: value.release.decision,
    effectivenessConclusion: value.effectiveness.conclusion,
    comparisonConclusion: value.comparison.conclusion,
    utilityConclusion: value.utility?.conclusion ?? null,
    nonInferiorityStatus: value.nonInferiority?.status ?? null,
    inconclusiveStrata: value.corpus.inconclusiveStrata,
  })
  const expectedEcosystems = [...new Set(value.scope.supportedEcosystems)].sort()
  const expectedModes = [...new Set(value.scope.assessmentModes)].sort()
  const expectedProfiles = [...new Set(value.scope.profiles)].sort()
  if (
    JSON.stringify(value.scope.supportedEcosystems) !== JSON.stringify(expectedEcosystems)
    || JSON.stringify(value.scope.assessmentModes) !== JSON.stringify(expectedModes)
    || JSON.stringify(value.scope.profiles) !== JSON.stringify(expectedProfiles)
    || JSON.stringify(value.limitations) !== JSON.stringify(expectedLimitations)
    || value.failures.productFailureCount !== value.corpus.productFailures
    || JSON.stringify(value.failures.releaseReasonCodes)
      !== JSON.stringify(value.release.reasonCodes)
    || JSON.stringify(value.failures.failedReleaseChecks) !== JSON.stringify(failedChecks)
    || JSON.stringify(value.failures.inconclusiveReleaseChecks)
      !== JSON.stringify(inconclusiveChecks)
    || JSON.stringify(value.failures.effectivenessReasonCodes)
      !== JSON.stringify(value.effectiveness.reasonCodes)
    || JSON.stringify(value.failures.comparisonReasonCodes)
      !== JSON.stringify(value.comparison.reasonCodes)
    || JSON.stringify(value.failures.utilityReasonCodes)
      !== JSON.stringify(value.utility?.reasonCodes ?? [])
    || JSON.stringify(value.failures.nonInferiorityReasonCodes)
      !== JSON.stringify(value.nonInferiority?.reasonCodes ?? [])
  ) {
    context.addIssue({ code: 'custom', message: 'Inconsistent public Scorecard disclosure.' })
  }
})

export type PublicSecurityScorecardV1 = z.infer<typeof publicSecurityScorecardV1Schema>

/** Stable, detail-free rejection for malformed Scorecard publication input. */
export class PublicSecurityScorecardInputError extends Error {
  readonly code = 'INVALID_PUBLIC_SECURITY_SCORECARD_INPUT' as const

  constructor() {
    super('Publication input does not match Public Security Scorecard v1.')
    this.name = 'PublicSecurityScorecardInputError'
  }
}

interface PublicScorecardLimitationInput {
  readonly decision: ReleaseConstitutionDecisionV1['decision']
  readonly effectivenessConclusion: EffectivenessMetricsV1['conclusion']
  readonly comparisonConclusion: PairedArmComparisonV1['conclusion']
  readonly utilityConclusion: UtilityMetricsV1['conclusion'] | null
  readonly nonInferiorityStatus: NonInferiorityComparisonV1['status'] | null
  readonly inconclusiveStrata: number
}

function publicScorecardLimitations(
  input: PublicScorecardLimitationInput,
): PublicSecurityScorecardLimitationCode[] {
  const limitations: PublicSecurityScorecardLimitationCode[] = [
    'NO_SECURITY_GUARANTEE',
    'NO_COMPLETE_VULNERABILITY_DISCOVERY_CLAIM',
    'OUTSIDE_DECLARED_SCOPE_UNSUPPORTED',
    'ACTIVE_HOLDOUT_DETAILS_WITHHELD',
    'SENSITIVE_EVIDENCE_WITHHELD',
    'PRIVATE_VULNERABILITIES_WITHHELD',
  ]
  if (input.inconclusiveStrata > 0) limitations.push('INCONCLUSIVE_BENCHMARK_STRATA')
  if (input.effectivenessConclusion === 'INCONCLUSIVE') {
    limitations.push('INCONCLUSIVE_EFFECTIVENESS')
  }
  if (input.comparisonConclusion === 'INCONCLUSIVE') {
    limitations.push('INCONCLUSIVE_PAIRED_COMPARISON')
  }
  if (input.utilityConclusion !== 'MEASURED') limitations.push('INCONCLUSIVE_UTILITY')
  if (input.nonInferiorityStatus !== 'PASSED') {
    limitations.push('NON_INFERIORITY_NOT_PROVEN')
  }
  if (input.decision !== 'PROMOTE') limitations.push('NOT_A_STABLE_RELEASE_CLAIM')
  return limitations
}

/** Render one deterministic, whitelist-only public View from private release Evidence. */
export function renderPublicSecurityScorecardV1(
  input: unknown,
): PublicSecurityScorecardV1 {
  const parsed = publicSecurityScorecardRequestV1Schema.safeParse(input)
  if (!parsed.success) throw new PublicSecurityScorecardInputError()
  const { publication, releaseEvaluation } = parsed.data
  const releaseDecision = evaluateReleaseConstitutionV1(releaseEvaluation)
  const paired = releaseEvaluation.candidate.pairedComparison
  const effectiveness = paired.candidate.metrics
  const utility = paired.utilityComparison?.candidate ?? null
  const nonInferiority = paired.nonInferiority
  const limitations = publicScorecardLimitations({
    decision: releaseDecision.decision,
    effectivenessConclusion: effectiveness.conclusion,
    comparisonConclusion: paired.conclusion,
    utilityConclusion: utility?.conclusion ?? null,
    nonInferiorityStatus: nonInferiority?.status ?? null,
    inconclusiveStrata: effectiveness.counts.inconclusiveStrata,
  })
  const failedReleaseChecks = releaseDecision.checks
    .filter(item => item.status === 'FAILED')
    .map(item => item.checkId)
  const inconclusiveReleaseChecks = releaseDecision.checks
    .filter(item => item.status === 'INCONCLUSIVE')
    .map(item => item.checkId)
  const mandatoryStrata = nonInferiority === null
    ? null
    : {
        total: nonInferiority.strata.length,
        passed: nonInferiority.strata.filter(item => item.validatedRecall.status === 'PASSED')
          .length,
        failed: nonInferiority.strata.filter(item => item.validatedRecall.status === 'FAILED')
          .length,
        inconclusive: nonInferiority.strata.filter(
          item => item.validatedRecall.status === 'INCONCLUSIVE',
        ).length,
      }
  const result: PublicSecurityScorecardV1 = {
    schemaVersion: 1,
    engineId: PUBLIC_SECURITY_SCORECARD_ENGINE_ID,
    publishedAtEpochMs: publication.publishedAtEpochMs,
    release: {
      releaseVersion: publication.releaseVersion,
      candidateArtifactDigest: releaseDecision.candidateArtifactDigest,
      decision: releaseDecision.decision,
      reasonCodes: releaseDecision.reasonCodes,
      checks: releaseDecision.checks,
    },
    scope: {
      harnessTargetVersion: publication.harnessTargetVersion,
      supportMatrixVersion: publication.supportMatrixVersion,
      policyVersion: publication.policyVersion,
      benchmarkVersion: publication.benchmarkVersion,
      corpusVersion: publication.corpusVersion,
      supportedEcosystems: [...publication.supportedEcosystems].sort(),
      assessmentModes: [...publication.assessmentModes].sort(),
      profiles: [...publication.profiles].sort(),
      model: publication.model,
    },
    method: {
      releaseConstitutionEngineId: RELEASE_CONSTITUTION_ENGINE_ID,
      comparisonEngineId: PAIRED_ARM_COMPARISON_ENGINE_ID,
      effectivenessEngineId: EFFECTIVENESS_METRICS_ENGINE_ID,
      utilityEngineId: UTILITY_METRICS_ENGINE_ID,
      uncertaintyMethod: effectiveness.repetitionAnalysis?.method ?? null,
      nonInferiorityMethod: nonInferiority?.method ?? null,
    },
    corpus: effectiveness.counts,
    budget: paired.budgetComparison,
    effectiveness: {
      conclusion: effectiveness.conclusion,
      reasonCodes: effectiveness.reasonCodes,
      counts: effectiveness.counts,
      metrics: effectiveness.metrics,
      repetitionAnalysis: effectiveness.repetitionAnalysis,
    },
    utility: utility === null
      ? null
      : {
          conclusion: utility.conclusion,
          reasonCodes: utility.reasonCodes,
          validatedFindings: utility.validatedFindings,
          executionCostMicrounits: utility.evidence.executionCostMicrounits,
          metrics: utility.metrics,
        },
    comparison: {
      view: paired.comparisonView,
      conclusion: paired.conclusion,
      reasonCodes: paired.reasonCodes,
      effectiveness: paired.metrics,
      utility: paired.utilityComparison?.metrics ?? null,
    },
    nonInferiority: nonInferiority === null || mandatoryStrata === null
      ? null
      : {
          method: nonInferiority.method,
          status: nonInferiority.status,
          reasonCodes: nonInferiority.reasonCodes,
          metrics: nonInferiority.metrics,
          mandatoryStrata,
        },
    limitations,
    failures: {
      productFailureCount: effectiveness.counts.productFailures,
      releaseReasonCodes: releaseDecision.reasonCodes,
      failedReleaseChecks,
      inconclusiveReleaseChecks,
      effectivenessReasonCodes: effectiveness.reasonCodes,
      comparisonReasonCodes: paired.reasonCodes,
      utilityReasonCodes: utility?.reasonCodes ?? [],
      nonInferiorityReasonCodes: nonInferiority?.reasonCodes ?? [],
    },
  }
  return deepFreeze(publicSecurityScorecardV1Schema.parse(result))
}

export const RELEASE_EVIDENCE_MANIFEST_ENGINE_ID =
  'security/release-evidence-manifest/v1' as const

export const RELEASE_EVIDENCE_PROOF_KINDS = [
  'ARTIFACT_IDENTITY',
  'CAPABILITY_CONFORMANCE',
  'WINDOWS_PLATFORM',
  'LINUX_PLATFORM',
  'MACOS_PLATFORM',
  'WORKBENCH',
  'LIFECYCLE',
  'FAULT',
  'RACE',
  'MUTATION',
  'RESOURCE',
  'EFFECTIVENESS',
  'UTILITY',
  'NON_INFERIORITY',
  'DOGFOOD',
  'SELF_SECURITY',
  'GROUND_TRUTH_AIR_GAP',
  'DETERMINISTIC_FAILURES',
  'SECURITY_SUPPORT_MATRIX',
  'RISK_ACCEPTANCES',
  'EVALUATION_RUN_BUNDLE',
  'PUBLIC_SCORECARD',
  'RELEASE_CONSTITUTION',
] as const

export type ReleaseEvidenceProofKind = typeof RELEASE_EVIDENCE_PROOF_KINDS[number]

const releaseEvidenceReportedStatusV1Schema = z.enum(['PASSED', 'FAILED', 'INCONCLUSIVE'])

export const releaseEvidenceProofV1Schema = z.strictObject({
  proofKind: z.enum(RELEASE_EVIDENCE_PROOF_KINDS),
  evidenceId: boundedEvaluationIdSchema,
  evidenceDigest: digestEnvelopeV1Schema,
  reportedStatus: releaseEvidenceReportedStatusV1Schema,
  candidateArtifactDigest: digestEnvelopeV1Schema,
  completedAtEpochMs: evaluationEpochMsSchema,
})

export type ReleaseEvidenceProofV1 = z.infer<typeof releaseEvidenceProofV1Schema>

const releaseDependencyLockV1Schema = z.strictObject({
  lockKind: z.enum([
    'NPM_PACKAGE_LOCK',
    'NPM_SHRINKWRAP',
    'PNPM_LOCK',
    'YARN_LOCK',
    'OTHER_CANONICAL_LOCK',
  ]),
  lockDigest: digestEnvelopeV1Schema,
})

const releaseEvaluationRunBundleReferenceV1Schema = z.strictObject({
  role: z.enum(['CANDIDATE', 'PRIOR_STABLE']),
  bundleId: boundedEvaluationIdSchema,
  bundleDigest: digestEnvelopeV1Schema,
  artifactDigest: digestEnvelopeV1Schema,
})

const releaseRiskAcceptanceReferenceV1Schema = z.strictObject({
  riskAcceptanceId: boundedEvaluationIdSchema,
  decisionDigest: digestEnvelopeV1Schema,
  status: z.enum(['ACTIVE', 'EXPIRED', 'REVOKED']),
  expiresAtEpochMs: evaluationEpochMsSchema,
  compensationEvidenceDigest: digestEnvelopeV1Schema,
  adrId: boundedEvaluationIdSchema,
})

export const releaseEvidenceManifestRequestV1Schema = z.strictObject({
  schemaVersion: z.literal(1),
  engineId: z.literal(RELEASE_EVIDENCE_MANIFEST_ENGINE_ID),
  manifestId: boundedEvaluationIdSchema,
  assembledAtEpochMs: evaluationEpochMsSchema,
  sourceRevision: z.string().regex(/^(?:[0-9a-f]{40}|[0-9a-f]{64})$/),
  dependencyLocks: z.array(releaseDependencyLockV1Schema).min(1).max(5),
  releaseEvaluation: releaseConstitutionEvaluationRequestV1Schema,
  publicScorecard: publicSecurityScorecardV1Schema,
  proofs: z.array(releaseEvidenceProofV1Schema)
    .max(RELEASE_EVIDENCE_PROOF_KINDS.length),
  evaluationRunBundles: z.array(releaseEvaluationRunBundleReferenceV1Schema)
    .min(2)
    .max(1_000),
  riskAcceptances: z.array(releaseRiskAcceptanceReferenceV1Schema).max(1_000),
}).superRefine((value, context) => {
  const proofKinds = value.proofs.map(item => item.proofKind)
  const lockKinds = value.dependencyLocks.map(item => item.lockKind)
  const bundleIds = value.evaluationRunBundles.map(item => item.bundleId)
  const riskAcceptanceIds = value.riskAcceptances.map(item => item.riskAcceptanceId)
  const bundleRoles = new Set(value.evaluationRunBundles.map(item => item.role))
  if (
    new Set(proofKinds).size !== proofKinds.length
    || new Set(lockKinds).size !== lockKinds.length
    || new Set(bundleIds).size !== bundleIds.length
    || new Set(riskAcceptanceIds).size !== riskAcceptanceIds.length
    || !bundleRoles.has('CANDIDATE')
    || !bundleRoles.has('PRIOR_STABLE')
    || value.publicScorecard.publishedAtEpochMs > value.assembledAtEpochMs
    || value.proofs.some(item => item.completedAtEpochMs > value.assembledAtEpochMs)
    || value.riskAcceptances.some(item => (
      item.status === 'ACTIVE' && item.expiresAtEpochMs <= value.assembledAtEpochMs
    ))
  ) {
    context.addIssue({ code: 'custom', message: 'Inconsistent Release Evidence input.' })
  }
})

export type ReleaseEvidenceManifestRequestV1 = z.infer<
  typeof releaseEvidenceManifestRequestV1Schema
>

const normalizedReleaseEvidenceProofV1Schema = z.strictObject({
  proofKind: z.enum(RELEASE_EVIDENCE_PROOF_KINDS),
  evidenceId: boundedEvaluationIdSchema.nullable(),
  evidenceDigest: digestEnvelopeV1Schema.nullable(),
  reportedStatus: z.enum(['PASSED', 'FAILED', 'INCONCLUSIVE', 'MISSING']),
  candidateArtifactDigest: digestEnvelopeV1Schema.nullable(),
  completedAtEpochMs: evaluationEpochMsSchema.nullable(),
  artifactBinding: z.enum(['MATCHED', 'MISMATCH', 'MISSING']),
  constitutionAlignment: z.enum(['MATCHED', 'MISMATCH', 'NOT_APPLICABLE', 'MISSING']),
  sourceEvidenceAlignment: z.enum(['MATCHED', 'MISMATCH', 'NOT_APPLICABLE', 'MISSING']),
  verificationStatus: z.enum(['PASSED', 'FAILED', 'INCONCLUSIVE']),
}).superRefine((value, context) => {
  const missing = value.reportedStatus === 'MISSING'
  const missingFields = value.evidenceId === null
    && value.evidenceDigest === null
    && value.candidateArtifactDigest === null
    && value.completedAtEpochMs === null
  const expectedVerification = missing
    ? 'INCONCLUSIVE'
    : value.reportedStatus === 'FAILED'
      || value.artifactBinding === 'MISMATCH'
      || value.constitutionAlignment === 'MISMATCH'
      || value.sourceEvidenceAlignment === 'MISMATCH'
      ? 'FAILED'
      : value.reportedStatus === 'INCONCLUSIVE' ? 'INCONCLUSIVE' : 'PASSED'
  if (
    (missing && (
      !missingFields
      || value.artifactBinding !== 'MISSING'
      || value.constitutionAlignment !== 'MISSING'
      || value.sourceEvidenceAlignment !== 'MISSING'
    ))
    || (!missing && (
      !value.evidenceId
      || !value.evidenceDigest
      || !value.candidateArtifactDigest
      || value.completedAtEpochMs === null
      || value.artifactBinding === 'MISSING'
      || value.constitutionAlignment === 'MISSING'
      || value.sourceEvidenceAlignment === 'MISSING'
    ))
    || value.verificationStatus !== expectedVerification
  ) {
    context.addIssue({ code: 'custom', message: 'Inconsistent normalized Release proof.' })
  }
})

export type NormalizedReleaseEvidenceProofV1 = z.infer<
  typeof normalizedReleaseEvidenceProofV1Schema
>

export const RELEASE_EVIDENCE_MANIFEST_REASON_CODES = [
  'RELEASE_CONSTITUTION_BLOCKED',
  'RELEASE_CONSTITUTION_INCONCLUSIVE',
  'PROOF_FAILED',
  'PROOF_MISSING',
  'PROOF_INCONCLUSIVE',
  'PROOF_ARTIFACT_MISMATCH',
  'PROOF_CONSTITUTION_MISMATCH',
  'PROOF_EVIDENCE_MISMATCH',
  'PUBLIC_SCORECARD_MISMATCH',
  'EVALUATION_BUNDLE_ARTIFACT_MISMATCH',
] as const

export type ReleaseEvidenceManifestReasonCode =
  typeof RELEASE_EVIDENCE_MANIFEST_REASON_CODES[number]

const releaseEvidenceManifestReasonCodeSchema = z.enum(
  RELEASE_EVIDENCE_MANIFEST_REASON_CODES,
)

const releaseEvidenceScorecardReferenceV1Schema = z.strictObject({
  engineId: z.literal(PUBLIC_SECURITY_SCORECARD_ENGINE_ID),
  publishedAtEpochMs: evaluationEpochMsSchema,
  releaseVersion: publicSemanticVersionSchema,
  harnessTargetVersion: publicSemanticVersionSchema,
  candidateArtifactDigest: digestEnvelopeV1Schema,
  decision: releaseConstitutionDecisionV1Schema.shape.decision,
  reasonCodes: releaseConstitutionDecisionV1Schema.shape.reasonCodes,
  checks: releaseConstitutionDecisionV1Schema.shape.checks,
  limitationCodes: z.array(publicSecurityScorecardLimitationCodeSchema)
    .min(6)
    .max(PUBLIC_SECURITY_SCORECARD_LIMITATION_CODES.length),
})

const releaseConstitutionEvidenceReferencesV1Schema = z.strictObject({
  constitution: z.strictObject({
    evidenceId: boundedEvaluationIdSchema,
    evidenceDigest: digestEnvelopeV1Schema,
  }),
  hardSafety: z.strictObject({
    evidenceId: boundedEvaluationIdSchema,
    evidenceDigest: digestEnvelopeV1Schema,
  }),
  evidenceSet: z.strictObject({
    evidenceId: boundedEvaluationIdSchema,
    evidenceDigest: digestEnvelopeV1Schema,
  }),
  platforms: z.array(z.strictObject({
    platform: z.enum(['WINDOWS', 'LINUX', 'MACOS']),
    evidenceId: boundedEvaluationIdSchema,
    evidenceDigest: digestEnvelopeV1Schema,
  })).max(3),
})

const releaseEvidenceManifestVerificationV1Schema = z.strictObject({
  decision: z.enum(['VERIFIED', 'BLOCKED', 'INCONCLUSIVE']),
  reasonCodes: z.array(releaseEvidenceManifestReasonCodeSchema)
    .max(RELEASE_EVIDENCE_MANIFEST_REASON_CODES.length),
  failedProofKinds: z.array(z.enum(RELEASE_EVIDENCE_PROOF_KINDS))
    .max(RELEASE_EVIDENCE_PROOF_KINDS.length),
  inconclusiveProofKinds: z.array(z.enum(RELEASE_EVIDENCE_PROOF_KINDS))
    .max(RELEASE_EVIDENCE_PROOF_KINDS.length),
  mismatchedProofKinds: z.array(z.enum(RELEASE_EVIDENCE_PROOF_KINDS))
    .max(RELEASE_EVIDENCE_PROOF_KINDS.length),
})

export const releaseEvidenceManifestV1Schema = z.strictObject({
  schemaVersion: z.literal(1),
  engineId: z.literal(RELEASE_EVIDENCE_MANIFEST_ENGINE_ID),
  manifestId: boundedEvaluationIdSchema,
  assembledAtEpochMs: evaluationEpochMsSchema,
  releaseCandidateId: boundedEvaluationIdSchema,
  sourceRevision: z.string().regex(/^(?:[0-9a-f]{40}|[0-9a-f]{64})$/),
  harnessTargetVersion: publicSemanticVersionSchema,
  candidateArtifactDigest: digestEnvelopeV1Schema,
  qualifiedArtifactDigest: digestEnvelopeV1Schema,
  proposedPromotionArtifactDigest: digestEnvelopeV1Schema,
  dependencyLocks: z.array(releaseDependencyLockV1Schema).min(1).max(5),
  releaseConstitution: releaseConstitutionDecisionV1Schema,
  constitutionEvidence: releaseConstitutionEvidenceReferencesV1Schema,
  publicScorecard: releaseEvidenceScorecardReferenceV1Schema,
  proofs: z.array(normalizedReleaseEvidenceProofV1Schema)
    .length(RELEASE_EVIDENCE_PROOF_KINDS.length),
  evaluationRunBundles: z.array(releaseEvaluationRunBundleReferenceV1Schema)
    .min(2)
    .max(1_000),
  knownLimitations: z.array(publicSecurityScorecardLimitationCodeSchema)
    .min(6)
    .max(PUBLIC_SECURITY_SCORECARD_LIMITATION_CODES.length),
  riskAcceptances: z.array(releaseRiskAcceptanceReferenceV1Schema).max(1_000),
  verification: releaseEvidenceManifestVerificationV1Schema,
}).superRefine((value, context) => {
  const actualKinds = value.proofs.map(item => item.proofKind)
  const expectedLocks = [...value.dependencyLocks]
    .sort((left, right) => left.lockKind.localeCompare(right.lockKind))
  const expectedBundles = [...value.evaluationRunBundles].sort(compareReleaseBundleReferences)
  const expectedRiskAcceptances = [...value.riskAcceptances]
    .sort((left, right) => left.riskAcceptanceId.localeCompare(right.riskAcceptanceId))
  const expectedPlatforms = [...value.constitutionEvidence.platforms]
    .sort((left, right) => left.platform.localeCompare(right.platform))
  const expectedVerification = releaseEvidenceManifestVerification({
    releaseConstitution: value.releaseConstitution,
    publicScorecard: value.publicScorecard,
    proofs: value.proofs,
    evaluationRunBundles: value.evaluationRunBundles,
    candidateArtifactDigest: value.candidateArtifactDigest,
  })
  const proofAlignmentMismatch = value.proofs.some(proof => {
    if (proof.reportedStatus === 'MISSING') return false
    const expectedStatus = expectedConstitutionProofStatus(
      proof.proofKind,
      value.releaseConstitution,
    )
    const expectedAlignment = expectedStatus === null
      ? 'NOT_APPLICABLE'
      : proof.reportedStatus === expectedStatus ? 'MATCHED' : 'MISMATCH'
    const expectedSource = expectedProofSourceEvidence(
      proof.proofKind,
      value.constitutionEvidence,
    )
    const expectedSourceAlignment = expectedSource === undefined
      ? 'NOT_APPLICABLE'
      : expectedSource === null
        ? 'MISMATCH'
        : proof.evidenceId === expectedSource.evidenceId
          && sameDigest(
            proof.evidenceDigest as z.infer<typeof digestEnvelopeV1Schema>,
            expectedSource.evidenceDigest,
          )
          ? 'MATCHED'
          : 'MISMATCH'
    const expectedBinding = sameDigest(
      proof.candidateArtifactDigest as z.infer<typeof digestEnvelopeV1Schema>,
      value.candidateArtifactDigest,
    ) ? 'MATCHED' : 'MISMATCH'
    return proof.constitutionAlignment !== expectedAlignment
      || proof.artifactBinding !== expectedBinding
      || proof.sourceEvidenceAlignment !== expectedSourceAlignment
  })
  if (
    JSON.stringify(actualKinds) !== JSON.stringify(RELEASE_EVIDENCE_PROOF_KINDS)
    || JSON.stringify(value.dependencyLocks) !== JSON.stringify(expectedLocks)
    || JSON.stringify(value.evaluationRunBundles) !== JSON.stringify(expectedBundles)
    || JSON.stringify(value.riskAcceptances) !== JSON.stringify(expectedRiskAcceptances)
    || JSON.stringify(value.constitutionEvidence.platforms)
      !== JSON.stringify(expectedPlatforms)
    || new Set(value.constitutionEvidence.platforms.map(item => item.platform)).size
      !== value.constitutionEvidence.platforms.length
    || JSON.stringify(value.knownLimitations)
      !== JSON.stringify(value.publicScorecard.limitationCodes)
    || value.releaseCandidateId !== value.releaseConstitution.releaseCandidateId
    || value.harnessTargetVersion !== value.publicScorecard.harnessTargetVersion
    || !sameDigest(
      value.candidateArtifactDigest,
      value.releaseConstitution.candidateArtifactDigest,
    )
    || !sameDigest(
      value.qualifiedArtifactDigest,
      value.releaseConstitution.qualifiedArtifactDigest,
    )
    || !sameDigest(
      value.proposedPromotionArtifactDigest,
      value.releaseConstitution.proposedPromotionArtifactDigest,
    )
    || value.constitutionEvidence.constitution.evidenceId
      !== value.releaseConstitution.constitutionId
    || !sameDigest(
      value.constitutionEvidence.constitution.evidenceDigest,
      value.releaseConstitution.constitutionDigest,
    )
    || value.constitutionEvidence.evidenceSet.evidenceId
      !== value.releaseConstitution.evidenceSetId
    || !sameDigest(
      value.constitutionEvidence.evidenceSet.evidenceDigest,
      value.releaseConstitution.evidenceSetDigest,
    )
    || value.publicScorecard.publishedAtEpochMs > value.assembledAtEpochMs
    || value.riskAcceptances.some(item => (
      item.status === 'ACTIVE' && item.expiresAtEpochMs <= value.assembledAtEpochMs
    ))
    || proofAlignmentMismatch
    || JSON.stringify(value.verification) !== JSON.stringify(expectedVerification)
  ) {
    context.addIssue({ code: 'custom', message: 'Inconsistent Release Evidence Manifest.' })
  }
})

export type ReleaseEvidenceManifestV1 = z.infer<typeof releaseEvidenceManifestV1Schema>

/** Stable, detail-free rejection for malformed Release Evidence Manifest input. */
export class ReleaseEvidenceManifestInputError extends Error {
  readonly code = 'INVALID_RELEASE_EVIDENCE_MANIFEST_INPUT' as const

  constructor() {
    super('Evidence does not match Release Evidence Manifest v1.')
    this.name = 'ReleaseEvidenceManifestInputError'
  }
}

type ReleaseProofReportedStatus = z.infer<typeof releaseEvidenceReportedStatusV1Schema>

function aggregateReleaseCheckStatus(
  decision: ReleaseConstitutionDecisionV1,
  checkIds: readonly ReleaseConstitutionCheckId[],
): ReleaseProofReportedStatus {
  const statuses = checkIds.map(checkId => (
    decision.checks.find(item => item.checkId === checkId)?.status ?? 'INCONCLUSIVE'
  ))
  return statuses.some(status => status === 'FAILED')
    ? 'FAILED'
    : statuses.some(status => status === 'INCONCLUSIVE') ? 'INCONCLUSIVE' : 'PASSED'
}

function expectedConstitutionProofStatus(
  proofKind: ReleaseEvidenceProofKind,
  decision: ReleaseConstitutionDecisionV1,
): ReleaseProofReportedStatus | null {
  switch (proofKind) {
    case 'ARTIFACT_IDENTITY':
      return aggregateReleaseCheckStatus(decision, ['EXACT_QUALIFIED_ARTIFACT'])
    case 'CAPABILITY_CONFORMANCE':
      return aggregateReleaseCheckStatus(decision, ['COMPLETE_CAPABILITY_CONFORMANCE'])
    case 'WINDOWS_PLATFORM':
      return aggregateReleaseCheckStatus(decision, ['WINDOWS_PACKED_CONFORMANCE'])
    case 'LINUX_PLATFORM':
      return aggregateReleaseCheckStatus(decision, ['LINUX_PACKED_CONFORMANCE'])
    case 'MACOS_PLATFORM':
      return aggregateReleaseCheckStatus(decision, ['MACOS_PACKED_CONFORMANCE'])
    case 'EFFECTIVENESS':
      return aggregateReleaseCheckStatus(decision, RELEASE_CONSTITUTION_CHECK_IDS.slice(20, 25))
    case 'UTILITY':
      return aggregateReleaseCheckStatus(decision, RELEASE_CONSTITUTION_CHECK_IDS.slice(25))
    case 'NON_INFERIORITY':
      return aggregateReleaseCheckStatus(decision, ['MANDATORY_STRATA_NON_INFERIOR'])
    case 'SELF_SECURITY':
      return aggregateReleaseCheckStatus(decision, [
        'SELF_SECURITY_CRITICAL_HIGH_CLEAR',
        'SELF_SECURITY_BLOCKING_MEDIUM_CLEAR',
      ])
    case 'GROUND_TRUTH_AIR_GAP':
      return aggregateReleaseCheckStatus(decision, ['NO_GROUND_TRUTH_LEAKAGE'])
    case 'DETERMINISTIC_FAILURES':
      return aggregateReleaseCheckStatus(decision, ['NO_UNRESOLVED_DETERMINISTIC_FAILURES'])
    case 'SECURITY_SUPPORT_MATRIX':
      return aggregateReleaseCheckStatus(decision, [
        'WINDOWS_PACKED_CONFORMANCE',
        'LINUX_PACKED_CONFORMANCE',
        'MACOS_PACKED_CONFORMANCE',
      ])
    case 'RISK_ACCEPTANCES':
      return aggregateReleaseCheckStatus(decision, ['NO_UNAUTHORIZED_RISK_ACCEPTANCE'])
    case 'EVALUATION_RUN_BUNDLE':
      return aggregateReleaseCheckStatus(decision, ['PAIRED_EVIDENCE_CONCLUSIVE'])
    case 'RELEASE_CONSTITUTION':
      return decision.decision === 'PROMOTE'
        ? 'PASSED'
        : decision.decision === 'BLOCKED' ? 'FAILED' : 'INCONCLUSIVE'
    default:
      return null
  }
}

type ReleaseConstitutionEvidenceReferencesV1 = z.infer<
  typeof releaseConstitutionEvidenceReferencesV1Schema
>

interface ExpectedProofSourceEvidence {
  readonly evidenceId: string
  readonly evidenceDigest: z.infer<typeof digestEnvelopeV1Schema>
}

function expectedProofSourceEvidence(
  proofKind: ReleaseEvidenceProofKind,
  references: ReleaseConstitutionEvidenceReferencesV1,
): ExpectedProofSourceEvidence | null | undefined {
  switch (proofKind) {
    case 'CAPABILITY_CONFORMANCE':
    case 'SELF_SECURITY':
    case 'GROUND_TRUTH_AIR_GAP':
    case 'DETERMINISTIC_FAILURES':
    case 'RISK_ACCEPTANCES':
      return references.hardSafety
    case 'WINDOWS_PLATFORM':
    case 'LINUX_PLATFORM':
    case 'MACOS_PLATFORM': {
      const platform = proofKind.replace('_PLATFORM', '') as 'WINDOWS' | 'LINUX' | 'MACOS'
      return references.platforms.find(item => item.platform === platform) ?? null
    }
    case 'EVALUATION_RUN_BUNDLE':
      return references.evidenceSet
    case 'RELEASE_CONSTITUTION':
      return references.constitution
    default:
      return undefined
  }
}

function compareReleaseBundleReferences(
  left: z.infer<typeof releaseEvaluationRunBundleReferenceV1Schema>,
  right: z.infer<typeof releaseEvaluationRunBundleReferenceV1Schema>,
): number {
  return left.role.localeCompare(right.role) || left.bundleId.localeCompare(right.bundleId)
}

interface ReleaseEvidenceVerificationInput {
  readonly releaseConstitution: ReleaseConstitutionDecisionV1
  readonly publicScorecard: z.infer<typeof releaseEvidenceScorecardReferenceV1Schema>
  readonly proofs: readonly NormalizedReleaseEvidenceProofV1[]
  readonly evaluationRunBundles: readonly z.infer<
    typeof releaseEvaluationRunBundleReferenceV1Schema
  >[]
  readonly candidateArtifactDigest: z.infer<typeof digestEnvelopeV1Schema>
}

function scorecardMatchesRelease(input: ReleaseEvidenceVerificationInput): boolean {
  const { publicScorecard, releaseConstitution } = input
  return sameDigest(
    publicScorecard.candidateArtifactDigest,
    releaseConstitution.candidateArtifactDigest,
  )
    && publicScorecard.decision === releaseConstitution.decision
    && JSON.stringify(publicScorecard.reasonCodes)
      === JSON.stringify(releaseConstitution.reasonCodes)
    && JSON.stringify(publicScorecard.checks) === JSON.stringify(releaseConstitution.checks)
}

function releaseEvidenceManifestVerification(
  input: ReleaseEvidenceVerificationInput,
): z.infer<typeof releaseEvidenceManifestVerificationV1Schema> {
  const failedProofKinds = input.proofs
    .filter(item => item.verificationStatus === 'FAILED')
    .map(item => item.proofKind)
  const inconclusiveProofKinds = input.proofs
    .filter(item => item.verificationStatus === 'INCONCLUSIVE')
    .map(item => item.proofKind)
  const mismatchedProofKinds = input.proofs
    .filter(item => (
      item.artifactBinding === 'MISMATCH'
      || item.constitutionAlignment === 'MISMATCH'
      || item.sourceEvidenceAlignment === 'MISMATCH'
    ))
    .map(item => item.proofKind)
  const missingProof = input.proofs.some(item => item.reportedStatus === 'MISSING')
  const inconclusiveProof = input.proofs.some(item => item.reportedStatus === 'INCONCLUSIVE')
  const artifactMismatch = input.proofs.some(item => item.artifactBinding === 'MISMATCH')
  const constitutionMismatch = input.proofs.some(
    item => item.constitutionAlignment === 'MISMATCH',
  )
  const evidenceMismatch = input.proofs.some(
    item => item.sourceEvidenceAlignment === 'MISMATCH',
  )
  const scorecardMismatch = !scorecardMatchesRelease(input)
  const bundleArtifactMismatch = input.evaluationRunBundles.some(item => (
    item.role === 'CANDIDATE'
    && !sameDigest(item.artifactDigest, input.candidateArtifactDigest)
  ))
  const reasonCodes: ReleaseEvidenceManifestReasonCode[] = []
  if (input.releaseConstitution.decision === 'BLOCKED') {
    reasonCodes.push('RELEASE_CONSTITUTION_BLOCKED')
  }
  if (input.releaseConstitution.decision === 'INCONCLUSIVE') {
    reasonCodes.push('RELEASE_CONSTITUTION_INCONCLUSIVE')
  }
  if (failedProofKinds.length > 0) reasonCodes.push('PROOF_FAILED')
  if (missingProof) reasonCodes.push('PROOF_MISSING')
  if (inconclusiveProof) reasonCodes.push('PROOF_INCONCLUSIVE')
  if (artifactMismatch) reasonCodes.push('PROOF_ARTIFACT_MISMATCH')
  if (constitutionMismatch) reasonCodes.push('PROOF_CONSTITUTION_MISMATCH')
  if (evidenceMismatch) reasonCodes.push('PROOF_EVIDENCE_MISMATCH')
  if (scorecardMismatch) reasonCodes.push('PUBLIC_SCORECARD_MISMATCH')
  if (bundleArtifactMismatch) reasonCodes.push('EVALUATION_BUNDLE_ARTIFACT_MISMATCH')
  const blocked = input.releaseConstitution.decision === 'BLOCKED'
    || failedProofKinds.length > 0
    || scorecardMismatch
    || bundleArtifactMismatch
  const inconclusive = input.releaseConstitution.decision === 'INCONCLUSIVE'
    || inconclusiveProofKinds.length > 0
  return {
    decision: blocked ? 'BLOCKED' : inconclusive ? 'INCONCLUSIVE' : 'VERIFIED',
    reasonCodes,
    failedProofKinds,
    inconclusiveProofKinds,
    mismatchedProofKinds,
  }
}

/** Assemble and verify the digest-bound proof index for one exact release candidate. */
export function assembleReleaseEvidenceManifestV1(
  input: unknown,
): ReleaseEvidenceManifestV1 {
  const parsed = releaseEvidenceManifestRequestV1Schema.safeParse(input)
  if (!parsed.success) throw new ReleaseEvidenceManifestInputError()
  const request = parsed.data
  const releaseConstitution = evaluateReleaseConstitutionV1(request.releaseEvaluation)
  const candidateArtifactDigest = releaseConstitution.candidateArtifactDigest
  const constitutionEvidence: ReleaseConstitutionEvidenceReferencesV1 = {
    constitution: {
      evidenceId: request.releaseEvaluation.constitution.constitutionId,
      evidenceDigest: request.releaseEvaluation.constitution.constitutionDigest,
    },
    hardSafety: {
      evidenceId: request.releaseEvaluation.candidate.hardSafetyEvidence.evidenceId,
      evidenceDigest: request.releaseEvaluation.candidate.hardSafetyEvidence.evidenceDigest,
    },
    evidenceSet: {
      evidenceId: request.releaseEvaluation.candidate.evidenceSetId,
      evidenceDigest: request.releaseEvaluation.candidate.evidenceSetDigest,
    },
    platforms: request.releaseEvaluation.candidate.platformProofs.map(item => ({
      platform: item.platform,
      evidenceId: item.evidenceId,
      evidenceDigest: item.evidenceDigest,
    })).sort((left, right) => left.platform.localeCompare(right.platform)),
  }
  const suppliedProofs = new Map(request.proofs.map(item => [item.proofKind, item]))
  const proofs: NormalizedReleaseEvidenceProofV1[] = RELEASE_EVIDENCE_PROOF_KINDS.map(
    proofKind => {
      const supplied = suppliedProofs.get(proofKind)
      if (supplied === undefined) {
        return {
          proofKind,
          evidenceId: null,
          evidenceDigest: null,
          reportedStatus: 'MISSING',
          candidateArtifactDigest: null,
          completedAtEpochMs: null,
          artifactBinding: 'MISSING',
          constitutionAlignment: 'MISSING',
          sourceEvidenceAlignment: 'MISSING',
          verificationStatus: 'INCONCLUSIVE',
        }
      }
      const artifactBinding = sameDigest(
        supplied.candidateArtifactDigest,
        candidateArtifactDigest,
      ) ? 'MATCHED' : 'MISMATCH'
      const expectedStatus = expectedConstitutionProofStatus(proofKind, releaseConstitution)
      const constitutionAlignment = expectedStatus === null
        ? 'NOT_APPLICABLE'
        : supplied.reportedStatus === expectedStatus ? 'MATCHED' : 'MISMATCH'
      const expectedSource = expectedProofSourceEvidence(proofKind, constitutionEvidence)
      const sourceEvidenceAlignment = expectedSource === undefined
        ? 'NOT_APPLICABLE'
        : expectedSource === null
          ? 'MISMATCH'
          : supplied.evidenceId === expectedSource.evidenceId
            && sameDigest(supplied.evidenceDigest, expectedSource.evidenceDigest)
            ? 'MATCHED'
            : 'MISMATCH'
      const verificationStatus = supplied.reportedStatus === 'FAILED'
        || artifactBinding === 'MISMATCH'
        || constitutionAlignment === 'MISMATCH'
        || sourceEvidenceAlignment === 'MISMATCH'
        ? 'FAILED'
        : supplied.reportedStatus === 'INCONCLUSIVE' ? 'INCONCLUSIVE' : 'PASSED'
      return {
        proofKind,
        evidenceId: supplied.evidenceId,
        evidenceDigest: supplied.evidenceDigest,
        reportedStatus: supplied.reportedStatus,
        candidateArtifactDigest: supplied.candidateArtifactDigest,
        completedAtEpochMs: supplied.completedAtEpochMs,
        artifactBinding,
        constitutionAlignment,
        sourceEvidenceAlignment,
        verificationStatus,
      }
    },
  )
  const publicScorecard = {
    engineId: request.publicScorecard.engineId,
    publishedAtEpochMs: request.publicScorecard.publishedAtEpochMs,
    releaseVersion: request.publicScorecard.release.releaseVersion,
    harnessTargetVersion: request.publicScorecard.scope.harnessTargetVersion,
    candidateArtifactDigest: request.publicScorecard.release.candidateArtifactDigest,
    decision: request.publicScorecard.release.decision,
    reasonCodes: request.publicScorecard.release.reasonCodes,
    checks: request.publicScorecard.release.checks,
    limitationCodes: request.publicScorecard.limitations,
  }
  const evaluationRunBundles = [...request.evaluationRunBundles]
    .sort(compareReleaseBundleReferences)
  const verification = releaseEvidenceManifestVerification({
    releaseConstitution,
    publicScorecard,
    proofs,
    evaluationRunBundles,
    candidateArtifactDigest,
  })
  const result: ReleaseEvidenceManifestV1 = {
    schemaVersion: 1,
    engineId: RELEASE_EVIDENCE_MANIFEST_ENGINE_ID,
    manifestId: request.manifestId,
    assembledAtEpochMs: request.assembledAtEpochMs,
    releaseCandidateId: releaseConstitution.releaseCandidateId,
    sourceRevision: request.sourceRevision,
    harnessTargetVersion: request.publicScorecard.scope.harnessTargetVersion,
    candidateArtifactDigest,
    qualifiedArtifactDigest: releaseConstitution.qualifiedArtifactDigest,
    proposedPromotionArtifactDigest: releaseConstitution.proposedPromotionArtifactDigest,
    dependencyLocks: [...request.dependencyLocks]
      .sort((left, right) => left.lockKind.localeCompare(right.lockKind)),
    releaseConstitution,
    constitutionEvidence,
    publicScorecard,
    proofs,
    evaluationRunBundles,
    knownLimitations: request.publicScorecard.limitations,
    riskAcceptances: [...request.riskAcceptances]
      .sort((left, right) => left.riskAcceptanceId.localeCompare(right.riskAcceptanceId)),
    verification,
  }
  return deepFreeze(releaseEvidenceManifestV1Schema.parse(result))
}
