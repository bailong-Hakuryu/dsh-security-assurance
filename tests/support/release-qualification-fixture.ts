import type { DigestEnvelopeV1 } from '../../src/digest-envelope.js'
import {
  DETERMINISTIC_RELEASE_PROOF_KINDS,
  RELEASE_EVIDENCE_PROOF_KINDS,
  assembleReleaseEvidenceManifestV1,
  calculatePairedArmComparisonV1,
  pairedArmComparisonRequestV1Schema,
  publicSecurityScorecardRequestV1Schema,
  renderPublicSecurityScorecardV1,
  type PairedArmComparisonRequestV1,
  type ReleaseEvidenceManifestRequestV1,
} from '../../src/evaluation.js'

const strata = [
  { stratumId: 'severity-critical', selector: { dimension: 'SEVERITY', value: 'CRITICAL' }, minimumSamples: 1 },
  { stratumId: 'severity-high', selector: { dimension: 'SEVERITY', value: 'HIGH' }, minimumSamples: 1 },
  { stratumId: 'weakness-cwe-79', selector: { dimension: 'WEAKNESS_FAMILY', value: 'cwe-79' }, minimumSamples: 1 },
  { stratumId: 'mode-change', selector: { dimension: 'ASSESSMENT_MODE', value: 'CHANGE' }, minimumSamples: 1 },
  { stratumId: 'ecosystem-node', selector: { dimension: 'SUPPORTED_ECOSYSTEM', value: 'node' }, minimumSamples: 1 },
] as const

const repetitionStrata = strata.map(definition => ({
  ...definition,
  maximumValidatedRecallIntervalWidth: 0.99,
}))

const limits = {
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

const repetitionIds = Array.from(
  { length: 32 },
  (_value, index) => `rep-${String(index).padStart(2, '0')}`,
)

function evidenceDigest(character: string): DigestEnvelopeV1 {
  return {
    schemaVersion: 1,
    algorithm: 'sha256',
    mediaType: 'application/json',
    byteLength: 128,
    canonicalization: 'dsh-canonical-json-v1',
    value: character.repeat(64),
  }
}

function metricsRequest(successful: boolean) {
  return {
    schemaVersion: 1,
    engineId: 'security/effectiveness-metrics/v1',
    severityWeights: { CRITICAL: 8, HIGH: 5, MEDIUM: 3, LOW: 2, INFORMATIONAL: 1 },
    stratumDefinitions: repetitionStrata,
    repetitionPlan: {
      method: 'HOEFFDING_TWO_SIDED_V1',
      repetitionIds,
      benchmarkCaseIds: ['case-paired'],
      confidenceLevel: 0.95,
      maximumConfidenceIntervalWidth: 0.99,
    },
    cases: repetitionIds.map(repetitionId => ({
      caseId: 'case-paired',
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
      }, {
        defectId: 'defect-critical',
        severity: 'CRITICAL',
        weaknessFamily: 'cwe-79',
        policyBlocking: true,
      }],
      result: {
        kind: 'COMPLETED',
        verdict: successful ? 'FAILED' : 'SATISFIED',
        coverageStatus: successful ? 'GAP' : 'COMPLETE',
        findings: [{
          findingId: `${successful ? 'finding-match' : 'finding-false-positive'}-${repetitionId}`,
          adjudication: successful
            ? { status: 'MATCHED', defectId: 'defect-high' }
            : { status: 'NOT_MATCHED' },
        }, ...successful ? [{
          findingId: `finding-critical-${repetitionId}`,
          adjudication: { status: 'MATCHED', defectId: 'defect-critical' },
        }] : []],
      },
    })),
  }
}

function budget(modelTokens: number, wallTimeMs = limits.wallTimeMs) {
  return {
    limits,
    usage: { ...limits, modelTokens, wallTimeMs },
  }
}

function utilityEvidence(improved: boolean) {
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

function pairedComparisonEvidence() {
  const plan = {
    planId: 'release-ni-plan',
    registrationRecordId: 'qualification-registry/ni-plan',
    registeredAtEpochMs: 100,
    evidenceCollectionStartedAtEpochMs: 150,
    method: 'CONSERVATIVE_HOEFFDING_BOUNDS_V1',
    metricMargins: {
      criticalHighValidatedRecall: 0.99,
      severityWeightedValidatedRecall: 0.99,
      validatedPrecision: 0.99,
      unsafeSatisfactionRate: 0.99,
      coverageHonestyRate: 0.99,
    },
    stratumMargins: strata.map(definition => ({
      stratumId: definition.stratumId,
      validatedRecallMargin: 0.99,
    })),
  }
  const request = {
    schemaVersion: 1,
    engineId: 'security/paired-arm-comparison/v1',
    comparisonView: 'MATCHED_BUDGET',
    baseline: {
      armId: 'baseline-arm',
      metricsRequest: metricsRequest(true),
      budget: budget(9_000),
      utilityEvidence: utilityEvidence(false),
    },
    candidate: {
      armId: 'candidate-arm',
      metricsRequest: metricsRequest(true),
      budget: budget(8_000, 30_000),
      utilityEvidence: utilityEvidence(true),
    },
    nonInferiorityPlan: plan,
  }
  const parsed = pairedArmComparisonRequestV1Schema.safeParse(request)
  if (!parsed.success) throw new Error(JSON.stringify(parsed.error.issues, null, 2))
  return {
    request: request as unknown as PairedArmComparisonRequestV1,
    result: calculatePairedArmComparisonV1(request as unknown as PairedArmComparisonRequestV1),
  }
}

function deterministicHistory(candidateArtifactDigest: DigestEnvelopeV1) {
  return {
    schemaVersion: 1,
    engineId: 'security/deterministic-failure-history/v1',
    evaluatedAtEpochMs: 260,
    candidateArtifactDigest,
    requiredProofKinds: [...DETERMINISTIC_RELEASE_PROOF_KINDS],
    runs: DETERMINISTIC_RELEASE_PROOF_KINDS.map((proofKind, index) => ({
      kind: 'QUALIFICATION',
      runId: `qualification/${proofKind.toLowerCase().replaceAll('_', '-')}`,
      proofKind,
      candidateArtifactDigest,
      status: 'PASSED',
      evidenceId: `evidence/${proofKind.toLowerCase().replaceAll('_', '-')}`,
      evidenceDigest: evidenceDigest(String(index % 10)),
      completedAtEpochMs: 240,
    })),
    resolutions: [],
  }
}

export function releaseQualificationFixture(input: {
  sourceRevision: string
  candidateArtifactDigest: DigestEnvelopeV1
  lockDigest: DigestEnvelopeV1
}): ReleaseEvidenceManifestRequestV1 {
  const { candidateArtifactDigest } = input
  const comparison = pairedComparisonEvidence()
  const releaseEvaluation = {
    schemaVersion: 1,
    engineId: 'security/release-constitution/v1',
    constitution: {
      constitutionId: 'release-constitution-v1',
      constitutionDigest: evidenceDigest('b'),
      registrationRecordId: 'qualification/release-constitution-v1',
      registeredAtEpochMs: 100,
      calibrationEvidence: [{
        evidenceId: 'qualification/calibration-v1',
        evidenceDigest: evidenceDigest('c'),
        corpusLane: 'QUALIFICATION',
        completedAtEpochMs: 80,
      }],
      requiredNonInferiorityPlanId: 'release-ni-plan',
      effectivenessThresholds: {
        criticalHighValidatedRecallMinimum: 0,
        severityWeightedValidatedRecallMinimum: 0,
        validatedPrecisionMinimum: 0,
        unsafeSatisfactionRateMaximum: 1,
        coverageHonestyRateMinimum: 0,
      },
      utilityThresholds: {
        validatedFindingYieldPerRuntimeHourMinimum: 240,
        validatedFindingYieldPerCostUnitMinimum: 4,
        timeToFirstValidatedFindingMsMaximum: 10_000,
        humanTriageMinutesPerValidatedFindingMaximum: 2.5,
        verifiedRemediationSuccessRateMinimum: 1,
        meanVerifiedRemediationDurationMsMaximum: 300_000,
        unnecessaryReworkCountMaximum: 1,
        validApprovalYieldMinimum: 0.75,
        unsafeApprovalRateMaximum: 0,
      },
    },
    candidate: {
      releaseCandidateId: 'security-assurance-0.1.0-rc.10',
      candidateArmId: 'candidate-arm',
      priorStableArmId: 'baseline-arm',
      evidenceSetId: 'release-evidence-set-v1',
      evidenceSetDigest: evidenceDigest('d'),
      holdoutStartedAtEpochMs: 200,
      holdoutCompletedAtEpochMs: 300,
      candidateArtifactDigest,
      qualifiedArtifactDigest: candidateArtifactDigest,
      proposedPromotionArtifactDigest: candidateArtifactDigest,
      hardSafetyEvidence: {
        evidenceId: 'hard-safety-evidence-v1',
        evidenceDigest: evidenceDigest('e'),
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
        deterministicFailureHistory: deterministicHistory(candidateArtifactDigest),
      },
      platformProofs: ['WINDOWS', 'LINUX', 'MACOS'].map((platform, index) => ({
        platform,
        status: 'PASSED',
        evidenceId: `platform-proof/${platform.toLowerCase()}`,
        evidenceDigest: evidenceDigest(String(index + 1)),
        packedArtifactDigest: candidateArtifactDigest,
      })),
      pairedComparisonRequest: comparison.request,
      pairedComparison: comparison.result,
    },
  } as ReleaseEvidenceManifestRequestV1['releaseEvaluation']
  const scorecardRequest = {
    schemaVersion: 1,
    engineId: 'security/public-scorecard/v1',
    publication: {
      publishedAtEpochMs: 400,
      releaseVersion: '0.1.0-rc.10',
      harnessTargetVersion: '0.1.2-rc.1',
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
        providerVersion: '2026.09',
        modelId: 'reference-model',
        modelVersion: 'v1',
      },
    },
    releaseEvaluation,
  }
  const parsedScorecard = publicSecurityScorecardRequestV1Schema.safeParse(scorecardRequest)
  if (!parsedScorecard.success) {
    throw new Error(JSON.stringify(parsedScorecard.error.issues, null, 2))
  }
  const publicScorecard = renderPublicSecurityScorecardV1(scorecardRequest)
  const request: ReleaseEvidenceManifestRequestV1 = {
    schemaVersion: 1,
    engineId: 'security/release-evidence-manifest/v1',
    manifestId: 'release-evidence-manifest-v1',
    assembledAtEpochMs: 500,
    sourceRevision: input.sourceRevision,
    dependencyLocks: [{ lockKind: 'PNPM_LOCK', lockDigest: input.lockDigest }],
    releaseEvaluation,
    publicScorecard,
    proofs: RELEASE_EVIDENCE_PROOF_KINDS.map((proofKind, index) => {
      let evidenceId = `proof/${proofKind.toLowerCase().replaceAll('_', '-')}`
      let digest = evidenceDigest(String(index % 10))
      if ([
        'CAPABILITY_CONFORMANCE',
        'SELF_SECURITY',
        'GROUND_TRUTH_AIR_GAP',
        'DETERMINISTIC_FAILURES',
        'RISK_ACCEPTANCES',
      ].includes(proofKind)) {
        evidenceId = releaseEvaluation.candidate.hardSafetyEvidence.evidenceId
        digest = releaseEvaluation.candidate.hardSafetyEvidence.evidenceDigest
      } else if (proofKind.endsWith('_PLATFORM')) {
        const platform = proofKind.replace('_PLATFORM', '')
        const platformProof = releaseEvaluation.candidate.platformProofs.find(
          item => item.platform === platform,
        )
        if (platformProof !== undefined) {
          evidenceId = platformProof.evidenceId
          digest = platformProof.evidenceDigest
        }
      } else if (proofKind === 'EVALUATION_RUN_BUNDLE') {
        evidenceId = releaseEvaluation.candidate.evidenceSetId
        digest = releaseEvaluation.candidate.evidenceSetDigest
      } else if (proofKind === 'RELEASE_CONSTITUTION') {
        evidenceId = releaseEvaluation.constitution.constitutionId
        digest = releaseEvaluation.constitution.constitutionDigest
      }
      return {
        proofKind,
        evidenceId,
        evidenceDigest: digest,
        reportedStatus: 'PASSED',
        candidateArtifactDigest,
        completedAtEpochMs: 350,
      }
    }),
    evaluationRunBundles: [{
      role: 'PRIOR_STABLE',
      bundleId: 'evaluation-bundle/prior-stable',
      bundleDigest: evidenceDigest('8'),
      artifactDigest: evidenceDigest('f'),
    }, {
      role: 'CANDIDATE',
      bundleId: 'evaluation-bundle/candidate',
      bundleDigest: evidenceDigest('9'),
      artifactDigest: candidateArtifactDigest,
    }],
    riskAcceptances: [],
  }
  assembleReleaseEvidenceManifestV1(request)
  return request
}
