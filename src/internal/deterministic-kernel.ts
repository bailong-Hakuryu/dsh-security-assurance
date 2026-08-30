import type {
  AssessmentCoverageSnapshotV1,
  AssessmentMode,
  AssessmentProfileId,
  AssessmentTargetSelectorV1,
  DigestEnvelopeV1,
  SecuritySubmissionJsonV1,
  SecurityVerdict,
} from '../contracts.ts'
import type {
  AnalyzerContributionV1,
  AnalyzerPortfolioEntryV1,
} from '../analyzer.ts'
import {
  securitySubmissionJsonV1Schema,
  SECURITY_ASSURANCE_PRODUCT_NAME,
  SECURITY_ASSURANCE_PRODUCT_VERSION,
} from '../contracts.ts'
import { canonicalJson, sha256Hex, structuredDigest } from './canonical.ts'
import { validateExternalAnalyzerCandidates } from './candidate-validation.ts'
import {
  BUILTIN_NODE_PACKAGE_LIFECYCLE_DESCRIPTOR,
  BUILTIN_NODE_PACKAGE_LIFECYCLE_QUALIFICATION,
  contributionAsJson,
  nodePackageLifecycleAnalyzerContributionV1Schema,
} from './builtin-node-package-lifecycle-analyzer.ts'
import type { NodePackageLifecycleAnalyzerContributionV1 } from './builtin-node-package-lifecycle-analyzer.ts'
import type {
  EvidencePublicationInputV1,
  EvidencePublicationReceiptV1,
} from './evidence-persistence.ts'
import type { VerifiedSubjectTextSliceV1 } from './subject-freeze.ts'

const POLICY_MEDIA_TYPE = 'application/vnd.dsh.security.policy+json'
const COVERAGE_MEDIA_TYPE = 'application/vnd.dsh.security.coverage+json'

export interface PreparedAssessmentContractV1 {
  readonly schemaVersion: 1
  readonly assessmentMode: AssessmentMode
  readonly assessmentProfileId: AssessmentProfileId
  readonly target: AssessmentTargetSelectorV1
  readonly targetDigest: DigestEnvelopeV1
  readonly requestedStrongerControlIds: readonly string[]
  readonly policy: {
    readonly policyId: string
    readonly digest: DigestEnvelopeV1
    readonly value: SecuritySubmissionJsonV1
  }
  readonly analyzerPortfolio: readonly AnalyzerPortfolioEntryV1[]
  readonly coverage: AssessmentCoverageSnapshotV1
}

export interface DeterministicAssessmentOutcomeV1 {
  readonly coverage: AssessmentCoverageSnapshotV1
  readonly findings: SecuritySubmissionJsonV1[]
  readonly verdict: SecurityVerdict
  readonly evaluationTrace: NonNullable<SecuritySubmissionJsonV1>
  readonly providerComposition: NonNullable<SecuritySubmissionJsonV1>
  readonly evidence: readonly EvidencePublicationInputV1[]
}

export interface AdmittedAnalyzerInputV1 {
  readonly expectedSubjectDigest: DigestEnvelopeV1
  readonly contribution: NodePackageLifecycleAnalyzerContributionV1
}

export interface AdmittedExternalAnalyzerInputV1 {
  readonly portfolioEntry: AnalyzerPortfolioEntryV1
  readonly contribution: AnalyzerContributionV1
  readonly subjectSlices: readonly VerifiedSubjectTextSliceV1[]
}

function coverageSnapshot(
  targetDigest: DigestEnvelopeV1,
  value: Omit<AssessmentCoverageSnapshotV1, 'digest'>,
): AssessmentCoverageSnapshotV1 {
  return {
    ...value,
    digest: structuredDigest(COVERAGE_MEDIA_TYPE, { targetDigest, ...value }),
  }
}

function json(value: unknown): NonNullable<SecuritySubmissionJsonV1> {
  const normalized = securitySubmissionJsonV1Schema.parse(value)
  if (normalized === null) throw new TypeError('domain artifact must be a non-null JSON value')
  return normalized
}

function emptyProviderComposition(): NonNullable<SecuritySubmissionJsonV1> {
  return json({
    schemaVersion: 1,
    providerId: SECURITY_ASSURANCE_PRODUCT_NAME,
    providerVersion: SECURITY_ASSURANCE_PRODUCT_VERSION,
    analyzers: [],
  })
}

function externalProviderComposition(
  portfolio: readonly AnalyzerPortfolioEntryV1[],
): NonNullable<SecuritySubmissionJsonV1> {
  return json({
    schemaVersion: 1,
    providerId: SECURITY_ASSURANCE_PRODUCT_NAME,
    providerVersion: SECURITY_ASSURANCE_PRODUCT_VERSION,
    analyzers: portfolio.map(entry => ({
      analyzerId: entry.descriptor.analyzerId,
      analyzerVersion: entry.descriptor.analyzerVersion,
      descriptorSchemaVersion: entry.descriptor.descriptorSchemaVersion,
      buildDigest: entry.descriptor.buildDigest,
      executionClass: entry.descriptor.executionClass,
      qualificationId: entry.qualification?.qualificationId ?? null,
      qualificationDigest: entry.qualification?.qualificationDigest ?? null,
      verdictEligible: entry.eligibility.decision === 'ELIGIBLE',
    })),
  })
}

function externalAnalyzerEvidence(
  contract: PreparedAssessmentContractV1,
  analyses: readonly AdmittedExternalAnalyzerInputV1[],
  obligationId: string,
): readonly EvidencePublicationInputV1[] {
  const evidence: EvidencePublicationInputV1[] = []
  const artifactIds = new Set<string>()
  for (const analysis of analyses) {
    for (const item of analysis.contribution.evidence) {
      if (artifactIds.has(item.artifactId)) throw new TypeError('External Analyzer Evidence identity collides')
      artifactIds.add(item.artifactId)
      evidence.push(item)
    }
    const contributionArtifactId = `analyzer-contribution-${sha256Hex(canonicalJson({
      analyzerId: analysis.portfolioEntry.descriptor.analyzerId,
      analyzerVersion: analysis.portfolioEntry.descriptor.analyzerVersion,
    })).slice(0, 16)}`
    if (artifactIds.has(contributionArtifactId)) throw new TypeError('Analyzer Contribution identity collides')
    artifactIds.add(contributionArtifactId)
    evidence.push({
      artifactId: contributionArtifactId,
      schemaId: 'dsh/security-analyzer-contribution',
      mediaType: 'application/vnd.dsh.security.analyzer-contribution+json',
      value: json(analysis.contribution),
    })
    const eligibilityArtifactId = `evidence-eligibility-${sha256Hex(canonicalJson({
      analyzerIdentity: analysis.contribution.analyzerIdentity,
      qualificationId: analysis.portfolioEntry.eligibility.qualificationId,
    })).slice(0, 16)}`
    if (artifactIds.has(eligibilityArtifactId)) throw new TypeError('Eligibility Decision identity collides')
    artifactIds.add(eligibilityArtifactId)
    const structurallyBoundCoverage = externalCompleteCoverageClaimIsStructurallyBound(
      analysis,
      obligationId,
    )
    // Protocol v1 has one package-owned conformance verifier. Arbitrary
    // external Evidence schemas remain advisory even when Host-qualified.
    const evidenceEligible = contract.policy.policyId === 'security/reference-validation'
      && analysis.contribution.candidateFindings.length > 0
      && structurallyBoundCoverage
    const eligibilityReason = evidenceEligible
      ? null
      : analysis.portfolioEntry.eligibility.reason
        ?? (analysis.contribution.candidateFindings.length > 0
          ? 'UNRESOLVED_CANDIDATES'
          : structurallyBoundCoverage
            ? 'INDEPENDENT_VERIFIER_UNAVAILABLE'
            : 'CONTRIBUTION_INELIGIBLE')
    evidence.push({
      artifactId: eligibilityArtifactId,
      schemaId: 'dsh/security-evidence-eligibility-decision',
      mediaType: 'application/vnd.dsh.security.evidence-eligibility-decision+json',
      value: json({
        schemaVersion: 1,
        decision: evidenceEligible ? 'ELIGIBLE' : 'INELIGIBLE',
        reason: eligibilityReason,
        evaluatedAt: analysis.portfolioEntry.eligibility.evaluatedAt,
        analyzerIdentity: analysis.portfolioEntry.eligibility.analyzerIdentity,
        qualificationId: analysis.portfolioEntry.eligibility.qualificationId,
        qualificationDigest: analysis.portfolioEntry.eligibility.qualificationDigest,
        subjectDigest: analysis.contribution.subjectDigest,
        policyDigest: contract.policy.digest,
        obligationId,
        evidenceArtifactIds: analysis.contribution.evidence.map(item => item.artifactId),
      }),
    })
  }
  return evidence
}

/** Purely freeze the minimum v1 Policy and Coverage Plan admitted by this development slice. */
export function prepareAssessmentContract(input: {
  readonly policyId: string
  readonly assessmentMode: AssessmentMode
  readonly assessmentProfileId: AssessmentProfileId
  readonly target: AssessmentTargetSelectorV1
  readonly targetDigest: DigestEnvelopeV1
  readonly requestedStrongerControlIds: readonly string[]
  readonly analyzerPortfolio?: readonly AnalyzerPortfolioEntryV1[]
}): PreparedAssessmentContractV1 {
  const nodePackageLifecyclePolicy = input.policyId === 'security/node-package-lifecycle'
  const policyValue = securitySubmissionJsonV1Schema.parse({
    schemaVersion: 1,
    policyId: input.policyId,
    methodVersion: nodePackageLifecyclePolicy
      ? 'dsh-security-node-package-lifecycle-policy-v1'
      : 'dsh-security-default-policy-v1',
    obligations: [{
      obligationId: nodePackageLifecyclePolicy
        ? 'node-package-install-lifecycle-policy'
        : 'application-security-analysis',
      mandatory: true,
      eligibleExecutionClass: nodePackageLifecyclePolicy
        ? 'qualified-builtin-pure-analyzer'
        : 'qualified-analyzer',
    }],
    verdictRule: 'blocking-finding-then-mandatory-coverage-v1',
  })
  return {
    schemaVersion: 1,
    assessmentMode: input.assessmentMode,
    assessmentProfileId: input.assessmentProfileId,
    target: input.target,
    targetDigest: input.targetDigest,
    requestedStrongerControlIds: input.requestedStrongerControlIds,
    policy: {
      policyId: input.policyId,
      digest: structuredDigest(POLICY_MEDIA_TYPE, policyValue),
      value: policyValue,
    },
    analyzerPortfolio: input.analyzerPortfolio ?? [],
    coverage: coverageSnapshot(input.targetDigest, {
      status: 'PENDING',
      mandatoryObligations: 1,
      satisfiedObligations: 0,
      gapObligations: 0,
      resolutions: [],
    }),
  }
}

function indeterminateOutcome(
  contract: PreparedAssessmentContractV1,
  evaluationInstant: string,
  obligationId: string,
  reason: 'NO_ELIGIBLE_ANALYZER' | 'UNSUPPORTED_SUBJECT' | 'ANALYZER_INCOMPLETE' | 'EVIDENCE_INELIGIBLE',
  providerComposition: NonNullable<SecuritySubmissionJsonV1> = emptyProviderComposition(),
  evidence: readonly EvidencePublicationInputV1[] = [],
): DeterministicAssessmentOutcomeV1 {
  const coverage = coverageSnapshot(contract.targetDigest, {
    status: 'GAP',
    mandatoryObligations: 1,
    satisfiedObligations: 0,
    gapObligations: 1,
    resolutions: [{ obligationId, state: 'GAP', reason }],
  })
  return {
    coverage,
    findings: [],
    verdict: 'INDETERMINATE',
    evaluationTrace: json({
      schemaVersion: 1,
      evaluatorVersion: 'dsh-security-policy-evaluator-v1',
      evaluationInstant,
      policyDigest: contract.policy.digest,
      rules: [
        { ruleId: 'blocking-policy-violation', matched: false },
        { ruleId: 'mandatory-coverage-gap', matched: true, outcome: 'INDETERMINATE' },
        { ruleId: 'complete-mandatory-coverage', matched: false },
      ],
      diagnostics: [{ code: reason, obligationId }],
    }),
    providerComposition,
    evidence,
  }
}

function analyzerProviderComposition(verdictEligible: boolean): NonNullable<SecuritySubmissionJsonV1> {
  return json({
    schemaVersion: 1,
    providerId: SECURITY_ASSURANCE_PRODUCT_NAME,
    providerVersion: SECURITY_ASSURANCE_PRODUCT_VERSION,
    analyzers: [{
      analyzerId: BUILTIN_NODE_PACKAGE_LIFECYCLE_DESCRIPTOR.analyzerId,
      analyzerVersion: BUILTIN_NODE_PACKAGE_LIFECYCLE_DESCRIPTOR.analyzerVersion,
      descriptorSchemaVersion: BUILTIN_NODE_PACKAGE_LIFECYCLE_DESCRIPTOR.descriptorSchemaVersion,
      buildDigest: BUILTIN_NODE_PACKAGE_LIFECYCLE_DESCRIPTOR.buildDigest,
      executionClass: BUILTIN_NODE_PACKAGE_LIFECYCLE_DESCRIPTOR.executionClass,
      qualificationId: BUILTIN_NODE_PACKAGE_LIFECYCLE_QUALIFICATION.qualificationId,
      qualificationDigest: BUILTIN_NODE_PACKAGE_LIFECYCLE_QUALIFICATION.qualificationDigest,
      verdictEligible,
    }],
  })
}

function analyzerEvidenceIsEligible(
  contract: PreparedAssessmentContractV1,
  analysis: AdmittedAnalyzerInputV1,
): boolean {
  const contribution = nodePackageLifecycleAnalyzerContributionV1Schema.safeParse(analysis.contribution)
  if (!contribution.success) return false
  const {
    qualificationDigest,
    ...qualificationCore
  } = BUILTIN_NODE_PACKAGE_LIFECYCLE_QUALIFICATION
  const observedQualificationDigest = structuredDigest(
    qualificationDigest.mediaType,
    qualificationCore,
  )
  if (
    contract.policy.policyId !== 'security/node-package-lifecycle'
    || contract.assessmentMode !== 'REPOSITORY'
    || canonicalJson(contribution.data.subjectDigest) !== canonicalJson(analysis.expectedSubjectDigest)
    || contribution.data.analyzerIdentity.analyzerId !== BUILTIN_NODE_PACKAGE_LIFECYCLE_DESCRIPTOR.analyzerId
    || contribution.data.analyzerIdentity.analyzerVersion !== BUILTIN_NODE_PACKAGE_LIFECYCLE_DESCRIPTOR.analyzerVersion
    || canonicalJson(contribution.data.analyzerIdentity.buildDigest)
      !== canonicalJson(BUILTIN_NODE_PACKAGE_LIFECYCLE_DESCRIPTOR.buildDigest)
    || canonicalJson(observedQualificationDigest) !== canonicalJson(qualificationDigest)
  ) return false
  const observedEvidenceDigest = structuredDigest(
    contribution.data.manifestEvidence.digest.mediaType,
    contribution.data.manifestEvidence.value,
  )
  if (canonicalJson(observedEvidenceDigest) !== canonicalJson(contribution.data.manifestEvidence.digest)) return false
  return contribution.data.candidateFindings.every(candidate => {
    if (canonicalJson(candidate.evidenceDigest) !== canonicalJson(contribution.data.manifestEvidence.digest)) return false
    const manifest = contribution.data.manifestEvidence.value.manifests.find(entry => (
      entry.path === candidate.sourceAnchor.path
      && canonicalJson(entry.digest) === canonicalJson(candidate.sourceAnchor.fileDigest)
    ))
    const lifecycleName = candidate.sourceAnchor.jsonPointer.split('/').at(-1)
    return manifest !== undefined
      && lifecycleName !== undefined
      && manifest.installLifecycleScripts.includes(lifecycleName as 'preinstall' | 'install' | 'postinstall')
  })
}

function completeCoverageClaimIsEligible(
  contribution: NodePackageLifecycleAnalyzerContributionV1,
): boolean {
  if (contribution.completionDisposition !== 'COMPLETE' || contribution.coverageClaims.length !== 1) {
    return false
  }
  const claim = contribution.coverageClaims[0]
  return claim !== undefined
    && claim.obligationId === 'node-package-install-lifecycle-policy'
    && canonicalJson(claim.evidenceDigest) === canonicalJson(contribution.manifestEvidence.digest)
}

function externalCompleteCoverageClaimIsStructurallyBound(
  analysis: AdmittedExternalAnalyzerInputV1,
  obligationId: string,
): boolean {
  const { portfolioEntry, contribution } = analysis
  if (
    portfolioEntry.eligibility.decision !== 'ELIGIBLE'
    || portfolioEntry.qualification === null
    || contribution.completionDisposition !== 'COMPLETE'
    || contribution.coverageClaims.length !== 1
  ) return false
  const claim = contribution.coverageClaims[0]
  if (claim === undefined || claim.obligationId !== obligationId) return false
  const evidence = contribution.evidence.find(item => item.artifactId === claim.evidenceArtifactId)
  return evidence !== undefined
    && portfolioEntry.qualification.coverageObligationIds.includes(obligationId)
    && portfolioEntry.qualification.evidenceSchemaIds.includes(evidence.schemaId)
}

/** Pure Policy evaluation over one frozen qualified Analyzer Contribution. */
export function evaluateDeterministicAssessment(
  contract: PreparedAssessmentContractV1,
  evaluationInstant: string,
  analysis?: AdmittedAnalyzerInputV1,
  externalAnalyses: readonly AdmittedExternalAnalyzerInputV1[] = [],
): DeterministicAssessmentOutcomeV1 {
  if (contract.policy.policyId !== 'security/node-package-lifecycle') {
    if (externalAnalyses.length > 0) {
      const obligationId = 'application-security-analysis'
      const providerComposition = externalProviderComposition(contract.analyzerPortfolio)
      const candidateValidation = validateExternalAnalyzerCandidates(externalAnalyses.map(analysis => ({
        portfolioEntry: analysis.portfolioEntry,
        contribution: analysis.contribution,
        subjectSlices: analysis.subjectSlices,
        policyId: contract.policy.policyId,
        policyDigest: contract.policy.digest,
      })))
      const evidence = [
        ...externalAnalyzerEvidence(contract, externalAnalyses, obligationId),
        ...candidateValidation.evidence,
      ]
      // Gate-bearing complete Coverage is reserved for the one package-owned
      // conformance contract after every contributed Candidate is independently
      // validated or rejected against the frozen Subject.
      const completeCoverage = contract.policy.policyId === 'security/reference-validation'
        && candidateValidation.unresolvedCandidateIds.length === 0
        && externalAnalyses.some(analysis => (
          analysis.contribution.candidateFindings.length > 0
          && externalCompleteCoverageClaimIsStructurallyBound(analysis, obligationId)
        ))
      if (candidateValidation.findings.length > 0) {
        const coverageComplete = completeCoverage
          && candidateValidation.unresolvedCandidateIds.length === 0
        const coverage = coverageComplete
          ? coverageSnapshot(contract.targetDigest, {
              status: 'COMPLETE',
              mandatoryObligations: 1,
              satisfiedObligations: 1,
              gapObligations: 0,
              resolutions: [{
                obligationId,
                state: 'SATISFIED',
                reason: 'ELIGIBLE_EVIDENCE',
              }],
            })
          : coverageSnapshot(contract.targetDigest, {
              status: 'GAP',
              mandatoryObligations: 1,
              satisfiedObligations: 0,
              gapObligations: 1,
              resolutions: [{
                obligationId,
                state: 'GAP',
                reason: 'EVIDENCE_INELIGIBLE',
              }],
            })
        return {
          coverage,
          findings: [...candidateValidation.findings],
          verdict: 'FAILED',
          evaluationTrace: json({
            schemaVersion: 1,
            evaluatorVersion: 'dsh-security-policy-evaluator-v1',
            evaluationInstant,
            policyDigest: contract.policy.digest,
            rules: [
              { ruleId: 'blocking-policy-violation', matched: true, outcome: 'FAILED' },
              { ruleId: 'mandatory-coverage-gap', matched: !coverageComplete, outcome: null },
              { ruleId: 'complete-mandatory-coverage', matched: coverageComplete, outcome: 'FAILED' },
            ],
            diagnostics: [],
          }),
          providerComposition,
          evidence,
        }
      }
      if (candidateValidation.unresolvedCandidateIds.length > 0) {
        return indeterminateOutcome(
          contract,
          evaluationInstant,
          obligationId,
          'EVIDENCE_INELIGIBLE',
          providerComposition,
          evidence,
        )
      }
      if (completeCoverage) {
        return {
          coverage: coverageSnapshot(contract.targetDigest, {
            status: 'COMPLETE',
            mandatoryObligations: 1,
            satisfiedObligations: 1,
            gapObligations: 0,
            resolutions: [{
              obligationId,
              state: 'SATISFIED',
              reason: 'ELIGIBLE_EVIDENCE',
            }],
          }),
          findings: [],
          verdict: 'SATISFIED',
          evaluationTrace: json({
            schemaVersion: 1,
            evaluatorVersion: 'dsh-security-policy-evaluator-v1',
            evaluationInstant,
            policyDigest: contract.policy.digest,
            rules: [
              { ruleId: 'blocking-policy-violation', matched: false },
              { ruleId: 'mandatory-coverage-gap', matched: false },
              { ruleId: 'complete-mandatory-coverage', matched: true, outcome: 'SATISFIED' },
            ],
            diagnostics: [],
          }),
          providerComposition,
          evidence,
        }
      }
      const dispositions = new Set(externalAnalyses.map(item => item.contribution.completionDisposition))
      const reason = dispositions.has('INCOMPLETE')
        ? 'ANALYZER_INCOMPLETE'
        : dispositions.size === 1 && dispositions.has('UNSUPPORTED')
          ? 'UNSUPPORTED_SUBJECT'
          : 'EVIDENCE_INELIGIBLE'
      return indeterminateOutcome(
        contract,
        evaluationInstant,
        obligationId,
        reason,
        providerComposition,
        evidence,
      )
    }
    return indeterminateOutcome(
      contract,
      evaluationInstant,
      'application-security-analysis',
      'NO_ELIGIBLE_ANALYZER',
    )
  }
  if (analysis === undefined) {
    return indeterminateOutcome(
      contract,
      evaluationInstant,
      'node-package-install-lifecycle-policy',
      'NO_ELIGIBLE_ANALYZER',
    )
  }
  const composition = analyzerProviderComposition(false)
  const contribution = nodePackageLifecycleAnalyzerContributionV1Schema.parse(analysis.contribution)
  const commonEvidence: EvidencePublicationInputV1[] = [{
    artifactId: 'node-package-manifest-evidence',
    schemaId: contribution.manifestEvidence.schemaId,
    mediaType: contribution.manifestEvidence.digest.mediaType,
    value: json(contribution.manifestEvidence.value),
  }, {
    artifactId: 'analyzer-contribution',
    schemaId: 'dsh/security-analyzer-contribution',
    mediaType: 'application/vnd.dsh.security.analyzer-contribution+json',
    value: contributionAsJson(contribution),
  }]
  if (contribution.completionDisposition === 'UNSUPPORTED') {
    return indeterminateOutcome(
      contract,
      evaluationInstant,
      'node-package-install-lifecycle-policy',
      'UNSUPPORTED_SUBJECT',
      composition,
      commonEvidence,
    )
  }
  const evidenceEligible = analyzerEvidenceIsEligible(contract, analysis)
  if (!evidenceEligible) {
    return indeterminateOutcome(
      contract,
      evaluationInstant,
      'node-package-install-lifecycle-policy',
      'EVIDENCE_INELIGIBLE',
      composition,
      commonEvidence,
    )
  }
  if (
    contribution.completionDisposition === 'INCOMPLETE'
    && contribution.candidateFindings.length === 0
  ) {
    return indeterminateOutcome(
      contract,
      evaluationInstant,
      'node-package-install-lifecycle-policy',
      'ANALYZER_INCOMPLETE',
      composition,
      commonEvidence,
    )
  }
  if (
    contribution.completionDisposition === 'COMPLETE'
    && !completeCoverageClaimIsEligible(contribution)
  ) {
    return indeterminateOutcome(
      contract,
      evaluationInstant,
      'node-package-install-lifecycle-policy',
      'EVIDENCE_INELIGIBLE',
      composition,
      commonEvidence,
    )
  }

  const eligibleComposition = analyzerProviderComposition(true)
  const eligibilityDecision = json({
    schemaVersion: 1,
    decision: 'ELIGIBLE',
    analyzerIdentity: contribution.analyzerIdentity,
    qualificationId: BUILTIN_NODE_PACKAGE_LIFECYCLE_QUALIFICATION.qualificationId,
    qualificationDigest: BUILTIN_NODE_PACKAGE_LIFECYCLE_QUALIFICATION.qualificationDigest,
    subjectDigest: analysis.expectedSubjectDigest,
    policyDigest: contract.policy.digest,
    obligationId: 'node-package-install-lifecycle-policy',
    evidenceDigest: contribution.manifestEvidence.digest,
    executionClass: 'PURE',
    scope: contribution.completionDisposition === 'COMPLETE'
      ? 'COVERAGE_AND_CANDIDATES'
      : 'VALIDATED_CANDIDATES_ONLY',
  })
  const findings = contribution.candidateFindings.map(candidate => json({
    schemaVersion: 1,
    findingId: `finding-${sha256Hex(canonicalJson({
      candidateId: candidate.candidateId,
      validationContract: 'dsh-node-package-install-lifecycle-validation-v1',
      subjectDigest: analysis.expectedSubjectDigest,
    }))}`,
    candidateId: candidate.candidateId,
    kind: candidate.kind,
    weaknessId: candidate.weaknessId,
    sourceAnchor: candidate.sourceAnchor,
    securityClaim: candidate.securityClaim,
    validation: {
      state: 'VALIDATED',
      contractId: 'dsh-node-package-install-lifecycle-validation-v1',
      contractVersion: 1,
      evidenceDigest: candidate.evidenceDigest,
      negativeControls: ['exact-json-pointer', 'non-empty-string-value', 'verified-subject-file-digest'],
    },
    technicalSeverity: {
      value: 'MEDIUM',
      methodVersion: 'dsh-node-install-lifecycle-severity-v1',
      rationale: 'The declared install-time code execution surface violates this scoped Policy; malicious behavior is not inferred.',
    },
    evidenceConfidence: {
      value: 'HIGH',
      methodVersion: 'dsh-deterministic-manifest-evidence-confidence-v1',
    },
    policySignificance: 'BLOCKING',
  }))
  const complete = contribution.completionDisposition === 'COMPLETE'
  const verdict: SecurityVerdict = findings.length > 0 ? 'FAILED' : 'SATISFIED'
  const coverage = complete
    ? coverageSnapshot(contract.targetDigest, {
        status: 'COMPLETE',
        mandatoryObligations: 1,
        satisfiedObligations: 1,
        gapObligations: 0,
        resolutions: [{
          obligationId: 'node-package-install-lifecycle-policy',
          state: 'SATISFIED',
          reason: 'ELIGIBLE_EVIDENCE',
        }],
      })
    : coverageSnapshot(contract.targetDigest, {
        status: 'GAP',
        mandatoryObligations: 1,
        satisfiedObligations: 0,
        gapObligations: 1,
        resolutions: [{
          obligationId: 'node-package-install-lifecycle-policy',
          state: 'GAP',
          reason: 'ANALYZER_INCOMPLETE',
        }],
      })
  const evaluationTrace = json({
    schemaVersion: 1,
    evaluatorVersion: 'dsh-security-policy-evaluator-v1',
    evaluationInstant,
    policyDigest: contract.policy.digest,
    rules: [
      { ruleId: 'blocking-policy-violation', matched: findings.length > 0, outcome: findings.length > 0 ? 'FAILED' : null },
      {
        ruleId: 'mandatory-coverage-gap',
        matched: !complete,
        outcome: !complete && findings.length === 0 ? 'INDETERMINATE' : null,
      },
      { ruleId: 'complete-mandatory-coverage', matched: complete, outcome: complete ? verdict : null },
    ],
    diagnostics: [],
  })
  return {
    coverage,
    findings,
    verdict,
    evaluationTrace,
    providerComposition: eligibleComposition,
    evidence: [...commonEvidence, {
      artifactId: 'evidence-eligibility-decision',
      schemaId: 'dsh/security-evidence-eligibility-decision',
      mediaType: 'application/vnd.dsh.security.evidence-eligibility-decision+json',
      value: eligibilityDecision,
    }],
  }
}

/** Independent pure readiness decision; evaluator output alone cannot authorize sealing. */
export function checkSealReadiness(
  contract: PreparedAssessmentContractV1,
  outcome: DeterministicAssessmentOutcomeV1,
  publishedEvidence: readonly EvidencePublicationReceiptV1[] = [],
): { readonly ready: true } | { readonly ready: false; readonly violations: readonly string[] } {
  const violations: string[] = []
  // Re-derive the coverage attestation at the sealing seam.  Evaluator output
  // is a caller-provided value at this boundary, so equality with the frozen
  // target and the complete coverage core must be checked independently.
  try {
    const { digest: observedDigest, ...coverageValue } = outcome.coverage
    const recomputedDigest = coverageSnapshot(contract.targetDigest, coverageValue).digest
    if (canonicalJson(observedDigest) !== canonicalJson(recomputedDigest)) {
      violations.push('coverage_digest_mismatch')
    }
  } catch {
    violations.push('coverage_digest_unverifiable')
  }
  const trace = outcome.evaluationTrace as unknown as Record<string, unknown>
  try {
    if (canonicalJson(trace.policyDigest) !== canonicalJson(contract.policy.digest)) {
      violations.push('evaluation_trace_policy_mismatch')
    }
  } catch {
    violations.push('evaluation_trace_policy_unverifiable')
  }
  const blockingFindings = outcome.findings.filter(finding => (
    typeof finding === 'object'
    && finding !== null
    && !Array.isArray(finding)
    && finding.policySignificance === 'BLOCKING'
  ))
  if (contract.coverage.status !== 'PENDING') violations.push('frozen_plan_not_pending_at_start')
  if (outcome.coverage.mandatoryObligations !== 1) violations.push('mandatory_obligation_count_mismatch')
  if (outcome.coverage.resolutions.length !== 1) violations.push('coverage_resolution_count_mismatch')
  if (outcome.verdict === 'INDETERMINATE') {
    if (outcome.coverage.status !== 'GAP' || outcome.coverage.gapObligations !== 1) {
      violations.push('indeterminate_without_mandatory_gap')
    }
    if (blockingFindings.length !== 0) violations.push('blocking_finding_did_not_take_precedence')
  } else if (outcome.verdict === 'SATISFIED') {
    if (outcome.coverage.status !== 'COMPLETE' || outcome.coverage.satisfiedObligations !== 1) {
      violations.push('satisfied_without_complete_coverage')
    }
    if (blockingFindings.length !== 0) violations.push('satisfied_with_blocking_finding')
  } else {
    if (blockingFindings.length === 0) violations.push('failed_without_blocking_finding')
  }
  if (publishedEvidence.length !== outcome.evidence.length) {
    violations.push('evidence_publication_count_mismatch')
  } else {
    for (const expected of outcome.evidence) {
      const digest = structuredDigest(expected.mediaType, expected.value)
      const receipt = publishedEvidence.find(value => value.artifactId === expected.artifactId)
      if (
        receipt === undefined
        || receipt.schemaId !== expected.schemaId
        || canonicalJson(receipt.digest) !== canonicalJson(digest)
      ) violations.push(`evidence_not_published:${expected.artifactId}`)
    }
  }
  return violations.length === 0 ? { ready: true } : { ready: false, violations }
}
