import { securitySubmissionJsonV1Schema } from '../contracts.ts'
import type {
  AssessmentAvailableActionV1,
  AvailableRiskDecisionOptionV1,
  FindingDetailViewV1,
  RecordRiskDecisionRequest,
  RiskDecisionAuthorizationModeV1,
  TechnicalSeverity,
} from '../contracts.ts'
import type { InternalAssessmentRecordV1 } from './assessment-record.ts'
import type { ResolvedSecurityAuthority } from './authority.ts'
import { canonicalJson } from './canonical.ts'
import type { DeterministicAssessmentOutcomeV1 } from './deterministic-kernel.ts'
import type { EvidencePublicationInputV1 } from './evidence-persistence.ts'

export class RiskDecisionPolicyError extends Error {}

export interface RiskDecisionAdmissionContextV1 {
  readonly criticalBreakGlassEnabled: boolean
  readonly criticalBreakGlassAuthorized: boolean
}

const CRITICAL_MAXIMUM_LIFETIME_SECONDS = 86_400 as const

function ordinaryMaximumLifetimeSeconds(severity: TechnicalSeverity): number {
  return severity === 'HIGH' ? 7 * 24 * 60 * 60 : 30 * 24 * 60 * 60
}

/** Deep Module owning Risk Decision admission and its deterministic Verdict input. */
export class RiskDecisionModule {
  projectAvailableAction(
    assessment: InternalAssessmentRecordV1,
    finding: FindingDetailViewV1,
    authority: ResolvedSecurityAuthority,
    evaluationInstant: string,
  ): AssessmentAvailableActionV1 | undefined {
    const window = assessment.riskDecisionWindow
    if (
      !authority.permissions.has('risk:decide')
      || assessment.state !== 'BLOCKED'
      || window?.state !== 'OPEN'
      || !window.findingRecordIds.includes(finding.recordId)
      || finding.recordKind !== 'FINDING'
      || finding.validation.state !== 'VALIDATED'
    ) return undefined

    const criticalAcceptanceAuthorized = authority.kind === 'host-operator'
      && authority.permissions.has('risk:break-glass')
      && assessment.contract.requestedStrongerControlIds.includes('security/critical-break-glass-v1')
    const attestations = finding.riskDecision.state === 'NOT_RECORDED'
      ? []
      : finding.riskDecision.attestations ?? []
    let options: AvailableRiskDecisionOptionV1[]
    if (finding.riskDecision.state === 'NOT_RECORDED') {
      options = [{
        decision: 'DENY',
        consequence: 'KEEPS_FINDING_BLOCKING',
      }]
      if (finding.technicalSeverity?.value === 'CRITICAL' && criticalAcceptanceAuthorized) {
        options.push({
          decision: 'ACCEPT',
          consequence: 'REQUIRES_SECOND_AUTHORITY',
          authorizationMode: 'CRITICAL_DUAL_AUTHORITY',
          minimumCompensatingControls: 2,
          maximumLifetimeSeconds: CRITICAL_MAXIMUM_LIFETIME_SECONDS,
          requiredAttestations: 2,
          completedAttestations: 0,
          exactMatchRequired: false,
        })
      } else if (finding.technicalSeverity !== null && finding.technicalSeverity.value !== 'CRITICAL') {
        options.push({
          decision: 'ACCEPT',
          consequence: 'MAKES_FINDING_NON_BLOCKING',
          authorizationMode: 'SINGLE_AUTHORITY',
          minimumCompensatingControls: 1,
          maximumLifetimeSeconds: ordinaryMaximumLifetimeSeconds(finding.technicalSeverity.value),
          requiredAttestations: 1,
          completedAttestations: 0,
          exactMatchRequired: false,
        })
      }
    } else if (
      finding.riskDecision.state === 'PENDING_DUAL_AUTHORITY'
      && finding.technicalSeverity?.value === 'CRITICAL'
      && criticalAcceptanceAuthorized
      && finding.riskDecision.authorizationMode === 'CRITICAL_DUAL_AUTHORITY'
      && attestations.length === 1
      && attestations.every(
        attestation => attestation.decisionMaker.principalId.toLocaleLowerCase('en-US')
          !== authority.principalId.toLocaleLowerCase('en-US'),
      )
      && finding.riskDecision.expiresAt !== null
      && Date.parse(finding.riskDecision.expiresAt) > Date.parse(evaluationInstant)
      && finding.riskDecision.scope !== undefined
      && canonicalJson(finding.riskDecision.scope.subjectDigest) === canonicalJson(assessment.subject.digest)
      && canonicalJson(finding.riskDecision.scope.policyDigest) === canonicalJson(assessment.contract.policy.digest)
    ) {
      options = [{
        decision: 'ACCEPT',
        consequence: 'MAKES_FINDING_NON_BLOCKING',
        authorizationMode: 'CRITICAL_DUAL_AUTHORITY',
        minimumCompensatingControls: 2,
        maximumLifetimeSeconds: CRITICAL_MAXIMUM_LIFETIME_SECONDS,
        requiredAttestations: 2,
        completedAttestations: 1,
        exactMatchRequired: true,
      }]
    } else {
      return undefined
    }
    return {
      kind: 'RECORD_RISK_DECISION',
      expectedAssessmentRevision: assessment.assessmentRevision,
      finding: {
        recordId: finding.recordId,
        recordRevision: finding.recordRevision,
      },
      options,
    }
  }

  admit(
    finding: FindingDetailViewV1,
    request: RecordRiskDecisionRequest,
    evaluationInstant: string,
    context: RiskDecisionAdmissionContextV1,
  ): RiskDecisionAuthorizationModeV1 {
    if (finding.recordKind !== 'FINDING' || finding.validation.state !== 'VALIDATED') {
      throw new RiskDecisionPolicyError('Only a validated Security Finding admits a Risk Decision')
    }
    if (finding.riskDecision.state !== 'NOT_RECORDED') {
      throw new RiskDecisionPolicyError('The Finding already has an immutable Risk Decision')
    }
    if (request.decision === 'DENY') return 'SINGLE_AUTHORITY'
    if (finding.technicalSeverity === null) {
      throw new RiskDecisionPolicyError('Risk Acceptance requires a Technical Severity')
    }
    if (finding.technicalSeverity.value === 'CRITICAL') {
      if (!context.criticalBreakGlassEnabled || !context.criticalBreakGlassAuthorized) {
        throw new RiskDecisionPolicyError('Critical Risk Acceptance requires enabled qualified break-glass authority')
      }
      if (request.compensatingControls.length < 2 || request.expiresAt === null) {
        throw new RiskDecisionPolicyError('Critical Risk Acceptance requires tightly bounded compensating controls')
      }
      const evaluatedAt = Date.parse(evaluationInstant)
      const expiresAt = Date.parse(request.expiresAt)
      if (
        !Number.isFinite(evaluatedAt)
        || !Number.isFinite(expiresAt)
        || expiresAt <= evaluatedAt
        || expiresAt - evaluatedAt > 24 * 60 * 60 * 1_000
      ) throw new RiskDecisionPolicyError('Critical Risk Acceptance exceeds its 24-hour ceiling')
      return 'CRITICAL_DUAL_AUTHORITY'
    }
    if (request.expiresAt === null || request.compensatingControls.length === 0) {
      throw new RiskDecisionPolicyError('Risk Acceptance requires compensating controls and expiry')
    }
    const evaluatedAt = Date.parse(evaluationInstant)
    const expiresAt = Date.parse(request.expiresAt)
    const maximumLifetime = ordinaryMaximumLifetimeSeconds(finding.technicalSeverity.value) * 1_000
    if (
      !Number.isFinite(evaluatedAt)
      || !Number.isFinite(expiresAt)
      || expiresAt <= evaluatedAt
      || expiresAt - evaluatedAt > maximumLifetime
    ) {
      throw new RiskDecisionPolicyError('Risk Acceptance expiry exceeds its severity ceiling')
    }
    return 'SINGLE_AUTHORITY'
  }

  finalizedOutcome(
    assessment: InternalAssessmentRecordV1,
    evidence: readonly EvidencePublicationInputV1[],
    finalizationInstant: string,
  ): DeterministicAssessmentOutcomeV1 {
    const window = assessment.riskDecisionWindow
    if (
      assessment.state !== 'BLOCKED'
      || window?.state !== 'RESOLVED'
      || assessment.evaluationTrace === null
      || window.providerComposition === null
      || window.resolvedAt === null
      || assessment.riskDecisions.length !== window.findingRecordIds.length
    ) throw new RiskDecisionPolicyError('Risk Decision Window is not ready for deterministic finalization')
    const decisions = new Map(assessment.riskDecisions.map(decision => [
      decision.finding.recordId,
      decision,
    ]))
    if (
      decisions.size !== assessment.riskDecisions.length
      || window.findingRecordIds.some(recordId => !decisions.has(recordId))
    ) throw new RiskDecisionPolicyError('Risk Decision Window has incomplete or ambiguous decisions')
    const trace = assessment.evaluationTrace
    if (typeof trace !== 'object' || trace === null || Array.isArray(trace)) {
      throw new RiskDecisionPolicyError('Risk Decision Window Evaluation Trace is invalid')
    }
    const finalizationEpochMs = Date.parse(finalizationInstant)
    if (!Number.isFinite(finalizationEpochMs)) {
      throw new RiskDecisionPolicyError('Risk Decision finalization instant is invalid')
    }
    const hasDeniedRisk = assessment.riskDecisions.some(decision => decision.decision === 'DENY')
    const hasExpiredAcceptance = assessment.riskDecisions.some(decision => (
      decision.decision === 'ACCEPT'
      && decision.expiresAt !== null
      && Date.parse(decision.expiresAt) <= finalizationEpochMs
    ))
    const verdict = hasDeniedRisk
      ? window.proposedVerdict
      : hasExpiredAcceptance
        ? window.proposedVerdict
        : assessment.coverage.status === 'COMPLETE'
        ? 'SATISFIED'
        : 'INDETERMINATE'
    const findings = assessment.findings.map(finding => {
      if (typeof finding !== 'object' || finding === null || Array.isArray(finding)) {
        throw new RiskDecisionPolicyError('Risk Decision Finding is invalid')
      }
      const findingId = finding.findingId
      const decision = typeof findingId === 'string' ? decisions.get(findingId) : undefined
      if (
        decision?.decision !== 'ACCEPT'
        || decision.expiresAt === null
        || Date.parse(decision.expiresAt) <= finalizationEpochMs
      ) return finding
      const accepted = securitySubmissionJsonV1Schema.parse({
        ...finding,
        policySignificance: 'NON_BLOCKING',
        policySignificanceTrace: {
          ruleId: 'authorized-time-bounded-risk-acceptance-v1',
          policyDigest: assessment.contract.policy.digest,
          riskDecisionId: decision.decisionId,
          matched: true,
          prior: finding.policySignificanceTrace ?? null,
        },
      })
      if (accepted === null) throw new RiskDecisionPolicyError('Accepted Finding cannot be null')
      return accepted
    })
    const evaluationTrace = securitySubmissionJsonV1Schema.parse({
      ...trace,
      evaluationInstant: finalizationInstant,
      riskDecisionResolvedAt: window.resolvedAt,
      preDecisionEvaluationInstant: window.evaluationInstant,
      riskDecisions: assessment.riskDecisions,
      riskDecisionRule: {
        ruleId: hasDeniedRisk
          ? 'explicit-risk-denial-preserves-policy-significance'
          : 'authorized-time-bounded-risk-acceptance-removes-policy-blocking',
        matched: true,
        outcome: verdict,
      },
    })
    if (evaluationTrace === null) {
      throw new RiskDecisionPolicyError('Risk Decision Evaluation Trace cannot be null')
    }
    return {
      coverage: assessment.coverage,
      findings,
      verdict,
      evaluationTrace,
      providerComposition: window.providerComposition,
      evidence,
    }
  }
}
