import { securitySubmissionJsonV1Schema } from '../contracts.ts'
import type {
  FindingDetailViewV1,
  RecordRiskDecisionRequest,
} from '../contracts.ts'
import type { InternalAssessmentRecordV1 } from './assessment-record.ts'
import type { DeterministicAssessmentOutcomeV1 } from './deterministic-kernel.ts'
import type { EvidencePublicationInputV1 } from './evidence-persistence.ts'

export class RiskDecisionPolicyError extends Error {}

/** Deep Module owning Risk Decision admission and its deterministic Verdict input. */
export class RiskDecisionModule {
  admit(
    finding: FindingDetailViewV1,
    request: RecordRiskDecisionRequest,
    evaluationInstant: string,
  ): void {
    if (finding.recordKind !== 'FINDING' || finding.validation.state !== 'VALIDATED') {
      throw new RiskDecisionPolicyError('Only a validated Security Finding admits a Risk Decision')
    }
    if (finding.riskDecision.state !== 'NOT_RECORDED') {
      throw new RiskDecisionPolicyError('The Finding already has an immutable Risk Decision')
    }
    if (request.decision === 'DENY') return
    if (finding.technicalSeverity === null) {
      throw new RiskDecisionPolicyError('Risk Acceptance requires a Technical Severity')
    }
    if (finding.technicalSeverity.value === 'CRITICAL') {
      throw new RiskDecisionPolicyError('Critical Risk Acceptance requires independent dual authority')
    }
    if (request.expiresAt === null || request.compensatingControls.length === 0) {
      throw new RiskDecisionPolicyError('Risk Acceptance requires compensating controls and expiry')
    }
    const evaluatedAt = Date.parse(evaluationInstant)
    const expiresAt = Date.parse(request.expiresAt)
    const maximumLifetime = finding.technicalSeverity.value === 'HIGH'
      ? 7 * 24 * 60 * 60 * 1_000
      : 30 * 24 * 60 * 60 * 1_000
    if (
      !Number.isFinite(evaluatedAt)
      || !Number.isFinite(expiresAt)
      || expiresAt <= evaluatedAt
      || expiresAt - evaluatedAt > maximumLifetime
    ) {
      throw new RiskDecisionPolicyError('Risk Acceptance expiry exceeds its severity ceiling')
    }
  }

  finalizedOutcome(
    assessment: InternalAssessmentRecordV1,
    evidence: readonly EvidencePublicationInputV1[],
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
    const hasDeniedRisk = assessment.riskDecisions.some(decision => decision.decision === 'DENY')
    const verdict = hasDeniedRisk
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
      if (decision?.decision !== 'ACCEPT') return finding
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
      evaluationInstant: window.resolvedAt,
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
