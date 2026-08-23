import { createHash } from 'node:crypto'
import type { Context } from '@deepseek-ai/cordis'
import type EngineeringControlPlane from 'dsh-engineering-control-plane'
import {
  parseExternalAssessmentFailureV1,
  sealAssuranceSubmissionV1,
  type AssuranceClaimedOutcomeV1,
  type AssuranceExecutionContext,
  type AssuranceProviderDescriptorV1,
  type AssuranceProviderCancellationOutcomeV1,
  type AssuranceProviderOutcomeV1,
  type AssuranceProviderV1,
  type AssuranceRequestV1,
  type AssuranceSubmissionArtifactDraftV1,
  type ExternalAssessmentFailureV1,
  type ProviderInvocationOptions,
} from 'dsh-engineering-control-plane/assurance-provider'
import {
  repositoryIdSchema,
  SECURITY_ASSURANCE_PRODUCT_VERSION,
  type AssessmentSnapshotV1,
  type RepositoryId,
  type SecurityAssuranceSubmissionV1,
  type SecurityInvocation,
  type StartAssessmentRequest,
} from './contracts.ts'
import type { SecurityAssuranceService } from './index.ts'
import { resolveTrustedInvocation } from './internal/authority.ts'
import { canonicalJson } from './internal/canonical.ts'
import { lookupControlPlaneAssessment } from './internal/control-plane-assessment.ts'
import { reachControlPlaneCancellationCrashCheckpoint } from './internal/control-plane-cancellation-crash-checkpoint.ts'

declare module '@deepseek-ai/cordis' {
  interface Context {
    engineeringControlPlane: EngineeringControlPlane
  }
}

export const SECURITY_ASSURANCE_CONTROL_PLANE_DESCRIPTOR = Object.freeze({
  schemaVersion: 1,
  providerId: 'dsh/security-assurance',
  providerVersion: SECURITY_ASSURANCE_PRODUCT_VERSION,
}) satisfies AssuranceProviderDescriptorV1

function externalFailure(
  reason: ExternalAssessmentFailureV1['reason'],
  code: string,
): AssuranceProviderOutcomeV1 {
  return {
    kind: 'external_failure',
    failure: parseExternalAssessmentFailureV1({ schemaVersion: 1, reason, code }),
  }
}

function securityError(code: string): AssuranceProviderOutcomeV1 {
  return externalFailure(
    code === 'CANCELED' ? 'canceled' : code === 'UNAVAILABLE' ? 'blocked' : 'failed',
    `security_${code.toLowerCase()}`,
  )
}

function invocationOptions(options?: ProviderInvocationOptions) {
  return options?.signal === undefined ? {} : { signal: options.signal }
}

function configuredRepositoryId(request: AssuranceRequestV1): RepositoryId | undefined {
  const configuration = request.configuration
  if (
    configuration === undefined
    || Object.keys(configuration).length !== 1
    || !Object.hasOwn(configuration, 'repositoryId')
  ) return undefined
  const parsed = repositoryIdSchema.safeParse(configuration.repositoryId)
  return parsed.success ? parsed.data : undefined
}

function assessmentIdempotencyKey(context: AssuranceExecutionContext): string {
  const digest = createHash('sha256')
    .update(`${context.invocationId}\0${context.missionId}\0${context.attempt}`)
    .digest('hex')
  return `control-plane-${digest}`
}

function assessmentResumeIdempotencyKey(context: AssuranceExecutionContext): string {
  const digest = createHash('sha256')
    .update(`resume\0${context.invocationId}\0${context.missionId}\0${context.attempt}`)
    .digest('hex')
  return `control-plane-resume-${digest}`
}

function assessmentCancellationIdempotencyKey(context: AssuranceExecutionContext): string {
  const digest = createHash('sha256')
    .update(`cancel\0${context.invocationId}\0${context.missionId}\0${context.attempt}`)
    .digest('hex')
  return `control-plane-cancel-${digest}`
}

function startRequest(
  context: AssuranceExecutionContext,
  repositoryId: RepositoryId,
  assessmentProfileId: string,
): StartAssessmentRequest {
  return {
    schemaVersion: 1,
    idempotencyKey: assessmentIdempotencyKey(context),
    repositoryId,
    subject: { kind: 'workspace_snapshot' },
    assessmentMode: 'REPOSITORY',
    assessmentProfileId,
    target: { kind: 'repository' },
    requestedStrongerControlIds: [],
  }
}

function claimedOutcome(verdict: AssessmentSnapshotV1['verdict']): AssuranceClaimedOutcomeV1 {
  if (verdict === 'SATISFIED') return 'satisfied'
  if (verdict === 'FAILED') return 'failed'
  return 'indeterminate'
}

function canonicalSubmissionEvidence(
  submission: SecurityAssuranceSubmissionV1,
): AssuranceSubmissionArtifactDraftV1 {
  return {
    artifactId: 'security-assurance-submission',
    schemaId: 'dsh/security-assurance-submission',
    schemaVersion: 1,
    value: {
      schemaVersion: 1,
      sourceDigest: `sha256:${submission.digest.value}`,
      sourceMediaType: submission.digest.mediaType,
      canonicalSubmission: canonicalJson(submission),
    },
  }
}

function sealControlPlaneSubmission(
  descriptor: AssuranceProviderDescriptorV1,
  context: AssuranceExecutionContext,
  assessment: AssessmentSnapshotV1,
  securitySubmission: SecurityAssuranceSubmissionV1,
) {
  const outcome = claimedOutcome(assessment.verdict)
  const evidence = [canonicalSubmissionEvidence(securitySubmission)]
  const resolutions = assessment.coverage.resolutions.length === 0
    ? [{
        obligationId: 'security/assessment',
        state: assessment.coverage.status === 'COMPLETE' ? 'SATISFIED' as const : 'GAP' as const,
      }]
    : assessment.coverage.resolutions
  const coverageComplete = assessment.coverage.status === 'COMPLETE'
    && resolutions.every(resolution => resolution.state === 'SATISFIED')
  const draft = {
    schemaVersion: 1 as const,
    binding: {
      invocationId: context.invocationId,
      missionId: context.missionId,
      attempt: context.attempt,
      provider: descriptor,
      subject: context.subject,
      effectivePolicyDigest: context.effectivePolicyDigest,
    },
    externalAssessment: {
      state: 'sealed' as const,
      assessmentId: assessment.assessmentId,
      claimedOutcome: outcome,
    },
    providerComposition: {
      artifactId: 'security-assurance-provider-composition',
      schemaId: 'dsh/assurance-provider-composition',
      schemaVersion: 1,
      value: {
        schemaVersion: 1,
        provider: descriptor,
        components: [{
          componentId: 'dsh-security-assurance/assessment-kernel',
          componentVersion: SECURITY_ASSURANCE_PRODUCT_VERSION,
        }],
      },
    },
    providerPolicy: {
      artifactId: 'security-assurance-provider-policy',
      schemaId: 'dsh/assurance-provider-policy',
      schemaVersion: 1,
      value: { schemaVersion: 1, effectivePolicyDigest: context.effectivePolicyDigest },
    },
    coverage: {
      artifactId: 'security-assurance-coverage',
      schemaId: 'dsh/assurance-provider-coverage',
      schemaVersion: 1,
      value: {
        schemaVersion: 1,
        status: coverageComplete ? 'complete' : 'incomplete',
        dimensions: resolutions.map(resolution => ({
          dimensionId: resolution.obligationId,
          status: resolution.state === 'SATISFIED' ? 'covered' : 'not_covered',
        })),
      },
    },
    provenance: {
      artifactId: 'security-assurance-provenance',
      schemaId: 'dsh/assurance-provider-provenance',
      schemaVersion: 1,
      value: {
        schemaVersion: 1,
        assessor: { kind: 'machine_provider', provider: descriptor },
      },
    },
    evidence,
  }
  const provisional = sealAssuranceSubmissionV1({
    ...draft,
    sourceSeal: {
      artifactId: 'security-assurance-source-seal',
      schemaId: 'dsh/assurance-provider-source-seal',
      schemaVersion: 1,
      value: { schemaVersion: 1, state: 'sealed', subject: context.subject, evidenceDigests: [] },
    },
  })
  return sealAssuranceSubmissionV1({
    ...draft,
    sourceSeal: {
      artifactId: 'security-assurance-source-seal',
      schemaId: 'dsh/assurance-provider-source-seal',
      schemaVersion: 1,
      value: {
        schemaVersion: 1,
        state: 'sealed',
        subject: context.subject,
        evidenceDigests: provisional.payload.evidence.map(artifact => artifact.digest.value),
      },
    },
  })
}

class SecurityAssuranceProvider implements AssuranceProviderV1 {
  constructor(
    readonly descriptor: AssuranceProviderDescriptorV1,
    private readonly service: SecurityAssuranceService,
    private readonly invocation: SecurityInvocation,
  ) {}

  async assess(
    context: AssuranceExecutionContext,
    request: AssuranceRequestV1,
    options?: ProviderInvocationOptions,
  ): Promise<AssuranceProviderOutcomeV1> {
    return this.execute(context, request, options, false)
  }

  async recover(
    context: AssuranceExecutionContext,
    request: AssuranceRequestV1,
    options?: ProviderInvocationOptions,
  ): Promise<AssuranceProviderOutcomeV1> {
    return this.execute(context, request, options, true)
  }

  private async execute(
    context: AssuranceExecutionContext,
    request: AssuranceRequestV1,
    options: ProviderInvocationOptions | undefined,
    recovering: boolean,
  ): Promise<AssuranceProviderOutcomeV1> {
    const repositoryId = configuredRepositoryId(request)
    if (repositoryId === undefined) return externalFailure('blocked', 'invalid_provider_configuration')
    const callOptions = invocationOptions(options)
    const repository = await this.service.getRepository(
      this.invocation,
      { schemaVersion: 1, repositoryId },
      callOptions,
    )
    if (!repository.ok) return securityError(repository.error.code)
    if (repository.value.state !== 'ENABLED') return externalFailure('blocked', 'repository_disabled')

    const started = await this.service.startAssessment(
      this.invocation,
      startRequest(context, repositoryId, repository.value.bindings.assessmentProfileId),
      callOptions,
    )
    if (!started.ok) return securityError(started.error.code)
    await reachControlPlaneCancellationCrashCheckpoint(
      this.service,
      'after_assessment_started',
      started.value.assessmentId,
    )

    let revision: number = started.value.assessmentRevision
    while (true) {
      const assessment = await this.service.getAssessment(
        this.invocation,
        { schemaVersion: 1, assessmentId: started.value.assessmentId },
        callOptions,
      )
      if (!assessment.ok) return securityError(assessment.error.code)
      revision = assessment.value.assessmentRevision
      if (assessment.value.state === 'SEALED') {
        const submission = await this.service.getAssuranceSubmission(
          this.invocation,
          { schemaVersion: 1, assessmentId: started.value.assessmentId },
          callOptions,
        )
        if (!submission.ok) return securityError(submission.error.code)
        return {
          kind: 'sealed_submission',
          submission: sealControlPlaneSubmission(
            this.descriptor,
            context,
            assessment.value,
            submission.value,
          ),
        }
      }
      if (assessment.value.state === 'BLOCKED') {
        if (!recovering) return externalFailure('blocked', 'assessment_blocked')
        const resumed = await this.service.resumeAssessment(this.invocation, {
          schemaVersion: 1,
          assessmentId: assessment.value.assessmentId,
          expectedAssessmentRevision: assessment.value.assessmentRevision,
          idempotencyKey: assessmentResumeIdempotencyKey(context),
          reason: {
            code: 'CONTROL_PLANE_PROVIDER_RECOVERY',
            summary: 'Reconcile the durable Control Plane Provider invocation after host restart.',
          },
        }, callOptions)
        if (!resumed.ok) return securityError(resumed.error.code)
        revision = resumed.value.assessmentRevision
        continue
      }
      if (assessment.value.state === 'CANCELED') return externalFailure('canceled', 'assessment_canceled')

      const changed = await this.service.waitForAssessmentRevision(this.invocation, {
        schemaVersion: 1,
        assessmentId: started.value.assessmentId,
        afterRevision: revision,
        timeoutMs: 5_000,
      }, callOptions)
      if (!changed.ok) return securityError(changed.error.code)
      revision = changed.value.assessmentRevision
    }
  }

  async cancel(
    context: AssuranceExecutionContext,
    request: AssuranceRequestV1,
    options?: ProviderInvocationOptions,
  ): Promise<AssuranceProviderCancellationOutcomeV1> {
    const repositoryId = configuredRepositoryId(request)
    if (repositoryId === undefined) throw new Error('Security Provider configuration is invalid')
    const callOptions = invocationOptions(options)
    const started = await lookupControlPlaneAssessment(this.service, this.invocation, {
      idempotencyKey: assessmentIdempotencyKey(context),
      repositoryId,
    })
    if (started === undefined) return { kind: 'external_assessment_not_started' }

    for (let reconciliation = 0; reconciliation < 4; reconciliation += 1) {
      const assessment = await this.service.getAssessment(
        this.invocation,
        { schemaVersion: 1, assessmentId: started.assessmentId },
        callOptions,
      )
      if (!assessment.ok) throw new Error(`Security Assessment lookup failed (${assessment.error.code})`)
      if (assessment.value.state === 'SEALED') {
        return {
          kind: 'external_assessment_terminal',
          externalAssessmentId: assessment.value.assessmentId,
          terminalState: 'sealed',
        }
      }
      if (assessment.value.state === 'CANCELED') {
        return {
          kind: 'external_assessment_terminal',
          externalAssessmentId: assessment.value.assessmentId,
          terminalState: 'canceled',
        }
      }
      const canceled = await this.service.cancelAssessment(this.invocation, {
        schemaVersion: 1,
        assessmentId: assessment.value.assessmentId,
        expectedAssessmentRevision: assessment.value.assessmentRevision,
        idempotencyKey: assessmentCancellationIdempotencyKey(context),
        reason: {
          code: 'CONTROL_PLANE_MISSION_CANCELED',
          summary: 'Cancel the external Assessment because its owning Mission was explicitly canceled.',
        },
      }, callOptions)
      if (!canceled.ok) {
        if (canceled.error.code === 'CONFLICT') continue
        throw new Error(`Security Assessment cancellation failed (${canceled.error.code})`)
      }
      const terminal = await this.service.getAssessment(
        this.invocation,
        { schemaVersion: 1, assessmentId: assessment.value.assessmentId },
        callOptions,
      )
      if (!terminal.ok || terminal.value.state !== 'CANCELED') {
        throw new Error('Security Assessment cancellation did not reach CANCELED')
      }
      await reachControlPlaneCancellationCrashCheckpoint(
        this.service,
        'after_assessment_canceled_before_provider_outcome',
        terminal.value.assessmentId,
      )
      return {
        kind: 'external_assessment_canceled',
        externalAssessmentId: terminal.value.assessmentId,
      }
    }
    throw new Error('Security Assessment changed repeatedly during cancellation')
  }
}

/** Optional Cordis contributor. Both root Services remain independently installable. */
const SecurityAssuranceControlPlaneProvider = {
  name: 'dsh-security-assurance-control-plane-provider',
  inject: ['engineeringControlPlane', 'securityAssurance'],
  apply(ctx: Context) {
    const invocation = resolveTrustedInvocation(ctx.securityAssurance, {
      kind: 'control-plane',
      principalId: 'engineering-control-plane-assurance-provider',
      permissions: [
        'repository:read',
        'assessment:start',
        'assessment:read',
        'assessment:resume',
        'assessment:cancel',
      ],
    })
    return ctx.engineeringControlPlane.registerAssuranceProvider(
      SECURITY_ASSURANCE_CONTROL_PLANE_DESCRIPTOR,
      (descriptor: AssuranceProviderDescriptorV1) => (
        new SecurityAssuranceProvider(descriptor, ctx.securityAssurance, invocation)
      ),
    )
  },
}

export default SecurityAssuranceControlPlaneProvider
