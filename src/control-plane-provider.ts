import type { Context } from '@deepseek-ai/cordis'
import type EngineeringControlPlane from 'dsh-engineering-control-plane'
import {
  parseExternalAssessmentFailureV1,
  sealAssuranceSubmissionV1,
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
  type RepositoryId,
  type SecurityInvocation,
} from './contracts.ts'
import type { SecurityAssuranceService } from './index.ts'
import type { SecurityAssuranceHostRepositoryProvider } from './host-repository-provider.ts'
import { createTrustedCallerChannel, resolveTrustedInvocation } from './internal/authority.ts'
import { canonicalJson } from './internal/canonical.ts'
import {
  executeControlPlaneProviderOperation,
  type ControlPlaneAssessmentOperationOutcome,
  type ControlPlaneSealedAssessmentOutcome,
} from './internal/control-plane-provider-operation.ts'

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

function invocationOptions(options?: ProviderInvocationOptions) {
  return options?.signal === undefined ? {} : { signal: options.signal }
}

async function configuredRepositoryId(
  ctx: Context,
  request: AssuranceRequestV1,
): Promise<RepositoryId | undefined> {
  const configuration = request.configuration
  if (
    configuration === undefined
    || Object.keys(configuration).length !== 1
  ) return undefined
  if (Object.hasOwn(configuration, 'repositoryId')) {
    const parsed = repositoryIdSchema.safeParse(configuration.repositoryId)
    return parsed.success ? parsed.data : undefined
  }
  if (!Object.hasOwn(configuration, 'repositoryBindingId')) return undefined
  const bindingId = configuration.repositoryBindingId
  if (typeof bindingId !== 'string') return undefined
  let provider: SecurityAssuranceHostRepositoryProvider | undefined
  try {
    provider = ctx.get('securityAssuranceHostRepositories') as SecurityAssuranceHostRepositoryProvider | undefined
  } catch {
    return undefined
  }
  const binding = await provider?.resolve(bindingId)
  return binding?.state === 'ENABLED' ? binding.repositoryId : undefined
}

function canonicalSubmissionEvidence(
  submission: ControlPlaneSealedAssessmentOutcome['securitySubmission'],
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
  outcome: ControlPlaneSealedAssessmentOutcome,
) {
  const evidence = [canonicalSubmissionEvidence(outcome.securitySubmission)]
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
      assessmentId: outcome.assessmentId,
      claimedOutcome: outcome.claimedOutcome,
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
      value: { schemaVersion: 1, ...outcome.coverage },
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

function assessmentOutcome(
  descriptor: AssuranceProviderDescriptorV1,
  context: AssuranceExecutionContext,
  outcome: ControlPlaneAssessmentOperationOutcome,
): AssuranceProviderOutcomeV1 {
  if (outcome.kind === 'EXTERNAL_FAILURE') {
    return externalFailure(outcome.reason, outcome.code)
  }
  return {
    kind: 'sealed_submission',
    submission: sealControlPlaneSubmission(descriptor, context, outcome),
  }
}

class SecurityAssuranceProvider implements AssuranceProviderV1 {
  constructor(
    readonly descriptor: AssuranceProviderDescriptorV1,
    private readonly ctx: Context,
    private readonly service: SecurityAssuranceService,
    private readonly invocation: SecurityInvocation,
  ) {}

  async assess(
    context: AssuranceExecutionContext,
    request: AssuranceRequestV1,
    options?: ProviderInvocationOptions,
  ): Promise<AssuranceProviderOutcomeV1> {
    const repositoryId = await configuredRepositoryId(this.ctx, request)
    if (repositoryId === undefined) return externalFailure('failed', 'invalid_provider_configuration')
    const outcome = await executeControlPlaneProviderOperation(
      this.service,
      this.invocation,
      { kind: 'ASSESS', context, repositoryId },
      invocationOptions(options),
    )
    return assessmentOutcome(this.descriptor, context, outcome)
  }

  async recover(
    context: AssuranceExecutionContext,
    request: AssuranceRequestV1,
    options?: ProviderInvocationOptions,
  ): Promise<AssuranceProviderOutcomeV1> {
    const repositoryId = await configuredRepositoryId(this.ctx, request)
    if (repositoryId === undefined) return externalFailure('failed', 'invalid_provider_configuration')
    const outcome = await executeControlPlaneProviderOperation(
      this.service,
      this.invocation,
      { kind: 'RECOVER', context, repositoryId },
      invocationOptions(options),
    )
    return assessmentOutcome(this.descriptor, context, outcome)
  }

  async cancel(
    context: AssuranceExecutionContext,
    request: AssuranceRequestV1,
    options?: ProviderInvocationOptions,
  ): Promise<AssuranceProviderCancellationOutcomeV1> {
    const repositoryId = await configuredRepositoryId(this.ctx, request)
    if (repositoryId === undefined) throw new Error('Security Provider configuration is invalid')
    const outcome = await executeControlPlaneProviderOperation(
      this.service,
      this.invocation,
      { kind: 'CANCEL', context, repositoryId },
      invocationOptions(options),
    )
    if (outcome.kind === 'EXTERNAL_ASSESSMENT_NOT_STARTED') {
      return { kind: 'external_assessment_not_started' }
    }
    if (outcome.kind === 'EXTERNAL_ASSESSMENT_TERMINAL') {
      return {
        kind: 'external_assessment_terminal',
        externalAssessmentId: outcome.externalAssessmentId,
        terminalState: outcome.terminalState,
      }
    }
    return {
      kind: 'external_assessment_canceled',
      externalAssessmentId: outcome.externalAssessmentId,
    }
  }
}

/** Optional Cordis contributor. Both root Services remain independently installable. */
const SecurityAssuranceControlPlaneProvider = {
  name: 'dsh-security-assurance-control-plane-provider',
  inject: ['engineeringControlPlane', 'securityAssurance'],
  apply(ctx: Context) {
    const invocation = resolveTrustedInvocation(ctx.securityAssurance, createTrustedCallerChannel({
      kind: 'control-plane',
      principalId: 'engineering-control-plane-assurance-provider',
      permissions: [
        'repository:read',
        'assessment:start',
        'assessment:read',
        'assessment:resume',
        'assessment:cancel',
        'assurance-submission:read',
      ],
    }))
    return ctx.engineeringControlPlane.registerAssuranceProvider(
      SECURITY_ASSURANCE_CONTROL_PLANE_DESCRIPTOR,
      (descriptor: AssuranceProviderDescriptorV1) => (
        new SecurityAssuranceProvider(descriptor, ctx, ctx.securityAssurance, invocation)
      ),
    )
  },
}

export default SecurityAssuranceControlPlaneProvider
