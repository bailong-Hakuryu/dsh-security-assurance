import { createHash } from 'node:crypto'
import type {
  AssessmentId,
  InvocationOptions,
  RepositoryId,
  SecurityAssuranceSubmissionV1,
  SecurityInvocation,
} from '../contracts.ts'
import type { ControlPlaneRepositoryBindingMatcher } from './control-plane-repository-binding.ts'

export interface ControlPlaneProviderContext extends ControlPlaneRepositoryBindingMatcher {
  readonly invocationId: string
  readonly missionId: string
  readonly attempt: number
  readonly subject: {
    readonly kind: 'git_worktree'
    readonly branch: string
    readonly head: string
    readonly workspaceFingerprint: string
    readonly producedChangeFingerprint: string
  }
}

/**
 * Derive a stable operation identity without allowing a Repository rebind to
 * alias the original Assessment start. Resume and cancellation remain scoped
 * to the immutable Control Plane invocation they reconcile.
 */
export function controlPlaneOperationIdempotencyKey(
  operation: 'start',
  context: ControlPlaneProviderContext,
  repositoryId: RepositoryId,
): string
export function controlPlaneOperationIdempotencyKey(
  operation: 'resume' | 'cancel',
  context: ControlPlaneProviderContext,
): string
export function controlPlaneOperationIdempotencyKey(
  operation: 'start' | 'resume' | 'cancel',
  context: ControlPlaneProviderContext,
  repositoryId?: RepositoryId,
): string {
  if (operation === 'start' && repositoryId === undefined) {
    throw new TypeError('control-plane start identity requires a Repository binding')
  }
  const prefix = operation === 'start'
    ? `start\0${repositoryId as string}\0`
    : `${operation}\0`
  const digest = createHash('sha256')
    .update(`${prefix}${context.invocationId}\0${context.missionId}\0${context.attempt}`)
    .digest('hex')
  return operation === 'start'
    ? `control-plane-${digest}`
    : `control-plane-${operation}-${digest}`
}

export interface ControlPlaneAssessmentOperation {
  readonly kind: 'ASSESS' | 'RECOVER'
  readonly context: ControlPlaneProviderContext
  readonly repositoryId: RepositoryId
}

export interface ControlPlaneCancellationOperation {
  readonly kind: 'CANCEL'
  readonly context: ControlPlaneProviderContext
  readonly repositoryId: RepositoryId
}

export type ControlPlaneProviderOperation =
  | ControlPlaneAssessmentOperation
  | ControlPlaneCancellationOperation

export interface ControlPlaneExternalFailureOutcome {
  readonly kind: 'EXTERNAL_FAILURE'
  readonly reason: 'blocked' | 'canceled' | 'failed'
  readonly code: string
}

export interface ControlPlaneSealedAssessmentOutcome {
  readonly kind: 'SEALED_ASSESSMENT'
  readonly assessmentId: AssessmentId
  readonly claimedOutcome: 'satisfied' | 'failed' | 'indeterminate'
  readonly coverage: {
    readonly status: 'complete' | 'incomplete'
    readonly dimensions: readonly {
      readonly dimensionId: string
      readonly status: 'covered' | 'not_covered'
    }[]
  }
  readonly securitySubmission: SecurityAssuranceSubmissionV1
}

export type ControlPlaneAssessmentOperationOutcome =
  | ControlPlaneExternalFailureOutcome
  | ControlPlaneSealedAssessmentOutcome

export type ControlPlaneCancellationOperationOutcome =
  | {
      readonly kind: 'EXTERNAL_ASSESSMENT_NOT_STARTED'
    }
  | {
      readonly kind: 'EXTERNAL_ASSESSMENT_TERMINAL'
      readonly externalAssessmentId: AssessmentId
      readonly terminalState: 'sealed' | 'canceled'
    }
  | {
      readonly kind: 'EXTERNAL_ASSESSMENT_CANCELED'
      readonly externalAssessmentId: AssessmentId
    }

export type ControlPlaneProviderOperationOutcome =
  | ControlPlaneAssessmentOperationOutcome
  | ControlPlaneCancellationOperationOutcome

export const EXECUTE_CONTROL_PLANE_PROVIDER_OPERATION = Symbol.for(
  'dsh-security-assurance/internal/execute-control-plane-provider-operation/v1',
)

type ControlPlaneProviderOperationExecutor = (
  invocation: SecurityInvocation,
  operation: ControlPlaneProviderOperation,
  options: InvocationOptions,
) => Promise<ControlPlaneProviderOperationOutcome>

export function executeControlPlaneProviderOperation(
  owner: object,
  invocation: SecurityInvocation,
  operation: ControlPlaneAssessmentOperation,
  options?: InvocationOptions,
): Promise<ControlPlaneAssessmentOperationOutcome>
export function executeControlPlaneProviderOperation(
  owner: object,
  invocation: SecurityInvocation,
  operation: ControlPlaneCancellationOperation,
  options?: InvocationOptions,
): Promise<ControlPlaneCancellationOperationOutcome>
export function executeControlPlaneProviderOperation(
  owner: object,
  invocation: SecurityInvocation,
  operation: ControlPlaneProviderOperation,
  options: InvocationOptions = {},
): Promise<ControlPlaneProviderOperationOutcome> {
  const execute = Reflect.get(owner, EXECUTE_CONTROL_PLANE_PROVIDER_OPERATION) as unknown
  if (typeof execute !== 'function') {
    throw new TypeError('control-plane Provider operation is not installed')
  }
  return (execute as ControlPlaneProviderOperationExecutor)(invocation, operation, options)
}
