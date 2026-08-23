import type {
  AssessmentReceiptV1,
  RepositoryId,
  SecurityInvocation,
} from '../contracts.ts'
import { repositoryIdSchema } from '../contracts.ts'
import { z } from 'zod'

export interface ControlPlaneAssessmentIdentity {
  readonly idempotencyKey: string
  readonly repositoryId: RepositoryId
}

export const controlPlaneAssessmentIdentitySchema: z.ZodType<ControlPlaneAssessmentIdentity> = z.strictObject({
  idempotencyKey: z.string().min(1).max(128).regex(/^[a-zA-Z0-9._:-]+$/),
  repositoryId: repositoryIdSchema,
})

/** Package-private lookup used only by the optional Control Plane Adapter. */
export const LOOKUP_CONTROL_PLANE_ASSESSMENT = Symbol(
  'dsh-security-assurance.lookup-control-plane-assessment',
)

interface ControlPlaneAssessmentLookupOwner {
  [LOOKUP_CONTROL_PLANE_ASSESSMENT](
    invocation: SecurityInvocation,
    identity: ControlPlaneAssessmentIdentity,
  ): Promise<AssessmentReceiptV1 | undefined>
}

/** Resolve an existing start identity without admitting or launching an Assessment. */
export function lookupControlPlaneAssessment(
  owner: object,
  invocation: SecurityInvocation,
  identity: ControlPlaneAssessmentIdentity,
): Promise<AssessmentReceiptV1 | undefined> {
  const lookup = Reflect.get(owner, LOOKUP_CONTROL_PLANE_ASSESSMENT) as unknown
  if (typeof lookup !== 'function') throw new TypeError('control-plane Assessment lookup is not installed')
  return (lookup as ControlPlaneAssessmentLookupOwner[typeof LOOKUP_CONTROL_PLANE_ASSESSMENT])(
    invocation,
    identity,
  )
}
