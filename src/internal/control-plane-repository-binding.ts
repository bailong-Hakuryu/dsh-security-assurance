import type { RepositoryId, SecurityInvocation } from '../contracts.ts'
import { repositoryIdSchema } from '../contracts.ts'

/** Process-local matcher implemented only by a Kernel-issued Control Plane context. */
export interface ControlPlaneRepositoryBindingMatcher {
  readonly matchesCanonicalRepository: (candidateCanonicalRoot: string) => boolean
}

export const VERIFY_CONTROL_PLANE_REPOSITORY_BINDING = Symbol(
  'dsh-security-assurance.verify-control-plane-repository-binding',
)

interface ControlPlaneRepositoryBindingOwner {
  [VERIFY_CONTROL_PLANE_REPOSITORY_BINDING](
    invocation: SecurityInvocation,
    repositoryId: RepositoryId,
    matcher: ControlPlaneRepositoryBindingMatcher,
  ): Promise<boolean>
}

/** Compare inside the Security Service so its private canonical root is never returned to the Adapter. */
export function verifyControlPlaneRepositoryBinding(
  owner: object,
  invocation: SecurityInvocation,
  repositoryId: RepositoryId,
  matcher: ControlPlaneRepositoryBindingMatcher,
): Promise<boolean> {
  if (!repositoryIdSchema.safeParse(repositoryId).success) {
    throw new TypeError('control-plane Repository binding identity is invalid')
  }
  if (typeof matcher.matchesCanonicalRepository !== 'function') {
    throw new TypeError('control-plane Repository binding matcher is invalid')
  }
  const verify = Reflect.get(owner, VERIFY_CONTROL_PLANE_REPOSITORY_BINDING) as unknown
  if (typeof verify !== 'function') {
    throw new TypeError('control-plane Repository binding verifier is not installed')
  }
  return (verify as ControlPlaneRepositoryBindingOwner[typeof VERIFY_CONTROL_PLANE_REPOSITORY_BINDING])(
    invocation,
    repositoryId,
    matcher,
  )
}
