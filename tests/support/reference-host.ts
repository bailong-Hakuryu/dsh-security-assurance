import type { SecurityAssuranceService, SecurityInvocation } from '../../src/index.ts'
import {
  resolveTrustedInvocation,
  type SecurityPermission,
} from '../../src/internal/authority.ts'

const fullReferenceHostPermissions = [
  'health:read',
  'repository:read',
  'repository:admin',
  'assessment:start',
  'assessment:read',
  'assessment:resume',
  'assessment:cancel',
  'evidence:disclose:validation-review',
  'assurance-submission:read',
  'export:request',
  'export:read',
  'risk:decide',
  'risk:break-glass',
] as const satisfies readonly SecurityPermission[]

export function referenceHostInvocationWithPermissions(
  service: SecurityAssuranceService,
  permissions: readonly SecurityPermission[],
  principalId = 'reference-host-operator',
): SecurityInvocation {
  return resolveTrustedInvocation(service, {
    kind: 'host-operator',
    principalId,
    permissions,
  })
}

/** A production-shaped trusted Host adapter used only to compose public tests. */
export function referenceHostInvocation(
  service: SecurityAssuranceService,
  principalId = 'reference-host-operator',
): SecurityInvocation {
  return referenceHostInvocationWithPermissions(service, fullReferenceHostPermissions, principalId)
}
