import type { SecurityAssuranceService, SecurityInvocation } from '../../src/index.ts'
import { resolveTrustedInvocation } from '../../src/internal/authority.ts'

/** A production-shaped trusted Host adapter used only to compose public tests. */
export function referenceHostInvocation(service: SecurityAssuranceService): SecurityInvocation {
  return resolveTrustedInvocation(service, {
    kind: 'host-operator',
    principalId: 'reference-host-operator',
    permissions: [
      'health:read',
      'repository:read',
      'repository:admin',
      'assessment:start',
      'assessment:read',
      'assessment:resume',
      'assessment:cancel',
    ],
  })
}
