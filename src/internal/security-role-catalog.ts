import type {
  SecurityCatalogRoleV1,
  SecurityRoleIdV1,
} from '../contracts.ts'
import { structuredDigest } from './canonical.ts'
import { deepFreeze } from './freeze.ts'

const ROLE_CATALOG_ENTRY_MEDIA_TYPE = 'application/vnd.dsh.security.role-catalog-entry+json'
const ROLE_CATALOG_ENTRY_VERSION = '1.0.0'
const ROLE_IDS: readonly SecurityRoleIdV1[] = [
  'threat-modeler',
  'discovery-analyst',
  'validation-analyst',
  'attack-path-analyst',
  'challenge-analyst',
]

function catalogEntry(roleId: SecurityRoleIdV1): SecurityCatalogRoleV1 {
  const identity = {
    schemaVersion: 1 as const,
    roleId,
    catalogEntryVersion: ROLE_CATALOG_ENTRY_VERSION,
    authority: 'PROPOSAL_ONLY' as const,
  }
  return {
    roleId,
    catalogEntryVersion: ROLE_CATALOG_ENTRY_VERSION,
    catalogEntryDigest: structuredDigest(ROLE_CATALOG_ENTRY_MEDIA_TYPE, identity),
    executionSupport: 'UNSUPPORTED',
    authority: 'PROPOSAL_ONLY',
  }
}

/** Package-owned stable Role identities, separate from effective execution qualification. */
export const SECURITY_ROLE_CATALOG: readonly SecurityCatalogRoleV1[] = deepFreeze(
  ROLE_IDS.map(catalogEntry),
)
