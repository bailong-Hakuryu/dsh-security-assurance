import { describe, expect, it } from 'vitest'
import type { RepositorySnapshotV1, StartAssessmentSelectionV1 } from '../src/index.ts'
import { buildSecurityCatalog } from '../src/internal/security-catalog.ts'

const repository: RepositorySnapshotV1 = {
  schemaVersion: 1,
  repositoryId: 'repo-00000000-0000-0000-0000-000000000259',
  repositoryRevision: 7,
  state: 'ENABLED',
  displayName: 'Catalog compliance fixture',
  rootIdentityDigest: `sha256:${'a'.repeat(64)}`,
  bindings: {
    policyId: 'security/node-package-lifecycle',
    assessmentProfileId: 'security/standard',
    evidenceProtectionId: 'evidence/local-protected',
    dataEgressPolicyId: 'egress/deny-by-default',
    platform: 'linux',
    deliveryDestinationIds: ['delivery/local-audit'],
  },
  createdAt: '2026-08-28T00:00:00.000Z',
  updatedAt: '2026-08-28T00:00:00.000Z',
}

const selection: StartAssessmentSelectionV1 = {
  schemaVersion: 1,
  repositoryId: repository.repositoryId,
  subject: { kind: 'workspace_snapshot' },
  assessmentMode: 'REPOSITORY',
  assessmentProfileId: 'security/standard',
  target: { kind: 'repository' },
  requestedStrongerControlIds: [],
}

describe('ADR 0259 Security Catalog capability boundary', () => {
  it('reports only qualified ecosystem and platform claims with bounded dependency summaries', () => {
    const catalog = buildSecurityCatalog({
      repository,
      proposedStart: selection,
      portfolioForMode: () => [],
    })

    expect(catalog).toMatchObject({
      schemaVersion: 1,
      supportedEcosystemIds: ['node-package-manifest'],
      supportedPlatforms: ['win32', 'linux', 'darwin'],
      supportMatrixReferences: ['dsh-security-assurance/support-matrix/v0.1-development'],
      strongerControls: [
        { controlId: 'security/risk-decision-window-v1', requiresControlIds: [] },
        {
          controlId: 'security/critical-break-glass-v1',
          requiresControlIds: ['security/risk-decision-window-v1'],
        },
      ],
      startPreflight: {
        providerComposition: [{
          providerId: 'dsh-security-assurance',
          analyzerId: 'dsh/builtin-node-package-lifecycle',
          eligibility: 'ELIGIBLE',
          supportedEcosystemIds: ['node-package-manifest'],
          supportedPlatforms: ['win32', 'linux', 'darwin'],
        }],
      },
    })
    expect(JSON.stringify(catalog)).not.toMatch(
      /canonicalRoot|factory|credential|executionBackendId|qualificationDigest|probeDiagnostic/iu,
    )
    expect(Object.isFrozen(catalog)).toBe(true)
    expect(Object.isFrozen(catalog.startPreflight?.providerComposition[0])).toBe(true)
  })
})
