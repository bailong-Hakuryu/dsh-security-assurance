import { describe, expect, it } from 'vitest'
import {
  cancelAssessmentRequestSchema,
  disableRepositoryRequestSchema,
  mutationEnvelopeV1Schema,
  recordRiskDecisionRequestSchema,
  registerRepositoryRequestSchema,
  requestExportRequestSchema,
  resumeAssessmentRequestSchema,
  startAssessmentRequestSchema,
  updateRepositoryRequestSchema,
} from '../src/index.ts'

const repositoryId = 'repo-00000000-0000-0000-0000-000000000273'
const assessmentId = 'asm-00000000-0000-0000-0000-000000000273'
const envelope = { schemaVersion: 1, contractVersion: 1 as const, idempotencyKey: 'adr-0273-command' }
const bindings = {
  policyId: 'security/default-policy',
  assessmentProfileId: 'security/default-profile',
  evidenceProtectionId: 'security/local-protection',
  dataEgressPolicyId: 'security/local-only',
  platform: 'win32',
  deliveryDestinationIds: ['delivery/local-audit'],
}
const reason = { code: 'OPERATOR_ACTION', summary: 'Perform the exact revision-bound command.' }

const mutations = [
  [registerRepositoryRequestSchema, {
    ...envelope,
    root: 'D:/workspace',
    displayName: 'ADR 0273 Repository',
    bindings,
  }],
  [updateRepositoryRequestSchema, {
    ...envelope,
    repositoryId,
    expectedRepositoryRevision: 3,
    displayName: 'Updated Repository',
  }],
  [disableRepositoryRequestSchema, {
    ...envelope,
    repositoryId,
    expectedRepositoryRevision: 3,
  }],
  [startAssessmentRequestSchema, {
    ...envelope,
    repositoryId,
    subject: { kind: 'workspace_snapshot' },
    assessmentMode: 'REPOSITORY',
    assessmentProfileId: 'security/default-profile',
    target: { kind: 'repository' },
    requestedStrongerControlIds: [],
  }],
  [resumeAssessmentRequestSchema, {
    ...envelope,
    assessmentId,
    expectedAssessmentRevision: 7,
    reason,
  }],
  [cancelAssessmentRequestSchema, {
    ...envelope,
    assessmentId,
    expectedAssessmentRevision: 7,
    reason,
  }],
  [recordRiskDecisionRequestSchema, {
    ...envelope,
    assessmentId,
    expectedAssessmentRevision: 7,
    finding: { recordId: `finding-${'3'.repeat(64)}`, recordRevision: 1 },
    decision: 'DENY',
    rationale: 'The finding remains blocking and cannot be accepted safely.',
    compensatingControls: [],
    expiresAt: null,
  }],
  [requestExportRequestSchema, {
    ...envelope,
    assessmentId,
    expectedAssessmentRevision: 7,
    exportProfileId: 'security/export/internal-json-v1',
    deliveryDestinationId: 'delivery/local-audit',
  }],
] as const

describe('ADR 0273 shared versioned idempotent CAS envelope', () => {
  it('defines one strict public Mutation Envelope without caller metadata', () => {
    const value = { contractVersion: 1, idempotencyKey: 'adr-0273-envelope' }
    expect(mutationEnvelopeV1Schema.safeParse(value).success).toBe(true)
    expect(mutationEnvelopeV1Schema.safeParse({ ...value, contractVersion: 2 }).success).toBe(false)
    expect(mutationEnvelopeV1Schema.safeParse({ ...value, authority: 'caller-supplied' }).success).toBe(false)
  })

  it('requires contract version and idempotency on every public mutation', () => {
    for (const [schema, request] of mutations) {
      expect(schema.safeParse(request).success).toBe(true)
      const { contractVersion: _omitted, ...withoutContractVersion } = request
      expect(schema.safeParse(withoutContractVersion).success).toBe(false)
      expect(schema.safeParse({ ...request, contractVersion: 2 }).success).toBe(false)
      expect(schema.safeParse({ ...request, callerAuthority: 'admin' }).success).toBe(false)
    }
  })

  it('requires exact revisions for mutations of existing Aggregates or Registry entries', () => {
    for (const [schema, request] of mutations.slice(1).filter(([, request]) => (
      'expectedRepositoryRevision' in request || 'expectedAssessmentRevision' in request
    ))) {
      const revisionField = 'expectedRepositoryRevision' in request
        ? 'expectedRepositoryRevision'
        : 'expectedAssessmentRevision'
      expect(schema.safeParse({ ...request, [revisionField]: undefined }).success).toBe(false)
      expect(schema.safeParse({ ...request, [revisionField]: 0 }).success).toBe(false)
    }
  })
})
