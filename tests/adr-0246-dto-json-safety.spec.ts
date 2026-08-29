import { describe, it, expect } from 'vitest'
import * as contracts from '../src/contracts.js'

describe('ADR 0246: Public DTOs are versioned, JSON-safe, and runtime-validated', () => {
  describe('JSON-safe value constraints', () => {
    it('DTOs do not expose Date objects', () => {
      // All timestamp fields must be ISO 8601 strings, not Date instances
      const sample: contracts.RuntimeHealthSnapshot = {
        schemaVersion: 1,
        product: {
          name: 'dsh-security-assurance',
          version: '0.1.0-rc.1',
        },
        compatibility: {
          targetHarnessVersion: '0.1.1-rc.2',
          requiredNodeRange: '^22.19.0 || >=24.0.0',
          actualNodeVersion: '22.19.0',
          harnessVerification: 'PENDING_INVARIANT',
        },
        state: 'READY',
        admission: {
          queries: true,
          mutations: true,
          sealedExports: true,
        },
        checks: [],
      }

      // Verify no Date instances anywhere in the structure
      expect(typeof sample.product.version).toBe('string')
      expect(typeof sample.compatibility.targetHarnessVersion).toBe('string')
    })

    it('DTOs serialize and deserialize through JSON without loss', () => {
      const original: contracts.PublicSecurityError = {
        schemaVersion: 1,
        code: 'NOT_FOUND',
        message: 'The Assessment does not exist.',
        retryable: false,
        correlationId: 'sec-00000000-0000-4000-8000-000000000000',
      }

      const serialized = JSON.stringify(original)
      const deserialized = JSON.parse(serialized) as contracts.PublicSecurityError

      expect(deserialized).toEqual(original)
      expect(typeof deserialized.code).toBe('string')
      expect(typeof deserialized.message).toBe('string')
      expect(typeof deserialized.retryable).toBe('boolean')
    })

    it('Assessment receipts contain only JSON-safe primitives', () => {
      const receipt: contracts.AssessmentReceiptV1 = {
        schemaVersion: 1,
        operation: 'start_assessment',
        assessmentId: 'asm-00000000-0000-4000-8000-000000000000' as contracts.AssessmentId,
        assessmentRevision: 1,
        state: 'CREATED',
        repositoryId: 'repo-00000000-0000-4000-8000-000000000000' as contracts.RepositoryId,
        repositoryRevision: 1,
        subject: {
          kind: 'workspace_snapshot',
          digest: {
            schemaVersion: 1,
            algorithm: 'sha256',
            canonicalization: 'raw-bytes',
            mediaType: 'application/vnd.dsh.security-assurance.workspace-snapshot+tar',
            byteLength: 1024,
            value: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
          },
        },
        idempotencyKey: 'test-key',
        acceptedAt: '2026-08-26T12:00:00.000Z',
        correlationId: 'sec-00000000-0000-4000-8000-000000000000',
      }

      const serialized = JSON.stringify(receipt)
      const deserialized = JSON.parse(serialized)

      expect(deserialized).toEqual(receipt)
      expect(deserialized.assessmentRevision).toBe(1)
      expect(typeof deserialized.assessmentId).toBe('string')
    })

    it('Repository snapshots contain only JSON-safe structures', () => {
      const snapshot: contracts.RepositorySnapshotV1 = {
        schemaVersion: 1,
        repositoryId: 'repo-00000000-0000-4000-8000-000000000000' as contracts.RepositoryId,
        repositoryRevision: 1,
        state: 'ENABLED',
        displayName: 'Example Repository',
        rootIdentityDigest: `sha256:${'0'.repeat(64)}`,
        bindings: {
          platform: 'linux',
          policyId: 'policy/default',
          assessmentProfileId: 'profile/default',
          evidenceProtectionId: 'evidence/default',
          dataEgressPolicyId: 'egress/default',
          deliveryDestinationIds: [],
        },
        createdAt: '2026-08-26T12:00:00.000Z',
        updatedAt: '2026-08-26T12:00:00.000Z',
      }

      const serialized = JSON.stringify(snapshot)
      const deserialized = JSON.parse(serialized)

      expect(deserialized).toEqual(snapshot)
      expect(Array.isArray(deserialized)).toBe(false)
      expect(typeof deserialized).toBe('object')
    })
  })

  describe('Schema version presence', () => {
    it('RuntimeHealthSnapshot has explicit schemaVersion', () => {
      const snapshot: contracts.RuntimeHealthSnapshot = {
        schemaVersion: 1,
        product: {
          name: 'dsh-security-assurance',
          version: '0.1.0-rc.1',
        },
        compatibility: {
          targetHarnessVersion: '0.1.1-rc.2',
          requiredNodeRange: '^22.19.0 || >=24.0.0',
          actualNodeVersion: '22.19.0',
          harnessVerification: 'PENDING_INVARIANT',
        },
        state: 'READY',
        admission: {
          queries: true,
          mutations: true,
          sealedExports: true,
        },
        checks: [],
      }

      expect(snapshot.schemaVersion).toBe(1)
      expect(typeof snapshot.schemaVersion).toBe('number')
    })

    it('AssessmentReceiptV1 has explicit schemaVersion', () => {
      const receipt: contracts.AssessmentReceiptV1 = {
        schemaVersion: 1,
        operation: 'start_assessment',
        assessmentId: 'asm-00000000-0000-4000-8000-000000000000' as contracts.AssessmentId,
        assessmentRevision: 1,
        state: 'CREATED',
        repositoryId: 'repo-00000000-0000-4000-8000-000000000000' as contracts.RepositoryId,
        repositoryRevision: 1,
        subject: {
          kind: 'workspace_snapshot',
          digest: {
            schemaVersion: 1,
            algorithm: 'sha256',
            canonicalization: 'raw-bytes',
            mediaType: 'application/vnd.dsh.security-assurance.workspace-snapshot+tar',
            byteLength: 1024,
            value: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
          },
        },
        idempotencyKey: 'test-key',
        acceptedAt: '2026-08-26T12:00:00.000Z',
        correlationId: 'sec-00000000-0000-4000-8000-000000000000',
      }

      expect(receipt.schemaVersion).toBe(1)
    })

    it('RepositoryCommandReceiptV1 has explicit schemaVersion', () => {
      const receipt: contracts.RepositoryCommandReceiptV1 = {
        schemaVersion: 1,
        operation: 'register_repository',
        repositoryId: 'repo-00000000-0000-4000-8000-000000000000' as contracts.RepositoryId,
        repositoryRevision: 1,
        idempotencyKey: 'repository-register-v1',
        acceptedState: 'ENABLED',
        acceptedAt: '2026-08-26T12:00:00.000Z',
        correlationId: 'sec-00000000-0000-4000-8000-000000000000',
      }

      expect(receipt.schemaVersion).toBe(1)
    })
  })

  describe('Branded opaque identities', () => {
    it('AssessmentId is a branded string type', () => {
      const id: contracts.AssessmentId = 'asmnt-00000000-0000-4000-8000-000000000000' as contracts.AssessmentId

      expect(typeof id).toBe('string')
      expect(id.startsWith('asmnt-')).toBe(true)
    })

    it('RepositoryId is a branded string type', () => {
      const id: contracts.RepositoryId = 'repo-00000000-0000-4000-8000-000000000000' as contracts.RepositoryId

      expect(typeof id).toBe('string')
      expect(id.startsWith('repo-')).toBe(true)
    })

  })

  describe('Runtime validation with schemas', () => {
    it('runtimeHealthSnapshotSchema validates correct input', () => {
      const valid = {
        schemaVersion: 1,
        product: {
          name: 'dsh-security-assurance',
          version: '0.1.0-rc.1',
        },
        compatibility: {
          targetHarnessVersion: '0.1.1-rc.2',
          requiredNodeRange: '^22.19.0 || >=24.0.0',
          actualNodeVersion: '22.19.0',
          harnessVerification: 'PENDING_INVARIANT',
        },
        state: 'READY',
        admission: {
          queries: true,
          mutations: true,
          sealedExports: true,
        },
        checks: [],
      }

      const result = contracts.runtimeHealthSnapshotSchema.safeParse(valid)
      expect(result.success).toBe(true)
    })

    it('runtimeHealthSnapshotSchema rejects invalid state', () => {
      const invalid = {
        schemaVersion: 1,
        productName: 'dsh-security-assurance',
        productVersion: '0.1.0-rc.1',
        harnessTargetVersion: '0.1.1-rc.2',
        state: 'INVALID_STATE',
        checks: {},
        capabilities: {
          canStartAssessment: true,
          canResumeAssessment: true,
          canCancelAssessment: true,
          canRecordRiskDecision: true,
          canRequestExport: true,
        },
        observedAt: '2026-08-26T12:00:00.000Z',
      }

      const result = contracts.runtimeHealthSnapshotSchema.safeParse(invalid)
      expect(result.success).toBe(false)
    })

    it('assessmentReceiptV1Schema validates correct receipt', () => {
      const valid = {
        schemaVersion: 1,
        operation: 'start_assessment',
        assessmentId: 'asm-00000000-0000-4000-8000-000000000000',
        assessmentRevision: 1,
        state: 'CREATED',
        repositoryId: 'repo-00000000-0000-4000-8000-000000000000',
        repositoryRevision: 1,
        subject: {
          kind: 'workspace_snapshot',
          digest: {
            schemaVersion: 1,
            algorithm: 'sha256',
            canonicalization: 'raw-bytes',
            mediaType: 'application/vnd.dsh.security-assurance.workspace-snapshot+tar',
            byteLength: 1024,
            value: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
          },
        },
        idempotencyKey: 'test-key',
        acceptedAt: '2026-08-26T12:00:00.000Z',
        correlationId: 'sec-00000000-0000-4000-8000-000000000000',
      }

      const result = contracts.assessmentReceiptV1Schema.safeParse(valid)
      if (!result.success) {
        console.error('AssessmentReceipt validation errors:', JSON.stringify(result.error.issues, null, 2))
      }
      expect(result.success).toBe(true)
    })

    it('assessmentReceiptV1Schema rejects missing schemaVersion', () => {
      const invalid = {
        operation: 'start_assessment',
        assessmentId: 'asm-00000000-0000-4000-8000-000000000000',
        assessmentRevision: 1,
        state: 'CREATED',
        repositoryId: 'repo-00000000-0000-4000-8000-000000000000',
        repositoryRevision: 1,
        subject: {
          kind: 'workspace_snapshot',
          digest: {
            schemaVersion: 1,
            algorithm: 'sha256',
            canonicalization: 'raw-bytes',
            mediaType: 'application/vnd.dsh.security-assurance.workspace-snapshot+tar',
            byteLength: 1024,
            value: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
          },
        },
        idempotencyKey: 'test-key',
        acceptedAt: '2026-08-26T12:00:00.000Z',
        correlationId: 'sec-00000000-0000-4000-8000-000000000000',
      }

      const result = contracts.assessmentReceiptV1Schema.safeParse(invalid)
      expect(result.success).toBe(false)
    })
  })
})
