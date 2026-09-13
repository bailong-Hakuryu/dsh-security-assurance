import { afterEach, describe, expect, it } from 'vitest'
import { mkdtemp, readdir } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { DatabaseSync } from 'node:sqlite'
import { createRoleContextGrantV1 } from '../src/role-context-grant.ts'
import { binaryDigest, structuredDigest } from '../src/internal/canonical.ts'
import type {
  SourceSliceEgressInvocationReceiptCoreV1,
  SourceSliceEgressInvocationReceiptV1,
} from '../src/internal/source-slice-egress-invocation.ts'
import {
  SOURCE_SLICE_EGRESS_ATTEMPT_FENCE_MEDIA_TYPE,
  SOURCE_SLICE_EGRESS_BROKER_REQUEST_MEDIA_TYPE,
  SOURCE_SLICE_EGRESS_INVOCATION_RECEIPT_MEDIA_TYPE,
} from '../src/internal/source-slice-egress-invocation.ts'
import {
  SOURCE_SLICE_EGRESS_AUTHORIZATION_MEDIA_TYPE,
  SOURCE_SLICE_EGRESS_BROKER_IMPLEMENTATION_MEDIA_TYPE,
} from '../src/internal/source-slice-egress-authorization.ts'
import {
  createModelInvocationBudgetReservationV1,
  MODEL_INVOCATION_RECORD_MEDIA_TYPE,
  parseModelInvocationRecordV1,
  settleSourceSliceModelInvocationV1,
} from '../src/internal/model-invocation-settlement.ts'
import type {
  ModelInvocationBudgetReservationCoreV1,
} from '../src/internal/model-invocation-settlement.ts'
import {
  MODEL_INVOCATION_EVIDENCE_LINK_MEDIA_TYPE,
  MODEL_INVOCATION_EVIDENCE_SCHEMA_ID,
  MODEL_INVOCATION_EVIDENCE_PUBLICATION_RECEIPT_MEDIA_TYPE,
  publishModelInvocationEvidenceV1,
  readPublishedModelInvocationEvidenceV1,
} from '../src/internal/model-invocation-evidence.ts'
import { prepareAssessmentContract } from '../src/internal/deterministic-kernel.ts'
import { openSecurityPersistence } from '../src/internal/persistence.ts'
import { removeTemporaryRoots } from './support/remove-temporary-root.ts'

const temporaryRoots: string[] = []

afterEach(async () => {
  await removeTemporaryRoots(temporaryRoots)
})

const attemptId = 'role-attempt-00000000-0000-0000-0000-000000000178'
const invocationId = 'egress-invocation-00000000-0000-0000-0000-000000000178'
const attemptFenceDigest = structuredDigest(
  SOURCE_SLICE_EGRESS_ATTEMPT_FENCE_MEDIA_TYPE,
  {
    attemptId,
    generation: 1,
    fencingToken: 'fence/role-attempt-0178/generation-1',
  },
)

function contextGrant() {
  return createRoleContextGrantV1({
    schemaVersion: 1,
    assessmentId: 'asm-00000000-0000-0000-0000-000000000178',
    roleAttemptId: attemptId,
    roleDefinition: {
      roleId: 'discovery-analyst',
      roleVersion: '1.0.0',
      definitionDigest: structuredDigest(
        'application/vnd.dsh.security.role-definition+json',
        { role: 'discovery-analyst', version: '1.0.0' },
      ),
    },
    purpose: {
      purposeId: 'security/deep-discovery',
      assessmentMode: 'TARGETED',
      assessmentProfileId: 'security/deep',
      targetDigest: structuredDigest(
        'application/vnd.dsh.security.target+json',
        { target: 'src/provider.ts' },
      ),
      coverageObligationIds: ['security/source-review'],
      constraintIds: ['security/read-only'],
      peerContributionVisibility: 'NONE',
    },
    subject: {
      digest: structuredDigest(
        'application/vnd.dsh.security.subject-manifest+json',
        { commit: 'a'.repeat(40) },
      ),
      inventory: [{
        artifactId: 'inventory-model-invocation-0178',
        schemaId: 'dsh/security-subject-inventory',
        digest: structuredDigest(
          'application/vnd.dsh.security.subject-inventory+json',
          { inventory: 'model-invocation-0178' },
        ),
        disclosureCategoryId: 'security/subject-inventory',
      }],
      sourceSlices: [],
    },
    evidenceProjections: [],
    disclosure: {
      dataEgressPolicyId: 'egress/host-qualified-v1',
      destinationId: 'provider/reference',
      categoryIds: ['security/subject-inventory'],
    },
    budget: {
      contextBytes: { limit: 65_536, granted: 0 },
      tokens: { limit: 8_192, granted: 0 },
    },
  })
}

function completedReceipt(): SourceSliceEgressInvocationReceiptV1 {
  const core = {
    schemaVersion: 1,
    invocationId,
    attemptId,
    attemptGeneration: 1,
    attemptFenceDigest,
    egressAuthorizationDigest: structuredDigest(
      SOURCE_SLICE_EGRESS_AUTHORIZATION_MEDIA_TYPE,
      { authorization: 'fixture-0178' },
    ),
    brokerRequestDigest: structuredDigest(
      SOURCE_SLICE_EGRESS_BROKER_REQUEST_MEDIA_TYPE,
      { request: 'fixture-0178' },
    ),
    brokerIdentity: {
      brokerId: 'broker/reference',
      brokerVersion: '1.0.0',
      implementationDigest: structuredDigest(
        SOURCE_SLICE_EGRESS_BROKER_IMPLEMENTATION_MEDIA_TYPE,
        { implementation: 'fixture-0178' },
      ),
    },
    providerId: 'provider/reference',
    destinationId: 'provider/reference',
    dataEgressPolicyId: 'egress/host-qualified-v1',
    auditPolicyId: 'audit/model-invocation-v1',
    requestBytes: 256,
    tokenLimit: 128,
    startedAt: '2026-09-13T00:00:01.000Z',
    completedAt: '2026-09-13T00:00:02.000Z',
    status: 'COMPLETED',
    failureCode: null,
    providerRequestId: 'provider-request/fixture-0178',
    backendId: 'backend/reference',
    deploymentId: 'deployment/reference',
    modelId: 'model/reference',
    responseDigest: binaryDigest('text/plain', Buffer.from('protected response', 'utf8')),
    finishReason: 'STOP',
    usage: {
      requestCount: 1,
      requestBytes: 256,
      inputTokens: 32,
      outputTokens: 8,
    },
    diagnosticCodes: ['CACHE_MISS'],
  } satisfies SourceSliceEgressInvocationReceiptCoreV1
  return {
    ...core,
    receiptDigest: structuredDigest(SOURCE_SLICE_EGRESS_INVOCATION_RECEIPT_MEDIA_TYPE, core),
  }
}

function lineage() {
  return {
    provider: { movingProvider: false },
    prompt: {
      promptId: 'security/deep-discovery',
      promptVersion: '1.0.0',
      promptDigest: structuredDigest(
        'application/vnd.dsh.security.role-prompt+json',
        { prompt: 'protected' },
      ),
      toolSchemaDigest: structuredDigest(
        'application/schema+json',
        { tool: 'source-slice' },
      ),
    },
    parameters: {
      maxOutputTokens: 64,
      temperature: null,
      topP: null,
      randomnessStrategyId: 'deterministic/provider-default-v1',
    },
  } as const
}

function budgetReservation(
  grant: ReturnType<typeof contextGrant>,
  overrides: Partial<ModelInvocationBudgetReservationCoreV1> = {},
) {
  const receipt = completedReceipt()
  return createModelInvocationBudgetReservationV1({
    schemaVersion: 1,
    reservationId: 'reservation/model-invocation-0178',
    invocationId,
    attemptId,
    attemptGeneration: 1,
    attemptFenceDigest,
    contextGrantDigest: grant.grantDigest,
    egressAuthorizationDigest: receipt.egressAuthorizationDigest,
    brokerRequestDigest: receipt.brokerRequestDigest,
    requestLimit: 1,
    tokenLimit: 128,
    reservedAt: '2026-09-13T00:00:00.000Z',
    deadlineAt: '2026-09-13T00:01:00.000Z',
    ...overrides,
  })
}

function settledInvocationFixture() {
  const grant = contextGrant()
  const receipt = completedReceipt()
  const reservation = budgetReservation(grant)
  const record = settleSourceSliceModelInvocationV1({
    contextGrant: grant,
    reservation,
    receipt,
    lineage: lineage(),
  })
  const expected = {
    invocationId,
    attemptId,
    attemptGeneration: 1,
    attemptFenceDigest,
    contextGrantDigest: grant.grantDigest,
    reservationDigest: reservation.reservationDigest,
    receiptDigest: receipt.receiptDigest,
  }
  return { grant, record, expected }
}

async function runningAssessmentPersistence(
  securityRoot: string,
  grant: ReturnType<typeof contextGrant>,
) {
  const persistence = await openSecurityPersistence({
    databasePath: join(securityRoot, 'security-assurance.sqlite'),
    now: () => '2026-09-13T00:00:03.000Z',
    nextRepositoryId: () => 'repo-00000000-0000-0000-0000-000000000178',
    nextAssessmentId: () => grant.assessmentId,
    nextCorrelationId: () => 'sec-00000000-0000-0000-0000-000000000178',
  })
  const bindings = {
    policyId: 'security/default',
    assessmentProfileId: 'security/standard',
    evidenceProtectionId: 'evidence/local-protected',
    dataEgressPolicyId: 'egress/deny-by-default',
    platform: process.platform as 'win32' | 'linux' | 'darwin',
    deliveryDestinationIds: [],
  }
  const registered = persistence.registerRepository({
    principalId: 'operator:model-invocation-fixture',
    authorityKind: 'host-operator',
    idempotencyKey: 'model-invocation-repository',
    canonicalRequest: { operation: 'register-model-invocation-fixture' },
    canonicalRoot: 'D:/model-invocation-fixture',
    displayName: 'Model Invocation fixture',
    bindings,
  })
  const repository = persistence.getRepository(registered.repositoryId)
  if (repository === undefined) throw new Error('repository fixture was not persisted')
  const target = { kind: 'repository' as const }
  const created = persistence.createAssessment({
    principalId: 'operator:model-invocation-fixture',
    authorityKind: 'host-operator',
    idempotencyKey: 'model-invocation-assessment',
    repositoryId: repository.repositoryId,
    expectedRepositoryRevision: repository.repositoryRevision,
    canonicalRequest: { operation: 'start-model-invocation-fixture' },
    subject: { kind: 'workspace_snapshot' },
    subjectDigest: grant.subject.digest,
    subjectStats: { files: 0, bytes: 0, symbolicLinks: 0, submodules: 0 },
    preparedContract: prepareAssessmentContract({
      policyId: bindings.policyId,
      assessmentMode: 'REPOSITORY',
      assessmentProfileId: bindings.assessmentProfileId,
      target,
      targetDigest: structuredDigest(
        'application/vnd.dsh.security.target-selector+json',
        target,
      ),
      requestedStrongerControlIds: [],
      analyzerPortfolio: [],
    }),
  })
  const running = persistence.beginAssessment(created.assessmentId)
  if (running === undefined) throw new Error('assessment fixture did not begin')
  return { persistence, running }
}

function installReleasedSchemaV1(databasePath: string): void {
  const database = new DatabaseSync(databasePath)
  try {
    database.exec(`
      CREATE TABLE repositories (
        repository_id TEXT PRIMARY KEY, canonical_root TEXT NOT NULL UNIQUE,
        current_revision INTEGER NOT NULL, snapshot_json TEXT NOT NULL,
        created_at TEXT NOT NULL, updated_at TEXT NOT NULL
      ) STRICT;
      CREATE TABLE repository_revisions (
        repository_id TEXT NOT NULL REFERENCES repositories(repository_id),
        repository_revision INTEGER NOT NULL, snapshot_json TEXT NOT NULL,
        committed_at TEXT NOT NULL,
        PRIMARY KEY (repository_id, repository_revision)
      ) STRICT;
      CREATE TABLE idempotency_records (
        principal_id TEXT NOT NULL, authority_kind TEXT NOT NULL,
        operation TEXT NOT NULL, target_key TEXT NOT NULL,
        idempotency_key TEXT NOT NULL, request_digest TEXT NOT NULL,
        receipt_json TEXT NOT NULL, committed_at TEXT NOT NULL,
        PRIMARY KEY (
          principal_id, authority_kind, operation, target_key, idempotency_key
        )
      ) STRICT;
      CREATE TABLE assessments (
        assessment_id TEXT PRIMARY KEY,
        repository_id TEXT NOT NULL REFERENCES repositories(repository_id),
        repository_revision INTEGER NOT NULL, current_revision INTEGER NOT NULL,
        state TEXT NOT NULL, subject_digest TEXT NOT NULL,
        snapshot_json TEXT NOT NULL, created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
      ) STRICT;
      CREATE TABLE assessment_revisions (
        assessment_id TEXT NOT NULL REFERENCES assessments(assessment_id),
        assessment_revision INTEGER NOT NULL, event_kind TEXT NOT NULL,
        snapshot_json TEXT NOT NULL, committed_at TEXT NOT NULL,
        PRIMARY KEY (assessment_id, assessment_revision)
      ) STRICT;
      PRAGMA application_id = 0x44534853;
      PRAGMA user_version = 1;
    `)
  } finally {
    database.close()
  }
}

describe('ADR 0178 Model Invocation settlement', () => {
  it('records complete protected lineage and settles actual token usage against the exact Attempt reservation', () => {
    const grant = contextGrant()
    const receipt = completedReceipt()
    const reservation = budgetReservation(grant)

    const record = settleSourceSliceModelInvocationV1({
      contextGrant: grant,
      reservation,
      receipt,
      lineage: lineage(),
    })

    expect(record).toMatchObject({
      schemaVersion: 1,
      invocationId,
      assessmentId: grant.assessmentId,
      parentAttempt: {
        attemptId,
        generation: 1,
        fenceDigest: attemptFenceDigest,
      },
      roleDefinition: grant.roleDefinition,
      provider: {
        providerId: 'provider/reference',
        backendId: 'backend/reference',
        deploymentId: 'deployment/reference',
        modelId: 'model/reference',
        movingProvider: false,
      },
      budgetSettlement: {
        reservationId: reservation.reservationId,
        reservationDigest: reservation.reservationDigest,
        requestLimit: 1,
        requestsUsed: 1,
        requestsReleased: 0,
        tokenLimit: 128,
        inputTokens: 32,
        outputTokens: 8,
        tokensUsed: 40,
        tokensReleased: 88,
      },
      receiptDigest: receipt.receiptDigest,
    })
    expect(record.recordDigest.mediaType).toBe(MODEL_INVOCATION_RECORD_MEDIA_TYPE)
    expect(record.contextGrantDigest).toEqual(grant.grantDigest)
    expect(record.prompt).toEqual(lineage().prompt)
    expect(record.parameters).toEqual(lineage().parameters)
    expect(Object.isFrozen(record)).toBe(true)
    expect(JSON.stringify(record)).not.toContain('protected')
    expect(parseModelInvocationRecordV1(record, {
      invocationId,
      attemptId,
      attemptGeneration: 1,
      attemptFenceDigest,
      contextGrantDigest: grant.grantDigest,
      reservationDigest: reservation.reservationDigest,
      receiptDigest: receipt.receiptDigest,
    })).toEqual(record)
  })

  it('refuses to settle a receipt completed at the reservation deadline', () => {
    const grant = contextGrant()
    const reservation = budgetReservation(grant, {
      deadlineAt: '2026-09-13T00:00:02.000Z',
    })
    const baseReceipt = completedReceipt()
    const { receiptDigest: _receiptDigest, ...baseCore } = baseReceipt
    const atDeadlineCore = {
      ...baseCore,
      completedAt: reservation.deadlineAt,
    }
    const atDeadlineReceipt = {
      ...atDeadlineCore,
      receiptDigest: structuredDigest(
        SOURCE_SLICE_EGRESS_INVOCATION_RECEIPT_MEDIA_TYPE,
        atDeadlineCore,
      ),
    }

    expect(() => settleSourceSliceModelInvocationV1({
      contextGrant: grant,
      reservation,
      receipt: atDeadlineReceipt,
      lineage: lineage(),
    })).toThrow(/deadline|reservation/iu)
  })

  it('refuses a response digest that does not prove exact response bytes', () => {
    const grant = contextGrant()
    const reservation = budgetReservation(grant)
    const baseReceipt = completedReceipt()
    const { receiptDigest: _receiptDigest, ...baseCore } = baseReceipt
    const nonBinaryCore = {
      ...baseCore,
      responseDigest: structuredDigest('text/plain', { response: 'protected response' }),
    }
    const nonBinaryReceipt = {
      ...nonBinaryCore,
      receiptDigest: structuredDigest(
        SOURCE_SLICE_EGRESS_INVOCATION_RECEIPT_MEDIA_TYPE,
        nonBinaryCore,
      ),
    }

    expect(() => settleSourceSliceModelInvocationV1({
      contextGrant: grant,
      reservation,
      receipt: nonBinaryReceipt,
      lineage: lineage(),
    })).toThrow(/response|bytes|digest/iu)
  })

  it('refuses a Prompt digest that does not bind canonical structured lineage', () => {
    const grant = contextGrant()
    const receipt = completedReceipt()
    const nonCanonicalLineage = {
      ...lineage(),
      prompt: {
        ...lineage().prompt,
        promptDigest: binaryDigest(
          'application/vnd.dsh.security.role-prompt+json',
          Buffer.from('{"prompt":"protected"}', 'utf8'),
        ),
      },
    }

    expect(() => settleSourceSliceModelInvocationV1({
      contextGrant: grant,
      reservation: budgetReservation(grant),
      receipt,
      lineage: nonCanonicalLineage,
    })).toThrow(/prompt|canonical|digest/iu)
  })

  it('refuses a self-consistent Broker receipt whose request lineage was not reserved', () => {
    const grant = contextGrant()
    const receipt = completedReceipt()
    const reservation = budgetReservation(grant)
    const { receiptDigest: _receiptDigest, ...baseCore } = receipt
    const substitutedCore = {
      ...baseCore,
      brokerRequestDigest: structuredDigest(
        SOURCE_SLICE_EGRESS_BROKER_REQUEST_MEDIA_TYPE,
        { request: 'substituted-after-reservation' },
      ),
    }
    const substitutedReceipt = {
      ...substitutedCore,
      receiptDigest: structuredDigest(
        SOURCE_SLICE_EGRESS_INVOCATION_RECEIPT_MEDIA_TYPE,
        substitutedCore,
      ),
    }

    expect(() => settleSourceSliceModelInvocationV1({
      contextGrant: grant,
      reservation,
      receipt: substitutedReceipt,
      lineage: lineage(),
    })).toThrow(/reserved|request|lineage|invocation/iu)
  })

  it('refuses invocation parameters that could exceed the token reservation', () => {
    const grant = contextGrant()
    const receipt = completedReceipt()
    const overcommittedLineage = {
      ...lineage(),
      parameters: {
        ...lineage().parameters,
        maxOutputTokens: 97,
      },
    }

    expect(() => settleSourceSliceModelInvocationV1({
      contextGrant: grant,
      reservation: budgetReservation(grant),
      receipt,
      lineage: overcommittedLineage,
    })).toThrow(/parameter|budget|token|reservation/iu)
  })

  it('does not manufacture complete lineage or release budget from a failed Broker receipt', () => {
    const grant = contextGrant()
    const completed = completedReceipt()
    const { receiptDigest: _receiptDigest, ...completedCore } = completed
    const failedCore = {
      ...completedCore,
      status: 'FAILED' as const,
      failureCode: 'BROKER_FAILED' as const,
      providerRequestId: null,
      backendId: null,
      deploymentId: null,
      modelId: null,
      responseDigest: null,
      finishReason: null,
      usage: null,
      diagnosticCodes: ['BROKER_FAILED'],
    }
    const failedReceipt = {
      ...failedCore,
      receiptDigest: structuredDigest(
        SOURCE_SLICE_EGRESS_INVOCATION_RECEIPT_MEDIA_TYPE,
        failedCore,
      ),
    }

    expect(() => settleSourceSliceModelInvocationV1({
      contextGrant: grant,
      reservation: budgetReservation(grant),
      receipt: failedReceipt,
      lineage: lineage(),
    })).toThrow(/failed|settle|usage/iu)
  })

  it('rejects a reservation whose budget changed after its digest was issued', () => {
    const grant = contextGrant()
    const receipt = completedReceipt()
    const reservation = budgetReservation(grant)

    expect(() => settleSourceSliceModelInvocationV1({
      contextGrant: grant,
      reservation: { ...reservation, tokenLimit: 129 },
      receipt,
      lineage: lineage(),
    })).toThrow(/reservation|digest/iu)
  })

  it('revalidates the pre-call token ceiling when a protected record is read back', () => {
    const grant = contextGrant()
    const receipt = completedReceipt()
    const reservation = budgetReservation(grant)
    const record = settleSourceSliceModelInvocationV1({
      contextGrant: grant,
      reservation,
      receipt,
      lineage: lineage(),
    })
    const { recordDigest: _recordDigest, ...recordCore } = record
    const overcommittedCore = {
      ...recordCore,
      parameters: { ...recordCore.parameters, maxOutputTokens: 97 },
    }
    const overcommittedRecord = {
      ...overcommittedCore,
      recordDigest: structuredDigest(MODEL_INVOCATION_RECORD_MEDIA_TYPE, overcommittedCore),
    }

    expect(() => parseModelInvocationRecordV1(overcommittedRecord, {
      invocationId,
      attemptId,
      attemptGeneration: 1,
      attemptFenceDigest,
      contextGrantDigest: grant.grantDigest,
      reservationDigest: reservation.reservationDigest,
      receiptDigest: receipt.receiptDigest,
    })).toThrow(/usage|settlement|token|budget/iu)
  })
})

describe('ADR 0178 Model Invocation Evidence publication', () => {
  it('atomically publishes one exact Attempt-bound record and reads it back idempotently', async () => {
    const { grant, record, expected } = settledInvocationFixture()
    const securityRoot = await mkdtemp(join(tmpdir(), 'dsh-model-invocation-evidence-'))
    temporaryRoots.push(securityRoot)
    const input = {
      securityRoot,
      contextGrant: grant,
      record,
      expected,
    }

    const publication = await publishModelInvocationEvidenceV1(input)
    const repeatedPublication = await publishModelInvocationEvidenceV1(input)

    expect(repeatedPublication).toEqual(publication)
    expect(publication).toMatchObject({
      schemaVersion: 1,
      assessmentId: grant.assessmentId,
      subjectDigest: grant.subject.digest,
      schemaId: MODEL_INVOCATION_EVIDENCE_SCHEMA_ID,
      invocationId,
      parentAttempt: {
        attemptId,
        generation: 1,
        fenceDigest: attemptFenceDigest,
      },
      recordDigest: record.recordDigest,
    })
    expect(Object.isFrozen(publication)).toBe(true)
    expect(JSON.stringify(publication)).not.toContain(securityRoot)
    expect(JSON.stringify(publication)).not.toContain('protected')

    const readRecord = await readPublishedModelInvocationEvidenceV1({
      securityRoot,
      contextGrant: grant,
      receipt: publication,
      expected,
    })

    expect(readRecord).toEqual(record)
    expect(Object.isFrozen(readRecord)).toBe(true)
  })

  it('refuses a self-consistent publication receipt rebound to another Attempt generation', async () => {
    const { grant, record, expected } = settledInvocationFixture()
    const securityRoot = await mkdtemp(join(tmpdir(), 'dsh-model-invocation-evidence-'))
    temporaryRoots.push(securityRoot)
    const publication = await publishModelInvocationEvidenceV1({
      securityRoot,
      contextGrant: grant,
      record,
      expected,
    })
    const { publicationReceiptDigest: _publicationReceiptDigest, ...publicationCore } = publication
    const reboundCore = {
      ...publicationCore,
      parentAttempt: {
        ...publicationCore.parentAttempt,
        generation: 2,
      },
    }
    const reboundReceipt = {
      ...reboundCore,
      publicationReceiptDigest: structuredDigest(
        MODEL_INVOCATION_EVIDENCE_PUBLICATION_RECEIPT_MEDIA_TYPE,
        reboundCore,
      ),
    }

    await expect(readPublishedModelInvocationEvidenceV1({
      securityRoot,
      contextGrant: grant,
      receipt: reboundReceipt,
      expected,
    })).rejects.toThrow(/Attempt|expected|binding/iu)
  })

  it('refuses to publish a settled record under another assessment', async () => {
    const { grant, record, expected } = settledInvocationFixture()
    const securityRoot = await mkdtemp(join(tmpdir(), 'dsh-model-invocation-evidence-'))
    temporaryRoots.push(securityRoot)
    const { grantDigest: _grantDigest, ...grantCore } = grant
    const otherAssessmentGrant = createRoleContextGrantV1({
      ...grantCore,
      assessmentId: 'asm-00000000-0000-0000-0000-000000000179',
    })

    await expect(publishModelInvocationEvidenceV1({
      securityRoot,
      contextGrant: otherAssessmentGrant,
      record,
      expected,
    })).rejects.toThrow(/assessment|grant|binding|lineage/iu)
  })

  it('refuses to read an Evidence object through another Subject binding', async () => {
    const { grant, record, expected } = settledInvocationFixture()
    const securityRoot = await mkdtemp(join(tmpdir(), 'dsh-model-invocation-evidence-'))
    temporaryRoots.push(securityRoot)
    const publication = await publishModelInvocationEvidenceV1({
      securityRoot,
      contextGrant: grant,
      record,
      expected,
    })
    const otherSubjectDigest = structuredDigest(
      'application/vnd.dsh.security.subject-manifest+json',
      { commit: 'b'.repeat(40) },
    )
    const { grantDigest: _grantDigest, ...grantCore } = grant
    const otherSubjectGrant = createRoleContextGrantV1({
      ...grantCore,
      subject: {
        ...grant.subject,
        digest: otherSubjectDigest,
      },
    })

    await expect(readPublishedModelInvocationEvidenceV1({
      securityRoot,
      contextGrant: otherSubjectGrant,
      receipt: publication,
      expected,
    })).rejects.toThrow(/subject|grant|expected|binding|lineage/iu)
  })

  it('atomically links one published record to its exact durable Assessment and Attempt', async () => {
    const { grant, record, expected } = settledInvocationFixture()
    const securityRoot = await mkdtemp(join(tmpdir(), 'dsh-model-invocation-link-'))
    temporaryRoots.push(securityRoot)
    const publication = await publishModelInvocationEvidenceV1({
      securityRoot,
      contextGrant: grant,
      record,
      expected,
    })
    const { persistence, running } = await runningAssessmentPersistence(securityRoot, grant)
    try {
      const input = {
        contextGrant: grant,
        expectedAssessmentRevision: running.assessmentRevision,
        receipt: publication,
        expected,
      }

      const link = persistence.linkModelInvocationEvidence(input)
      const replay = persistence.linkModelInvocationEvidence(input)

      expect(replay).toEqual(link)
      expect(link).toMatchObject({
        schemaVersion: 1,
        assessmentRevision: running.assessmentRevision + 1,
        contextGrantDigest: grant.grantDigest,
        publicationReceipt: publication,
        linkedAt: '2026-09-13T00:00:03.000Z',
      })
      expect(link.linkDigest.mediaType).toBe(MODEL_INVOCATION_EVIDENCE_LINK_MEDIA_TYPE)
      expect(Object.isFrozen(link)).toBe(true)
      expect(persistence.getModelInvocationEvidenceLink(
        grant.assessmentId,
        invocationId,
      )).toEqual(link)
      expect(persistence.getAssessmentRecord(grant.assessmentId)).toMatchObject({
        assessmentRevision: running.assessmentRevision + 1,
        modelInvocationEvidenceLinks: [link],
      })
    } finally {
      persistence.close()
    }
  })

  it('rolls back when the same invocation is linked to a different published record', async () => {
    const { grant, record, expected } = settledInvocationFixture()
    const securityRoot = await mkdtemp(join(tmpdir(), 'dsh-model-invocation-conflict-'))
    const conflictingEvidenceRoot = await mkdtemp(join(
      tmpdir(),
      'dsh-model-invocation-conflicting-evidence-',
    ))
    temporaryRoots.push(securityRoot, conflictingEvidenceRoot)
    const publication = await publishModelInvocationEvidenceV1({
      securityRoot,
      contextGrant: grant,
      record,
      expected,
    })
    const receipt = completedReceipt()
    const reservation = budgetReservation(grant)
    const conflictingRecord = settleSourceSliceModelInvocationV1({
      contextGrant: grant,
      reservation,
      receipt,
      lineage: {
        ...lineage(),
        provider: { movingProvider: true },
      },
    })
    const conflictingPublication = await publishModelInvocationEvidenceV1({
      securityRoot: conflictingEvidenceRoot,
      contextGrant: grant,
      record: conflictingRecord,
      expected,
    })
    const { persistence, running } = await runningAssessmentPersistence(securityRoot, grant)
    const databasePath = join(securityRoot, 'security-assurance.sqlite')
    try {
      const linked = persistence.linkModelInvocationEvidence({
        contextGrant: grant,
        expectedAssessmentRevision: running.assessmentRevision,
        receipt: publication,
        expected,
      })
      const assessmentBeforeConflict = persistence.getAssessmentRecord(grant.assessmentId)

      expect(() => persistence.linkModelInvocationEvidence({
        contextGrant: grant,
        expectedAssessmentRevision: linked.assessmentRevision,
        receipt: conflictingPublication,
        expected,
      })).toThrow(/already linked to different Evidence/iu)
      expect(persistence.getAssessmentRecord(grant.assessmentId)).toEqual(assessmentBeforeConflict)
      expect(persistence.getModelInvocationEvidenceLink(grant.assessmentId, invocationId))
        .toEqual(linked)
    } finally {
      persistence.close()
    }

    const forensic = new DatabaseSync(databasePath, { readOnly: true })
    try {
      expect(forensic.prepare(`
        SELECT count(*) AS count FROM model_invocation_evidence_links
      `).get()).toEqual({ count: 1 })
      expect(forensic.prepare(`
        SELECT count(*) AS count FROM assessment_revisions WHERE assessment_id = ?
      `).get(grant.assessmentId)).toEqual({ count: 3 })
    } finally {
      forensic.close()
    }
  })

  it('opens a released schema-v1 Store only after a verified backup and v2 migration', async () => {
    const securityRoot = await mkdtemp(join(tmpdir(), 'dsh-model-invocation-migration-'))
    temporaryRoots.push(securityRoot)
    const databasePath = join(securityRoot, 'security-assurance.sqlite')
    installReleasedSchemaV1(databasePath)

    const persistence = await openSecurityPersistence({
      databasePath,
      now: () => '2026-09-13T00:00:04.000Z',
    })
    persistence.close()

    const migrated = new DatabaseSync(databasePath, { readOnly: true })
    try {
      expect(migrated.prepare('PRAGMA user_version').get()).toEqual({ user_version: 2 })
      expect(migrated.prepare(`
        SELECT source_version, target_version, committed_at
        FROM schema_migrations
      `).get()).toEqual({
        source_version: 1,
        target_version: 2,
        committed_at: '2026-09-13T00:00:04.000Z',
      })
      expect(migrated.prepare(`
        SELECT backup_name, source_state_digest, result_digest
        FROM schema_migrations
      `).get()).toMatchObject({
        backup_name: expect.stringMatching(
          /^security-assurance\.sqlite\.pre-migration-v1-[0-9a-f-]{36}\.sqlite$/u,
        ),
        source_state_digest: expect.stringMatching(/^sha256:[0-9a-f]{64}$/u),
        result_digest: expect.stringMatching(/^sha256:[0-9a-f]{64}$/u),
      })
      expect(migrated.prepare(`
        SELECT name FROM sqlite_master
        WHERE type = 'table' AND name = 'model_invocation_evidence_links'
      `).get()).toEqual({ name: 'model_invocation_evidence_links' })
    } finally {
      migrated.close()
    }

    const backupNames = (await readdir(securityRoot))
      .filter(name => /^security-assurance\.sqlite\.pre-migration-v1-[0-9a-f-]{36}\.sqlite$/u
        .test(name))
    expect(backupNames).toHaveLength(1)
    const backup = new DatabaseSync(join(securityRoot, backupNames[0]!), { readOnly: true })
    try {
      expect(backup.prepare('PRAGMA application_id').get())
        .toEqual({ application_id: 0x4453_4853 })
      expect(backup.prepare('PRAGMA user_version').get()).toEqual({ user_version: 1 })
      expect(backup.prepare('PRAGMA quick_check').get()).toEqual({ quick_check: 'ok' })
    } finally {
      backup.close()
    }

    const tampered = new DatabaseSync(databasePath)
    try {
      tampered.prepare(`
        UPDATE schema_migrations SET result_digest = ? WHERE target_version = 2
      `).run(`sha256:${'0'.repeat(64)}`)
    } finally {
      tampered.close()
    }
    await expect(openSecurityPersistence({ databasePath })).rejects.toMatchObject({
      code: 'corrupt_database',
      message: 'SQLite migration history is invalid',
    })
  })
})
