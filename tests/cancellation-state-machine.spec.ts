import { DatabaseSync } from 'node:sqlite'
import { mkdtemp, rm } from 'node:fs/promises'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { afterEach, describe, expect, it } from 'vitest'
import { openSecurityPersistence } from '../src/internal/persistence.ts'
import { prepareAssessmentContract } from '../src/internal/deterministic-kernel.ts'
import { structuredDigest } from '../src/internal/canonical.ts'

const temporaryRoots: string[] = []

afterEach(async () => {
  await Promise.all(temporaryRoots.splice(0).map(path => rm(path, { recursive: true, force: true })))
})

function repositoryBindings() {
  return {
    policyId: 'security/default',
    assessmentProfileId: 'security/standard',
    evidenceProtectionId: 'evidence/local-protected',
    dataEgressPolicyId: 'egress/deny-by-default',
    platform: process.platform as 'win32' | 'linux' | 'darwin',
    deliveryDestinationIds: [],
  }
}

async function assessmentFixture() {
  const home = await mkdtemp(join(tmpdir(), 'dsh-security-cancellation-state-'))
  temporaryRoots.push(home)
  const databasePath = join(home, 'security-assurance.sqlite')
  const store = await openSecurityPersistence({
    databasePath,
    now: () => '2026-08-30T00:00:00.000Z',
    nextRepositoryId: () => 'repo-00000000-0000-0000-0000-000000000001',
    nextAssessmentId: () => 'asm-00000000-0000-0000-0000-000000000001',
    nextCorrelationId: () => 'sec-00000000-0000-0000-0000-000000000001',
  })
  const bindings = repositoryBindings()
  const registered = store.registerRepository({
    principalId: 'operator:cancellation-fixture',
    authorityKind: 'host-operator',
    idempotencyKey: 'cancellation-repository-register',
    canonicalRequest: { operation: 'register', root: 'D:/cancellation-fixture' },
    canonicalRoot: 'D:/cancellation-fixture',
    displayName: 'Cancellation fixture',
    bindings,
  })
  const repository = store.getRepository(registered.repositoryId)
  if (repository === undefined) throw new Error('repository fixture was not persisted')
  const target = { kind: 'repository' as const }
  const targetDigest = structuredDigest('application/vnd.dsh.security.target-selector+json', target)
  const contract = prepareAssessmentContract({
    policyId: bindings.policyId,
    assessmentMode: 'REPOSITORY',
    assessmentProfileId: bindings.assessmentProfileId,
    target,
    targetDigest,
    requestedStrongerControlIds: [],
    analyzerPortfolio: [],
  })
  const receipt = store.createAssessment({
    principalId: 'operator:cancellation-fixture',
    authorityKind: 'host-operator',
    idempotencyKey: 'cancellation-assessment-start',
    repositoryId: repository.repositoryId,
    expectedRepositoryRevision: repository.repositoryRevision,
    canonicalRequest: { operation: 'start', idempotencyKey: 'cancellation-assessment-start' },
    subject: { kind: 'workspace_snapshot' },
    subjectDigest: structuredDigest(
      'application/vnd.dsh.security.subject-manifest+json',
      { fixture: 'cancellation' },
    ),
    subjectStats: { files: 0, bytes: 0, symbolicLinks: 0, submodules: 0 },
    preparedContract: contract,
  })
  return { databasePath, store, receipt }
}

describe('cancellation state machine', () => {
  it('fences every revision-advancing execution after cancellation is accepted', async () => {
    const { store, receipt } = await assessmentFixture()
    const cancellation = store.requestAssessmentCancellation({
      principalId: 'operator:cancellation-fixture',
      authorityKind: 'host-operator',
      idempotencyKey: 'cancellation-request',
      assessmentId: receipt.assessmentId,
      expectedAssessmentRevision: receipt.assessmentRevision,
      reason: { code: 'OPERATOR_CANCEL', summary: 'Stop the fixture.' },
      canonicalRequest: { operation: 'cancel', idempotencyKey: 'cancellation-request' },
    })

    expect(() => store.resumeAssessment({
      principalId: 'operator:cancellation-fixture',
      authorityKind: 'host-operator',
      idempotencyKey: 'resume-after-cancel',
      assessmentId: receipt.assessmentId,
      expectedAssessmentRevision: cancellation.assessmentRevision,
      reason: { code: 'OPERATOR_RETRY', summary: 'Must be rejected.' },
      canonicalRequest: { operation: 'resume', idempotencyKey: 'resume-after-cancel' },
    })).toThrowError('Assessment is not resumable at this revision')
    expect(store.beginAssessment(receipt.assessmentId)).toBeUndefined()
    expect(store.completeAssessmentCancellation(receipt.assessmentId, cancellation.assessmentRevision).state)
      .toBe('CANCELED')
    store.close()
  })

  it('recovers a pending cancellation even when an older writer advanced the revision', async () => {
    const { databasePath, store, receipt } = await assessmentFixture()
    const cancellation = store.requestAssessmentCancellation({
      principalId: 'operator:cancellation-fixture',
      authorityKind: 'host-operator',
      idempotencyKey: 'cancellation-recovery-request',
      assessmentId: receipt.assessmentId,
      expectedAssessmentRevision: receipt.assessmentRevision,
      reason: { code: 'OPERATOR_CANCEL', summary: 'Recover the fixture cancellation.' },
      canonicalRequest: { operation: 'cancel', idempotencyKey: 'cancellation-recovery-request' },
    })
    const pending = store.getAssessmentRecord(receipt.assessmentId)
    if (pending === undefined) throw new Error('pending cancellation was not persisted')
    store.close()

    const database = new DatabaseSync(databasePath)
    const advanced = { ...pending, assessmentRevision: pending.assessmentRevision + 1 }
    database.prepare(
      'UPDATE assessments SET current_revision = ?, snapshot_json = ?, state = ? WHERE assessment_id = ?',
    ).run(advanced.assessmentRevision, JSON.stringify(advanced), advanced.state, advanced.assessmentId)
    database.close()

    const recovered = await openSecurityPersistence({ databasePath })
    recovered.recoverInterruptedAssessments()
    expect(recovered.getAssessmentRecord(receipt.assessmentId)).toMatchObject({
      state: 'CANCELED',
      pendingCancellation: { requestRevision: cancellation.assessmentRevision },
    })
    recovered.close()
  })
})
