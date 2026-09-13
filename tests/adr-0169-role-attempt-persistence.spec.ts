import { afterEach, describe, expect, it } from 'vitest'
import { mkdtemp } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { assessmentSnapshotV1Schema } from '../src/contracts.ts'
import { createRoleContextGrantV1 } from '../src/role-context-grant.ts'
import { publicAssessmentSnapshot } from '../src/internal/assessment-record.ts'
import { structuredDigest } from '../src/internal/canonical.ts'
import { prepareAssessmentContract } from '../src/internal/deterministic-kernel.ts'
import {
  MODEL_INVOCATION_PROMPT_MEDIA_TYPE,
  MODEL_INVOCATION_TOOL_SCHEMA_MEDIA_TYPE,
} from '../src/internal/model-invocation-settlement.ts'
import { openSecurityPersistence } from '../src/internal/persistence.ts'
import { ROLE_CONTRIBUTION_MEDIA_TYPE } from '../src/internal/role-contribution.ts'
import { ROLE_ATTEMPT_RECORD_MEDIA_TYPE } from '../src/internal/role-attempt.ts'
import { SOURCE_SLICE_EGRESS_ATTEMPT_FENCE_MEDIA_TYPE } from '../src/internal/source-slice-egress-invocation.ts'
import { removeTemporaryRoots } from './support/remove-temporary-root.ts'

const temporaryRoots: string[] = []

afterEach(async () => {
  await removeTemporaryRoots(temporaryRoots)
})

const assessmentId = 'asm-00000000-0000-0000-0000-000000000169'
const attemptId = 'role-attempt-00000000-0000-0000-0000-000000000169'
const attemptFenceDigest = structuredDigest(
  SOURCE_SLICE_EGRESS_ATTEMPT_FENCE_MEDIA_TYPE,
  {
    attemptId,
    generation: 1,
    fencingToken: 'fence/role-attempt-0169/generation-1',
  },
)

function roleContextGrant(roleAttemptId = attemptId) {
  return createRoleContextGrantV1({
    schemaVersion: 1,
    assessmentId,
    roleAttemptId,
    roleDefinition: {
      roleId: 'discovery-analyst',
      roleVersion: '1.0.0',
      definitionDigest: structuredDigest(
        'application/vnd.dsh.security.role-definition+json',
        { roleId: 'discovery-analyst', roleVersion: '1.0.0' },
      ),
    },
    purpose: {
      purposeId: 'security/deep-discovery',
      assessmentMode: 'REPOSITORY',
      assessmentProfileId: 'security/standard',
      targetDigest: structuredDigest(
        'application/vnd.dsh.security.target+json',
        { kind: 'repository' },
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
        artifactId: 'inventory-role-attempt-0169',
        schemaId: 'dsh/security-subject-inventory',
        digest: structuredDigest(
          'application/vnd.dsh.security.subject-inventory+json',
          { inventory: 'role-attempt-0169' },
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
      contextBytes: { limit: 65_536, granted: 1_024 },
      tokens: { limit: 8_192, granted: 1_024 },
    },
  })
}

async function runningAssessment(securityRoot: string) {
  const contextGrant = roleContextGrant()
  const persistence = await openSecurityPersistence({
    databasePath: join(securityRoot, 'security-assurance.sqlite'),
    now: () => '2026-09-13T01:00:00.000Z',
    nextRepositoryId: () => 'repo-00000000-0000-0000-0000-000000000169',
    nextAssessmentId: () => assessmentId,
    nextCorrelationId: () => 'sec-00000000-0000-0000-0000-000000000169',
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
    principalId: 'operator:role-attempt-fixture',
    authorityKind: 'host-operator',
    idempotencyKey: 'role-attempt-repository',
    canonicalRequest: { operation: 'register-role-attempt-fixture' },
    canonicalRoot: 'D:/role-attempt-fixture',
    displayName: 'Role Attempt fixture',
    bindings,
  })
  const repository = persistence.getRepository(registered.repositoryId)
  if (repository === undefined) throw new Error('repository fixture was not persisted')
  const target = { kind: 'repository' as const }
  const created = persistence.createAssessment({
    principalId: 'operator:role-attempt-fixture',
    authorityKind: 'host-operator',
    idempotencyKey: 'role-attempt-assessment',
    repositoryId: repository.repositoryId,
    expectedRepositoryRevision: repository.repositoryRevision,
    canonicalRequest: { operation: 'start-role-attempt-fixture' },
    subject: { kind: 'workspace_snapshot' },
    subjectDigest: contextGrant.subject.digest,
    subjectStats: { files: 0, bytes: 0, symbolicLinks: 0, submodules: 0 },
    preparedContract: prepareAssessmentContract({
      policyId: bindings.policyId,
      assessmentMode: 'REPOSITORY',
      assessmentProfileId: bindings.assessmentProfileId,
      target,
      targetDigest: contextGrant.purpose.targetDigest,
      requestedStrongerControlIds: [],
      analyzerPortfolio: [],
    }),
  })
  const running = persistence.beginAssessment(created.assessmentId)
  if (running === undefined) throw new Error('assessment fixture did not begin')
  return { contextGrant, persistence, running }
}

function startInput(
  contextGrant: ReturnType<typeof roleContextGrant>,
  expectedAssessmentRevision: number,
) {
  return {
    contextGrant,
    expectedAssessmentRevision,
    generation: 1,
    fenceDigest: attemptFenceDigest,
    parentAttemptId: null,
    independenceClass: 'DISTINCT_ATTEMPT' as const,
    provider: {
      providerId: 'provider/reference',
      modelId: 'model/reference',
      movingProvider: false,
    },
    prompt: {
      promptId: 'security/deep-discovery',
      promptVersion: '1.0.0',
      promptDigest: structuredDigest(
        MODEL_INVOCATION_PROMPT_MEDIA_TYPE,
        { promptId: 'security/deep-discovery', promptVersion: '1.0.0' },
      ),
      toolSchemaDigest: structuredDigest(
        MODEL_INVOCATION_TOOL_SCHEMA_MEDIA_TYPE,
        { tools: ['source-slice'] },
      ),
    },
    budget: {
      requestLimit: 4,
      tokenLimit: 8_192,
    },
  }
}

function completionInput(expectedAssessmentRevision: number) {
  return {
    assessmentId,
    attemptId,
    generation: 1,
    fenceDigest: attemptFenceDigest,
    expectedAssessmentRevision,
    contributionId: 'role-contribution-00000000-0000-0000-0000-000000000169',
    contributionDigest: structuredDigest(
      ROLE_CONTRIBUTION_MEDIA_TYPE,
      { contribution: 'not-admitted' },
    ),
    milestones: [{
      milestoneId: 'INITIAL_CONTRIBUTION_FROZEN',
      state: 'REACHED' as const,
      recordedAt: '2026-09-13T01:00:00.000Z',
    }],
  }
}

function failureInput(expectedAssessmentRevision: number) {
  return {
    assessmentId,
    attemptId,
    generation: 1,
    fenceDigest: attemptFenceDigest,
    expectedAssessmentRevision,
    failureCode: 'ROLE_PROVIDER_FAILED',
    usage: { requestsUsed: 1, tokensUsed: 16 },
    evidenceCount: 0,
    candidateCount: 0,
    milestones: [],
  }
}

describe('ADR 0169 durable Role Attempt persistence', () => {
  it('atomically starts one exact Role Attempt and replays it without another revision', async () => {
    const securityRoot = await mkdtemp(join(tmpdir(), 'dsh-role-attempt-start-'))
    temporaryRoots.push(securityRoot)
    const { contextGrant, persistence, running } = await runningAssessment(securityRoot)
    try {
      const input = startInput(contextGrant, running.assessmentRevision)

      const attempt = persistence.startRoleAttempt(input)
      const replay = persistence.startRoleAttempt(input)

      expect(replay).toEqual(attempt)
      expect(attempt).toMatchObject({
        schemaVersion: 1,
        assessmentId,
        assessmentRevision: running.assessmentRevision + 1,
        attemptId,
        generation: 1,
        fenceDigest: attemptFenceDigest,
        contextGrantDigest: contextGrant.grantDigest,
        lifecycleState: 'RUNNING',
        startedAt: '2026-09-13T01:00:00.000Z',
        completedAt: null,
        completionDisposition: 'NOT_AVAILABLE',
      })
      expect(attempt.recordDigest.mediaType).toBe(ROLE_ATTEMPT_RECORD_MEDIA_TYPE)
      expect(Object.isFrozen(attempt)).toBe(true)
      expect(persistence.getRoleAttempt(assessmentId, attemptId, 1)).toEqual(attempt)
      expect(persistence.getAssessmentRecord(assessmentId)).toMatchObject({
        assessmentRevision: running.assessmentRevision + 1,
        roleCards: [{
          attempt: {
            attemptId,
            lifecycleState: 'RUNNING',
          },
        }],
      })

      const generationTwoFence = structuredDigest(
        SOURCE_SLICE_EGRESS_ATTEMPT_FENCE_MEDIA_TYPE,
        {
          attemptId,
          generation: 2,
          fencingToken: 'fence/role-attempt-0169/generation-2',
        },
      )
      expect(() => persistence.startRoleAttempt({
        ...input,
        expectedAssessmentRevision: attempt.assessmentRevision,
        generation: 2,
        fenceDigest: generationTwoFence,
      })).toThrow(/different generation/iu)
      expect(persistence.getAssessmentRecord(assessmentId)?.assessmentRevision)
        .toBe(attempt.assessmentRevision)
    } finally {
      persistence.close()
    }
  })

  it('does not start against a Context Grant from a different Assessment contract', async () => {
    const securityRoot = await mkdtemp(join(tmpdir(), 'dsh-role-attempt-contract-'))
    temporaryRoots.push(securityRoot)
    const { contextGrant, persistence, running } = await runningAssessment(securityRoot)
    try {
      const { grantDigest: _grantDigest, ...grantCore } = contextGrant
      const mismatchedGrant = createRoleContextGrantV1({
        ...grantCore,
        purpose: {
          ...grantCore.purpose,
          assessmentProfileId: 'security/deep',
        },
      })

      expect(() => persistence.startRoleAttempt(
        startInput(mismatchedGrant, running.assessmentRevision),
      )).toThrow(/Assessment contract/iu)
      expect(persistence.getAssessmentRecord(assessmentId)).toEqual(running)
      expect(persistence.getRoleAttempt(assessmentId, attemptId, 1)).toBeUndefined()
    } finally {
      persistence.close()
    }
  })

  it('refuses to complete a Role Attempt before its terminal Contribution is admitted', async () => {
    const securityRoot = await mkdtemp(join(tmpdir(), 'dsh-role-attempt-complete-'))
    temporaryRoots.push(securityRoot)
    const { contextGrant, persistence, running } = await runningAssessment(securityRoot)
    try {
      const started = persistence.startRoleAttempt(
        startInput(contextGrant, running.assessmentRevision),
      )
      const input = completionInput(started.assessmentRevision)

      expect(() => persistence.completeRoleAttempt(input)).toThrow(/admitted Role Contribution/iu)
      expect(persistence.getRoleAttempt(assessmentId, attemptId, 1)).toEqual(started)
      expect(persistence.getAssessmentRecord(assessmentId)?.assessmentRevision)
        .toBe(started.assessmentRevision)
    } finally {
      persistence.close()
    }
  })

  it('rejects a stale fence without changing either durable projection', async () => {
    const securityRoot = await mkdtemp(join(tmpdir(), 'dsh-role-attempt-stale-fence-'))
    temporaryRoots.push(securityRoot)
    const { contextGrant, persistence, running } = await runningAssessment(securityRoot)
    try {
      const started = persistence.startRoleAttempt(
        startInput(contextGrant, running.assessmentRevision),
      )
      const staleFenceDigest = structuredDigest(
        SOURCE_SLICE_EGRESS_ATTEMPT_FENCE_MEDIA_TYPE,
        {
          attemptId,
          generation: 1,
          fencingToken: 'fence/role-attempt-0169/stale-generation-1',
        },
      )

      expect(() => persistence.completeRoleAttempt({
        ...completionInput(started.assessmentRevision),
        fenceDigest: staleFenceDigest,
      })).toThrow(/stale|different fence/iu)

      expect(persistence.getRoleAttempt(assessmentId, attemptId, 1)).toEqual(started)
      expect(persistence.getAssessmentRecord(assessmentId)).toMatchObject({
        assessmentRevision: started.assessmentRevision,
        roleCards: [{
          attempt: {
            attemptId,
            lifecycleState: 'RUNNING',
          },
        }],
      })
    } finally {
      persistence.close()
    }
  })

  it('atomically fails one required Role Attempt and blocks its Assessment', async () => {
    const securityRoot = await mkdtemp(join(tmpdir(), 'dsh-role-attempt-failed-'))
    temporaryRoots.push(securityRoot)
    const { contextGrant, persistence, running } = await runningAssessment(securityRoot)
    try {
      const started = persistence.startRoleAttempt(
        startInput(contextGrant, running.assessmentRevision),
      )
      const input = failureInput(started.assessmentRevision)
      const staleFenceDigest = structuredDigest(
        SOURCE_SLICE_EGRESS_ATTEMPT_FENCE_MEDIA_TYPE,
        {
          attemptId,
          generation: 1,
          fencingToken: 'fence/role-attempt-0169/stale-failure',
        },
      )

      expect(() => persistence.failRoleAttempt({
        ...input,
        fenceDigest: staleFenceDigest,
      })).toThrow(/stale|different fence/iu)
      expect(persistence.getRoleAttempt(assessmentId, attemptId, 1)).toEqual(started)

      const failed = persistence.failRoleAttempt(input)
      const replay = persistence.failRoleAttempt(input)

      expect(replay).toEqual(failed)
      expect(() => persistence.failRoleAttempt({
        ...input,
        failureCode: 'ROLE_TIMEOUT',
      })).toThrow(/already failed|different result/iu)
      expect(() => persistence.completeRoleAttempt(
        completionInput(started.assessmentRevision),
      )).toThrow(/terminal result/iu)
      expect(persistence.getRoleAttempt(assessmentId, attemptId, 1)).toEqual(failed)
      expect(failed).toMatchObject({
        assessmentRevision: started.assessmentRevision + 1,
        lifecycleState: 'FAILED',
        completedAt: '2026-09-13T01:00:00.000Z',
        completionDisposition: 'FAILED',
        failureCode: 'ROLE_PROVIDER_FAILED',
        budget: {
          requestLimit: 4,
          requestsUsed: 1,
          tokenLimit: 8_192,
          tokensUsed: 16,
        },
      })
      const blockedAssessment = persistence.getAssessmentRecord(assessmentId)
      expect(blockedAssessment).toMatchObject({
        assessmentRevision: failed.assessmentRevision,
        state: 'BLOCKED',
        failureCode: 'ROLE_PROVIDER_FAILED',
        blockingAttempt: {
          attemptId,
          attemptKind: 'ROLE_EXECUTION',
          lifecycleState: 'FAILED',
        },
        roleCards: [{
          attempt: { attemptId, lifecycleState: 'FAILED' },
          completionDisposition: 'FAILED',
        }],
      })
      if (blockedAssessment === undefined) throw new Error('blocked Assessment was not persisted')
      expect(assessmentSnapshotV1Schema.parse(
        publicAssessmentSnapshot(blockedAssessment, []),
      ).blockedRecovery).toMatchObject({
        blocker: {
          code: 'ROLE_PROVIDER_FAILED',
          phase: 'ROLE_EXECUTION',
          interruption: 'FAILED',
        },
        attempt: {
          status: 'IDENTIFIED',
          attemptId,
          attemptKind: 'ROLE_EXECUTION',
          lifecycleState: 'FAILED',
        },
        recovery: { requiredCondition: 'EXPLICIT_RESUME_REQUIRED' },
      })
    } finally {
      persistence.close()
    }
  })

  it('does not block on one Role failure while another Role Attempt is still running', async () => {
    const securityRoot = await mkdtemp(join(tmpdir(), 'dsh-role-attempt-failure-quiescence-'))
    temporaryRoots.push(securityRoot)
    const { contextGrant, persistence, running } = await runningAssessment(securityRoot)
    try {
      const started = persistence.startRoleAttempt(
        startInput(contextGrant, running.assessmentRevision),
      )
      const secondAttemptId = 'role-attempt-00000000-0000-0000-0000-000000000172'
      const secondFence = structuredDigest(
        SOURCE_SLICE_EGRESS_ATTEMPT_FENCE_MEDIA_TYPE,
        {
          attemptId: secondAttemptId,
          generation: 1,
          fencingToken: 'fence/role-attempt-0172/generation-1',
        },
      )
      const secondStarted = persistence.startRoleAttempt({
        ...startInput(roleContextGrant(secondAttemptId), started.assessmentRevision),
        fenceDigest: secondFence,
      })

      expect(() => persistence.failRoleAttempt(
        failureInput(secondStarted.assessmentRevision),
      )).toThrow(/another|running|quiescence/iu)

      expect(persistence.getRoleAttempt(assessmentId, attemptId, 1)).toEqual(started)
      expect(persistence.getRoleAttempt(assessmentId, secondAttemptId, 1)).toEqual(secondStarted)
      expect(persistence.getAssessmentRecord(assessmentId)).toMatchObject({
        state: 'RUNNING',
        assessmentRevision: secondStarted.assessmentRevision,
        roleCards: [
          { attempt: { attemptId, lifecycleState: 'RUNNING' } },
          { attempt: { attemptId: secondAttemptId, lifecycleState: 'RUNNING' } },
        ],
      })
    } finally {
      persistence.close()
    }
  })

  it('cancels every RUNNING Role Attempt only after Assessment quiescence is proved', async () => {
    const securityRoot = await mkdtemp(join(tmpdir(), 'dsh-role-attempt-canceled-'))
    temporaryRoots.push(securityRoot)
    const { contextGrant, persistence, running } = await runningAssessment(securityRoot)
    try {
      const started = persistence.startRoleAttempt(
        startInput(contextGrant, running.assessmentRevision),
      )
      const secondAttemptId = 'role-attempt-00000000-0000-0000-0000-000000000171'
      const secondFence = structuredDigest(
        SOURCE_SLICE_EGRESS_ATTEMPT_FENCE_MEDIA_TYPE,
        {
          attemptId: secondAttemptId,
          generation: 1,
          fencingToken: 'fence/role-attempt-0171/generation-1',
        },
      )
      const secondStarted = persistence.startRoleAttempt({
        ...startInput(roleContextGrant(secondAttemptId), started.assessmentRevision),
        fenceDigest: secondFence,
      })
      const cancellation = persistence.requestAssessmentCancellation({
        principalId: 'operator:role-attempt-fixture',
        authorityKind: 'host-operator',
        idempotencyKey: 'cancel-running-role-attempt',
        assessmentId,
        expectedAssessmentRevision: secondStarted.assessmentRevision,
        reason: { code: 'OPERATOR_CANCEL', summary: 'Stop the running Role Attempt.' },
        canonicalRequest: { operation: 'cancel-running-role-attempt' },
      })

      expect(persistence.getRoleAttempt(assessmentId, attemptId, 1)?.lifecycleState)
        .toBe('RUNNING')
      expect(persistence.getRoleAttempt(assessmentId, secondAttemptId, 1)?.lifecycleState)
        .toBe('RUNNING')
      expect(() => persistence.completeRoleAttempt(
        completionInput(cancellation.assessmentRevision),
      )).toThrow(/revision|complete/iu)

      const canceledAssessment = persistence.completeAssessmentCancellation(
        assessmentId,
        cancellation.assessmentRevision,
      )
      const replay = persistence.completeAssessmentCancellation(
        assessmentId,
        cancellation.assessmentRevision,
      )
      const canceledAttempt = persistence.getRoleAttempt(assessmentId, attemptId, 1)

      expect(replay).toEqual(canceledAssessment)
      expect(canceledAssessment).toMatchObject({
        state: 'CANCELED',
        assessmentRevision: cancellation.assessmentRevision + 1,
        roleCards: [{
          attempt: { attemptId, lifecycleState: 'CANCELED' },
          completionDisposition: 'CANCELED',
        }, {
          attempt: { attemptId: secondAttemptId, lifecycleState: 'CANCELED' },
          completionDisposition: 'CANCELED',
        }],
      })
      expect(canceledAttempt).toMatchObject({
        lifecycleState: 'CANCELED',
        completionDisposition: 'CANCELED',
        cancellationRevision: cancellation.assessmentRevision,
        assessmentRevision: canceledAssessment.assessmentRevision,
      })
      expect(() => persistence.completeRoleAttempt(
        completionInput(started.assessmentRevision),
      )).toThrow(/terminal result/iu)
      expect(persistence.getRoleAttempt(assessmentId, attemptId, 1)).toEqual(canceledAttempt)
      expect(persistence.getRoleAttempt(assessmentId, secondAttemptId, 1)).toMatchObject({
        lifecycleState: 'CANCELED',
        cancellationRevision: cancellation.assessmentRevision,
        assessmentRevision: canceledAssessment.assessmentRevision,
      })
    } finally {
      persistence.close()
    }
  })

  it('resumes a failed Role only through a new Attempt with durable parent lineage', async () => {
    const securityRoot = await mkdtemp(join(tmpdir(), 'dsh-role-attempt-resume-'))
    temporaryRoots.push(securityRoot)
    const { contextGrant, persistence, running } = await runningAssessment(securityRoot)
    try {
      const started = persistence.startRoleAttempt(
        startInput(contextGrant, running.assessmentRevision),
      )
      const failed = persistence.failRoleAttempt(failureInput(started.assessmentRevision))
      const retryAttemptId = 'role-attempt-00000000-0000-0000-0000-000000000170'
      const retryGrant = roleContextGrant(retryAttemptId)
      const retryFence = structuredDigest(
        SOURCE_SLICE_EGRESS_ATTEMPT_FENCE_MEDIA_TYPE,
        {
          attemptId: retryAttemptId,
          generation: 1,
          fencingToken: 'fence/role-attempt-0170/generation-1',
        },
      )
      const retryStart = {
        ...startInput(retryGrant, failed.assessmentRevision),
        parentAttemptId: attemptId,
        fenceDigest: retryFence,
      }

      expect(() => persistence.startRoleAttempt(retryStart)).toThrow(/revision/iu)
      const resume = persistence.resumeAssessment({
        principalId: 'operator:role-attempt-fixture',
        authorityKind: 'host-operator',
        idempotencyKey: 'resume-failed-role-attempt',
        assessmentId,
        expectedAssessmentRevision: failed.assessmentRevision,
        reason: { code: 'OPERATOR_RETRY', summary: 'Retry the failed required Role.' },
        canonicalRequest: { operation: 'resume-failed-role-attempt' },
      })
      const resumed = persistence.beginAssessment(assessmentId)
      if (resumed === undefined) throw new Error('resumed Assessment did not begin')

      expect(() => persistence.startRoleAttempt({
        ...retryStart,
        expectedAssessmentRevision: resumed.assessmentRevision,
        parentAttemptId: 'role-attempt-00000000-0000-0000-0000-000000000999',
      })).toThrow(/parent/iu)
      expect(() => persistence.startRoleAttempt({
        ...retryStart,
        expectedAssessmentRevision: resumed.assessmentRevision,
        parentAttemptId: null,
      })).toThrow(/parent|lineage/iu)

      const retry = persistence.startRoleAttempt({
        ...retryStart,
        expectedAssessmentRevision: resumed.assessmentRevision,
      })

      expect(resume).toMatchObject({ state: 'CREATED' })
      expect(retry).toMatchObject({
        attemptId: retryAttemptId,
        parentAttemptId: attemptId,
        lifecycleState: 'RUNNING',
      })
      expect(persistence.getRoleAttempt(assessmentId, attemptId, 1)).toEqual(failed)
      expect(persistence.getAssessmentRecord(assessmentId)).toMatchObject({
        state: 'RUNNING',
        failureCode: null,
        blockingAttempt: null,
        roleCards: [
          { attempt: { attemptId, lifecycleState: 'FAILED' } },
          { attempt: { attemptId: retryAttemptId, lifecycleState: 'RUNNING' } },
        ],
      })
    } finally {
      persistence.close()
    }
  })
})
