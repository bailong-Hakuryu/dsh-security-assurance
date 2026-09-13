import { afterEach, describe, expect, it } from 'vitest'
import { mkdtemp } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createRoleContextGrantV1 } from '../src/role-context-grant.ts'
import { structuredDigest } from '../src/internal/canonical.ts'
import { prepareAssessmentContract } from '../src/internal/deterministic-kernel.ts'
import {
  MODEL_INVOCATION_PROMPT_MEDIA_TYPE,
  MODEL_INVOCATION_TOOL_SCHEMA_MEDIA_TYPE,
} from '../src/internal/model-invocation-settlement.ts'
import { openSecurityPersistence } from '../src/internal/persistence.ts'
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

function roleContextGrant() {
  return createRoleContextGrantV1({
    schemaVersion: 1,
    assessmentId,
    roleAttemptId: attemptId,
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
    completionDisposition: 'COMPLETE' as const,
    usage: { requestsUsed: 1, tokensUsed: 40 },
    evidenceCount: 1,
    candidateCount: 1,
    milestones: [{
      milestoneId: 'INITIAL_CONTRIBUTION_FROZEN',
      state: 'REACHED' as const,
      recordedAt: '2026-09-13T01:00:00.000Z',
    }],
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

  it('completes one current fenced Role Attempt at most once', async () => {
    const securityRoot = await mkdtemp(join(tmpdir(), 'dsh-role-attempt-complete-'))
    temporaryRoots.push(securityRoot)
    const { contextGrant, persistence, running } = await runningAssessment(securityRoot)
    try {
      const started = persistence.startRoleAttempt(
        startInput(contextGrant, running.assessmentRevision),
      )
      const input = completionInput(started.assessmentRevision)

      const completed = persistence.completeRoleAttempt(input)
      const replay = persistence.completeRoleAttempt(input)
      const startReplay = persistence.startRoleAttempt(
        startInput(contextGrant, running.assessmentRevision),
      )

      expect(replay).toEqual(completed)
      expect(startReplay).toEqual(completed)
      expect(completed).toMatchObject({
        assessmentRevision: started.assessmentRevision + 1,
        lifecycleState: 'COMPLETED',
        completedAt: '2026-09-13T01:00:00.000Z',
        completionDisposition: 'COMPLETE',
        budget: {
          requestLimit: 4,
          requestsUsed: 1,
          tokenLimit: 8_192,
          tokensUsed: 40,
        },
        evidenceCount: 1,
        candidateCount: 1,
      })
      expect(persistence.getAssessmentRecord(assessmentId)).toMatchObject({
        assessmentRevision: started.assessmentRevision + 1,
        roleCards: [{
          attempt: {
            attemptId,
            lifecycleState: 'COMPLETED',
          },
          completionDisposition: 'COMPLETE',
        }],
      })
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

  it('rejects a conflicting completion replay without rewriting the first result', async () => {
    const securityRoot = await mkdtemp(join(tmpdir(), 'dsh-role-attempt-conflict-'))
    temporaryRoots.push(securityRoot)
    const { contextGrant, persistence, running } = await runningAssessment(securityRoot)
    try {
      const started = persistence.startRoleAttempt(
        startInput(contextGrant, running.assessmentRevision),
      )
      const input = completionInput(started.assessmentRevision)
      const completed = persistence.completeRoleAttempt(input)

      expect(() => persistence.completeRoleAttempt({
        ...input,
        evidenceCount: 2,
      })).toThrow(/already completed|different result/iu)

      expect(persistence.getRoleAttempt(assessmentId, attemptId, 1)).toEqual(completed)
      expect(persistence.getAssessmentRecord(assessmentId)).toMatchObject({
        assessmentRevision: completed.assessmentRevision,
        roleCards: [{
          evidenceCount: 1,
          attempt: { lifecycleState: 'COMPLETED' },
        }],
      })
    } finally {
      persistence.close()
    }
  })
})
