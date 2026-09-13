import { describe, expect, it } from 'vitest'
import {
  ROLE_CONTEXT_GRANT_MEDIA_TYPE,
} from '../src/role-context-grant.ts'
import { binaryDigest, structuredDigest } from '../src/internal/canonical.ts'
import {
  createRoleContributionV1,
  parseRoleContributionV1,
  ROLE_CONTRIBUTION_MEDIA_TYPE,
} from '../src/internal/role-contribution.ts'
import { MODEL_INVOCATION_RECORD_MEDIA_TYPE } from '../src/internal/model-invocation-settlement.ts'
import { SOURCE_SLICE_EGRESS_ATTEMPT_FENCE_MEDIA_TYPE } from '../src/internal/source-slice-egress-invocation.ts'

const ASSESSMENT_ID = 'asm-018f1f9a-29a3-7b11-b6de-2f6f7f5b8c01' as const
const ATTEMPT_ID = 'role-attempt-018f1f9a-29a3-7b11-b6de-2f6f7f5b8c02'
const CONTRIBUTION_ID = 'role-contribution-018f1f9a-29a3-4b11-b6de-2f6f7f5b8c03'
const FOLLOW_UP_ID = 'follow-up-018f1f9a-29a3-4b11-b6de-2f6f7f5b8c04'
const EVIDENCE_REQUEST_ID = 'evidence-request-018f1f9a-29a3-4b11-b6de-2f6f7f5b8c05'
const CANDIDATE_ID = `candidate-${'1'.repeat(64)}`

function contributionInput() {
  const evidenceArtifactIds = ['role-observation', 'source-trace']
  return {
    schemaVersion: 1,
    contributionId: CONTRIBUTION_ID,
    assessmentId: ASSESSMENT_ID,
    subjectDigest: structuredDigest('application/vnd.dsh.security.subject+json', {
      assessmentId: ASSESSMENT_ID,
    }),
    parentAttempt: {
      attemptId: ATTEMPT_ID,
      generation: 1,
      fenceDigest: structuredDigest(SOURCE_SLICE_EGRESS_ATTEMPT_FENCE_MEDIA_TYPE, {
        attemptId: ATTEMPT_ID,
        generation: 1,
      }),
    },
    contextGrantDigest: structuredDigest(ROLE_CONTEXT_GRANT_MEDIA_TYPE, {
      roleAttemptId: ATTEMPT_ID,
    }),
    roleDefinition: {
      roleId: 'discovery-analyst',
      roleVersion: '1.0.0',
      definitionDigest: structuredDigest('application/vnd.dsh.security.role-definition+json', {
        roleId: 'discovery-analyst',
        roleVersion: '1.0.0',
      }),
    },
    modelInvocations: [{
      invocationId: 'invocation-1',
      recordDigest: structuredDigest(MODEL_INVOCATION_RECORD_MEDIA_TYPE, {
        invocationId: 'invocation-1',
      }),
      responseDigest: binaryDigest('application/json', Buffer.from('{"ok":true}', 'utf8')),
      inputTokens: 120,
      outputTokens: 80,
    }],
    hypotheses: [{
      hypothesisId: 'hypothesis-install-script',
      securityClaim: 'The install lifecycle can execute repository-controlled code.',
      evidenceArtifactIds: ['role-observation'],
    }],
    candidateFindings: [{
      schemaVersion: 1,
      candidateId: CANDIDATE_ID,
      weaknessClassification: {
        schemaVersion: 1,
        primary: 'cwe/94',
        secondary: ['security/install-lifecycle'],
      },
      affectedControlId: 'security/node-package-lifecycle',
      securityClaim: 'A repository-controlled install script executes during installation.',
      sourceAnchors: [{
        path: 'package.json',
        fileDigest: binaryDigest('application/json', Buffer.from('{"scripts":{}}', 'utf8')),
        byteSpan: { start: 1, length: 12 },
        symbolId: '/scripts/preinstall',
      }],
      evidenceArtifactIds: ['source-trace'],
    }],
    coverageObservations: [{
      obligationId: 'security/install-lifecycle',
      state: 'SUPPORTED',
      evidenceArtifactIds: ['source-trace'],
      explanation: 'The exact manifest bytes contain the lifecycle key.',
    }],
    evidenceArtifactIds,
    evidenceRequests: [{
      requestId: EVIDENCE_REQUEST_ID,
      evidenceKindId: 'security/static-trace',
      purpose: 'Validate whether installation reaches the lifecycle script.',
      relatedCandidateIds: [CANDIDATE_ID],
    }],
    challenges: [{
      challengeId: 'challenge-install-path',
      targetCandidateId: CANDIDATE_ID,
      disposition: 'FOLLOW_UP_REQUESTED',
      evidenceArtifactIds: ['source-trace'],
      rationale: 'The execution path needs independent validation.',
    }],
    uncertainty: ['The package-manager configuration has not yet been validated.'],
    limitations: ['No network behavior was observed.'],
    followUpRequests: [{
      requestId: FOLLOW_UP_ID,
      unresolvedObligationId: 'security/install-lifecycle',
      requestedRoleId: 'validation-analyst',
      requiredCapabilityId: 'security/safe-reproducer',
      evidenceArtifactIds: ['source-trace'],
      reason: 'A separate validation attempt is required.',
    }],
    resourceUse: {
      requests: 1,
      inputTokens: 120,
      outputTokens: 80,
      tokens: 200,
    },
    completionDisposition: 'PARTIAL',
  }
}

function mutableCopy<T>(value: T): T {
  return structuredClone(value)
}

describe('ADR 0176 Role Contribution contract', () => {
  it('creates a bounded immutable proposal with exact protected lineage', () => {
    const contribution = createRoleContributionV1(contributionInput())

    expect(contribution.contributionDigest.mediaType).toBe(ROLE_CONTRIBUTION_MEDIA_TYPE)
    expect(parseRoleContributionV1(structuredClone(contribution))).toEqual(contribution)
    expect(Object.isFrozen(contribution)).toBe(true)
    expect(Object.isFrozen(contribution.candidateFindings[0]?.sourceAnchors[0])).toBe(true)
    expect(contribution.resourceUse).toEqual({
      requests: 1,
      inputTokens: 120,
      outputTokens: 80,
      tokens: 200,
    })
  })

  it('rejects digest tampering and authority-bearing output fields', () => {
    const contribution = createRoleContributionV1(contributionInput())
    const tampered = {
      ...structuredClone(contribution),
      limitations: ['The limitation was silently removed.'],
    }

    expect(() => parseRoleContributionV1(tampered)).toThrow(/digest is invalid/u)
    expect(() => createRoleContributionV1({
      ...contributionInput(),
      securityVerdict: 'SATISFIED',
    })).toThrow()
    expect(() => createRoleContributionV1({
      ...contributionInput(),
      riskAcceptance: { decision: 'ACCEPTED' },
    })).toThrow()
  })

  it('requires resource use to equal the exact Model Invocation lineage', () => {
    const wrongUsage = mutableCopy(contributionInput())
    wrongUsage.resourceUse.tokens += 1
    expect(() => createRoleContributionV1(wrongUsage)).toThrow(/resource use/u)

    const duplicateInvocation = mutableCopy(contributionInput())
    duplicateInvocation.modelInvocations.push(duplicateInvocation.modelInvocations[0]!)
    duplicateInvocation.resourceUse.requests = 2
    duplicateInvocation.resourceUse.inputTokens = 240
    duplicateInvocation.resourceUse.outputTokens = 160
    duplicateInvocation.resourceUse.tokens = 400
    expect(() => createRoleContributionV1(duplicateInvocation)).toThrow(/unique/u)
  })

  it('fails closed on undeclared Evidence and Candidate references', () => {
    const undeclaredEvidence = mutableCopy(contributionInput())
    undeclaredEvidence.hypotheses[0]!.evidenceArtifactIds[0] = 'hidden-evidence'
    expect(() => createRoleContributionV1(undeclaredEvidence)).toThrow(/declared Evidence/u)

    const undeclaredCandidate = mutableCopy(contributionInput())
    undeclaredCandidate.challenges[0]!.targetCandidateId = `candidate-${'2'.repeat(64)}`
    expect(() => createRoleContributionV1(undeclaredCandidate)).toThrow(/declared Candidates/u)
  })

  it('rejects ambiguous or out-of-range Source Anchors', () => {
    const traversal = mutableCopy(contributionInput())
    traversal.candidateFindings[0]!.sourceAnchors[0]!.path = '../package.json'
    expect(() => createRoleContributionV1(traversal)).toThrow(/Subject-relative paths/u)

    const drivePath = mutableCopy(contributionInput())
    drivePath.candidateFindings[0]!.sourceAnchors[0]!.path = 'C:/workspace/package.json'
    expect(() => createRoleContributionV1(drivePath)).toThrow(/Subject-relative paths/u)

    const globPath = mutableCopy(contributionInput())
    globPath.candidateFindings[0]!.sourceAnchors[0]!.path = 'src/*.ts'
    expect(() => createRoleContributionV1(globPath)).toThrow(/Subject-relative paths/u)

    const unsafeSpan = mutableCopy(contributionInput())
    unsafeSpan.candidateFindings[0]!.sourceAnchors[0]!.byteSpan = {
      start: Number.MAX_SAFE_INTEGER,
      length: 1,
    }
    expect(() => createRoleContributionV1(unsafeSpan)).toThrow(/safe range/u)
  })

  it('enforces the aggregate contribution byte budget', () => {
    const oversized = mutableCopy(contributionInput())
    const text = 'x'.repeat(2_048)
    oversized.hypotheses = Array.from({ length: 128 }, (_, index) => ({
      hypothesisId: `hypothesis-${index}`,
      securityClaim: text,
      evidenceArtifactIds: ['role-observation'],
    }))
    oversized.coverageObservations = Array.from({ length: 256 }, (_, index) => ({
      obligationId: `security/obligation-${index}`,
      state: 'UNRESOLVED',
      evidenceArtifactIds: ['source-trace'],
      explanation: text,
    }))
    oversized.uncertainty = Array.from({ length: 128 }, () => text)
    oversized.limitations = Array.from({ length: 128 }, () => text)

    expect(() => createRoleContributionV1(oversized)).toThrow(/aggregate byte budget/u)
  })
})
