import { describe, expect, it } from 'vitest'
import { createRoleContextGrantV1 } from '../src/role-context-grant.ts'
import { binaryDigest, structuredDigest } from '../src/internal/canonical.ts'
import {
  createRoleCandidateAdmissionsV1,
  parseRoleCandidateAdmissionV1,
  ROLE_CANDIDATE_ADMISSION_MEDIA_TYPE,
  ROLE_CANDIDATE_FINDING_MEDIA_TYPE,
  RoleCandidateAdmissionError,
} from '../src/internal/role-candidate-admission.ts'
import {
  createRoleContributionAdmissionLinkV1,
  createRoleContributionV1,
} from '../src/internal/role-contribution.ts'
import { MODEL_INVOCATION_RECORD_MEDIA_TYPE } from '../src/internal/model-invocation-settlement.ts'
import { SOURCE_SLICE_EGRESS_ATTEMPT_FENCE_MEDIA_TYPE } from '../src/internal/source-slice-egress-invocation.ts'

const ASSESSMENT_ID = 'asm-018f1f9a-29a3-7b11-b6de-2f6f7f5b8181' as const
const ATTEMPT_ID = 'role-attempt-018f1f9a-29a3-7b11-b6de-2f6f7f5b8181'
const CONTRIBUTION_ID = 'role-contribution-018f1f9a-29a3-4b11-b6de-2f6f7f5b8181'
const CANDIDATE_ID = `candidate-${'1'.repeat(64)}`
const SOURCE_TEXT = '{"scripts":{"preinstall":"node install.js"}}'
const SOURCE_DIGEST = binaryDigest('application/octet-stream', Buffer.from(SOURCE_TEXT, 'utf8'))
const SUBJECT_DIGEST = structuredDigest(
  'application/vnd.dsh.security.subject-manifest+json',
  { assessmentId: ASSESSMENT_ID },
)
const ROLE_DEFINITION = {
  roleId: 'discovery-analyst' as const,
  roleVersion: '1.0.0',
  definitionDigest: structuredDigest('application/vnd.dsh.security.role-definition+json', {
    roleId: 'discovery-analyst',
    roleVersion: '1.0.0',
  }),
}

function contextGrantInput(purposeId = 'security/deep-discovery') {
  return {
    schemaVersion: 1 as const,
    assessmentId: ASSESSMENT_ID,
    roleAttemptId: ATTEMPT_ID,
    roleDefinition: ROLE_DEFINITION,
    purpose: {
      purposeId,
      assessmentMode: 'REPOSITORY' as const,
      assessmentProfileId: 'security/deep',
      targetDigest: structuredDigest('application/vnd.dsh.security.target-selector+json', {
        kind: 'repository',
      }),
      coverageObligationIds: ['security/install-lifecycle'],
      constraintIds: ['security/read-only'],
      peerContributionVisibility: 'NONE' as const,
    },
    subject: {
      digest: SUBJECT_DIGEST,
      inventory: [{
        artifactId: 'subject-inventory',
        schemaId: 'dsh/security-subject-inventory',
        digest: structuredDigest('application/vnd.dsh.security.subject-inventory+json', {
          subjectDigest: SUBJECT_DIGEST,
        }),
        disclosureCategoryId: 'security/subject-inventory',
      }],
      sourceSlices: [{
        artifactId: 'source-slice-package-json',
        schemaId: 'dsh/security-source-slice',
        digest: structuredDigest('application/vnd.dsh.security.source-slice+json', {
          path: 'package.json',
          digest: SOURCE_DIGEST,
        }),
        disclosureCategoryId: 'security/source-slice',
      }],
    },
    evidenceProjections: [],
    disclosure: {
      dataEgressPolicyId: 'egress/deny-by-default',
      destinationId: 'provider/reference',
      categoryIds: ['security/source-slice', 'security/subject-inventory'],
    },
    budget: {
      contextBytes: { limit: 65_536, granted: 8_192 },
      tokens: { limit: 8_192, granted: 4_096 },
    },
  }
}

function fixture(candidateOverrides: Record<string, unknown> = {}) {
  const contextGrant = createRoleContextGrantV1(contextGrantInput())
  const sourceAnchor = {
    path: 'package.json',
    fileDigest: SOURCE_DIGEST,
    byteSpan: { start: 0, length: SOURCE_DIGEST.byteLength },
    symbolId: '/scripts/preinstall',
  }
  const candidate = {
    schemaVersion: 1,
    candidateId: CANDIDATE_ID,
    weaknessClassification: {
      schemaVersion: 1,
      primary: 'cwe/94',
      secondary: ['security/install-lifecycle'],
    },
    affectedControlId: 'security/node-package-lifecycle',
    securityClaim: 'A repository-controlled install script executes during installation.',
    sourceAnchors: [sourceAnchor],
    evidenceArtifactIds: ['source-trace'],
    ...candidateOverrides,
  }
  const contribution = createRoleContributionV1({
    schemaVersion: 1,
    contributionId: CONTRIBUTION_ID,
    assessmentId: ASSESSMENT_ID,
    subjectDigest: SUBJECT_DIGEST,
    parentAttempt: {
      attemptId: ATTEMPT_ID,
      generation: 1,
      fenceDigest: structuredDigest(SOURCE_SLICE_EGRESS_ATTEMPT_FENCE_MEDIA_TYPE, {
        attemptId: ATTEMPT_ID,
        generation: 1,
      }),
    },
    contextGrantDigest: contextGrant.grantDigest,
    roleDefinition: ROLE_DEFINITION,
    modelInvocations: [{
      invocationId: 'invocation-role-0181',
      recordDigest: structuredDigest(MODEL_INVOCATION_RECORD_MEDIA_TYPE, {
        invocationId: 'invocation-role-0181',
      }),
      responseDigest: binaryDigest('application/json', Buffer.from('{"ok":true}', 'utf8')),
      inputTokens: 120,
      outputTokens: 80,
    }],
    hypotheses: [],
    candidateFindings: [candidate],
    coverageObservations: [],
    evidenceArtifactIds: ['source-trace'],
    evidenceRequests: [],
    challenges: [],
    uncertainty: [],
    limitations: [],
    followUpRequests: [],
    resourceUse: {
      requests: 1,
      inputTokens: 120,
      outputTokens: 80,
      tokens: 200,
    },
    completionDisposition: 'PARTIAL',
  })
  const contributionAdmissionLink = createRoleContributionAdmissionLinkV1({
    contribution,
    assessmentRevision: 12,
    admittedAt: '2026-09-14T03:00:00.000Z',
  })
  return {
    contextGrant,
    contribution,
    contributionAdmissionLink,
    sourceSlices: [{
      contextArtifactId: 'source-slice-package-json',
      subjectDigest: SUBJECT_DIGEST,
      path: 'package.json',
      digest: SOURCE_DIGEST,
      text: SOURCE_TEXT,
    }],
    durableEvidenceArtifactIds: ['source-trace'],
    sourceAnchor,
  }
}

function admissionErrorCode(action: () => unknown): string | undefined {
  try {
    action()
  } catch (error) {
    expect(error).toBeInstanceOf(RoleCandidateAdmissionError)
    return (error as RoleCandidateAdmissionError).code
  }
  return undefined
}

describe('ADR 0181/0182 Role Candidate Admission', () => {
  it('creates a separate immutable admission bound to exact Candidate and producer lineage', () => {
    const values = fixture()
    const admissions = createRoleCandidateAdmissionsV1(values)
    const admission = admissions[0]!

    expect(admission).toMatchObject({
      schemaVersion: 1,
      state: 'ADMITTED',
      candidateId: CANDIDATE_ID,
      assessmentId: ASSESSMENT_ID,
      assessmentRevision: 12,
      subjectDigest: SUBJECT_DIGEST,
      provenance: {
        roleDefinition: ROLE_DEFINITION,
        parentAttempt: values.contribution.parentAttempt,
        contextGrantDigest: values.contextGrant.grantDigest,
        contributionId: CONTRIBUTION_ID,
        contributionDigest: values.contribution.contributionDigest,
        contributionAdmissionLinkDigest: values.contributionAdmissionLink.linkDigest,
      },
      weaknessClassification: values.contribution.candidateFindings[0]!.weaknessClassification,
      affectedControlId: 'security/node-package-lifecycle',
      securityClaim: 'A repository-controlled install script executes during installation.',
      sourceAnchors: [values.sourceAnchor],
      evidenceArtifactIds: ['source-trace'],
      admittedAt: '2026-09-14T03:00:00.000Z',
    })
    expect(admission.candidateDigest).toEqual(structuredDigest(
      ROLE_CANDIDATE_FINDING_MEDIA_TYPE,
      values.contribution.candidateFindings[0],
    ))
    expect(admission.admissionDigest.mediaType).toBe(ROLE_CANDIDATE_ADMISSION_MEDIA_TYPE)
    expect(parseRoleCandidateAdmissionV1(structuredClone(admission))).toEqual(admission)
    expect(Object.isFrozen(admissions)).toBe(true)
    expect(Object.isFrozen(admission.provenance.parentAttempt)).toBe(true)
    expect(Object.isFrozen(admission.sourceAnchors[0])).toBe(true)
    expect(admission).not.toHaveProperty('validationOutcome')
    expect(admission).not.toHaveProperty('findingId')
  })

  it('fails closed when the durable Contribution Admission Link is substituted', () => {
    const values = fixture()
    const otherContributionCore = structuredClone(values.contribution) as unknown as Record<string, unknown>
    delete otherContributionCore.contributionDigest
    otherContributionCore.contributionId =
      'role-contribution-018f1f9a-29a3-4b11-b6de-2f6f7f5b8182'
    const otherContribution = createRoleContributionV1(otherContributionCore)
    const otherLink = createRoleContributionAdmissionLinkV1({
      contribution: otherContribution,
      assessmentRevision: 12,
      admittedAt: '2026-09-14T03:00:00.000Z',
    })

    expect(admissionErrorCode(() => createRoleCandidateAdmissionsV1({
      ...values,
      contributionAdmissionLink: otherLink,
    }))).toBe('LINEAGE_MISMATCH')
  })

  it('fails closed when the Context Grant does not bind the Contribution', () => {
    const values = fixture()
    const otherContextGrant = createRoleContextGrantV1(contextGrantInput('security/other-purpose'))

    expect(admissionErrorCode(() => createRoleCandidateAdmissionsV1({
      ...values,
      contextGrant: otherContextGrant,
    }))).toBe('LINEAGE_MISMATCH')
  })

  it('rejects drifted, out-of-Subject, and out-of-range Source Anchors', () => {
    const values = fixture()
    expect(admissionErrorCode(() => createRoleCandidateAdmissionsV1({
      ...values,
      sourceSlices: [{ ...values.sourceSlices[0]!, text: `${SOURCE_TEXT} ` }],
    }))).toBe('SOURCE_MATERIAL_INVALID')
    expect(admissionErrorCode(() => createRoleCandidateAdmissionsV1({
      ...values,
      sourceSlices: [{
        ...values.sourceSlices[0]!,
        contextArtifactId: 'source-slice-not-granted',
      }],
    }))).toBe('SOURCE_MATERIAL_INVALID')

    const wrongPath = fixture({
      sourceAnchors: [{ ...values.sourceAnchor, path: 'install.js' }],
    })
    expect(admissionErrorCode(() => createRoleCandidateAdmissionsV1(wrongPath)))
      .toBe('SOURCE_ANCHOR_UNBOUND')

    const outOfRange = fixture({
      sourceAnchors: [{
        ...values.sourceAnchor,
        byteSpan: { start: SOURCE_DIGEST.byteLength, length: 1 },
      }],
    })
    expect(admissionErrorCode(() => createRoleCandidateAdmissionsV1(outOfRange)))
      .toBe('SOURCE_ANCHOR_UNBOUND')
  })

  it('requires every Candidate Evidence reference to name a durable object', () => {
    const values = fixture()

    expect(admissionErrorCode(() => createRoleCandidateAdmissionsV1({
      ...values,
      durableEvidenceArtifactIds: [],
    }))).toBe('EVIDENCE_UNAVAILABLE')
    expect(admissionErrorCode(() => createRoleCandidateAdmissionsV1({
      ...values,
      durableEvidenceArtifactIds: ['source-trace', 'source-trace'],
    }))).toBe('EVIDENCE_UNAVAILABLE')
  })

  it('rejects ambiguous anchors and weakness identities before validation', () => {
    const values = fixture()
    const duplicateAnchor = fixture({
      sourceAnchors: [values.sourceAnchor, values.sourceAnchor],
    })
    expect(admissionErrorCode(() => createRoleCandidateAdmissionsV1(duplicateAnchor)))
      .toBe('CANDIDATE_AMBIGUOUS')

    const duplicateWeakness = fixture({
      weaknessClassification: {
        schemaVersion: 1,
        primary: 'cwe/94',
        secondary: ['cwe/94'],
      },
    })
    expect(admissionErrorCode(() => createRoleCandidateAdmissionsV1(duplicateWeakness)))
      .toBe('CANDIDATE_AMBIGUOUS')
  })

  it('recomputes Candidate and Admission digests before downstream use', () => {
    const admission = createRoleCandidateAdmissionsV1(fixture())[0]!

    expect(() => parseRoleCandidateAdmissionV1({
      ...structuredClone(admission),
      securityClaim: 'The claim was silently changed.',
    })).toThrow(/digest/iu)
    expect(() => parseRoleCandidateAdmissionV1({
      ...structuredClone(admission),
      candidateDigest: structuredDigest(ROLE_CANDIDATE_FINDING_MEDIA_TYPE, {
        candidateId: admission.candidateId,
      }),
    })).toThrow(/Candidate/iu)
    expect(() => parseRoleCandidateAdmissionV1({
      ...structuredClone(admission),
      admissionDigest: {
        ...admission.admissionDigest,
        value: '0'.repeat(64),
      },
    })).toThrow(/Admission digest/iu)
  })
})
