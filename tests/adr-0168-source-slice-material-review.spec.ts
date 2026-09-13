import LocalSubprocessRuntime from '@deepseek-ai/dsh-subprocess-local'
import { Context } from '@deepseek-ai/cordis'
import { execFile } from 'node:child_process'
import { mkdtemp, mkdir, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { promisify } from 'node:util'
import { afterEach, describe, expect, it } from 'vitest'
import {
  createRoleContextGrantV1,
  createSourceSliceRequestV1,
} from '../src/index.ts'
import type {
  AnalyzerPortfolioEntryV1,
} from '../src/analyzer.ts'
import { analyzerContributionV1Schema } from '../src/analyzer.ts'
import { binaryDigest, structuredDigest } from '../src/internal/canonical.ts'
import type {
  SourceSliceEgressBrokerRequestV1,
} from '../src/internal/source-slice-egress-invocation.ts'
import {
  issueAttemptScopedSourceSliceEgressCapability,
  parseSourceSliceEgressInvocationReceipt,
  SOURCE_SLICE_EGRESS_INVOCATION_RECEIPT_MEDIA_TYPE,
} from '../src/internal/source-slice-egress-invocation.ts'
import {
  createModelInvocationBudgetReservationV1,
  settleSourceSliceModelInvocationV1,
} from '../src/internal/model-invocation-settlement.ts'
import {
  parseProtectedSourceSliceMaterialReview,
  reviewRequestedSourceSliceMaterial,
  SOURCE_SLICE_MATERIAL_REVIEW_MEDIA_TYPE,
} from '../src/internal/source-slice-material-review.ts'
import {
  redactProtectedSourceSliceSecrets,
} from '../src/internal/source-slice-protection.ts'
import {
  admitQualifiedSourceSliceSecretReview,
  SOURCE_SLICE_SECRET_REVIEW_CONTRACT_ID,
  SOURCE_SLICE_SECRET_REVIEW_EVIDENCE_MEDIA_TYPE,
  SOURCE_SLICE_SECRET_REVIEW_EVIDENCE_SCHEMA_ID,
  SOURCE_SLICE_SECRET_REVIEW_INDEPENDENCE_MEDIA_TYPE,
  SOURCE_SLICE_SECRET_REVIEW_OBLIGATION_ID,
  SOURCE_SLICE_SECRET_REVIEW_POLICY_ID,
} from '../src/internal/source-slice-secret-review.ts'
import {
  freezeSubject,
  readVerifiedRequestedSourceSlice,
} from '../src/internal/subject-freeze.ts'
import { removeTemporaryRoots } from './support/remove-temporary-root.ts'

const run = promisify(execFile)
const temporaryRoots: string[] = []
const fingerprintKey = new Uint8Array(32).fill(17)
const sourceText = 'password = "correct-horse-battery-staple"\nexport const answer = 42\n'

afterEach(async () => {
  await removeTemporaryRoots(temporaryRoots)
})

async function materialReviewFixture(dataEgressPolicyId = 'egress/deny-by-default') {
  const repositoryRoot = await mkdtemp(join(tmpdir(), 'dsh-material-review-repository-'))
  const securityRoot = await mkdtemp(join(tmpdir(), 'dsh-material-review-security-'))
  temporaryRoots.push(repositoryRoot, securityRoot)
  await run('git', ['init', '-b', 'main'], { cwd: repositoryRoot })
  await run('git', ['config', 'user.email', 'fixture@example.invalid'], { cwd: repositoryRoot })
  await run('git', ['config', 'user.name', 'Fixture'], { cwd: repositoryRoot })
  await mkdir(join(repositoryRoot, 'src'))
  await writeFile(join(repositoryRoot, 'src', 'provider.ts'), sourceText, 'utf8')
  await run('git', ['add', '.'], { cwd: repositoryRoot })
  await run('git', ['commit', '-m', 'material review fixture'], { cwd: repositoryRoot })
  const commit = (await run('git', ['rev-parse', 'HEAD'], { cwd: repositoryRoot })).stdout.trim()
  const context = new Context()
  const subprocessFiber = await context.plugin(LocalSubprocessRuntime)
  const frozen = await freezeSubject({
    subprocess: context.subprocess,
    repositoryRoot,
    securityRoot,
    source: { kind: 'git_revision', commit },
    target: { kind: 'targeted', relativePaths: ['src/provider.ts'] },
  })
  const assessmentId = 'asm-00000000-0000-0000-0000-000000000168'
  const roleAttemptId = 'role-attempt-00000000-0000-0000-0000-000000000168'
  const contextGrant = createRoleContextGrantV1({
    schemaVersion: 1,
    assessmentId,
    roleAttemptId,
    roleDefinition: {
      roleId: 'discovery-analyst',
      roleVersion: '1.0.0',
      definitionDigest: structuredDigest(
        'application/vnd.dsh.security.role-definition+json',
        { role: 'discovery-analyst' },
      ),
    },
    purpose: {
      purposeId: 'security/deep-discovery',
      assessmentMode: 'TARGETED',
      assessmentProfileId: 'security/deep',
      targetDigest: frozen.targetDigest,
      coverageObligationIds: ['security/source-review'],
      constraintIds: ['security/read-only'],
      peerContributionVisibility: 'NONE',
    },
    subject: {
      digest: frozen.manifestDigest,
      inventory: [{
        artifactId: 'inventory-material-review-0168',
        schemaId: 'dsh/security-subject-inventory',
        digest: structuredDigest(
          'application/vnd.dsh.security.subject-inventory+json',
          { inventory: 'material-review-0168' },
        ),
        disclosureCategoryId: 'security/subject-inventory',
      }],
      sourceSlices: [],
    },
    evidenceProjections: [],
    disclosure: {
      dataEgressPolicyId,
      destinationId: 'provider/reference',
      categoryIds: ['security/source-slice', 'security/subject-inventory'],
    },
    budget: {
      contextBytes: { limit: 65_536, granted: 0 },
      tokens: { limit: 8_192, granted: 0 },
    },
  })
  const request = createSourceSliceRequestV1({
    schemaVersion: 1,
    requestId: 'slice-request-00000000-0000-0000-0000-000000000168',
    assessmentId,
    roleAttemptId,
    contextGrantDigest: contextGrant.grantDigest,
    subjectDigest: frozen.manifestDigest,
    purpose: {
      purposeId: 'security/deep-discovery',
      coverageObligationId: 'security/source-review',
      needId: 'security/trace-data-flow',
    },
    target: {
      path: 'src/provider.ts',
      expectedSourceDigest: binaryDigest(
        'application/octet-stream',
        Buffer.from(sourceText, 'utf8'),
      ),
    },
    disclosure: {
      dataEgressPolicyId,
      destinationId: 'provider/reference',
      categoryId: 'security/source-slice',
    },
    budget: { contextBytes: 512, tokens: 128 },
  })
  return { contextGrant, request, securityRoot, subprocessFiber }
}

async function qualifiedSecretReview(
  fixture: Awaited<ReturnType<typeof materialReviewFixture>>,
  overrides: {
    readonly decision?: 'CLEAR' | 'SECRET_FOUND' | 'INDETERMINATE'
    readonly qualificationExpiresAt?: string
    readonly qualificationPolicyId?: string
    readonly driftRedactedDigest?: boolean
    readonly omitIndependenceQualification?: boolean
  } = {},
) {
  const material = await readVerifiedRequestedSourceSlice({
    securityRoot: fixture.securityRoot,
    contextGrant: fixture.contextGrant,
    request: fixture.request,
  })
  const redaction = redactProtectedSourceSliceSecrets({
    material,
    fingerprintKey,
    fingerprintKeyId: 'host/secret-fingerprint-key-1',
  })
  const reviewedAt = '2026-09-12T00:00:00.000Z'
  const buildDigest = structuredDigest(
    'application/vnd.dsh.security.analyzer-method+json',
    { method: 'independent-source-slice-secret-review-v1' },
  )
  const independenceEvidenceDigest = structuredDigest(
    SOURCE_SLICE_SECRET_REVIEW_INDEPENDENCE_MEDIA_TYPE,
    { suite: 'source-slice-secret-review-independent-negative-controls-v1' },
  )
  const analyzerIdentity = {
    analyzerId: 'fixture/independent-secret-reviewer',
    analyzerVersion: '1.0.0',
    descriptorSchemaVersion: 1 as const,
    buildDigest,
  }
  const descriptor = {
    schemaVersion: 1 as const,
    ...analyzerIdentity,
    executionClass: 'PURE' as const,
    supportedAssessmentModes: ['TARGETED'] as const,
    supportedPolicyIds: [overrides.qualificationPolicyId ?? SOURCE_SLICE_SECRET_REVIEW_POLICY_ID],
    coverageObligationIds: [SOURCE_SLICE_SECRET_REVIEW_OBLIGATION_ID],
    evidenceSchemaIds: [SOURCE_SLICE_SECRET_REVIEW_EVIDENCE_SCHEMA_ID],
    egress: 'NONE' as const,
  }
  const qualificationCore = {
    schemaVersion: 1 as const,
    qualificationId: 'fixture/independent-secret-reviewer/v1',
    analyzerIdentity,
    issuerId: 'fixture/security-host',
    level: 'HOST_ATTESTED' as const,
    supportedEcosystemIds: ['source-slice-redacted-text'],
    supportedAssessmentModes: ['TARGETED'] as const,
    supportedPolicyIds: [SOURCE_SLICE_SECRET_REVIEW_POLICY_ID],
    coverageObligationIds: [SOURCE_SLICE_SECRET_REVIEW_OBLIGATION_ID],
    evidenceSchemaIds: [SOURCE_SLICE_SECRET_REVIEW_EVIDENCE_SCHEMA_ID],
    executionClass: 'PURE' as const,
    executionBackendId: 'dsh/security-assurance/in-process-pure-v1',
    providerIds: ['dsh-security-assurance'],
    egress: 'NONE' as const,
    platforms: ['win32'] as const,
    issuedAt: '2026-01-01T00:00:00.000Z',
    expiresAt: overrides.qualificationExpiresAt ?? '2027-01-01T00:00:00.000Z',
    evidenceDigests: overrides.omitIndependenceQualification
      ? [buildDigest]
      : [buildDigest, independenceEvidenceDigest],
    limitations: ['Reviews one exact redacted Source Slice only.'],
  }
  const qualification = {
    ...qualificationCore,
    qualificationDigest: structuredDigest(
      'application/vnd.dsh.security.analyzer-qualification+json',
      qualificationCore,
    ),
  }
  const portfolioEntry = {
    descriptor,
    qualification,
    eligibility: {
      schemaVersion: 1 as const,
      decision: 'ELIGIBLE' as const,
      reason: null,
      evaluatedAt: reviewedAt,
      analyzerIdentity,
      qualificationId: qualification.qualificationId,
      qualificationDigest: qualification.qualificationDigest,
      policyId: SOURCE_SLICE_SECRET_REVIEW_POLICY_ID,
      assessmentMode: 'TARGETED' as const,
      platform: 'win32' as const,
    },
  } satisfies AnalyzerPortfolioEntryV1
  const decision = overrides.decision ?? 'CLEAR'
  const completion = decision === 'INDETERMINATE' ? 'INCOMPLETE' as const : 'COMPLETE' as const
  const evidence = {
    schemaVersion: 1 as const,
    contractId: SOURCE_SLICE_SECRET_REVIEW_CONTRACT_ID,
    reviewedAt,
    scope: 'EXACT_REDACTED_SOURCE_SLICE' as const,
    requestDigest: material.requestDigest,
    subjectDigest: material.subjectDigest,
    sourceDigest: material.digest,
    path: material.path,
    redactionDigest: redaction.redactionDigest,
    redactedDigest: overrides.driftRedactedDigest
      ? { ...redaction.redactedDigest, value: '0'.repeat(64) }
      : redaction.redactedDigest,
    independenceEvidenceDigest,
    completion,
    decision,
    findingCount: decision === 'SECRET_FOUND' ? 1 : 0,
  }
  const contribution = analyzerContributionV1Schema.parse({
    schemaVersion: 1 as const,
    analyzerIdentity,
    subjectDigest: redaction.redactedDigest,
    completionDisposition: completion,
    coverageClaims: completion === 'COMPLETE' ? [{
      obligationId: SOURCE_SLICE_SECRET_REVIEW_OBLIGATION_ID,
      completion: 'COMPLETE' as const,
      evidenceArtifactId: 'source-slice-secret-review',
    }] : [],
    candidateFindings: [],
    evidence: [{
      artifactId: 'source-slice-secret-review',
      schemaId: SOURCE_SLICE_SECRET_REVIEW_EVIDENCE_SCHEMA_ID,
      mediaType: SOURCE_SLICE_SECRET_REVIEW_EVIDENCE_MEDIA_TYPE,
      value: evidence,
    }],
    diagnostics: completion === 'COMPLETE' ? [] : ['SECRET_REVIEW_INCOMPLETE'],
    resourceUse: {
      filesRead: 1,
      bytesRead: redaction.redactedDigest.byteLength,
    },
  })
  const admission = { portfolioEntry, contribution }
  const admitted = admitQualifiedSourceSliceSecretReview({
    material,
    redaction,
    assessmentMode: fixture.contextGrant.purpose.assessmentMode,
    ...admission,
  })
  return { admission, admitted, material, redaction }
}

function qualifiedEgressAuthorization(
  fixture: Awaited<ReturnType<typeof materialReviewFixture>>,
  secretReview: Awaited<ReturnType<typeof qualifiedSecretReview>>,
  overrides: {
    readonly qualificationExpiresAt?: string
    readonly providerId?: string
    readonly destinationId?: string
    readonly requestByteLimit?: number
    readonly auditPolicyId?: string
    readonly timeoutMilliseconds?: number
    readonly authorizationExpiresAt?: string
  } = {},
) {
  const evaluatedAt = '2026-09-12T00:05:00.000Z'
  const brokerIdentity = {
    brokerId: 'fixture/model-invoker',
    brokerVersion: '1.0.0',
    implementationDigest: structuredDigest(
      'application/vnd.dsh.security.egress-broker-implementation+json',
      { implementation: 'fixture-model-invoker-v1' },
    ),
  }
  const brokerQualificationCore = {
    schemaVersion: 1 as const,
    qualificationId: 'fixture/model-invoker/qualification-v1',
    brokerIdentity,
    issuerId: 'fixture/security-host',
    level: 'HOST_ATTESTED' as const,
    providerIds: ['provider/reference'],
    dataEgressPolicyIds: ['egress/host-qualified-v1'],
    destinationIds: ['provider/reference'],
    categoryIds: ['security/source-slice'],
    maximumRequestBytes: 512,
    maximumRequestCount: 1,
    maximumTimeoutMilliseconds: 30_000,
    auditPolicyIds: ['audit/source-slice-egress-v1'],
    issuedAt: '2026-01-01T00:00:00.000Z',
    expiresAt: overrides.qualificationExpiresAt ?? '2027-01-01T00:00:00.000Z',
    evidenceDigests: [structuredDigest(
      'application/vnd.dsh.security.egress-broker-conformance+json',
      { suite: 'fixture-model-invoker-conformance-v1' },
    )],
    limitations: ['One exact pre-authorized Source Slice per invocation.'],
  }
  const brokerQualification = {
    ...brokerQualificationCore,
    qualificationDigest: structuredDigest(
      'application/vnd.dsh.security.egress-broker-qualification+json',
      brokerQualificationCore,
    ),
  }
  const destinationAuthorizationCore = {
    schemaVersion: 1 as const,
    authorizationId: 'fixture/source-slice-destination-authorization-v1',
    issuerId: 'fixture/security-host',
    level: 'HOST_AUTHORIZED' as const,
    contextGrantDigest: fixture.contextGrant.grantDigest,
    requestDigest: fixture.request.requestDigest,
    subjectDigest: secretReview.material.subjectDigest,
    sourceDigest: secretReview.material.digest,
    path: secretReview.material.path,
    redactionDigest: secretReview.redaction.redactionDigest,
    redactedDigest: secretReview.redaction.redactedDigest,
    secretReviewDigest: secretReview.admitted.secretReviewDigest,
    brokerQualificationDigest: brokerQualification.qualificationDigest,
    brokerId: brokerIdentity.brokerId,
    providerId: overrides.providerId ?? 'provider/reference',
    credentialBindingId: 'credential/model-provider-reference-v1',
    dataEgressPolicyId: fixture.request.disclosure.dataEgressPolicyId,
    destinationId: overrides.destinationId ?? fixture.request.disclosure.destinationId,
    categoryId: fixture.request.disclosure.categoryId,
    requestByteLimit: overrides.requestByteLimit ?? fixture.request.budget.contextBytes,
    requestCountLimit: 1,
    timeoutMilliseconds: overrides.timeoutMilliseconds ?? 30_000,
    auditPolicyId: overrides.auditPolicyId ?? 'audit/source-slice-egress-v1',
    authorizedAt: '2026-09-12T00:00:00.000Z',
    expiresAt: overrides.authorizationExpiresAt ?? '2026-09-12T00:10:00.000Z',
  }
  return {
    brokerQualification,
    destinationAuthorization: {
      ...destinationAuthorizationCore,
      authorizationDigest: structuredDigest(
        'application/vnd.dsh.security.source-slice-destination-authorization+json',
        destinationAuthorizationCore,
      ),
    },
    evaluatedAt,
  }
}

describe('ADR 0168 protected Source Slice material review record', () => {
  it('satisfies secret redaction only with exact qualified independent CLEAR evidence', async () => {
    const fixture = await materialReviewFixture()
    try {
      const secretReview = await qualifiedSecretReview(fixture)
      const review = await reviewRequestedSourceSliceMaterial({
        securityRoot: fixture.securityRoot,
        contextGrant: fixture.contextGrant,
        request: fixture.request,
        fingerprintKey,
        fingerprintKeyId: 'host/secret-fingerprint-key-1',
        secretReview: secretReview.admission,
      })
      const bindings = {
        contextGrantDigest: fixture.contextGrant.grantDigest,
        requestDigest: fixture.request.requestDigest,
        subjectDigest: fixture.request.subjectDigest,
        secretReview: secretReview.admitted,
      }

      expect(review.checks.find(check => check.check === 'SECRET_REDACTION')).toEqual({
        check: 'SECRET_REDACTION',
        status: 'SATISFIED',
        reasonCodes: [],
      })
      expect(review.secretReview).toEqual(secretReview.admitted)
      expect(parseProtectedSourceSliceMaterialReview(review, bindings)).toEqual(review)
      expect(() => parseProtectedSourceSliceMaterialReview(review, {
        ...bindings,
        secretReview: undefined,
      })).toThrow(/secret review/iu)
      expect(JSON.stringify(review)).not.toContain('correct-horse-battery-staple')
    } finally {
      await fixture.subprocessFiber.dispose()
    }
  })

  it('carries qualified CLEAR review into Data Egress without approving Broker or destination', async () => {
    const fixture = await materialReviewFixture('egress/host-qualified-v1')
    try {
      const secretReview = await qualifiedSecretReview(fixture)
      const review = await reviewRequestedSourceSliceMaterial({
        securityRoot: fixture.securityRoot,
        contextGrant: fixture.contextGrant,
        request: fixture.request,
        fingerprintKey,
        fingerprintKeyId: 'host/secret-fingerprint-key-1',
        secretReview: secretReview.admission,
      })

      expect(review.decision).toBe('ADDITIONAL_REVIEW_REQUIRED')
      expect(review.checks.find(check => check.check === 'DATA_EGRESS')).toEqual({
        check: 'DATA_EGRESS',
        status: 'REVIEW_REQUIRED',
        reasonCodes: [
          'BROKER_QUALIFICATION_REQUIRED',
          'DESTINATION_AUTHORIZATION_REQUIRED',
        ],
      })
      expect(JSON.stringify(review)).not.toMatch(/APPROVED|AUTHORIZED|GRANTED/iu)
    } finally {
      await fixture.subprocessFiber.dispose()
    }
  })

  it('advances exact qualified Broker and destination Evidence only to Broker invocation', async () => {
    const fixture = await materialReviewFixture('egress/host-qualified-v1')
    try {
      const secretReview = await qualifiedSecretReview(fixture)
      const review = await reviewRequestedSourceSliceMaterial({
        securityRoot: fixture.securityRoot,
        contextGrant: fixture.contextGrant,
        request: fixture.request,
        fingerprintKey,
        fingerprintKeyId: 'host/secret-fingerprint-key-1',
        secretReview: secretReview.admission,
        egressAuthorization: qualifiedEgressAuthorization(fixture, secretReview),
      })

      expect(review.decision).toBe('ADDITIONAL_REVIEW_REQUIRED')
      expect(review.egressDecision).toBe('BROKER_INVOCATION_REQUIRED')
      expect(review.checks.find(check => check.check === 'DATA_EGRESS')).toEqual({
        check: 'DATA_EGRESS',
        status: 'REVIEW_REQUIRED',
        reasonCodes: ['BROKER_INVOCATION_REQUIRED'],
      })
      const bindings = {
        contextGrantDigest: fixture.contextGrant.grantDigest,
        requestDigest: fixture.request.requestDigest,
        subjectDigest: fixture.request.subjectDigest,
        secretReview: secretReview.admitted,
        egressAuthorization: review.egressAuthorization!,
      }
      expect(parseProtectedSourceSliceMaterialReview(review, bindings)).toEqual(review)
      expect(() => parseProtectedSourceSliceMaterialReview(review, {
        ...bindings,
        egressAuthorization: undefined,
      })).toThrow(/egress authorization/iu)
      expect(() => parseProtectedSourceSliceMaterialReview({
        ...review,
        egressAuthorization: {
          ...review.egressAuthorization!,
          providerId: 'provider/forged',
        },
      }, bindings)).toThrow(/egress authorization|digest/iu)
      expect(JSON.stringify(review)).not.toMatch(/APPROVED|AUTHORIZED|GRANTED/iu)
      expect(JSON.stringify(review)).not.toContain(sourceText)
    } finally {
      await fixture.subprocessFiber.dispose()
    }
  })

  it('invokes one exact redacted Slice and settles its protected Model Invocation lineage', async () => {
    const fixture = await materialReviewFixture('egress/host-qualified-v1')
    try {
      const secretReview = await qualifiedSecretReview(fixture)
      const egressEvidence = qualifiedEgressAuthorization(fixture, secretReview)
      const requests: SourceSliceEgressBrokerRequestV1[] = []
      const times = [
        '2026-09-12T00:05:00.000Z',
        '2026-09-12T00:05:01.000Z',
        '2026-09-12T00:05:02.000Z',
      ]
      const issued = issueAttemptScopedSourceSliceEgressCapability({
        invocationId: 'egress-invocation-00000000-0000-0000-0000-000000000168',
        attempt: {
          attemptId: fixture.contextGrant.roleAttemptId,
          generation: 1,
          fencingToken: 'fence/role-attempt-0168/generation-1',
          deadlineAt: '2026-09-12T00:06:00.000Z',
        },
        contextGrant: fixture.contextGrant,
        request: fixture.request,
        material: secretReview.material,
        redaction: secretReview.redaction,
        secretReview: secretReview.admitted,
        ...egressEvidence,
        broker: {
          identity: egressEvidence.brokerQualification.brokerIdentity,
          async invoke(request) {
            requests.push(request)
            return {
              schemaVersion: 1,
              brokerIdentity: egressEvidence.brokerQualification.brokerIdentity,
              providerId: 'provider/reference',
              destinationId: 'provider/reference',
              providerRequestId: 'provider-request/fixture-0168',
              backendId: 'backend/reference',
              deploymentId: 'deployment/reference',
              modelId: 'model/reference',
              response: { mediaType: 'text/plain', text: 'bounded analysis result' },
              usage: {
                requestCount: 1,
                requestBytes: secretReview.redaction.redactedDigest.byteLength,
                inputTokens: 32,
                outputTokens: 8,
              },
              finishReason: 'STOP',
              diagnostics: [],
            }
          },
        },
        now: () => times.shift()!,
      })

      const result = await issued.capability.invoke()

      expect(result.status).toBe('COMPLETED')
      expect(result.receipt.receiptDigest.mediaType)
        .toBe(SOURCE_SLICE_EGRESS_INVOCATION_RECEIPT_MEDIA_TYPE)
      expect(result.response?.text).toBe('bounded analysis result')
      expect(requests).toHaveLength(1)
      expect(requests[0]?.content.text).toBe(secretReview.redaction.redactedText)
      expect(requests[0]?.content.text).not.toContain('correct-horse-battery-staple')
      expect(requests[0]?.dataEgressPolicyId).toBe('egress/host-qualified-v1')
      expect(JSON.stringify(result.receipt)).not.toContain('bounded analysis result')
      expect(JSON.stringify(result.receipt)).not.toContain(sourceText)
      expect(parseSourceSliceEgressInvocationReceipt(result.receipt, {
        invocationId: requests[0]!.invocationId,
        attemptId: requests[0]!.attemptId,
        attemptGeneration: requests[0]!.attemptGeneration,
        attemptFenceDigest: requests[0]!.attemptFenceDigest,
        egressAuthorizationDigest: requests[0]!.egressAuthorizationDigest,
        brokerRequestDigest: requests[0]!.brokerRequestDigest,
      })).toEqual(result.receipt)
      const reservation = createModelInvocationBudgetReservationV1({
        schemaVersion: 1,
        reservationId: 'reservation/source-slice-invocation-0168',
        invocationId: requests[0]!.invocationId,
        attemptId: requests[0]!.attemptId,
        attemptGeneration: requests[0]!.attemptGeneration,
        attemptFenceDigest: requests[0]!.attemptFenceDigest,
        contextGrantDigest: fixture.contextGrant.grantDigest,
        egressAuthorizationDigest: requests[0]!.egressAuthorizationDigest,
        brokerRequestDigest: requests[0]!.brokerRequestDigest,
        requestLimit: 1,
        tokenLimit: requests[0]!.limits.tokenLimit,
        reservedAt: requests[0]!.issuedAt,
        deadlineAt: requests[0]!.deadlineAt,
      })
      const invocationRecord = settleSourceSliceModelInvocationV1({
        contextGrant: fixture.contextGrant,
        reservation,
        receipt: result.receipt,
        lineage: {
          provider: { movingProvider: false },
          prompt: {
            promptId: 'security/deep-discovery',
            promptVersion: '1.0.0',
            promptDigest: structuredDigest(
              'application/vnd.dsh.security.role-prompt+json',
              { prompt: 'fixture-0168' },
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
        },
      })
      expect(invocationRecord.budgetSettlement).toMatchObject({
        requestsUsed: 1,
        tokenLimit: 128,
        tokensUsed: 40,
        tokensReleased: 88,
      })
      expect(invocationRecord.receiptDigest).toEqual(result.receipt.receiptDigest)
      expect(JSON.stringify(invocationRecord)).not.toContain('bounded analysis result')
      expect(JSON.stringify(invocationRecord)).not.toContain(sourceText)
      expect(() => parseSourceSliceEgressInvocationReceipt({
        ...result.receipt,
        responseDigest: { ...result.receipt.responseDigest!, value: '0'.repeat(64) },
      }, {
        invocationId: requests[0]!.invocationId,
        attemptId: requests[0]!.attemptId,
        attemptGeneration: requests[0]!.attemptGeneration,
        attemptFenceDigest: requests[0]!.attemptFenceDigest,
        egressAuthorizationDigest: requests[0]!.egressAuthorizationDigest,
        brokerRequestDigest: requests[0]!.brokerRequestDigest,
      })).toThrow(/receipt|digest/iu)
      const { receiptDigest: _receiptDigest, ...forgedUsageCore } = {
        ...result.receipt,
        usage: { ...result.receipt.usage!, outputTokens: 129 },
      }
      expect(() => parseSourceSliceEgressInvocationReceipt({
        ...forgedUsageCore,
        receiptDigest: structuredDigest(
          SOURCE_SLICE_EGRESS_INVOCATION_RECEIPT_MEDIA_TYPE,
          forgedUsageCore,
        ),
      }, {
        invocationId: requests[0]!.invocationId,
        attemptId: requests[0]!.attemptId,
        attemptGeneration: requests[0]!.attemptGeneration,
        attemptFenceDigest: requests[0]!.attemptFenceDigest,
        egressAuthorizationDigest: requests[0]!.egressAuthorizationDigest,
        brokerRequestDigest: requests[0]!.brokerRequestDigest,
      })).toThrow(/receipt|usage|quota/iu)
      expect(JSON.stringify(issued.capability)).toBe('{}')
      await expect(issued.capability.invoke()).rejects.toThrow(/consumed/iu)
    } finally {
      await fixture.subprocessFiber.dispose()
    }
  })

  it('fails closed with bounded receipts when the Broker response drifts scope or usage', async () => {
    const fixture = await materialReviewFixture('egress/host-qualified-v1')
    try {
      const secretReview = await qualifiedSecretReview(fixture)
      const egressEvidence = qualifiedEgressAuthorization(fixture, secretReview)
      const baseResponse = {
        schemaVersion: 1 as const,
        brokerIdentity: egressEvidence.brokerQualification.brokerIdentity,
        providerId: 'provider/reference',
        destinationId: 'provider/reference',
        providerRequestId: 'provider-request/fixture-0168',
        backendId: 'backend/reference',
        deploymentId: 'deployment/reference',
        modelId: 'model/reference',
        response: { mediaType: 'text/plain', text: 'broker response must not enter a failed receipt' },
        usage: {
          requestCount: 1 as const,
          requestBytes: secretReview.redaction.redactedDigest.byteLength,
          inputTokens: 32,
          outputTokens: 8,
        },
        finishReason: 'STOP' as const,
        diagnostics: [] as const,
      }
      const cases = [
        {
          name: 'Provider drift',
          expectedFailure: 'BROKER_RESPONSE_SCOPE_MISMATCH',
          response: { ...baseResponse, providerId: 'provider/other' },
        },
        {
          name: 'token expansion',
          expectedFailure: 'BROKER_USAGE_EXCEEDED',
          response: { ...baseResponse, usage: { ...baseResponse.usage, outputTokens: 129 } },
        },
        {
          name: 'invalid response',
          expectedFailure: 'BROKER_RESPONSE_INVALID',
          response: { ...baseResponse, diagnostics: ['unbounded broker detail'] },
        },
      ] as const

      for (const [index, testCase] of cases.entries()) {
        const requests: SourceSliceEgressBrokerRequestV1[] = []
        const times = [
          '2026-09-12T00:05:00.000Z',
          '2026-09-12T00:05:01.000Z',
          '2026-09-12T00:05:02.000Z',
        ]
        const issued = issueAttemptScopedSourceSliceEgressCapability({
          invocationId: `egress-invocation-00000000-0000-0000-0000-00000000017${index}`,
          attempt: {
            attemptId: fixture.contextGrant.roleAttemptId,
            generation: index + 1,
            fencingToken: `fence/role-attempt-0168/generation-${index + 1}`,
            deadlineAt: '2026-09-12T00:06:00.000Z',
          },
          contextGrant: fixture.contextGrant,
          request: fixture.request,
          material: secretReview.material,
          redaction: secretReview.redaction,
          secretReview: secretReview.admitted,
          ...egressEvidence,
          broker: {
            identity: egressEvidence.brokerQualification.brokerIdentity,
            async invoke(request) {
              requests.push(request)
              return testCase.response as never
            },
          },
          now: () => times.shift()!,
        })

        const result = await issued.capability.invoke()

        expect(result.status, testCase.name).toBe('FAILED')
        expect(result.response, testCase.name).toBeNull()
        expect(result.receipt.failureCode, testCase.name).toBe(testCase.expectedFailure)
        expect(result.receipt.diagnosticCodes, testCase.name).toEqual([testCase.expectedFailure])
        expect(JSON.stringify(result.receipt), testCase.name)
          .not.toContain('broker response must not enter a failed receipt')
        expect(requests, testCase.name).toHaveLength(1)
        await expect(issued.capability.invoke()).rejects.toThrow(/consumed/iu)
      }
    } finally {
      await fixture.subprocessFiber.dispose()
    }
  })

  it('fences a Broker result when the parent Attempt settles in flight', async () => {
    const fixture = await materialReviewFixture('egress/host-qualified-v1')
    try {
      const secretReview = await qualifiedSecretReview(fixture)
      const egressEvidence = qualifiedEgressAuthorization(fixture, secretReview)
      const requests: SourceSliceEgressBrokerRequestV1[] = []
      let brokerSignal: AbortSignal | undefined
      let completeBroker!: () => void
      const brokerSettled = new Promise<void>((resolve) => {
        completeBroker = resolve
      })
      const times = [
        '2026-09-12T00:05:00.000Z',
        '2026-09-12T00:05:01.000Z',
        '2026-09-12T00:05:02.000Z',
      ]
      const issued = issueAttemptScopedSourceSliceEgressCapability({
        invocationId: 'egress-invocation-00000000-0000-0000-0000-000000000180',
        attempt: {
          attemptId: fixture.contextGrant.roleAttemptId,
          generation: 2,
          fencingToken: 'fence/role-attempt-0168/generation-2',
          deadlineAt: '2026-09-12T00:06:00.000Z',
        },
        contextGrant: fixture.contextGrant,
        request: fixture.request,
        material: secretReview.material,
        redaction: secretReview.redaction,
        secretReview: secretReview.admitted,
        ...egressEvidence,
        broker: {
          identity: egressEvidence.brokerQualification.brokerIdentity,
          async invoke(request, options) {
            requests.push(request)
            brokerSignal = options.signal
            await brokerSettled
            return {
              schemaVersion: 1,
              brokerIdentity: egressEvidence.brokerQualification.brokerIdentity,
              providerId: 'provider/reference',
              destinationId: 'provider/reference',
              providerRequestId: 'provider-request/late-fixture-0168',
              backendId: 'backend/reference',
              deploymentId: 'deployment/reference',
              modelId: 'model/reference',
              response: { mediaType: 'text/plain', text: 'late result must be rejected' },
              usage: {
                requestCount: 1,
                requestBytes: secretReview.redaction.redactedDigest.byteLength,
                inputTokens: 32,
                outputTokens: 8,
              },
              finishReason: 'STOP',
              diagnostics: [],
            }
          },
        },
        now: () => times.shift()!,
      })

      const pending = issued.capability.invoke()
      expect(requests).toHaveLength(1)
      issued.settle()
      expect(brokerSignal?.aborted).toBe(true)
      completeBroker()
      const result = await pending

      expect(result.status).toBe('FAILED')
      expect(result.receipt.failureCode).toBe('ATTEMPT_SETTLED')
      expect(result.response).toBeNull()
      expect(JSON.stringify(result.receipt)).not.toContain('late result must be rejected')
      await expect(issued.capability.invoke()).rejects.toThrow(/settled/iu)
    } finally {
      await fixture.subprocessFiber.dispose()
    }
  })

  it('does not invoke after cancellation and enforces its deadline when a Broker ignores abort', async () => {
    const fixture = await materialReviewFixture('egress/host-qualified-v1')
    try {
      const secretReview = await qualifiedSecretReview(fixture)
      const egressEvidence = qualifiedEgressAuthorization(fixture, secretReview)
      let invocationCount = 0
      const canceledTimes = [
        '2026-09-12T00:05:00.000Z',
        '2026-09-12T00:05:01.000Z',
        '2026-09-12T00:05:02.000Z',
      ]
      const canceled = issueAttemptScopedSourceSliceEgressCapability({
        invocationId: 'egress-invocation-00000000-0000-0000-0000-000000000181',
        attempt: {
          attemptId: fixture.contextGrant.roleAttemptId,
          generation: 3,
          fencingToken: 'fence/role-attempt-0168/generation-3',
          deadlineAt: '2026-09-12T00:06:00.000Z',
        },
        contextGrant: fixture.contextGrant,
        request: fixture.request,
        material: secretReview.material,
        redaction: secretReview.redaction,
        secretReview: secretReview.admitted,
        ...egressEvidence,
        broker: {
          identity: egressEvidence.brokerQualification.brokerIdentity,
          async invoke() {
            invocationCount += 1
            throw new Error('must not be called')
          },
        },
        now: () => canceledTimes.shift()!,
      })
      const controller = new AbortController()
      controller.abort()

      const canceledResult = await canceled.capability.invoke({ signal: controller.signal })

      expect(canceledResult.status).toBe('FAILED')
      expect(canceledResult.receipt.failureCode).toBe('INVOCATION_ABORTED')
      expect(invocationCount).toBe(0)

      let brokerSignal: AbortSignal | undefined
      const timeoutEvidence = qualifiedEgressAuthorization(fixture, secretReview, {
        timeoutMilliseconds: 10,
      })
      const timeoutTimes = [
        '2026-09-12T00:05:00.000Z',
        '2026-09-12T00:05:00.001Z',
        '2026-09-12T00:05:00.011Z',
      ]
      const timed = issueAttemptScopedSourceSliceEgressCapability({
        invocationId: 'egress-invocation-00000000-0000-0000-0000-000000000182',
        attempt: {
          attemptId: fixture.contextGrant.roleAttemptId,
          generation: 4,
          fencingToken: 'fence/role-attempt-0168/generation-4',
          deadlineAt: '2026-09-12T00:06:00.000Z',
        },
        contextGrant: fixture.contextGrant,
        request: fixture.request,
        material: secretReview.material,
        redaction: secretReview.redaction,
        secretReview: secretReview.admitted,
        ...timeoutEvidence,
        broker: {
          identity: timeoutEvidence.brokerQualification.brokerIdentity,
          invoke(_request, options) {
            invocationCount += 1
            brokerSignal = options.signal
            return new Promise<never>(() => {})
          },
        },
        now: () => timeoutTimes.shift()!,
      })

      const timedResult = await timed.capability.invoke()

      expect(timedResult.status).toBe('FAILED')
      expect(timedResult.receipt.failureCode).toBe('ATTEMPT_DEADLINE_EXCEEDED')
      expect(brokerSignal?.aborted).toBe(true)
      expect(invocationCount).toBe(1)
    } finally {
      await fixture.subprocessFiber.dispose()
    }
  })

  it.each([
    ['expired Broker qualification', { qualificationExpiresAt: '2026-09-12T00:04:00.000Z' }],
    ['Provider scope mismatch', { providerId: 'provider/unqualified' }],
    ['destination mismatch', { destinationId: 'provider/other' }],
    ['Request byte expansion', { requestByteLimit: 1024 }],
    ['audit policy mismatch', { auditPolicyId: 'audit/unqualified' }],
    ['timeout expansion', { timeoutMilliseconds: 60_000 }],
    ['expired destination authorization', {
      authorizationExpiresAt: '2026-09-12T00:04:00.000Z',
    }],
  ] as const)('fails closed on %s', async (_name, overrides) => {
    const fixture = await materialReviewFixture('egress/host-qualified-v1')
    try {
      const secretReview = await qualifiedSecretReview(fixture)
      await expect(reviewRequestedSourceSliceMaterial({
        securityRoot: fixture.securityRoot,
        contextGrant: fixture.contextGrant,
        request: fixture.request,
        fingerprintKey,
        fingerprintKeyId: 'host/secret-fingerprint-key-1',
        secretReview: secretReview.admission,
        egressAuthorization: qualifiedEgressAuthorization(fixture, secretReview, overrides),
      })).rejects.toThrow(/authorization|qualification|bounds|inputs/iu)
    } finally {
      await fixture.subprocessFiber.dispose()
    }
  })

  it('does not admit Broker Evidence without the exact complete CLEAR secret review', async () => {
    const fixture = await materialReviewFixture('egress/host-qualified-v1')
    try {
      const secretReview = await qualifiedSecretReview(fixture)
      await expect(reviewRequestedSourceSliceMaterial({
        securityRoot: fixture.securityRoot,
        contextGrant: fixture.contextGrant,
        request: fixture.request,
        fingerprintKey,
        fingerprintKeyId: 'host/secret-fingerprint-key-1',
        egressAuthorization: qualifiedEgressAuthorization(fixture, secretReview),
      })).rejects.toThrow(/requires secret review/iu)
    } finally {
      await fixture.subprocessFiber.dispose()
    }
  })

  it('rejects a redacted Slice when the qualified independent review still finds a secret', async () => {
    const fixture = await materialReviewFixture('egress/host-qualified-v1')
    try {
      const secretReview = await qualifiedSecretReview(fixture, {
        decision: 'SECRET_FOUND',
      })
      const review = await reviewRequestedSourceSliceMaterial({
        securityRoot: fixture.securityRoot,
        contextGrant: fixture.contextGrant,
        request: fixture.request,
        fingerprintKey,
        fingerprintKeyId: 'host/secret-fingerprint-key-1',
        secretReview: secretReview.admission,
      })

      expect(review.decision).toBe('REJECTED')
      expect(review.checks.find(check => check.check === 'SECRET_REDACTION')).toEqual({
        check: 'SECRET_REDACTION',
        status: 'REJECTED',
        reasonCodes: ['RESIDUAL_SECRET_DETECTED'],
      })
      expect(review.checks.find(check => check.check === 'DATA_EGRESS')).toEqual({
        check: 'DATA_EGRESS',
        status: 'REJECTED',
        reasonCodes: [
          'RESIDUAL_SECRET_DETECTED',
          'BROKER_QUALIFICATION_REQUIRED',
          'DESTINATION_AUTHORIZATION_REQUIRED',
        ],
      })
    } finally {
      await fixture.subprocessFiber.dispose()
    }
  })

  it('keeps an independently indeterminate review unresolved', async () => {
    const fixture = await materialReviewFixture('egress/host-qualified-v1')
    try {
      const secretReview = await qualifiedSecretReview(fixture, {
        decision: 'INDETERMINATE',
      })
      const review = await reviewRequestedSourceSliceMaterial({
        securityRoot: fixture.securityRoot,
        contextGrant: fixture.contextGrant,
        request: fixture.request,
        fingerprintKey,
        fingerprintKeyId: 'host/secret-fingerprint-key-1',
        secretReview: secretReview.admission,
      })

      expect(review.checks.find(check => check.check === 'SECRET_REDACTION')).toEqual({
        check: 'SECRET_REDACTION',
        status: 'REVIEW_REQUIRED',
        reasonCodes: ['SECRET_REVIEW_INCOMPLETE'],
      })
      expect(review.checks.find(check => check.check === 'DATA_EGRESS')).toEqual({
        check: 'DATA_EGRESS',
        status: 'REVIEW_REQUIRED',
        reasonCodes: [
          'SECRET_REVIEW_INCOMPLETE',
          'BROKER_QUALIFICATION_REQUIRED',
          'DESTINATION_AUTHORIZATION_REQUIRED',
        ],
      })
    } finally {
      await fixture.subprocessFiber.dispose()
    }
  })

  it.each([
    ['expired qualification', { qualificationExpiresAt: '2026-09-12T00:00:00.000Z' }],
    ['qualification scope mismatch', { qualificationPolicyId: 'security/unrelated-review' }],
    ['redacted digest drift', { driftRedactedDigest: true }],
    ['missing independence qualification', { omitIndependenceQualification: true }],
  ] as const)('fails closed on %s', async (_name, overrides) => {
    const fixture = await materialReviewFixture()
    try {
      await expect(qualifiedSecretReview(fixture, overrides)).rejects.toThrow(
        /qualification|incomplete|stale|independently|artifact/iu,
      )
    } finally {
      await fixture.subprocessFiber.dispose()
    }
  })

  it('aggregates satisfied local proofs and every unresolved material boundary', async () => {
    const fixture = await materialReviewFixture()
    try {
      const review = await reviewRequestedSourceSliceMaterial({
        securityRoot: fixture.securityRoot,
        contextGrant: fixture.contextGrant,
        request: fixture.request,
        fingerprintKey,
        fingerprintKeyId: 'host/secret-fingerprint-key-1',
      })

      expect(review.decision).toBe('REJECTED')
      expect(review.sensitivity).toEqual({
        classifierId: 'security/source-slice-sensitivity-baseline',
        classifierVersion: '1.0.0',
        category: 'SECRET_BEARING_SOURCE',
        indicatorCodes: ['HIGH_CONFIDENCE_SECRET_MATCH'],
        classificationDigest: expect.objectContaining({
          mediaType: 'application/vnd.dsh.security.source-slice-sensitivity-classification+json',
        }),
      })
      expect(review.checks).toEqual([
        { check: 'SUBJECT_CONTAINMENT', status: 'SATISFIED', reasonCodes: [] },
        { check: 'SOURCE_DIGEST_INTEGRITY', status: 'SATISFIED', reasonCodes: [] },
        {
          check: 'SENSITIVITY_CLASSIFICATION',
          status: 'SATISFIED',
          reasonCodes: [],
        },
        {
          check: 'SECRET_REDACTION',
          status: 'REVIEW_REQUIRED',
          reasonCodes: ['SECRET_REVIEW_INCOMPLETE'],
        },
        {
          check: 'DATA_EGRESS',
          status: 'REJECTED',
          reasonCodes: ['POLICY_DENIES_EGRESS'],
        },
        {
          check: 'ACTUAL_BUDGET',
          status: 'REVIEW_REQUIRED',
          reasonCodes: ['TOKEN_METERING_REQUIRED'],
        },
        {
          check: 'ROLE_NEED',
          status: 'REVIEW_REQUIRED',
          reasonCodes: ['ROLE_NEED_VALIDATION_REQUIRED'],
        },
      ])
      expect(review.observed.secretFindingCount).toBe(1)
      expect(review.observed.sourceBytes).toBe(Buffer.byteLength(sourceText, 'utf8'))
      expect(JSON.stringify(review)).not.toContain('correct-horse-battery-staple')
      expect(JSON.stringify(review)).not.toMatch(/workspaceRoot|credential|capability|GRANTED/iu)
      expect(Object.isFrozen(review)).toBe(true)
      expect(Object.isFrozen(review.checks)).toBe(true)
    } finally {
      await fixture.subprocessFiber.dispose()
    }
  })

  it('cannot approve a non-deny policy without Host and Broker evidence', async () => {
    const fixture = await materialReviewFixture('egress/host-qualified-v1')
    try {
      const review = await reviewRequestedSourceSliceMaterial({
        securityRoot: fixture.securityRoot,
        contextGrant: fixture.contextGrant,
        request: fixture.request,
        fingerprintKey,
        fingerprintKeyId: 'host/secret-fingerprint-key-1',
      })

      expect(review.decision).toBe('ADDITIONAL_REVIEW_REQUIRED')
      expect(review.checks.find(check => check.check === 'DATA_EGRESS')).toEqual({
        check: 'DATA_EGRESS',
        status: 'REVIEW_REQUIRED',
        reasonCodes: [
          'SECRET_REVIEW_INCOMPLETE',
          'BROKER_QUALIFICATION_REQUIRED',
          'DESTINATION_AUTHORIZATION_REQUIRED',
        ],
      })
      expect(JSON.stringify(review)).not.toMatch(/APPROVED|AUTHORIZED/iu)
    } finally {
      await fixture.subprocessFiber.dispose()
    }
  })

  it('parses only the exact immutable upstream digest chain', async () => {
    const fixture = await materialReviewFixture()
    try {
      const review = await reviewRequestedSourceSliceMaterial({
        securityRoot: fixture.securityRoot,
        contextGrant: fixture.contextGrant,
        request: fixture.request,
        fingerprintKey,
        fingerprintKeyId: 'host/secret-fingerprint-key-1',
      })
      const bindings = {
        contextGrantDigest: fixture.contextGrant.grantDigest,
        requestDigest: fixture.request.requestDigest,
        subjectDigest: fixture.request.subjectDigest,
      }

      expect(parseProtectedSourceSliceMaterialReview(review, bindings)).toEqual(review)
      expect(() => parseProtectedSourceSliceMaterialReview({
        ...review,
        decision: 'ADDITIONAL_REVIEW_REQUIRED',
      }, bindings)).toThrow(/decision|digest/iu)
      const forgedChecks = review.checks.map(check => check.check === 'DATA_EGRESS'
        ? {
            check: 'DATA_EGRESS' as const,
            status: 'REVIEW_REQUIRED' as const,
            reasonCodes: [
              'SECRET_REVIEW_INCOMPLETE' as const,
              'BROKER_QUALIFICATION_REQUIRED' as const,
              'DESTINATION_AUTHORIZATION_REQUIRED' as const,
            ],
          }
        : check)
      const { materialReviewDigest: _materialReviewDigest, ...reviewCore } = review
      const forgedCore = {
        ...reviewCore,
        egressDecision: 'BROKER_REVIEW_REQUIRED' as const,
        decision: 'ADDITIONAL_REVIEW_REQUIRED' as const,
        checks: forgedChecks,
      }
      expect(() => parseProtectedSourceSliceMaterialReview({
        ...forgedCore,
        materialReviewDigest: structuredDigest(
          SOURCE_SLICE_MATERIAL_REVIEW_MEDIA_TYPE,
          forgedCore,
        ),
      }, bindings)).toThrow(/Egress disposition/iu)
      expect(() => parseProtectedSourceSliceMaterialReview(review, {
        ...bindings,
        requestDigest: { ...bindings.requestDigest, value: '0'.repeat(64) },
      })).toThrow(/bind/iu)
    } finally {
      await fixture.subprocessFiber.dispose()
    }
  })

  it('fails closed before producing a record when protected content drifts', async () => {
    const fixture = await materialReviewFixture()
    try {
      const driftedRequest = {
        ...fixture.request,
        target: {
          ...fixture.request.target,
          expectedSourceDigest: {
            ...fixture.request.target.expectedSourceDigest,
            value: '0'.repeat(64),
          },
        },
      }
      await expect(reviewRequestedSourceSliceMaterial({
        securityRoot: fixture.securityRoot,
        contextGrant: fixture.contextGrant,
        request: driftedRequest,
        fingerprintKey,
        fingerprintKeyId: 'host/secret-fingerprint-key-1',
      })).rejects.toThrow()
    } finally {
      await fixture.subprocessFiber.dispose()
    }
  })

  it('keeps the composite material review outside the package root', async () => {
    const packageRoot = await import('../src/index.ts')

    expect(packageRoot).not.toHaveProperty('reviewRequestedSourceSliceMaterial')
    expect(packageRoot).not.toHaveProperty('parseProtectedSourceSliceMaterialReview')
    expect(packageRoot).not.toHaveProperty('admitQualifiedSourceSliceSecretReview')
    expect(packageRoot).not.toHaveProperty('parseProtectedSourceSliceSecretReview')
    expect(packageRoot).not.toHaveProperty('admitProtectedSourceSliceEgressAuthorization')
    expect(packageRoot).not.toHaveProperty('parseProtectedSourceSliceEgressAuthorization')
    expect(packageRoot).not.toHaveProperty('issueAttemptScopedSourceSliceEgressCapability')
    expect(packageRoot).not.toHaveProperty('parseSourceSliceEgressInvocationReceipt')
  })
})
