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
import { binaryDigest, structuredDigest } from '../src/internal/canonical.ts'
import {
  parseProtectedSourceSliceMaterialReview,
  reviewRequestedSourceSliceMaterial,
  SOURCE_SLICE_MATERIAL_REVIEW_MEDIA_TYPE,
} from '../src/internal/source-slice-material-review.ts'
import { freezeSubject } from '../src/internal/subject-freeze.ts'
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

describe('ADR 0168 protected Source Slice material review record', () => {
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
  })
})
