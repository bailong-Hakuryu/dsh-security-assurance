import { execFile } from 'node:child_process'
import { mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { promisify } from 'node:util'
import { Context } from '@deepseek-ai/cordis'
import { afterEach, describe, expect, it } from 'vitest'
import SecurityAssuranceService, {
  analyzerContributionV1Schema,
  securitySubmissionJsonV1Schema,
} from '../src/index.ts'
import type {
  AnalyzerDescriptorV1,
  AnalyzerQualificationRecordV1,
  AssessmentId,
  SecurityInvocation,
} from '../src/index.ts'
import { referenceHostInvocation } from './support/reference-host.ts'

const run = promisify(execFile)
const temporaryRoots: string[] = []

afterEach(async () => {
  await Promise.all(temporaryRoots.splice(0).map(path => rm(path, { recursive: true, force: true })))
})

async function validationRepositoryFixture(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), 'dsh-security-external-validation-'))
  temporaryRoots.push(root)
  await run('git', ['init', '-b', 'main'], { cwd: root })
  await run('git', ['config', 'user.email', 'fixture@example.invalid'], { cwd: root })
  await run('git', ['config', 'user.name', 'Fixture'], { cwd: root })
  await writeFile(join(root, 'package.json'), `${JSON.stringify({
    name: 'external-validation-fixture',
    version: '1.0.0',
    dshSecurity: { referenceControl: 'VIOLATED' },
  }, null, 2)}\n`, 'utf8')
  await run('git', ['add', '.'], { cwd: root })
  await run('git', ['commit', '-m', 'external validation fixture'], { cwd: root })
  return root
}

async function waitUntilSealed(
  service: SecurityAssuranceService,
  invocation: SecurityInvocation,
  assessmentId: AssessmentId,
): Promise<void> {
  let revision = 1
  for (let attempt = 0; attempt < 5; attempt += 1) {
    const changed = await service.waitForAssessmentRevision(invocation, {
      schemaVersion: 1,
      assessmentId,
      afterRevision: revision,
      timeoutMs: 5_000,
    })
    if (!changed.ok) throw new Error(`wait failed: ${changed.error.code}`)
    const assessment = await service.getAssessment(invocation, { schemaVersion: 1, assessmentId })
    if (!assessment.ok) throw new Error(`query failed: ${assessment.error.code}`)
    if (assessment.value.state === 'SEALED') return
    if (assessment.value.state === 'BLOCKED') throw new Error('Assessment unexpectedly blocked')
    revision = assessment.value.assessmentRevision
  }
  throw new Error('Assessment did not reach SEALED')
}

describe('external Analyzer Candidate validation', () => {
  it('rejects a Candidate that is not bound to contributed Evidence', () => {
    const digest = {
      schemaVersion: 1 as const,
      algorithm: 'sha256' as const,
      mediaType: 'application/json',
      byteLength: 1,
      canonicalization: 'dsh-canonical-json-v1' as const,
      value: 'd'.repeat(64),
    }
    expect(analyzerContributionV1Schema.safeParse({
      schemaVersion: 1,
      analyzerIdentity: {
        analyzerId: 'fixture/reference-validator',
        analyzerVersion: '1.0.0',
        descriptorSchemaVersion: 1,
        buildDigest: digest,
      },
      subjectDigest: digest,
      completionDisposition: 'INCOMPLETE',
      coverageClaims: [],
      candidateFindings: [{
        schemaVersion: 1,
        candidateId: `candidate-${'e'.repeat(64)}`,
        weaknessClassification: {
          schemaVersion: 1,
          primary: 'dsh/conformance/reference-control-violation',
          secondary: [],
        },
        affectedControlId: 'dsh/conformance/reference-control',
        securityClaim: 'The conformance reference security control is explicitly violated.',
        sourceAnchor: {
          path: 'package.json',
          fileDigest: digest,
          locator: { kind: 'JSON_POINTER', value: '/dshSecurity/referenceControl' },
        },
        evidenceArtifactIds: ['missing-validation-evidence'],
      }],
      evidence: [],
      diagnostics: [],
      resourceUse: { filesRead: 1, bytesRead: 1 },
    }).success).toBe(false)
  })

  it('validates a qualified deterministic Candidate into a blocking Finding and FAILED Verdict', async () => {
    const repository = await validationRepositoryFixture()
    const dshHome = await mkdtemp(join(tmpdir(), 'dsh-security-external-validation-home-'))
    temporaryRoots.push(dshHome)
    const ctx = new Context()
    const fiber = await ctx.plugin(SecurityAssuranceService, { dshHome })
    const descriptor: AnalyzerDescriptorV1 = {
      schemaVersion: 1,
      analyzerId: 'fixture/reference-validator',
      analyzerVersion: '1.0.0',
      descriptorSchemaVersion: 1,
      buildDigest: {
        schemaVersion: 1,
        algorithm: 'sha256',
        mediaType: 'application/vnd.fixture.reference-validator+json',
        byteLength: 1,
        canonicalization: 'dsh-canonical-json-v1',
        value: 'a'.repeat(64),
      },
      executionClass: 'PURE',
      supportedAssessmentModes: ['REPOSITORY'],
      supportedPolicyIds: ['security/reference-validation'],
      coverageObligationIds: ['application-security-analysis'],
      evidenceSchemaIds: ['fixture/reference-validation-evidence'],
      egress: 'NONE',
    }
    const qualification: AnalyzerQualificationRecordV1 = {
      schemaVersion: 1,
      qualificationId: 'fixture/qualification/reference-validator/v1',
      analyzerIdentity: {
        analyzerId: descriptor.analyzerId,
        analyzerVersion: descriptor.analyzerVersion,
        descriptorSchemaVersion: descriptor.descriptorSchemaVersion,
        buildDigest: descriptor.buildDigest,
      },
      issuerId: 'fixture/qualification-authority',
      level: 'HOST_ATTESTED',
      supportedEcosystemIds: ['fixture/reference'],
      supportedAssessmentModes: ['REPOSITORY'],
      supportedPolicyIds: ['security/reference-validation'],
      coverageObligationIds: ['application-security-analysis'],
      evidenceSchemaIds: ['fixture/reference-validation-evidence'],
      executionClass: 'PURE',
      executionBackendId: 'dsh/security-assurance/in-process-pure-v1',
      providerIds: ['dsh-security-assurance'],
      egress: 'NONE',
      platforms: ['win32', 'linux', 'darwin'],
      issuedAt: '2026-01-01T00:00:00.000Z',
      expiresAt: '2099-01-01T00:00:00.000Z',
      evidenceDigests: [{
        schemaVersion: 1,
        algorithm: 'sha256',
        mediaType: 'application/vnd.fixture.validation-qualification-evidence+json',
        byteLength: 1,
        canonicalization: 'dsh-canonical-json-v1',
        value: 'b'.repeat(64),
      }],
      limitations: ['Conformance reference validation only.'],
      qualificationDigest: {
        schemaVersion: 1,
        algorithm: 'sha256',
        mediaType: 'application/vnd.dsh.security.analyzer-qualification+json',
        byteLength: 1375,
        canonicalization: 'dsh-canonical-json-v1',
        value: 'b3a8db649fdeb8269abb8e8624b8df66ae68c7be05c09bda029df0d0e6a57357',
      },
    }
    const candidateId = `candidate-${'c'.repeat(64)}`
    const disposeAnalyzer = ctx.securityAssurance.registerAnalyzer(
      descriptor,
      normalizedDescriptor => ({
        descriptor: normalizedDescriptor,
        async analyze(input) {
          const manifest = input.subject.textSlices.find(slice => slice.path === 'package.json')
          if (manifest === undefined) throw new Error('Reference validation manifest is missing')
          const sourceAnchor = {
            path: manifest.path,
            fileDigest: manifest.digest,
            locator: { kind: 'JSON_POINTER' as const, value: '/dshSecurity/referenceControl' },
          }
          return {
            schemaVersion: 1,
            analyzerIdentity: {
              analyzerId: normalizedDescriptor.analyzerId,
              analyzerVersion: normalizedDescriptor.analyzerVersion,
              descriptorSchemaVersion: normalizedDescriptor.descriptorSchemaVersion,
              buildDigest: normalizedDescriptor.buildDigest,
            },
            subjectDigest: input.subject.digest,
            completionDisposition: 'COMPLETE',
            coverageClaims: [{
              obligationId: 'application-security-analysis',
              completion: 'COMPLETE',
              evidenceArtifactId: 'reference-validation-evidence',
            }],
            candidateFindings: [{
              schemaVersion: 1,
              candidateId,
              weaknessClassification: {
                schemaVersion: 1,
                primary: 'dsh/conformance/reference-control-violation',
                secondary: [],
              },
              affectedControlId: 'dsh/conformance/reference-control',
              securityClaim: 'The conformance reference security control is explicitly violated.',
              sourceAnchor,
              evidenceArtifactIds: ['reference-validation-evidence'],
            }],
            evidence: [{
              artifactId: 'reference-validation-evidence',
              schemaId: 'fixture/reference-validation-evidence',
              mediaType: 'application/json',
              value: securitySubmissionJsonV1Schema.parse({
                schemaVersion: 1,
                candidateId,
                subjectDigest: input.subject.digest,
                sourceAnchor,
                observedValue: 'VIOLATED',
              }),
            }],
            diagnostics: [],
            resourceUse: { filesRead: 1, bytesRead: manifest.text.length },
          }
        },
        async dispose() {},
      }),
    )
    const disposeQualification = ctx.securityAssurance.registerAnalyzerQualification(qualification)

    try {
      const invocation = referenceHostInvocation(ctx.securityAssurance)
      const platform = process.platform
      if (platform !== 'win32' && platform !== 'linux' && platform !== 'darwin') {
        throw new Error(`unsupported test platform: ${platform}`)
      }
      const registered = await ctx.securityAssurance.registerRepository(invocation, {
        schemaVersion: 1,
        idempotencyKey: 'external-validation-register-1',
        root: repository,
        displayName: 'External validation fixture',
        bindings: {
          policyId: 'security/reference-validation',
          assessmentProfileId: 'security/standard',
          evidenceProtectionId: 'evidence/local-protected',
          dataEgressPolicyId: 'egress/deny-by-default',
          platform,
          deliveryDestinationIds: [],
        },
      })
      if (!registered.ok) throw new Error(`registration failed: ${registered.error.code}`)
      const started = await ctx.securityAssurance.startAssessment(invocation, {
        schemaVersion: 1,
        idempotencyKey: 'external-validation-assessment-1',
        repositoryId: registered.value.repositoryId,
        subject: { kind: 'workspace_snapshot' },
        assessmentMode: 'REPOSITORY',
        assessmentProfileId: 'security/standard',
        target: { kind: 'repository' },
        requestedStrongerControlIds: [],
      })
      if (!started.ok) throw new Error(`start failed: ${started.error.code}`)
      await waitUntilSealed(ctx.securityAssurance, invocation, started.value.assessmentId)

      await expect(ctx.securityAssurance.getAssessment(invocation, {
        schemaVersion: 1,
        assessmentId: started.value.assessmentId,
      })).resolves.toMatchObject({
        ok: true,
        value: {
          state: 'SEALED',
          verdict: 'FAILED',
          coverage: { status: 'COMPLETE' },
        },
      })
      const submission = await ctx.securityAssurance.getAssuranceSubmission(invocation, {
        schemaVersion: 1,
        assessmentId: started.value.assessmentId,
      })
      expect(submission).toMatchObject({
        ok: true,
        value: {
          payload: {
            assessment: { verdict: 'FAILED' },
            findings: {
              value: {
                findings: [{
                  candidateId,
                  weaknessClassification: {
                    primary: 'dsh/conformance/reference-control-violation',
                  },
                  validation: {
                    state: 'VALIDATED',
                    contractId: 'dsh/conformance/reference-control-validation-v1',
                  },
                  technicalSeverity: {
                    value: 'HIGH',
                    methodVersion: 'dsh/conformance/reference-control-severity-v1',
                  },
                  evidenceConfidence: {
                    value: 'HIGH',
                    methodVersion: 'dsh/conformance/deterministic-evidence-confidence-v1',
                  },
                  policySignificance: 'BLOCKING',
                }],
              },
            },
            evidence: expect.arrayContaining([
              expect.objectContaining({ schemaId: 'dsh/security-candidate-admission' }),
              expect.objectContaining({ schemaId: 'dsh/security-validation-outcome' }),
              expect.objectContaining({ schemaId: 'dsh/security-validation-evidence-eligibility-decision' }),
            ]),
          },
        },
      })
    } finally {
      disposeQualification()
      disposeAnalyzer()
      await fiber.dispose()
    }
  })
})
