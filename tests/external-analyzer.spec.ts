import { execFile } from 'node:child_process'
import { mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { promisify } from 'node:util'
import { Context } from '@deepseek-ai/cordis'
import { afterEach, describe, expect, it } from 'vitest'
import SecurityAssuranceService from '../src/index.ts'
import type {
  AnalyzerDescriptorV1,
  AssessmentId,
  SecurityInvocation,
} from '../src/index.ts'
import { registerAnalyzerQualification } from '../src/internal/analyzer-qualification-registration.ts'
import { referenceHostInvocation } from './support/reference-host.ts'

const run = promisify(execFile)
const temporaryRoots: string[] = []

afterEach(async () => {
  await Promise.all(temporaryRoots.splice(0).map(path => rm(path, { recursive: true, force: true })))
})

async function repositoryFixture(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), 'dsh-security-external-analyzer-'))
  temporaryRoots.push(root)
  await run('git', ['init', '-b', 'main'], { cwd: root })
  await run('git', ['config', 'user.email', 'fixture@example.invalid'], { cwd: root })
  await run('git', ['config', 'user.name', 'Fixture'], { cwd: root })
  await writeFile(join(root, 'package.json'), `${JSON.stringify({
    name: 'external-analyzer-fixture',
    version: '1.0.0',
  }, null, 2)}\n`, 'utf8')
  await run('git', ['add', '.'], { cwd: root })
  await run('git', ['commit', '-m', 'external Analyzer fixture'], { cwd: root })
  return root
}

async function waitUntilState(
  service: SecurityAssuranceService,
  invocation: SecurityInvocation,
  assessmentId: AssessmentId,
  expectedState: 'SEALED' | 'BLOCKED',
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
    if (assessment.value.state === expectedState) return
    revision = assessment.value.assessmentRevision
  }
  throw new Error(`Assessment did not reach ${expectedState}`)
}

describe('external Analyzer composition', () => {
  it('keys startup registration by exact Analyzer ID and version', async () => {
    const dshHome = await mkdtemp(join(tmpdir(), 'dsh-security-analyzer-registration-home-'))
    temporaryRoots.push(dshHome)
    const ctx = new Context()
    const fiber = await ctx.plugin(SecurityAssuranceService, { dshHome })
    const descriptor: AnalyzerDescriptorV1 = {
      schemaVersion: 1,
      analyzerId: 'fixture/versioned-external',
      analyzerVersion: '1.0.0',
      descriptorSchemaVersion: 1,
      buildDigest: {
        schemaVersion: 1,
        algorithm: 'sha256',
        mediaType: 'application/vnd.fixture.versioned-analyzer+json',
        byteLength: 1,
        canonicalization: 'dsh-canonical-json-v1',
        value: '3'.repeat(64),
      },
      executionClass: 'PURE',
      supportedAssessmentModes: ['REPOSITORY'],
      supportedPolicyIds: ['security/reference-versioned'],
      coverageObligationIds: ['application-security-analysis'],
      evidenceSchemaIds: ['fixture/versioned-external-evidence'],
      egress: 'NONE',
    }
    const factory = (normalizedDescriptor: AnalyzerDescriptorV1) => ({
      descriptor: normalizedDescriptor,
      async analyze(): Promise<never> {
        throw new Error('Registration fixture must not execute')
      },
      async dispose() {},
    })
    const disposeV1 = ctx.securityAssurance.registerAnalyzer(descriptor, factory)
    const disposeV2 = ctx.securityAssurance.registerAnalyzer({
      ...descriptor,
      analyzerVersion: '2.0.0',
      buildDigest: { ...descriptor.buildDigest, value: '4'.repeat(64) },
    }, factory)

    try {
      expect(() => ctx.securityAssurance.registerAnalyzer(descriptor, factory)).toThrow(
        "Analyzer 'fixture/versioned-external@1.0.0' is already registered",
      )
      disposeV1()
      const disposeReplacementV1 = ctx.securityAssurance.registerAnalyzer(descriptor, factory)
      disposeReplacementV1()
    } finally {
      disposeV1()
      disposeV2()
      await fiber.dispose()
    }
  })

  it('seals an unqualified Reference Analyzer contribution as advisory without claiming mandatory Coverage', async () => {
    const repository = await repositoryFixture()
    const dshHome = await mkdtemp(join(tmpdir(), 'dsh-security-external-analyzer-home-'))
    temporaryRoots.push(dshHome)
    const ctx = new Context()
    const fiber = await ctx.plugin(SecurityAssuranceService, { dshHome })
    const descriptor: AnalyzerDescriptorV1 = {
      schemaVersion: 1 as const,
      analyzerId: 'fixture/reference-external',
      analyzerVersion: '1.0.0',
      descriptorSchemaVersion: 1 as const,
      buildDigest: {
        schemaVersion: 1 as const,
        algorithm: 'sha256' as const,
        mediaType: 'application/vnd.fixture.reference-analyzer+json',
        byteLength: 1,
        canonicalization: 'dsh-canonical-json-v1' as const,
        value: '1'.repeat(64),
      },
      executionClass: 'PURE' as const,
      supportedAssessmentModes: ['REPOSITORY'] as const,
      supportedPolicyIds: ['security/reference-external'] as const,
      coverageObligationIds: ['application-security-analysis'] as const,
      evidenceSchemaIds: ['fixture/reference-external-evidence'] as const,
      egress: 'NONE' as const,
    }
    let attemptDisposed = false
    let disposeRegistration = () => {}

    try {
      disposeRegistration = ctx.securityAssurance.registerAnalyzer(descriptor, normalizedDescriptor => ({
        descriptor: normalizedDescriptor,
        async analyze(input) {
          expect(Object.isFrozen(normalizedDescriptor)).toBe(true)
          expect(Object.isFrozen(input)).toBe(true)
          expect(JSON.stringify(input)).not.toContain(repository)
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
              evidenceArtifactId: 'reference-external-evidence',
            }],
            candidateFindings: [],
            evidence: [{
              artifactId: 'reference-external-evidence',
              schemaId: 'fixture/reference-external-evidence',
              mediaType: 'application/json',
              value: { schemaVersion: 1, result: 'advisory-clean' },
            }],
            diagnostics: [],
            resourceUse: { filesRead: 1, bytesRead: 0 },
          }
        },
        async dispose() {
          attemptDisposed = true
        },
      }))
      const invocation = referenceHostInvocation(ctx.securityAssurance)
      const platform = process.platform
      if (platform !== 'win32' && platform !== 'linux' && platform !== 'darwin') {
        throw new Error(`unsupported test platform: ${platform}`)
      }
      const registered = await ctx.securityAssurance.registerRepository(invocation, {
        schemaVersion: 1,
        idempotencyKey: 'external-analyzer-register-1',
        root: repository,
        displayName: 'External Analyzer fixture',
        bindings: {
          policyId: 'security/reference-external',
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
        idempotencyKey: 'external-analyzer-assessment-1',
        repositoryId: registered.value.repositoryId,
        subject: { kind: 'workspace_snapshot' },
        assessmentMode: 'REPOSITORY',
        assessmentProfileId: 'security/standard',
        target: { kind: 'repository' },
        requestedStrongerControlIds: [],
      })
      if (!started.ok) throw new Error(`start failed: ${started.error.code}`)
      await waitUntilState(
        ctx.securityAssurance,
        invocation,
        started.value.assessmentId,
        'SEALED',
      )

      expect(attemptDisposed).toBe(true)
      await expect(ctx.securityAssurance.getAssessment(invocation, {
        schemaVersion: 1,
        assessmentId: started.value.assessmentId,
      })).resolves.toMatchObject({
        ok: true,
        value: {
          state: 'SEALED',
          verdict: 'INDETERMINATE',
          coverage: {
            status: 'GAP',
            resolutions: [{
              obligationId: 'application-security-analysis',
              state: 'GAP',
              reason: 'EVIDENCE_INELIGIBLE',
            }],
          },
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
            assessment: { verdict: 'INDETERMINATE' },
            providerComposition: {
              value: {
                analyzers: [{
                  analyzerId: descriptor.analyzerId,
                  analyzerVersion: descriptor.analyzerVersion,
                  descriptorSchemaVersion: 1,
                  buildDigest: descriptor.buildDigest,
                  executionClass: 'PURE',
                  verdictEligible: false,
                }],
              },
            },
            evidence: expect.arrayContaining([
              expect.objectContaining({ schemaId: 'fixture/reference-external-evidence' }),
              expect.objectContaining({ schemaId: 'dsh/security-analyzer-contribution' }),
            ]),
          },
        },
      })
      expect(JSON.stringify(submission)).not.toContain(repository)
    } finally {
      disposeRegistration()
      await fiber.dispose()
    }
  })

  it('seals a precisely qualified Reference Analyzer contribution as Gate-bearing Coverage', async () => {
    const repository = await repositoryFixture()
    const dshHome = await mkdtemp(join(tmpdir(), 'dsh-security-qualified-analyzer-home-'))
    temporaryRoots.push(dshHome)
    const ctx = new Context()
    const fiber = await ctx.plugin(SecurityAssuranceService, { dshHome })
    const descriptor: AnalyzerDescriptorV1 = {
      schemaVersion: 1,
      analyzerId: 'fixture/reference-qualified',
      analyzerVersion: '1.0.0',
      descriptorSchemaVersion: 1,
      buildDigest: {
        schemaVersion: 1,
        algorithm: 'sha256',
        mediaType: 'application/vnd.fixture.reference-qualified-analyzer+json',
        byteLength: 1,
        canonicalization: 'dsh-canonical-json-v1',
        value: '5'.repeat(64),
      },
      executionClass: 'PURE',
      supportedAssessmentModes: ['REPOSITORY'],
      supportedPolicyIds: ['security/reference-qualified'],
      coverageObligationIds: ['application-security-analysis'],
      evidenceSchemaIds: ['fixture/reference-qualified-evidence'],
      egress: 'NONE',
    }
    const qualification = {
      schemaVersion: 1 as const,
      qualificationId: 'fixture/qualification/reference-qualified/v1',
      analyzerIdentity: {
        analyzerId: descriptor.analyzerId,
        analyzerVersion: descriptor.analyzerVersion,
        descriptorSchemaVersion: descriptor.descriptorSchemaVersion,
        buildDigest: descriptor.buildDigest,
      },
      issuerId: 'fixture/qualification-authority',
      level: 'HOST_ATTESTED' as const,
      supportedEcosystemIds: ['fixture/reference'],
      supportedAssessmentModes: ['REPOSITORY'] as const,
      supportedPolicyIds: ['security/reference-qualified'],
      coverageObligationIds: ['application-security-analysis'],
      evidenceSchemaIds: ['fixture/reference-qualified-evidence'],
      executionClass: 'PURE' as const,
      executionBackendId: 'dsh/security-assurance/in-process-pure-v1',
      providerIds: ['dsh-security-assurance'],
      egress: 'NONE' as const,
      platforms: ['win32', 'linux', 'darwin'] as const,
      issuedAt: '2026-01-01T00:00:00.000Z',
      expiresAt: '2099-01-01T00:00:00.000Z',
      evidenceDigests: [{
        schemaVersion: 1 as const,
        algorithm: 'sha256' as const,
        mediaType: 'application/vnd.fixture.qualification-evidence+json',
        byteLength: 1,
        canonicalization: 'dsh-canonical-json-v1' as const,
        value: '6'.repeat(64),
      }],
      limitations: ['Conformance reference only.'],
      qualificationDigest: {
        schemaVersion: 1 as const,
        algorithm: 'sha256' as const,
        mediaType: 'application/vnd.dsh.security.analyzer-qualification+json',
        byteLength: 1360,
        canonicalization: 'dsh-canonical-json-v1' as const,
        value: 'a2fb3a459aa2408b5fdc5b2ffd76094110b49037ba49b9049c39c2ce5be354eb',
      },
    }
    let disposeAnalyzer = () => {}
    let disposeQualification = () => {}

    try {
      disposeAnalyzer = ctx.securityAssurance.registerAnalyzer(descriptor, normalizedDescriptor => ({
        descriptor: normalizedDescriptor,
        async analyze(input) {
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
              evidenceArtifactId: 'reference-qualified-evidence',
            }],
            candidateFindings: [],
            evidence: [{
              artifactId: 'reference-qualified-evidence',
              schemaId: 'fixture/reference-qualified-evidence',
              mediaType: 'application/json',
              value: { schemaVersion: 1, result: 'qualified-clean' },
            }],
            diagnostics: [],
            resourceUse: { filesRead: 1, bytesRead: 0 },
          }
        },
        async dispose() {},
      }))
      expect(() => registerAnalyzerQualification(ctx.securityAssurance, {
        ...qualification,
        analyzerIdentity: {
          ...qualification.analyzerIdentity,
          analyzerVersion: '2.0.0',
        },
      })).toThrow('Analyzer Qualification digest does not bind its canonical record')
      disposeQualification = registerAnalyzerQualification(ctx.securityAssurance, qualification)
      expect(() => registerAnalyzerQualification(ctx.securityAssurance, qualification)).toThrow(
        `Analyzer Qualification '${qualification.qualificationId}' conflicts with an existing registration`,
      )
      expect(Object.isFrozen(qualification)).toBe(false)

      const invocation = referenceHostInvocation(ctx.securityAssurance)
      const platform = process.platform
      if (platform !== 'win32' && platform !== 'linux' && platform !== 'darwin') {
        throw new Error(`unsupported test platform: ${platform}`)
      }
      const registered = await ctx.securityAssurance.registerRepository(invocation, {
        schemaVersion: 1,
        idempotencyKey: 'qualified-analyzer-register-1',
        root: repository,
        displayName: 'Qualified Analyzer fixture',
        bindings: {
          policyId: 'security/reference-qualified',
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
        idempotencyKey: 'qualified-analyzer-assessment-1',
        repositoryId: registered.value.repositoryId,
        subject: { kind: 'workspace_snapshot' },
        assessmentMode: 'REPOSITORY',
        assessmentProfileId: 'security/standard',
        target: { kind: 'repository' },
        requestedStrongerControlIds: [],
      })
      if (!started.ok) throw new Error(`start failed: ${started.error.code}`)
      await waitUntilState(ctx.securityAssurance, invocation, started.value.assessmentId, 'SEALED')

      await expect(ctx.securityAssurance.getAssessment(invocation, {
        schemaVersion: 1,
        assessmentId: started.value.assessmentId,
      })).resolves.toMatchObject({
        ok: true,
        value: {
          state: 'SEALED',
          verdict: 'SATISFIED',
          coverage: {
            status: 'COMPLETE',
            resolutions: [{
              obligationId: 'application-security-analysis',
              state: 'SATISFIED',
              reason: 'ELIGIBLE_EVIDENCE',
            }],
          },
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
            assessment: { verdict: 'SATISFIED' },
            providerComposition: {
              value: {
                analyzers: [{
                  analyzerId: descriptor.analyzerId,
                  analyzerVersion: descriptor.analyzerVersion,
                  qualificationId: qualification.qualificationId,
                  qualificationDigest: qualification.qualificationDigest,
                  verdictEligible: true,
                }],
              },
            },
            evidence: expect.arrayContaining([
              expect.objectContaining({ schemaId: 'fixture/reference-qualified-evidence' }),
              expect.objectContaining({ schemaId: 'dsh/security-evidence-eligibility-decision' }),
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

  it('keeps an expired exact Qualification advisory and visible in Provider Composition', async () => {
    const repository = await repositoryFixture()
    const dshHome = await mkdtemp(join(tmpdir(), 'dsh-security-expired-qualification-home-'))
    temporaryRoots.push(dshHome)
    const ctx = new Context()
    const fiber = await ctx.plugin(SecurityAssuranceService, { dshHome })
    const descriptor: AnalyzerDescriptorV1 = {
      schemaVersion: 1,
      analyzerId: 'fixture/reference-expired',
      analyzerVersion: '1.0.0',
      descriptorSchemaVersion: 1,
      buildDigest: {
        schemaVersion: 1,
        algorithm: 'sha256',
        mediaType: 'application/vnd.fixture.reference-expired-analyzer+json',
        byteLength: 1,
        canonicalization: 'dsh-canonical-json-v1',
        value: '8'.repeat(64),
      },
      executionClass: 'PURE',
      supportedAssessmentModes: ['REPOSITORY'],
      supportedPolicyIds: ['security/reference-expired'],
      coverageObligationIds: ['application-security-analysis'],
      evidenceSchemaIds: ['fixture/reference-expired-evidence'],
      egress: 'NONE',
    }
    const qualification = {
      schemaVersion: 1 as const,
      qualificationId: 'fixture/qualification/reference-expired/v1',
      analyzerIdentity: {
        analyzerId: descriptor.analyzerId,
        analyzerVersion: descriptor.analyzerVersion,
        descriptorSchemaVersion: descriptor.descriptorSchemaVersion,
        buildDigest: descriptor.buildDigest,
      },
      issuerId: 'fixture/qualification-authority',
      level: 'HOST_ATTESTED' as const,
      supportedEcosystemIds: ['fixture/reference'],
      supportedAssessmentModes: ['REPOSITORY'] as const,
      supportedPolicyIds: ['security/reference-expired'],
      coverageObligationIds: ['application-security-analysis'],
      evidenceSchemaIds: ['fixture/reference-expired-evidence'],
      executionClass: 'PURE' as const,
      executionBackendId: 'dsh/security-assurance/in-process-pure-v1',
      providerIds: ['dsh-security-assurance'],
      egress: 'NONE' as const,
      platforms: ['win32', 'linux', 'darwin'] as const,
      issuedAt: '2020-01-01T00:00:00.000Z',
      expiresAt: '2021-01-01T00:00:00.000Z',
      evidenceDigests: [{
        schemaVersion: 1 as const,
        algorithm: 'sha256' as const,
        mediaType: 'application/vnd.fixture.qualification-evidence+json',
        byteLength: 1,
        canonicalization: 'dsh-canonical-json-v1' as const,
        value: '9'.repeat(64),
      }],
      limitations: ['Expired conformance reference.'],
      qualificationDigest: {
        schemaVersion: 1 as const,
        algorithm: 'sha256' as const,
        mediaType: 'application/vnd.dsh.security.analyzer-qualification+json',
        byteLength: 1353,
        canonicalization: 'dsh-canonical-json-v1' as const,
        value: '87c5a2fdd38e48b49cf87871e0ba786d61635edf8ef9ae0ba536fdd835118f17',
      },
    }
    const disposeAnalyzer = ctx.securityAssurance.registerAnalyzer(
      descriptor,
      normalizedDescriptor => ({
        descriptor: normalizedDescriptor,
        async analyze(input) {
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
              evidenceArtifactId: 'reference-expired-evidence',
            }],
            candidateFindings: [],
            evidence: [{
              artifactId: 'reference-expired-evidence',
              schemaId: 'fixture/reference-expired-evidence',
              mediaType: 'application/json',
              value: { schemaVersion: 1, result: 'expired-clean' },
            }],
            diagnostics: [],
            resourceUse: { filesRead: 1, bytesRead: 0 },
          }
        },
        async dispose() {},
      }),
    )
    const disposeQualification = registerAnalyzerQualification(ctx.securityAssurance, qualification)

    try {
      const invocation = referenceHostInvocation(ctx.securityAssurance)
      const platform = process.platform
      if (platform !== 'win32' && platform !== 'linux' && platform !== 'darwin') {
        throw new Error(`unsupported test platform: ${platform}`)
      }
      const registered = await ctx.securityAssurance.registerRepository(invocation, {
        schemaVersion: 1,
        idempotencyKey: 'expired-qualification-register-1',
        root: repository,
        displayName: 'Expired Qualification fixture',
        bindings: {
          policyId: 'security/reference-expired',
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
        idempotencyKey: 'expired-qualification-assessment-1',
        repositoryId: registered.value.repositoryId,
        subject: { kind: 'workspace_snapshot' },
        assessmentMode: 'REPOSITORY',
        assessmentProfileId: 'security/standard',
        target: { kind: 'repository' },
        requestedStrongerControlIds: [],
      })
      if (!started.ok) throw new Error(`start failed: ${started.error.code}`)
      await waitUntilState(ctx.securityAssurance, invocation, started.value.assessmentId, 'SEALED')

      await expect(ctx.securityAssurance.getAssessment(invocation, {
        schemaVersion: 1,
        assessmentId: started.value.assessmentId,
      })).resolves.toMatchObject({
        ok: true,
        value: {
          state: 'SEALED',
          verdict: 'INDETERMINATE',
          coverage: { status: 'GAP' },
        },
      })
      await expect(ctx.securityAssurance.getAssuranceSubmission(invocation, {
        schemaVersion: 1,
        assessmentId: started.value.assessmentId,
      })).resolves.toMatchObject({
        ok: true,
        value: {
          payload: {
            providerComposition: {
              value: {
                analyzers: [{
                  qualificationId: qualification.qualificationId,
                  qualificationDigest: qualification.qualificationDigest,
                  verdictEligible: false,
                }],
              },
            },
            evidence: expect.arrayContaining([
              expect.objectContaining({
                schemaId: 'dsh/security-evidence-eligibility-decision',
                value: expect.objectContaining({
                  decision: 'INELIGIBLE',
                  reason: 'QUALIFICATION_EXPIRED',
                }),
              }),
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

  it('blocks when an external Analyzer returns a Contribution for another Subject', async () => {
    const repository = await repositoryFixture()
    const dshHome = await mkdtemp(join(tmpdir(), 'dsh-security-external-analyzer-tampered-home-'))
    temporaryRoots.push(dshHome)
    const ctx = new Context()
    const fiber = await ctx.plugin(SecurityAssuranceService, { dshHome })
    const descriptor: AnalyzerDescriptorV1 = {
      schemaVersion: 1,
      analyzerId: 'fixture/tampered-external',
      analyzerVersion: '1.0.0',
      descriptorSchemaVersion: 1,
      buildDigest: {
        schemaVersion: 1,
        algorithm: 'sha256',
        mediaType: 'application/vnd.fixture.tampered-analyzer+json',
        byteLength: 1,
        canonicalization: 'dsh-canonical-json-v1',
        value: '2'.repeat(64),
      },
      executionClass: 'PURE',
      supportedAssessmentModes: ['REPOSITORY'],
      supportedPolicyIds: ['security/reference-tampered'],
      coverageObligationIds: ['application-security-analysis'],
      evidenceSchemaIds: ['fixture/tampered-external-evidence'],
      egress: 'NONE',
    }
    let attemptDisposed = false
    const disposeRegistration = ctx.securityAssurance.registerAnalyzer(
      descriptor,
      normalizedDescriptor => ({
        descriptor: normalizedDescriptor,
        async analyze(input) {
          return {
            schemaVersion: 1,
            analyzerIdentity: {
              analyzerId: normalizedDescriptor.analyzerId,
              analyzerVersion: normalizedDescriptor.analyzerVersion,
              descriptorSchemaVersion: normalizedDescriptor.descriptorSchemaVersion,
              buildDigest: normalizedDescriptor.buildDigest,
            },
            subjectDigest: { ...input.subject.digest, value: 'f'.repeat(64) },
            completionDisposition: 'COMPLETE',
            coverageClaims: [{
              obligationId: 'application-security-analysis',
              completion: 'COMPLETE',
              evidenceArtifactId: 'tampered-external-evidence',
            }],
            candidateFindings: [],
            evidence: [{
              artifactId: 'tampered-external-evidence',
              schemaId: 'fixture/tampered-external-evidence',
              mediaType: 'application/json',
              value: { schemaVersion: 1, result: 'forged-subject' },
            }],
            diagnostics: [],
            resourceUse: { filesRead: 1, bytesRead: 0 },
          }
        },
        async dispose() {
          attemptDisposed = true
        },
      }),
    )

    try {
      const invocation = referenceHostInvocation(ctx.securityAssurance)
      const platform = process.platform
      if (platform !== 'win32' && platform !== 'linux' && platform !== 'darwin') {
        throw new Error(`unsupported test platform: ${platform}`)
      }
      const registered = await ctx.securityAssurance.registerRepository(invocation, {
        schemaVersion: 1,
        idempotencyKey: 'tampered-external-register-1',
        root: repository,
        displayName: 'Tampered external Analyzer fixture',
        bindings: {
          policyId: 'security/reference-tampered',
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
        idempotencyKey: 'tampered-external-assessment-1',
        repositoryId: registered.value.repositoryId,
        subject: { kind: 'workspace_snapshot' },
        assessmentMode: 'REPOSITORY',
        assessmentProfileId: 'security/standard',
        target: { kind: 'repository' },
        requestedStrongerControlIds: [],
      })
      if (!started.ok) throw new Error(`start failed: ${started.error.code}`)
      await waitUntilState(
        ctx.securityAssurance,
        invocation,
        started.value.assessmentId,
        'BLOCKED',
      )

      expect(attemptDisposed).toBe(true)
      await expect(ctx.securityAssurance.getAssessment(invocation, {
        schemaVersion: 1,
        assessmentId: started.value.assessmentId,
      })).resolves.toMatchObject({
        ok: true,
        value: {
          state: 'BLOCKED',
          verdict: null,
          seal: null,
        },
      })
      await expect(ctx.securityAssurance.getAssuranceSubmission(invocation, {
        schemaVersion: 1,
        assessmentId: started.value.assessmentId,
      })).resolves.toMatchObject({ ok: false, error: { code: 'CONFLICT' } })
    } finally {
      disposeRegistration()
      await fiber.dispose()
    }
  })
})
