import { SecurityAssuranceTestComposition } from './support/security-assurance-test-composition.ts'
import { removeTemporaryRoots } from './support/remove-temporary-root.ts'
import { execFile } from 'node:child_process'
import { mkdir, mkdtemp, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { promisify } from 'node:util'
import { Context } from '@deepseek-ai/cordis'
import { afterEach, describe, expect, it } from 'vitest'
import SecurityAssuranceService from '../src/index.ts'
import type { AssessmentId, SecurityInvocation } from '../src/index.ts'
import { analyzeNodePackageInstallLifecycle } from '../src/internal/builtin-node-package-lifecycle-analyzer.ts'
import { structuredDigest } from '../src/internal/canonical.ts'
import { referenceHostInvocation } from './support/reference-host.ts'

const run = promisify(execFile)
const temporaryRoots: string[] = []

afterEach(async () => {
  await removeTemporaryRoots(temporaryRoots)
})

async function nodeRepositoryFixture(
  packageJson: unknown,
  extraFiles: Readonly<Record<string, string>> = {},
): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), 'dsh-security-qualified-node-'))
  temporaryRoots.push(root)
  await run('git', ['init', '-b', 'main'], { cwd: root })
  await run('git', ['config', 'user.email', 'fixture@example.invalid'], { cwd: root })
  await run('git', ['config', 'user.name', 'Fixture'], { cwd: root })
  await writeFile(join(root, 'package.json'), `${JSON.stringify(packageJson, null, 2)}\n`, 'utf8')
  await writeFile(join(root, 'index.js'), 'export const answer = 42\n', 'utf8')
  for (const [path, contents] of Object.entries(extraFiles)) {
    const destination = join(root, ...path.split('/'))
    await mkdir(dirname(destination), { recursive: true })
    await writeFile(destination, contents, 'utf8')
  }
  await run('git', ['add', '.'], { cwd: root })
  await run('git', ['commit', '-m', 'node fixture'], { cwd: root })
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
    revision = assessment.value.assessmentRevision
  }
  throw new Error('Assessment did not seal')
}

describe('qualified built-in Node package lifecycle Analyzer', () => {
  it('detects duplicate scripts keys without treating quoted descriptions as properties', () => {
    const subjectDigest = structuredDigest(
      'application/vnd.dsh.security.subject-manifest+json',
      { fixture: 'duplicate-scripts' },
    )
    const cleanText = '{"description":"literal \\"scripts\\": token","scripts":{"postinstall":"echo hi"}}\n'
    const clean = analyzeNodePackageInstallLifecycle({
      subjectDigest,
      slices: [{
        path: 'package.json',
        text: cleanText,
        digest: structuredDigest('application/octet-stream', { text: cleanText }),
      }],
    })
    expect(clean.completionDisposition).toBe('COMPLETE')
    expect(clean.diagnostics).not.toContain('PACKAGE_MANIFEST_DUPLICATE_SECURITY_KEY')

    const duplicateText = '{"scripts":{"postinstall":"echo first"},"scripts":{"postinstall":"echo second"}}\n'
    const duplicate = analyzeNodePackageInstallLifecycle({
      subjectDigest,
      slices: [{
        path: 'package.json',
        text: duplicateText,
        digest: structuredDigest('application/octet-stream', { text: duplicateText }),
      }],
    })
    expect(duplicate.completionDisposition).toBe('INCOMPLETE')
    expect(duplicate.diagnostics).toContain('PACKAGE_MANIFEST_DUPLICATE_SECURITY_KEY')
  })

  it('seals SATISFIED when eligible Evidence proves all Node package manifests omit install lifecycle scripts', async () => {
    const repository = await nodeRepositoryFixture({
      name: 'safe-node-fixture',
      version: '1.0.0',
      type: 'module',
    })
    const dshHome = await mkdtemp(join(tmpdir(), 'dsh-security-qualified-node-home-'))
    temporaryRoots.push(dshHome)
    const ctx = new Context()
    const fiber = await ctx.plugin(SecurityAssuranceTestComposition, { dshHome })
    const platform = process.platform
    if (platform !== 'win32' && platform !== 'linux' && platform !== 'darwin') {
      throw new Error(`unsupported test platform: ${platform}`)
    }

    try {
      const invocation = referenceHostInvocation(ctx.securityAssurance)
      const registered = await ctx.securityAssurance.registerRepository(invocation, {
        schemaVersion: 1,
        contractVersion: 1,
        idempotencyKey: 'qualified-node-safe-register-1',
        root: repository,
        displayName: 'Safe Node fixture',
        bindings: {
          policyId: 'security/node-package-lifecycle',
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
        contractVersion: 1,
        idempotencyKey: 'qualified-node-safe-assessment-1',
        repositoryId: registered.value.repositoryId,
        subject: { kind: 'workspace_snapshot' },
        assessmentMode: 'REPOSITORY',
        assessmentProfileId: 'security/standard',
        target: { kind: 'repository' },
        requestedStrongerControlIds: [],
      })
      if (!started.ok) throw new Error(`start failed: ${started.error.code}`)
      await waitUntilSealed(ctx.securityAssurance, invocation, started.value.assessmentId)

      const assessment = await ctx.securityAssurance.getAssessment(invocation, {
        schemaVersion: 1,
        assessmentId: started.value.assessmentId,
      })
      expect(assessment).toMatchObject({
        ok: true,
        value: {
          state: 'SEALED',
          verdict: 'SATISFIED',
          coverage: {
            status: 'COMPLETE',
            mandatoryObligations: 1,
            satisfiedObligations: 1,
            gapObligations: 0,
            resolutions: [{
              obligationId: 'node-package-install-lifecycle-policy',
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
                  analyzerId: 'dsh/builtin-node-package-lifecycle',
                  analyzerVersion: '1.1.0',
                  descriptorSchemaVersion: 1,
                  buildDigest: {
                    algorithm: 'sha256',
                    canonicalization: 'dsh-canonical-json-v1',
                  },
                  executionClass: 'PURE',
                  qualificationId: 'dsh/qualification/builtin-node-package-lifecycle/v2',
                  qualificationDigest: {
                    algorithm: 'sha256',
                    canonicalization: 'dsh-canonical-json-v1',
                  },
                  verdictEligible: true,
                }],
              },
            },
            findings: { value: { findings: [] } },
            evidence: expect.arrayContaining([
              expect.objectContaining({ schemaId: 'dsh/security-node-package-manifest-evidence' }),
              expect.objectContaining({ schemaId: 'dsh/security-analyzer-contribution' }),
              expect.objectContaining({ schemaId: 'dsh/security-evidence-eligibility-decision' }),
              expect.objectContaining({ schemaId: 'dsh/security-evaluation-trace' }),
            ]),
          },
        },
      })
      expect(JSON.stringify(submission)).not.toContain(repository)
    } finally {
      await fiber.dispose()
    }
  })

  it('seals and lists a blocking lifecycle Finding despite another manifest Coverage Gap', async () => {
    const repository = await nodeRepositoryFixture({
      name: 'unsafe-node-fixture',
      version: '1.0.0',
      scripts: { postinstall: 'node setup.js' },
    }, {
      'packages/broken/package.json': '{ invalid json\n',
      'setup.js': 'process.stdout.write("setup")\n',
    })
    const dshHome = await mkdtemp(join(tmpdir(), 'dsh-security-qualified-node-failed-home-'))
    temporaryRoots.push(dshHome)
    const ctx = new Context()
    const fiber = await ctx.plugin(SecurityAssuranceTestComposition, { dshHome })
    const platform = process.platform
    if (platform !== 'win32' && platform !== 'linux' && platform !== 'darwin') {
      throw new Error(`unsupported test platform: ${platform}`)
    }

    try {
      const invocation = referenceHostInvocation(ctx.securityAssurance)
      const registered = await ctx.securityAssurance.registerRepository(invocation, {
        schemaVersion: 1,
        contractVersion: 1,
        idempotencyKey: 'qualified-node-failed-register-1',
        root: repository,
        displayName: 'Unsafe Node fixture',
        bindings: {
          policyId: 'security/node-package-lifecycle',
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
        contractVersion: 1,
        idempotencyKey: 'qualified-node-failed-assessment-1',
        repositoryId: registered.value.repositoryId,
        subject: { kind: 'workspace_snapshot' },
        assessmentMode: 'REPOSITORY',
        assessmentProfileId: 'security/standard',
        target: { kind: 'repository' },
        requestedStrongerControlIds: [],
      })
      if (!started.ok) throw new Error(`start failed: ${started.error.code}`)
      await waitUntilSealed(ctx.securityAssurance, invocation, started.value.assessmentId)

      const assessment = await ctx.securityAssurance.getAssessment(invocation, {
        schemaVersion: 1,
        assessmentId: started.value.assessmentId,
      })
      expect(assessment).toMatchObject({
        ok: true,
        value: {
          state: 'SEALED',
          verdict: 'FAILED',
          coverage: {
            status: 'GAP',
            mandatoryObligations: 1,
            satisfiedObligations: 0,
            gapObligations: 1,
            resolutions: [{
              obligationId: 'node-package-install-lifecycle-policy',
              state: 'GAP',
              reason: 'ANALYZER_INCOMPLETE',
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
            assessment: { verdict: 'FAILED' },
            findings: {
              value: {
                findings: [{
                  kind: 'NODE_PACKAGE_INSTALL_LIFECYCLE_POLICY_VIOLATION',
                  weaknessId: 'DSH-NODE-POLICY-001',
                  sourceAnchor: {
                    path: 'package.json',
                    jsonPointer: '/scripts/postinstall',
                  },
                  validation: { state: 'VALIDATED' },
                  technicalSeverity: { value: 'MEDIUM' },
                  evidenceConfidence: { value: 'HIGH' },
                  policySignificance: 'BLOCKING',
                }],
              },
            },
            evidence: expect.arrayContaining([
              expect.objectContaining({ schemaId: 'dsh/security-node-package-manifest-evidence' }),
              expect.objectContaining({ schemaId: 'dsh/security-evidence-eligibility-decision' }),
            ]),
          },
        },
      })
      expect(JSON.stringify(submission)).not.toContain('node setup.js')
      expect(JSON.stringify(submission)).not.toContain(repository)
      const listed = await ctx.securityAssurance.listFindings(invocation, {
        schemaVersion: 1,
        assessmentId: started.value.assessmentId,
        limit: 10,
      })
      expect(listed).toMatchObject({
        ok: true,
        value: {
          findings: [{
            recordKind: 'FINDING',
            validationState: 'VALIDATED',
            validationContractId: 'dsh-node-package-install-lifecycle-validation-v1',
            weaknessClassification: {
              primary: 'DSH-NODE-POLICY-001',
              secondary: [],
            },
            technicalSeverity: 'MEDIUM',
            evidenceConfidence: 'HIGH',
            policySignificance: 'BLOCKING',
            hasProtectedDetail: true,
          }],
          nextCursor: null,
        },
      })
      if (!listed.ok || listed.value.findings[0] === undefined) {
        throw new Error('sealed built-in Finding was not listed')
      }
      const summary = listed.value.findings[0]
      const detail = await ctx.securityAssurance.getFinding(invocation, {
        schemaVersion: 1,
        assessmentId: started.value.assessmentId,
        assessmentRevision: summary.assessmentRevision,
        recordId: summary.recordId,
        recordRevision: summary.recordRevision,
      })
      expect(detail).toMatchObject({
        ok: true,
        value: {
          recordKind: 'FINDING',
          recordId: summary.recordId,
          candidateId: summary.candidateId,
          recordRevision: 1,
          affectedControlId: null,
          sourceAnchor: {
            path: 'package.json',
            locator: { kind: 'JSON_POINTER', value: '/scripts/postinstall' },
          },
          validation: {
            state: 'VALIDATED',
            contractId: 'dsh-node-package-install-lifecycle-validation-v1',
            contractVersion: 1,
            outcomeArtifactId: null,
            rejectionCondition: null,
            proofGaps: [],
            negativeControls: [
              'exact-json-pointer',
              'non-empty-string-value',
              'verified-subject-file-digest',
            ],
          },
          technicalSeverity: {
            value: 'MEDIUM',
            methodVersion: 'dsh-node-install-lifecycle-severity-v1',
            inputs: [],
          },
          evidenceConfidence: {
            value: 'HIGH',
            methodVersion: 'dsh-deterministic-manifest-evidence-confidence-v1',
            rubric: [],
          },
          policySignificance: 'BLOCKING',
          coverageRelations: [{
            obligationId: 'node-package-install-lifecycle-policy',
            state: 'GAP',
            reason: 'ANALYZER_INCOMPLETE',
          }],
          evidenceLinks: [{
            artifactId: 'node-package-manifest-evidence',
            schemaId: 'dsh/security-node-package-manifest-evidence',
            purpose: 'VALIDATION_EVIDENCE',
            eligibilityDecision: 'ELIGIBLE',
            eligibilityDecisionArtifactId: 'evidence-eligibility-decision',
          }],
          riskDecision: { state: 'NOT_RECORDED' },
          attackPath: { state: 'NOT_AVAILABLE' },
        },
      })
      expect(detail).not.toHaveProperty('value.evidenceLinks.0.value')
      if (!detail.ok || detail.value.evidenceLinks[0] === undefined) {
        throw new Error('sealed built-in Finding has no Evidence Link')
      }
      const evidenceLink = detail.value.evidenceLinks[0]
      const evidenceView = await ctx.securityAssurance.getEvidenceView(invocation, {
        schemaVersion: 1,
        assessmentId: started.value.assessmentId,
        assessmentRevision: summary.assessmentRevision,
        context: {
          kind: 'finding',
          recordId: summary.recordId,
          recordRevision: summary.recordRevision,
        },
        evidenceArtifactId: evidenceLink.artifactId,
        evidenceDigest: evidenceLink.digest,
        purpose: 'VALIDATION_REVIEW',
        viewProfileId: 'security/evidence-view/bounded-json-v1',
      })
      expect(evidenceView).toMatchObject({
        ok: true,
        value: {
          evidence: {
            artifactId: 'node-package-manifest-evidence',
            schemaId: 'dsh/security-node-package-manifest-evidence',
            classification: 'CONTROL_PLANE',
          },
          content: {
            kind: 'BOUNDED_JSON',
            value: {
              schemaVersion: 1,
              manifests: expect.arrayContaining([expect.objectContaining({
                path: 'package.json',
                parseStatus: 'VALID',
                installLifecycleScripts: ['postinstall'],
              })]),
            },
          },
        },
      })
      expect(JSON.stringify(evidenceView)).not.toContain('node setup.js')
      expect(JSON.stringify(evidenceView)).not.toContain(repository)
    } finally {
      await fiber.dispose()
    }
  })

  it('seals INDETERMINATE instead of treating a malformed lifecycle value as safe', async () => {
    const repository = await nodeRepositoryFixture({
      name: 'malformed-node-fixture',
      version: '1.0.0',
      scripts: { postinstall: 42 },
    })
    const dshHome = await mkdtemp(join(tmpdir(), 'dsh-security-qualified-node-malformed-home-'))
    temporaryRoots.push(dshHome)
    const ctx = new Context()
    const fiber = await ctx.plugin(SecurityAssuranceTestComposition, { dshHome })
    const platform = process.platform
    if (platform !== 'win32' && platform !== 'linux' && platform !== 'darwin') {
      throw new Error(`unsupported test platform: ${platform}`)
    }

    try {
      const invocation = referenceHostInvocation(ctx.securityAssurance)
      const registered = await ctx.securityAssurance.registerRepository(invocation, {
        schemaVersion: 1,
        contractVersion: 1,
        idempotencyKey: 'qualified-node-malformed-register-1',
        root: repository,
        displayName: 'Malformed Node fixture',
        bindings: {
          policyId: 'security/node-package-lifecycle',
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
        contractVersion: 1,
        idempotencyKey: 'qualified-node-malformed-assessment-1',
        repositoryId: registered.value.repositoryId,
        subject: { kind: 'workspace_snapshot' },
        assessmentMode: 'REPOSITORY',
        assessmentProfileId: 'security/standard',
        target: { kind: 'repository' },
        requestedStrongerControlIds: [],
      })
      if (!started.ok) throw new Error(`start failed: ${started.error.code}`)
      await waitUntilSealed(ctx.securityAssurance, invocation, started.value.assessmentId)

      const assessment = await ctx.securityAssurance.getAssessment(invocation, {
        schemaVersion: 1,
        assessmentId: started.value.assessmentId,
      })
      expect(assessment).toMatchObject({
        ok: true,
        value: {
          state: 'SEALED',
          verdict: 'INDETERMINATE',
          coverage: {
            status: 'GAP',
            resolutions: [{ reason: 'ANALYZER_INCOMPLETE' }],
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
            findings: { value: { findings: [] } },
            evidence: expect.arrayContaining([
              expect.objectContaining({
                schemaId: 'dsh/security-analyzer-contribution',
                value: expect.objectContaining({
                  completionDisposition: 'INCOMPLETE',
                  diagnostics: ['PACKAGE_MANIFEST_INVALID_SCRIPTS'],
                }),
              }),
            ]),
          },
        },
      })
    } finally {
      await fiber.dispose()
    }
  })

  it('fails closed when duplicate lifecycle keys make package JSON security semantics ambiguous', async () => {
    const repository = await nodeRepositoryFixture({ name: 'placeholder', version: '1.0.0' }, {
      'package.json': '{"name":"duplicate-key-fixture","scripts":{"postinstall":"node setup.js","postinstall":""}}\n',
    })
    const dshHome = await mkdtemp(join(tmpdir(), 'dsh-security-qualified-node-duplicate-home-'))
    temporaryRoots.push(dshHome)
    const ctx = new Context()
    const fiber = await ctx.plugin(SecurityAssuranceTestComposition, { dshHome })
    const platform = process.platform
    if (platform !== 'win32' && platform !== 'linux' && platform !== 'darwin') {
      throw new Error(`unsupported test platform: ${platform}`)
    }

    try {
      const invocation = referenceHostInvocation(ctx.securityAssurance)
      const registered = await ctx.securityAssurance.registerRepository(invocation, {
        schemaVersion: 1,
        contractVersion: 1,
        idempotencyKey: 'qualified-node-duplicate-register-1',
        root: repository,
        displayName: 'Duplicate key Node fixture',
        bindings: {
          policyId: 'security/node-package-lifecycle',
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
        contractVersion: 1,
        idempotencyKey: 'qualified-node-duplicate-assessment-1',
        repositoryId: registered.value.repositoryId,
        subject: { kind: 'workspace_snapshot' },
        assessmentMode: 'REPOSITORY',
        assessmentProfileId: 'security/standard',
        target: { kind: 'repository' },
        requestedStrongerControlIds: [],
      })
      if (!started.ok) throw new Error(`start failed: ${started.error.code}`)
      await waitUntilSealed(ctx.securityAssurance, invocation, started.value.assessmentId)

      const assessment = await ctx.securityAssurance.getAssessment(invocation, {
        schemaVersion: 1,
        assessmentId: started.value.assessmentId,
      })
      expect(assessment).toMatchObject({
        ok: true,
        value: {
          state: 'SEALED',
          verdict: 'INDETERMINATE',
          coverage: {
            status: 'GAP',
            resolutions: [{ reason: 'ANALYZER_INCOMPLETE' }],
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
            evidence: expect.arrayContaining([
              expect.objectContaining({
                schemaId: 'dsh/security-analyzer-contribution',
                value: expect.objectContaining({
                  completionDisposition: 'INCOMPLETE',
                  diagnostics: ['PACKAGE_MANIFEST_DUPLICATE_SECURITY_KEY'],
                }),
              }),
            ]),
          },
        },
      })
    } finally {
      await fiber.dispose()
    }
  })
})
