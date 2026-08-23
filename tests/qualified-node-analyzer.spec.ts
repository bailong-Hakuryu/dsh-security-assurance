import { execFile } from 'node:child_process'
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { promisify } from 'node:util'
import { Context } from '@deepseek-ai/cordis'
import { afterEach, describe, expect, it } from 'vitest'
import SecurityAssuranceService from '../src/index.ts'
import type { AssessmentId, SecurityInvocation } from '../src/index.ts'
import { referenceHostInvocation } from './support/reference-host.ts'

const run = promisify(execFile)
const temporaryRoots: string[] = []

afterEach(async () => {
  await Promise.all(temporaryRoots.splice(0).map(path => rm(path, { recursive: true, force: true })))
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
  it('seals SATISFIED when eligible Evidence proves all Node package manifests omit install lifecycle scripts', async () => {
    const repository = await nodeRepositoryFixture({
      name: 'safe-node-fixture',
      version: '1.0.0',
      type: 'module',
    })
    const dshHome = await mkdtemp(join(tmpdir(), 'dsh-security-qualified-node-home-'))
    temporaryRoots.push(dshHome)
    const ctx = new Context()
    const fiber = await ctx.plugin(SecurityAssuranceService, { dshHome })
    const platform = process.platform
    if (platform !== 'win32' && platform !== 'linux' && platform !== 'darwin') {
      throw new Error(`unsupported test platform: ${platform}`)
    }

    try {
      const invocation = referenceHostInvocation(ctx.securityAssurance)
      const registered = await ctx.securityAssurance.registerRepository(invocation, {
        schemaVersion: 1,
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
                  analyzerVersion: '1.0.0',
                  descriptorSchemaVersion: 1,
                  buildDigest: {
                    algorithm: 'sha256',
                    canonicalization: 'dsh-canonical-json-v1',
                  },
                  executionClass: 'PURE',
                  qualificationId: 'dsh/qualification/builtin-node-package-lifecycle/v1',
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

  it('seals FAILED when eligible Evidence proves a blocking lifecycle script despite another manifest Coverage Gap', async () => {
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
    const fiber = await ctx.plugin(SecurityAssuranceService, { dshHome })
    const platform = process.platform
    if (platform !== 'win32' && platform !== 'linux' && platform !== 'darwin') {
      throw new Error(`unsupported test platform: ${platform}`)
    }

    try {
      const invocation = referenceHostInvocation(ctx.securityAssurance)
      const registered = await ctx.securityAssurance.registerRepository(invocation, {
        schemaVersion: 1,
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
    const fiber = await ctx.plugin(SecurityAssuranceService, { dshHome })
    const platform = process.platform
    if (platform !== 'win32' && platform !== 'linux' && platform !== 'darwin') {
      throw new Error(`unsupported test platform: ${platform}`)
    }

    try {
      const invocation = referenceHostInvocation(ctx.securityAssurance)
      const registered = await ctx.securityAssurance.registerRepository(invocation, {
        schemaVersion: 1,
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
    const fiber = await ctx.plugin(SecurityAssuranceService, { dshHome })
    const platform = process.platform
    if (platform !== 'win32' && platform !== 'linux' && platform !== 'darwin') {
      throw new Error(`unsupported test platform: ${platform}`)
    }

    try {
      const invocation = referenceHostInvocation(ctx.securityAssurance)
      const registered = await ctx.securityAssurance.registerRepository(invocation, {
        schemaVersion: 1,
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
