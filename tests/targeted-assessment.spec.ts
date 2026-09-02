import { SecurityAssuranceTestComposition } from './support/security-assurance-test-composition.ts'
import { referenceHostInvocation } from './support/reference-host.ts'
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

const run = promisify(execFile)
const temporaryRoots: string[] = []

afterEach(async () => {
  await removeTemporaryRoots(temporaryRoots)
})

async function targetedRepositoryFixture(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), 'dsh-security-targeted-'))
  temporaryRoots.push(root)
  await run('git', ['init', '-b', 'main'], { cwd: root })
  await run('git', ['config', 'user.email', 'fixture@example.invalid'], { cwd: root })
  await run('git', ['config', 'user.name', 'Fixture'], { cwd: root })
  const files = {
    'package.json': '{"name":"targeted-root","version":"1.0.0"}\n',
    'README.md': '# targeted fixture\n',
    'packages/clean/package.json': '{"name":"targeted-clean","version":"1.0.0"}\n',
    'packages/risky/package.json': '{"name":"targeted-risky","version":"1.0.0","scripts":{"postinstall":"node setup.js"}}\n',
    'packages/risky/setup.js': 'export const setup = true\n',
  }
  for (const [path, contents] of Object.entries(files)) {
    const destination = join(root, ...path.split('/'))
    await mkdir(dirname(destination), { recursive: true })
    await writeFile(destination, contents, 'utf8')
  }
  await run('git', ['add', '.'], { cwd: root })
  await run('git', ['commit', '-m', 'targeted fixture'], { cwd: root })
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

describe('TARGETED Node package lifecycle Assessments', () => {
  it('evaluates only package manifests at or below the exact frozen Target paths', async () => {
    const repository = await targetedRepositoryFixture()
    const dshHome = await mkdtemp(join(tmpdir(), 'dsh-security-targeted-home-'))
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
        idempotencyKey: 'targeted-repository-v1',
        root: repository,
        displayName: 'Targeted fixture',
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

      const start = async (idempotencyKey: string, relativePaths: readonly string[]) => {
        const started = await ctx.securityAssurance.startAssessment(invocation, {
          schemaVersion: 1,
          contractVersion: 1,
          idempotencyKey,
          repositoryId: registered.value.repositoryId,
          subject: { kind: 'workspace_snapshot' },
          assessmentMode: 'TARGETED',
          assessmentProfileId: 'security/standard',
          target: { kind: 'targeted', relativePaths: [...relativePaths] },
          requestedStrongerControlIds: [],
        })
        if (!started.ok) throw new Error(`start failed: ${started.error.code}`)
        await waitUntilSealed(ctx.securityAssurance, invocation, started.value.assessmentId)
        const assessment = await ctx.securityAssurance.getAssessment(invocation, {
          schemaVersion: 1,
          assessmentId: started.value.assessmentId,
        })
        if (!assessment.ok) throw new Error(`query failed: ${assessment.error.code}`)
        return assessment.value
      }

      const clean = await start('targeted-clean-v1', ['packages/clean'])
      expect(clean).toMatchObject({
        state: 'SEALED',
        verdict: 'SATISFIED',
        contract: {
          assessmentMode: 'TARGETED',
          target: { kind: 'targeted', relativePaths: ['packages/clean'] },
        },
        coverage: {
          status: 'COMPLETE',
          resolutions: [{
            obligationId: 'node-package-install-lifecycle-policy',
            state: 'SATISFIED',
            reason: 'ELIGIBLE_EVIDENCE',
          }],
        },
      })

      const risky = await start('targeted-risky-v1', ['packages/risky'])
      expect(risky).toMatchObject({ state: 'SEALED', verdict: 'FAILED' })
      const submission = await ctx.securityAssurance.getAssuranceSubmission(invocation, {
        schemaVersion: 1,
        assessmentId: risky.assessmentId,
      })
      expect(submission).toMatchObject({
        ok: true,
        value: {
          payload: {
            findings: {
              value: {
                findings: [{
                  kind: 'NODE_PACKAGE_INSTALL_LIFECYCLE_POLICY_VIOLATION',
                  sourceAnchor: {
                    path: 'packages/risky/package.json',
                    jsonPointer: '/scripts/postinstall',
                  },
                }],
              },
            },
          },
        },
      })
      expect(JSON.stringify(submission)).not.toContain('node setup.js')
    } finally {
      await fiber.dispose()
    }
  })

  it('fails closed for nonexistent or policy-unsupported explicit Targets', async () => {
    const repository = await targetedRepositoryFixture()
    const dshHome = await mkdtemp(join(tmpdir(), 'dsh-security-targeted-negative-home-'))
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
        idempotencyKey: 'targeted-negative-repository-v1',
        root: repository,
        displayName: 'Targeted negative fixture',
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
      const request = {
        schemaVersion: 1 as const,
        contractVersion: 1 as const,
        repositoryId: registered.value.repositoryId,
        subject: { kind: 'workspace_snapshot' as const },
        assessmentMode: 'TARGETED' as const,
        assessmentProfileId: 'security/standard',
        requestedStrongerControlIds: [] as const,
      }

      await expect(ctx.securityAssurance.startAssessment(invocation, {
        ...request,
        idempotencyKey: 'targeted-missing-v1',
        target: { kind: 'targeted', relativePaths: ['missing'] },
      })).resolves.toMatchObject({ ok: false, error: { code: 'INVALID_REQUEST' } })

      const unsupported = await ctx.securityAssurance.startAssessment(invocation, {
        ...request,
        idempotencyKey: 'targeted-no-manifest-v1',
        target: { kind: 'targeted', relativePaths: ['README.md'] },
      })
      if (!unsupported.ok) throw new Error(`start failed: ${unsupported.error.code}`)
      await waitUntilSealed(ctx.securityAssurance, invocation, unsupported.value.assessmentId)
      await expect(ctx.securityAssurance.getAssessment(invocation, {
        schemaVersion: 1,
        assessmentId: unsupported.value.assessmentId,
      })).resolves.toMatchObject({
        ok: true,
        value: {
          state: 'SEALED',
          verdict: 'INDETERMINATE',
          coverage: {
            status: 'GAP',
            resolutions: [{
              obligationId: 'node-package-install-lifecycle-policy',
              state: 'GAP',
              reason: 'UNSUPPORTED_SUBJECT',
            }],
          },
        },
      })
    } finally {
      await fiber.dispose()
    }
  })
})
