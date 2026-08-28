import { execFile } from 'node:child_process'
import { mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { promisify } from 'node:util'
import { Context } from '@deepseek-ai/cordis'
import { afterEach, describe, expect, it } from 'vitest'
import SecurityAssuranceService from '../src/index.ts'
import { referenceHostInvocation } from './support/reference-host.ts'

const run = promisify(execFile)
const temporaryRoots: string[] = []

afterEach(async () => {
  await Promise.all(temporaryRoots.splice(0).map(path => rm(path, { recursive: true, force: true })))
})

describe('ADR 0264 atomic Subject Freeze', () => {
  it('creates no Assessment identity or idempotency reservation until freeze succeeds', async () => {
    const repository = await mkdtemp(join(tmpdir(), 'dsh-security-freeze-atomicity-'))
    const dshHome = await mkdtemp(join(tmpdir(), 'dsh-security-freeze-atomicity-home-'))
    temporaryRoots.push(repository, dshHome)
    await run('git', ['init', '-b', 'main'], { cwd: repository })
    await run('git', ['config', 'user.email', 'fixture@example.invalid'], { cwd: repository })
    await run('git', ['config', 'user.name', 'Fixture'], { cwd: repository })
    await writeFile(join(repository, 'README.md'), '# freeze atomicity fixture\n', 'utf8')
    await run('git', ['add', '.'], { cwd: repository })
    await run('git', ['commit', '-m', 'freeze atomicity baseline'], { cwd: repository })

    const ctx = new Context()
    const fiber = await ctx.plugin(SecurityAssuranceService, { dshHome })
    try {
      const invocation = referenceHostInvocation(ctx.securityAssurance)
      const registered = await ctx.securityAssurance.registerRepository(invocation, {
        schemaVersion: 1,
        idempotencyKey: 'freeze-atomicity-repository',
        root: repository,
        displayName: 'Freeze atomicity fixture',
        bindings: {
          policyId: 'security/default',
          assessmentProfileId: 'security/standard',
          evidenceProtectionId: 'evidence/local-protected',
          dataEgressPolicyId: 'egress/deny-by-default',
          platform: process.platform as 'win32' | 'linux' | 'darwin',
          deliveryDestinationIds: [],
        },
      })
      if (!registered.ok) throw new Error(`registration failed: ${registered.error.code}`)

      const idempotencyKey = 'freeze-before-assessment-identity'
      const failed = await ctx.securityAssurance.startAssessment(invocation, {
        schemaVersion: 1,
        idempotencyKey,
        repositoryId: registered.value.repositoryId,
        subject: { kind: 'git_revision', commit: '0000000000000000000000000000000000000000' },
        assessmentMode: 'REPOSITORY',
        assessmentProfileId: 'security/standard',
        target: { kind: 'repository' },
        requestedStrongerControlIds: [],
      })
      expect(failed).toMatchObject({ ok: false, error: { code: 'INVALID_REQUEST' } })
      expect(JSON.stringify(failed)).not.toContain('assessmentId')

      const beforeRetry = await ctx.securityAssurance.listAssessments(invocation, {
        schemaVersion: 1,
        limit: 10,
      })
      expect(beforeRetry).toMatchObject({ ok: true, value: { assessments: [] } })

      const retried = await ctx.securityAssurance.startAssessment(invocation, {
        schemaVersion: 1,
        idempotencyKey,
        repositoryId: registered.value.repositoryId,
        subject: { kind: 'workspace_snapshot' },
        assessmentMode: 'REPOSITORY',
        assessmentProfileId: 'security/standard',
        target: { kind: 'repository' },
        requestedStrongerControlIds: [],
      })
      expect(retried).toMatchObject({ ok: true, value: { idempotencyKey } })
      if (!retried.ok) throw new Error(`retry failed: ${retried.error.code}`)

      const afterRetry = await ctx.securityAssurance.listAssessments(invocation, {
        schemaVersion: 1,
        limit: 10,
      })
      expect(afterRetry).toMatchObject({
        ok: true,
        value: { assessments: [{ assessmentId: retried.value.assessmentId }] },
      })
    } finally {
      await fiber.dispose()
    }
  })
})
