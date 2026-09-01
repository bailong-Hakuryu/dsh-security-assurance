import { SecurityAssuranceTestComposition } from './support/security-assurance-test-composition.ts'
import { removeTemporaryRoots } from './support/remove-temporary-root.ts'
import { execFile } from 'node:child_process'
import { mkdtemp, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { promisify } from 'node:util'
import { Context } from '@deepseek-ai/cordis'
import { afterEach, describe, expect, it } from 'vitest'
import { referenceHostInvocation } from './support/reference-host.ts'

const run = promisify(execFile)
const temporaryRoots: string[] = []

afterEach(async () => {
  await removeTemporaryRoots(temporaryRoots)
})

describe('ADR 0266 bounded Assessment revision wait', () => {
  it('returns only a change signal with current state and refetch guidance', async () => {
    const repository = await mkdtemp(join(tmpdir(), 'dsh-security-revision-signal-'))
    const dshHome = await mkdtemp(join(tmpdir(), 'dsh-security-revision-signal-home-'))
    temporaryRoots.push(repository, dshHome)
    await run('git', ['init', '-b', 'main'], { cwd: repository })
    await run('git', ['config', 'user.email', 'fixture@example.invalid'], { cwd: repository })
    await run('git', ['config', 'user.name', 'Fixture'], { cwd: repository })
    await writeFile(join(repository, 'README.md'), '# revision signal fixture\n', 'utf8')
    await run('git', ['add', '.'], { cwd: repository })
    await run('git', ['commit', '-m', 'revision signal baseline'], { cwd: repository })

    const ctx = new Context()
    const fiber = await ctx.plugin(SecurityAssuranceTestComposition, { dshHome })
    try {
      const invocation = referenceHostInvocation(ctx.securityAssurance)
      const registered = await ctx.securityAssurance.registerRepository(invocation, {
        schemaVersion: 1,
        contractVersion: 1 as const,
        idempotencyKey: 'revision-signal-repository',
        root: repository,
        displayName: 'Revision signal fixture',
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
      const started = await ctx.securityAssurance.startAssessment(invocation, {
        schemaVersion: 1,
        contractVersion: 1 as const,
        idempotencyKey: 'revision-signal-assessment',
        repositoryId: registered.value.repositoryId,
        subject: { kind: 'workspace_snapshot' },
        assessmentMode: 'REPOSITORY',
        assessmentProfileId: 'security/standard',
        target: { kind: 'repository' },
        requestedStrongerControlIds: [],
      })
      if (!started.ok) throw new Error(`start failed: ${started.error.code}`)

      const changed = await ctx.securityAssurance.waitForAssessmentRevision(invocation, {
        schemaVersion: 1,
        assessmentId: started.value.assessmentId,
        afterRevision: started.value.assessmentRevision,
        timeoutMs: 5_000,
      })
      expect(changed).toMatchObject({
        ok: true,
        value: {
          kind: 'CHANGED',
          changed: true,
          state: expect.stringMatching(/^(?:CREATED|RUNNING|BLOCKED|SEALED|CANCELED)$/u),
          terminal: expect.any(Boolean),
          snapshotRefreshRequired: true,
        },
      })
      if (!changed.ok) throw new Error(`change wait failed: ${changed.error.code}`)
      expect(changed.value.terminal).toBe(['SEALED', 'CANCELED'].includes(changed.value.state))

      let snapshot = await ctx.securityAssurance.getAssessment(invocation, {
        schemaVersion: 1,
        assessmentId: started.value.assessmentId,
      })
      for (let attempt = 0; snapshot.ok && snapshot.value.state !== 'SEALED' && attempt < 10; attempt += 1) {
        await new Promise(resolve => setTimeout(resolve, 25))
        snapshot = await ctx.securityAssurance.getAssessment(invocation, {
          schemaVersion: 1,
          assessmentId: started.value.assessmentId,
        })
      }
      if (!snapshot.ok || snapshot.value.state !== 'SEALED') throw new Error('assessment did not seal')

      const unchanged = await ctx.securityAssurance.waitForAssessmentRevision(invocation, {
        schemaVersion: 1,
        assessmentId: started.value.assessmentId,
        afterRevision: snapshot.value.assessmentRevision,
        timeoutMs: 1,
      })
      expect(unchanged).toMatchObject({
        ok: true,
        value: {
          kind: 'TIMED_OUT',
          changed: false,
          assessmentRevision: snapshot.value.assessmentRevision,
          state: 'SEALED',
          terminal: true,
          snapshotRefreshRequired: false,
        },
      })
      const serialized = JSON.stringify(unchanged)
      for (const forbidden of ['journal', 'evidence', 'findings', 'logs', 'patch', 'subscription']) {
        expect(serialized).not.toContain(forbidden)
      }
    } finally {
      await fiber.dispose()
    }
  })
})
