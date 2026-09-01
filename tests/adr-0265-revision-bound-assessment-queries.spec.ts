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

describe('ADR 0265 revision-bound Assessment queries', () => {
  it('returns immutable contract identities and a redacted watermarked list', async () => {
    const repository = await mkdtemp(join(tmpdir(), 'dsh-security-query-contract-'))
    const dshHome = await mkdtemp(join(tmpdir(), 'dsh-security-query-contract-home-'))
    temporaryRoots.push(repository, dshHome)
    await run('git', ['init', '-b', 'main'], { cwd: repository })
    await run('git', ['config', 'user.email', 'fixture@example.invalid'], { cwd: repository })
    await run('git', ['config', 'user.name', 'Fixture'], { cwd: repository })
    await writeFile(join(repository, 'README.md'), '# revision-bound query fixture\n', 'utf8')
    await run('git', ['add', '.'], { cwd: repository })
    await run('git', ['commit', '-m', 'query baseline'], { cwd: repository })

    const ctx = new Context()
    const fiber = await ctx.plugin(SecurityAssuranceTestComposition, { dshHome })
    try {
      const invocation = referenceHostInvocation(ctx.securityAssurance)
      const registered = await ctx.securityAssurance.registerRepository(invocation, {
        schemaVersion: 1,
        contractVersion: 1 as const,
        idempotencyKey: 'query-contract-repository',
        root: repository,
        displayName: 'Query contract fixture',
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
        idempotencyKey: 'query-contract-assessment',
        repositoryId: registered.value.repositoryId,
        subject: { kind: 'workspace_snapshot' },
        assessmentMode: 'TARGETED',
        assessmentProfileId: 'security/standard',
        target: { kind: 'targeted', relativePaths: ['README.md'] },
        requestedStrongerControlIds: [],
      })
      if (!started.ok) throw new Error(`start failed: ${started.error.code}`)

      const snapshot = await ctx.securityAssurance.getAssessment(invocation, {
        schemaVersion: 1,
        assessmentId: started.value.assessmentId,
      })
      expect(snapshot).toMatchObject({
        ok: true,
        value: {
          assessmentId: started.value.assessmentId,
          contract: {
            schemaVersion: 1,
            assessmentMode: 'TARGETED',
            assessmentProfileId: 'security/standard',
            target: { kind: 'targeted', relativePaths: ['README.md'] },
            targetDigest: {
              mediaType: 'application/vnd.dsh.security.target-selector+json',
              value: expect.stringMatching(/^[0-9a-f]{64}$/u),
            },
            requestedStrongerControlIds: [],
          },
        },
      })
      if (!snapshot.ok) throw new Error(`snapshot failed: ${snapshot.error.code}`)
      expect(Object.isFrozen(snapshot.value)).toBe(true)
      expect(JSON.stringify(snapshot.value)).not.toContain(repository)

      const listed = await ctx.securityAssurance.listAssessments(invocation, {
        schemaVersion: 1,
        limit: 10,
      })
      expect(listed).toMatchObject({
        ok: true,
        value: {
          assessments: [{
            assessmentId: started.value.assessmentId,
            assessmentRevision: expect.any(Number),
          }],
          consistencyWatermark: expect.stringMatching(/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/u),
        },
      })
      expect(JSON.stringify(listed)).not.toContain(repository)
      expect(JSON.stringify(listed)).not.toContain('targetDigest')
    } finally {
      await fiber.dispose()
    }
  })
})
