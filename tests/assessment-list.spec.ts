import { execFile } from 'node:child_process'
import { mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { promisify } from 'node:util'
import { Context } from '@deepseek-ai/cordis'
import { afterEach, describe, expect, it } from 'vitest'
import SecurityAssuranceService from '../src/index.ts'
import { referenceHostInvocation, referenceHostInvocationWithPermissions } from './support/reference-host.ts'

const run = promisify(execFile)
const temporaryRoots: string[] = []
const contexts: Context[] = []

afterEach(async () => {
  await Promise.all(contexts.splice(0).map(ctx => ctx.fiber.dispose()))
  await Promise.all(temporaryRoots.splice(0).map(path => rm(path, { recursive: true, force: true })))
})

async function repositoryFixture(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), 'dsh-security-assessment-list-repository-'))
  temporaryRoots.push(root)
  await run('git', ['init', '-b', 'main'], { cwd: root })
  await run('git', ['config', 'user.email', 'fixture@example.invalid'], { cwd: root })
  await run('git', ['config', 'user.name', 'Fixture'], { cwd: root })
  await writeFile(join(root, 'README.md'), '# assessment list fixture\n', 'utf8')
  await run('git', ['add', '.'], { cwd: root })
  await run('git', ['commit', '-m', 'assessment list fixture'], { cwd: root })
  return root
}

describe('SecurityAssuranceService Assessment list', () => {
  it('returns a redacted, authority-bound keyset page with a first-page watermark', async () => {
    const repository = await repositoryFixture()
    const dshHome = await mkdtemp(join(tmpdir(), 'dsh-security-assessment-list-home-'))
    temporaryRoots.push(dshHome)
    const ctx = new Context()
    contexts.push(ctx)
    await ctx.plugin(SecurityAssuranceService, { dshHome })
    await ctx.securityAssurance.whenReady()

    const invocation = referenceHostInvocation(ctx.securityAssurance, 'assessment-list-reviewer')
    const registered = await ctx.securityAssurance.registerRepository(invocation, {
      schemaVersion: 1,
      idempotencyKey: 'assessment-list-repository-v1',
      root: repository,
      displayName: 'Assessment list fixture',
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

    const start = async (ordinal: number) => {
      const started = await ctx.securityAssurance.startAssessment(invocation, {
        schemaVersion: 1,
        idempotencyKey: `assessment-list-start-${ordinal}`,
        repositoryId: registered.value.repositoryId,
        subject: { kind: 'workspace_snapshot' as const },
        assessmentMode: 'REPOSITORY' as const,
        assessmentProfileId: 'security/standard',
        target: { kind: 'repository' as const },
        requestedStrongerControlIds: [],
      })
      if (!started.ok) throw new Error(`start failed: ${started.error.code}`)
      return started.value.assessmentId
    }

    const initialIds = await Promise.all([start(1), start(2), start(3)])
    const first = await ctx.securityAssurance.listAssessments(invocation, {
      schemaVersion: 1,
      limit: 2,
    })
    expect(first).toMatchObject({
      ok: true,
      value: {
        schemaVersion: 1,
        assessments: [{ schemaVersion: 1 }, { schemaVersion: 1 }],
      },
    })
    if (!first.ok || first.value.nextCursor === null) throw new Error('first page was not pageable')
    expect(first.value.consistencyWatermark).toMatch(/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/)
    expect(JSON.stringify(first.value)).not.toContain(repository)
    expect(JSON.stringify(first.value)).not.toContain('rootIdentityDigest')
    expect(JSON.stringify(first.value)).not.toContain('availableActions')

    const laterId = await start(4)
    const second = await ctx.securityAssurance.listAssessments(invocation, {
      schemaVersion: 1,
      limit: 2,
      cursor: first.value.nextCursor,
    })
    expect(second).toMatchObject({ ok: true, value: { consistencyWatermark: first.value.consistencyWatermark } })
    if (!second.ok) throw new Error(`second page failed: ${second.error.code}`)
    const observed = [...first.value.assessments, ...second.value.assessments]
      .map(item => item.assessmentId)
    expect(new Set(observed)).toEqual(new Set(initialIds))
    expect(observed).not.toContain(laterId)

    const cursor = first.value.nextCursor
    const tamperedCursor = `${cursor.slice(0, -1)}${cursor.endsWith('A') ? 'B' : 'A'}`
    await expect(ctx.securityAssurance.listAssessments(invocation, {
      schemaVersion: 1,
      limit: 2,
      cursor: tamperedCursor,
    })).resolves.toMatchObject({ ok: false, error: { code: 'INVALID_REQUEST' } })

    const otherPrincipal = referenceHostInvocationWithPermissions(
      ctx.securityAssurance,
      ['assessment:read'],
      'other-assessment-list-reviewer',
    )
    await expect(ctx.securityAssurance.listAssessments(otherPrincipal, {
      schemaVersion: 1,
      limit: 2,
      cursor: first.value.nextCursor,
    })).resolves.toMatchObject({ ok: false, error: { code: 'INVALID_REQUEST' } })
    await expect(ctx.securityAssurance.listAssessments(
      referenceHostInvocationWithPermissions(ctx.securityAssurance, ['health:read']),
      { schemaVersion: 1, limit: 10 },
    )).resolves.toMatchObject({ ok: false, error: { code: 'UNAUTHORIZED' } })
  })
})
