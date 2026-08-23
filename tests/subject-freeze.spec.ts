import { execFile } from 'node:child_process'
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { DatabaseSync } from 'node:sqlite'
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

async function repositoryFixture(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), 'dsh-security-subject-repository-'))
  temporaryRoots.push(root)
  await run('git', ['init', '-b', 'main'], { cwd: root })
  await run('git', ['config', 'user.email', 'fixture@example.invalid'], { cwd: root })
  await run('git', ['config', 'user.name', 'Fixture'], { cwd: root })
  await mkdir(join(root, 'src'))
  await writeFile(join(root, 'README.md'), '# subject fixture\n', 'utf8')
  await writeFile(join(root, 'src', 'tracked.ts'), 'export const tracked = 1\n', 'utf8')
  await run('git', ['add', '.'], { cwd: root })
  await run('git', ['commit', '-m', 'subject baseline'], { cwd: root })
  return root
}

describe('SecurityAssuranceService immutable Subject Freeze', () => {
  it('publishes a content-addressed Workspace Snapshot before creating the Assessment', async () => {
    const repository = await repositoryFixture()
    const workspaceFile = join(repository, 'src', 'workspace.ts')
    await writeFile(workspaceFile, 'export const frozen = 1\n', 'utf8')
    await rm(join(repository, 'src', 'tracked.ts'))
    const dshHome = await mkdtemp(join(tmpdir(), 'dsh-security-subject-home-'))
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
        idempotencyKey: 'subject-repository-register-1',
        root: repository,
        displayName: 'Subject fixture',
        bindings: {
          policyId: 'security/default',
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
        idempotencyKey: 'assessment-workspace-start-1',
        repositoryId: registered.value.repositoryId,
        subject: { kind: 'workspace_snapshot' as const },
        assessmentMode: 'REPOSITORY' as const,
        assessmentProfileId: 'security/standard',
        target: { kind: 'repository' as const },
        requestedStrongerControlIds: [],
      }
      const started = await ctx.securityAssurance.startAssessment(invocation, request)
      expect(started).toMatchObject({
        ok: true,
        value: {
          schemaVersion: 1,
          operation: 'start_assessment',
          assessmentId: expect.stringMatching(/^asm-[0-9a-f-]{36}$/u),
          assessmentRevision: 1,
          state: 'CREATED',
          repositoryId: registered.value.repositoryId,
          repositoryRevision: 1,
          idempotencyKey: request.idempotencyKey,
          subject: {
            kind: 'workspace_snapshot',
            digest: {
              schemaVersion: 1,
              algorithm: 'sha256',
              mediaType: 'application/vnd.dsh.security.subject-manifest+json',
              canonicalization: 'dsh-canonical-json-v1',
              value: expect.stringMatching(/^[0-9a-f]{64}$/u),
            },
          },
        },
      })
      if (!started.ok) throw new Error(`start failed: ${started.error.code}`)
      await expect(ctx.securityAssurance.startAssessment(invocation, request)).resolves.toEqual(started)
      await expect(ctx.securityAssurance.startAssessment(invocation, {
        ...request,
        subject: { kind: 'git_revision', commit: '0000000000000000000000000000000000000000' },
      })).resolves.toMatchObject({ ok: false, error: { code: 'IDEMPOTENCY_CONFLICT' } })

      const retried = await ctx.securityAssurance.startAssessment(invocation, {
        ...request,
        idempotencyKey: 'assessment-workspace-start-2',
      })
      expect(retried).toMatchObject({
        ok: true,
        value: {
          assessmentId: expect.stringMatching(/^asm-[0-9a-f-]{36}$/u),
          subject: { digest: started.value.subject.digest },
        },
      })
      if (!retried.ok) throw new Error(`retry start failed: ${retried.error.code}`)
      expect(retried.value.assessmentId).not.toBe(started.value.assessmentId)

      const subjectRoot = join(
        dshHome,
        'security-assurance',
        'subjects',
        started.value.subject.digest.value,
      )
      const manifest = JSON.parse(await readFile(join(subjectRoot, 'manifest.json'), 'utf8')) as unknown
      expect(manifest).toMatchObject({
        schemaVersion: 1,
        subject: { kind: 'workspace_snapshot' },
        entries: expect.arrayContaining([
          expect.objectContaining({ path: 'src/workspace.ts', kind: 'file' }),
        ]),
        exclusions: expect.arrayContaining([
          { kind: 'workspace_deleted', path: 'src/tracked.ts' },
        ]),
        rootDigest: started.value.subject.digest,
      })
      expect(await readFile(join(subjectRoot, 'content', 'src', 'workspace.ts'), 'utf8'))
        .toBe('export const frozen = 1\n')

      await writeFile(workspaceFile, 'export const frozen = 2\n', 'utf8')
      expect(await readFile(join(subjectRoot, 'content', 'src', 'workspace.ts'), 'utf8'))
        .toBe('export const frozen = 1\n')
      expect(JSON.stringify(started.value)).not.toContain(repository)
    } finally {
      await fiber.dispose()
    }
  })

  it('accepts exact Git revision and Change identities and creates no Assessment when freeze fails', async () => {
    const repository = await repositoryFixture()
    const base = (await run('git', ['rev-parse', 'HEAD'], { cwd: repository })).stdout.trim()
    await writeFile(join(repository, 'src', 'tracked.ts'), 'export const tracked = 2\n', 'utf8')
    await run('git', ['add', '.'], { cwd: repository })
    await run('git', ['commit', '-m', 'subject head'], { cwd: repository })
    const head = (await run('git', ['rev-parse', 'HEAD'], { cwd: repository })).stdout.trim()
    const dshHome = await mkdtemp(join(tmpdir(), 'dsh-security-subject-home-'))
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
        idempotencyKey: 'subject-repository-register-2',
        root: repository,
        displayName: 'Exact identity fixture',
        bindings: {
          policyId: 'security/default',
          assessmentProfileId: 'security/standard',
          evidenceProtectionId: 'evidence/local-protected',
          dataEgressPolicyId: 'egress/deny-by-default',
          platform,
          deliveryDestinationIds: [],
        },
      })
      if (!registered.ok) throw new Error(`registration failed: ${registered.error.code}`)

      const revision = await ctx.securityAssurance.startAssessment(invocation, {
        schemaVersion: 1,
        idempotencyKey: 'assessment-revision-start-1',
        repositoryId: registered.value.repositoryId,
        subject: { kind: 'git_revision', commit: head },
        assessmentMode: 'REPOSITORY',
        assessmentProfileId: 'security/standard',
        target: { kind: 'repository' },
        requestedStrongerControlIds: [],
      })
      expect(revision).toMatchObject({ ok: true, value: { subject: { kind: 'git_revision' } } })

      const change = await ctx.securityAssurance.startAssessment(invocation, {
        schemaVersion: 1,
        idempotencyKey: 'assessment-change-start-1',
        repositoryId: registered.value.repositoryId,
        subject: { kind: 'change', baseCommit: base, headCommit: head },
        assessmentMode: 'CHANGE',
        assessmentProfileId: 'security/standard',
        target: { kind: 'change', baseCommit: base, headCommit: head, impactCone: 'POLICY_DEFAULT' },
        requestedStrongerControlIds: [],
      })
      expect(change).toMatchObject({ ok: true, value: { subject: { kind: 'change' } } })

      const failed = await ctx.securityAssurance.startAssessment(invocation, {
        schemaVersion: 1,
        idempotencyKey: 'assessment-invalid-revision-1',
        repositoryId: registered.value.repositoryId,
        subject: { kind: 'git_revision', commit: '0000000000000000000000000000000000000000' },
        assessmentMode: 'REPOSITORY',
        assessmentProfileId: 'security/standard',
        target: { kind: 'repository' },
        requestedStrongerControlIds: [],
      })
      expect(failed).toMatchObject({ ok: false, error: { code: 'INVALID_REQUEST' } })
      expect(JSON.stringify(failed)).not.toContain('assessmentId')

      const db = new DatabaseSync(
        join(dshHome, 'security-assurance', 'security-assurance.sqlite'),
        { readOnly: true },
      )
      try {
        const row = db.prepare('SELECT count(*) AS count FROM assessments').get() as { count: number }
        expect(row.count).toBe(2)
      } finally {
        db.close()
      }
    } finally {
      await fiber.dispose()
    }
  })

  it('inventories Git symlinks and submodules without expanding either object', async () => {
    const repository = await repositoryFixture()
    const outside = await mkdtemp(join(tmpdir(), 'dsh-security-subject-outside-'))
    temporaryRoots.push(outside)
    await writeFile(join(outside, 'secret.txt'), 'must-not-enter-subject\n', 'utf8')
    const linkSpec = join(repository, 'link-spec.txt')
    await writeFile(linkSpec, '../../outside/secret.txt', 'utf8')
    const linkBlob = (await run('git', ['hash-object', '-w', 'link-spec.txt'], { cwd: repository })).stdout.trim()
    await rm(linkSpec)
    const head = (await run('git', ['rev-parse', 'HEAD'], { cwd: repository })).stdout.trim()
    await run('git', ['update-index', '--add', '--cacheinfo', '120000', linkBlob, 'escape-link'], { cwd: repository })
    await run('git', ['update-index', '--add', '--cacheinfo', '160000', head, 'vendor/child'], { cwd: repository })
    await run('git', ['commit', '-m', 'special objects'], { cwd: repository })
    const specialCommit = (await run('git', ['rev-parse', 'HEAD'], { cwd: repository })).stdout.trim()
    const dshHome = await mkdtemp(join(tmpdir(), 'dsh-security-subject-home-'))
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
        idempotencyKey: 'subject-repository-register-special-1',
        root: repository,
        displayName: 'Special object fixture',
        bindings: {
          policyId: 'security/default',
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
        idempotencyKey: 'assessment-special-start-1',
        repositoryId: registered.value.repositoryId,
        subject: { kind: 'git_revision', commit: specialCommit },
        assessmentMode: 'REPOSITORY',
        assessmentProfileId: 'security/standard',
        target: { kind: 'repository' },
        requestedStrongerControlIds: [],
      })
      if (!started.ok) throw new Error(`start failed: ${started.error.code}`)
      const subjectRoot = join(dshHome, 'security-assurance', 'subjects', started.value.subject.digest.value)
      const manifestText = await readFile(join(subjectRoot, 'manifest.json'), 'utf8')
      const manifest = JSON.parse(manifestText) as { entries: unknown[] }
      expect(manifest.entries).toEqual(expect.arrayContaining([
        expect.objectContaining({
          path: 'escape-link',
          kind: 'symbolic_link',
          targetScope: 'outside_subject_root',
        }),
        expect.objectContaining({
          path: 'vendor/child',
          kind: 'submodule',
          revision: head,
        }),
      ]))
      await expect(readFile(join(subjectRoot, 'content', 'escape-link'), 'utf8')).rejects.toMatchObject({
        code: 'ENOENT',
      })
      expect(manifestText).not.toContain('must-not-enter-subject')
    } finally {
      await fiber.dispose()
    }
  })
})
