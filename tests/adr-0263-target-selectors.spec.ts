import { SecurityAssuranceTestComposition } from './support/security-assurance-test-composition.ts'
import { removeTemporaryRoots } from './support/remove-temporary-root.ts'
import { execFile } from 'node:child_process'
import { mkdir, mkdtemp, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { promisify } from 'node:util'
import { Context } from '@deepseek-ai/cordis'
import { afterEach, describe, expect, it } from 'vitest'
import { assessmentTargetSelectorV1Schema } from '../src/index.ts'
import { referenceHostInvocation } from './support/reference-host.ts'

const run = promisify(execFile)
const temporaryRoots: string[] = []

afterEach(async () => {
  await removeTemporaryRoots(temporaryRoots)
})

async function repositoryFixture(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), 'dsh-security-target-selector-'))
  temporaryRoots.push(root)
  await run('git', ['init', '-b', 'main'], { cwd: root })
  await run('git', ['config', 'user.email', 'fixture@example.invalid'], { cwd: root })
  await run('git', ['config', 'user.name', 'Fixture'], { cwd: root })
  await mkdir(join(root, 'src'))
  await writeFile(join(root, 'README.md'), '# target selector fixture\n', 'utf8')
  await writeFile(join(root, 'src', 'index.ts'), 'export const target = true\n', 'utf8')
  await run('git', ['add', '.'], { cwd: root })
  await run('git', ['commit', '-m', 'target baseline'], { cwd: root })
  return root
}

describe('ADR 0263 mode-specific Target Selectors', () => {
  it('requires canonical explicit Targeted paths rather than globs or set-order variants', () => {
    expect(assessmentTargetSelectorV1Schema.safeParse({
      kind: 'targeted',
      relativePaths: ['README.md', 'src/index.ts'],
    }).success).toBe(true)
    for (const relativePaths of [
      ['src/**/*.ts'],
      ['src/index.ts', 'README.md'],
      ['README.md', 'README.md'],
    ]) {
      expect(assessmentTargetSelectorV1Schema.safeParse({
        kind: 'targeted',
        relativePaths,
      }).success).toBe(false)
    }
  })

  it('binds the canonical selector into both Subject and Coverage identities', async () => {
    const repository = await repositoryFixture()
    const dshHome = await mkdtemp(join(tmpdir(), 'dsh-security-target-home-'))
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
        contractVersion: 1 as const,
        idempotencyKey: 'target-selector-repository',
        root: repository,
        displayName: 'Target selector fixture',
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

      const start = async (idempotencyKey: string, relativePaths: readonly string[]) => {
        const result = await ctx.securityAssurance.startAssessment(invocation, {
          schemaVersion: 1,
          contractVersion: 1 as const,
          idempotencyKey,
          repositoryId: registered.value.repositoryId,
          subject: { kind: 'workspace_snapshot' },
          assessmentMode: 'TARGETED',
          assessmentProfileId: 'security/standard',
          target: { kind: 'targeted', relativePaths: [...relativePaths] },
          requestedStrongerControlIds: [],
        })
        if (!result.ok) throw new Error(`start failed: ${result.error.code}`)
        return result.value
      }
      const readme = await start('target-selector-readme', ['README.md'])
      const source = await start('target-selector-source', ['src/index.ts'])

      expect(readme.subject.digest).not.toEqual(source.subject.digest)
      const [readmeSnapshot, sourceSnapshot] = await Promise.all([
        ctx.securityAssurance.getAssessment(invocation, {
          schemaVersion: 1,
          assessmentId: readme.assessmentId,
        }),
        ctx.securityAssurance.getAssessment(invocation, {
          schemaVersion: 1,
          assessmentId: source.assessmentId,
        }),
      ])
      if (!readmeSnapshot.ok || !sourceSnapshot.ok) throw new Error('snapshot query failed')
      expect(readmeSnapshot.value.coverage.digest).not.toEqual(sourceSnapshot.value.coverage.digest)
    } finally {
      await fiber.dispose()
    }
  })
})
