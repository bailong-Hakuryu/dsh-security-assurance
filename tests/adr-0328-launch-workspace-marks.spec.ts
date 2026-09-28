import { execFile } from 'node:child_process'
import { mkdtemp, realpath, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { promisify } from 'node:util'
import { Context } from '@deepseek-ai/cordis'
import TypertGatewayService from '@deepseek-ai/dsh-api-gateway'
import TypertRegistry from '@deepseek-ai/dsh-typert-registry'
import { afterEach, describe, expect, it } from 'vitest'
import type { RepositoryBindingsV1, SecurityResult } from '../src/contracts.ts'
import SecurityAssuranceHostRepositoryProvider from '../src/host-repository-provider.ts'
import type { LocalWorkbenchContextV1 } from '../src/workbench-local.ts'
import * as workbenchLocal from '../src/workbench-local.ts'
import type { WorkbenchRepositoryListV1 } from '../src/workbench-remote.ts'
import { securityToolCard } from '../src/web-client/model.ts'
import { en as cardEn, zh as cardZh } from '../src/web-client/locales.ts'
import { SecurityAssuranceTestComposition } from './support/security-assurance-test-composition.ts'
import { referenceHostInvocation } from './support/reference-host.ts'
import { removeTemporaryRoots } from './support/remove-temporary-root.ts'

const run = promisify(execFile)
const temporaryRoots: string[] = []
const contexts: Context[] = []

afterEach(async () => {
  await Promise.all(contexts.splice(0).map(ctx => ctx.fiber.dispose()))
  await removeTemporaryRoots(temporaryRoots)
})

function bindings(): RepositoryBindingsV1 {
  return {
    policyId: 'security/node-package-lifecycle',
    assessmentProfileId: 'security/standard',
    evidenceProtectionId: 'evidence/local-protected',
    dataEgressPolicyId: 'egress/deny-by-default',
    platform: process.platform as 'win32' | 'linux' | 'darwin',
    deliveryDestinationIds: [],
  }
}

async function repositoryFixture(name: string): Promise<string> {
  const repository = await realpath(await mkdtemp(join(tmpdir(), `dsh-security-${name}-`)))
  temporaryRoots.push(repository)
  await run('git', ['init', '-b', 'main'], { cwd: repository })
  await writeFile(join(repository, 'README.md'), `# ${name}\n`, 'utf8')
  return repository
}

function settled(name: string, output: unknown) {
  return {
    kind: 'tool-result',
    callId: `${name}-1`,
    call: { name, argsRaw: '{}' },
    content: [{ type: 'text', text: JSON.stringify(output) }],
    isError: false,
  }
}

type CardLabel = { key: keyof typeof cardEn; values?: Record<string, string | number> } | { literal: string } | { join: readonly CardLabel[] }

function text(label: CardLabel | undefined, locale: Readonly<Record<keyof typeof cardEn, string>> = cardZh): string {
  if (label === undefined) return ''
  if ('literal' in label) return label.literal
  if ('join' in label) return label.join.map(part => text(part, locale)).join(' · ')
  return Object.entries(label.values ?? {}).reduce(
    (message, [key, value]) => message.replace(`{${key}}`, String(value)),
    locale[label.key] as string,
  )
}

describe('ADR 0328: every repository surface names the launch workspace', () => {
  it('marks the Host-bound Repository in the local Workbench listing without paths', async () => {
    const ctx = new Context()
    contexts.push(ctx)
    const dshHome = await realpath(await mkdtemp(join(tmpdir(), 'dsh-security-launch-marks-home-')))
    temporaryRoots.push(dshHome)
    const earlierLaunch = await repositoryFixture('earlier-launch')
    const launch = await repositoryFixture('launch')

    await ctx.plugin(TypertRegistry)
    await ctx.plugin(SecurityAssuranceTestComposition, { dshHome })
    await ctx.securityAssurance.whenReady()
    const earlier = await ctx.securityAssurance.registerRepository(referenceHostInvocation(ctx.securityAssurance), {
      schemaVersion: 1,
      contractVersion: 1,
      idempotencyKey: 'launch-marks-earlier-v1',
      root: earlierLaunch,
      displayName: 'Current workspace',
      bindings: bindings(),
    })
    if (!earlier.ok) throw new Error(`registration failed: ${earlier.error.code}`)
    await ctx.plugin(SecurityAssuranceHostRepositoryProvider, {
      repositories: [{ schemaVersion: 1, bindingId: 'current-workspace', root: launch, displayName: 'Current workspace', bindings: bindings() }],
    })
    const current = await ctx.securityAssuranceHostRepositories.resolve('current-workspace')
    if (current === undefined) throw new Error('Host binding did not resolve')
    await ctx.plugin(workbenchLocal, {})
    await ctx.plugin(TypertGatewayService)

    const opened = await ctx.typertGateway.invoke({
      namespace: 'securityAssuranceWorkbenchSession',
      method: 'openLocalContext',
      args: { request: { schemaVersion: 1 } },
    }) as LocalWorkbenchContextV1
    const listed = await ctx.typertGateway.invoke({
      namespace: 'securityAssuranceWorkbench',
      method: 'listRepositories',
      args: { securityAssuranceWorkbenchContextId: opened.contextId, request: { schemaVersion: 1, limit: 10 } },
    }) as SecurityResult<WorkbenchRepositoryListV1>
    if (!listed.ok) throw new Error(`listing failed: ${listed.error.code}`)

    expect(listed.value.repositories.find(repository => repository.repositoryId === current.repositoryId))
      .toMatchObject({ displayName: 'Current workspace', hostBindingIds: ['current-workspace'] })
    expect(listed.value.repositories.find(repository => repository.repositoryId === earlier.value.repositoryId))
      .not.toHaveProperty('hostBindingIds')
    expect(JSON.stringify(listed)).not.toContain(launch)
    expect(JSON.stringify(listed)).not.toContain(earlierLaunch)
  })

  it('puts the launch workspace first on the repositories card and tells same-named entries apart', () => {
    const card = securityToolCard('security_repositories', settled('security_repositories', {
      schemaVersion: 1,
      repositories: [
        { repositoryId: 'repo-41391502-68c9-4da9-8356-9a23f4cf7fb8', repositoryRevision: 1, state: 'ENABLED', displayName: 'Current workspace', policyId: 'p', assessmentProfileId: 'security/standard', platform: 'win32' },
        { repositoryId: 'repo-1f438805-cc2a-4c1b-9c41-01b632aa864c', repositoryRevision: 1, state: 'ENABLED', displayName: 'Current workspace', policyId: 'p', assessmentProfileId: 'security/standard', platform: 'win32', hostBindingIds: ['current-workspace'] },
      ],
      truncated: false,
    }))

    expect(card.fields.map(field => [text(field.label as CardLabel), text(field.value as CardLabel)])).toEqual([
      ['Current workspace · repo-1f438805', '已启用 · security/standard · 当前启动目录'],
      ['Current workspace · repo-41391502', '已启用 · security/standard'],
    ])
    expect(text(card.fields[0]?.value as CardLabel, cardEn)).toBe('Enabled · security/standard · Launch workspace')
  })
})
