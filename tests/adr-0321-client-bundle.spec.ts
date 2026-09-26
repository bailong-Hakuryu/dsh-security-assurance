import { readFile } from 'node:fs/promises'
import { join } from 'node:path'
import { runInThisContext } from 'node:vm'
import * as cordis from '@deepseek-ai/cordis'
import {
  apply as applyClientRemote,
  inject as clientRemoteInject,
} from '@deepseek-ai/dsh-api-gateway/src/client/index.ts'
import TypertRegistry from '@deepseek-ai/dsh-typert-registry'
import * as react from 'react'
import * as jsxRuntime from 'react/jsx-runtime'
import { afterEach, describe, expect, it } from 'vitest'
import { LOCAL_WORKBENCH_PERMISSIONS } from '../src/workbench-local.ts'
import * as icons from './support/ui-primitives.ts'
import { provideConnection, provideSlotRecorder } from './support/workbench-client-host.ts'

/** The modules every supported Harness Web page seeds into its client module table. */
const PLATFORM_MODULES: Readonly<Record<string, unknown>> = {
  'react': react,
  'react/jsx-runtime': jsxRuntime,
  'react-dom': {},
  'react-dom/client': {},
  '@deepseek-ai/cordis': cordis,
  '@deepseek-ai/dsh-client-store': {},
  '@deepseek-ai/dsh-client-ui-slots': {},
  '@deepseek-ai/dsh-client-ui-primitives': icons,
}

interface ClientRegistration {
  readonly id: string
  readonly factory: (require: (id: string) => unknown) => unknown
}

const contexts: cordis.Context[] = []

afterEach(async () => {
  await Promise.all(contexts.splice(0).map(ctx => ctx.fiber.dispose()))
})

/** Evaluate the built bundle the way the page's module loader does. */
async function loadBuiltClient(): Promise<{
  readonly id: string
  readonly requested: readonly string[]
  readonly plugin: { readonly name: string; readonly inject: readonly string[]; readonly apply: unknown }
}> {
  const source = await readFile(join(import.meta.dirname, '..', 'lib', 'client.js'), 'utf8')
  const registrations: ClientRegistration[] = []
  const register = runInThisContext(`(function (window) {\n${source}\n})`) as (window: unknown) => void
  register({ __ModuleLoader__: { load: (registration: ClientRegistration) => { registrations.push(registration) } } })
  expect(registrations).toHaveLength(1)
  const [registration] = registrations
  const requested: string[] = []
  const plugin = registration!.factory(id => {
    requested.push(id)
    if (!(id in PLATFORM_MODULES)) throw new Error(`The page module table has no ${id}`)
    return PLATFORM_MODULES[id]
  }) as { readonly name: string; readonly inject: readonly string[]; readonly apply: unknown }
  return { id: registration!.id, requested, plugin }
}

describe('ADR 0321 built Security client bundle', () => {
  it('registers under the package name and requests only Harness platform modules', async () => {
    const { id, requested, plugin } = await loadBuiltClient()
    expect(id).toBe('dsh-security-assurance')
    expect([...requested].sort()).toEqual([
      '@deepseek-ai/cordis',
      '@deepseek-ai/dsh-client-ui-primitives',
      'react',
      'react/jsx-runtime',
    ])
    expect(plugin.name).toBe('dsh-security-assurance/client')
    expect(plugin.inject).toEqual(['slots', 'locale'])
  })

  it('mounts the cards and the Workbench, whose bundled codecs carry the local selection', async () => {
    const { plugin } = await loadBuiltClient()
    const ctx = new cordis.Context()
    contexts.push(ctx)
    await ctx.plugin(TypertRegistry)
    const slots = provideSlotRecorder(ctx)
    const endpoints: string[] = []
    provideConnection(ctx, {
      call: (_path, endpoint) => {
        endpoints.push(endpoint)
        if (endpoint === 'securityAssuranceWorkbenchSession/openLocalContext') {
          return Promise.resolve({
            ok: true,
            value: {
              schemaVersion: 1,
              contextId: 'local-workbench-BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB',
              expiresAt: '2026-09-26T08:00:00.000Z',
              permissions: [...LOCAL_WORKBENCH_PERMISSIONS],
            },
          })
        }
        if (endpoint === 'securityAssuranceWorkbench/listAssessments') {
          return Promise.resolve({
            ok: true,
            value: {
              ok: true,
              value: { schemaVersion: 1, consistencyWatermark: 'bundle.signature', assessments: [], nextCursor: null },
            },
          })
        }
        throw new Error(`Unexpected endpoint: ${endpoint}`)
      },
    })
    await ctx.plugin({ inject: clientRemoteInject, apply: applyClientRemote })
    await ctx.plugin(plugin as unknown as cordis.Plugin)

    await expect.poll(() => slots.map(entry => entry.id ?? entry.name)).toEqual([
      ...Array(8).fill('tool.call.toolview'),
      'security-assurance-workbench-launcher',
      'security-assurance-workbench-overlay',
    ])
    const launcher = slots.find(entry => entry.id === 'security-assurance-workbench-launcher')
    const overlay = slots.find(entry => entry.id === 'security-assurance-workbench-overlay')
    const showWorkbench = launcher?.inject()['showWorkbench'] as (returnFocus: unknown) => Promise<void>
    await showWorkbench({ focus() {} })

    expect(endpoints).toEqual([
      'securityAssuranceWorkbenchSession/openLocalContext',
      'securityAssuranceWorkbench/listAssessments',
    ])
    const hooks = overlay?.inject()['hooks'] as {
      readonly presentation: { getSnapshot(): unknown }
      readonly assessment: { getSnapshot(): unknown }
    }
    expect(hooks.presentation.getSnapshot()).toEqual({ open: true })
    expect(hooks.assessment.getSnapshot()).toMatchObject({ kind: 'SELECTION_READY', assessments: [] })
  })
})
