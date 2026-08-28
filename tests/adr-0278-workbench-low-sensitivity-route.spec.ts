import { readFile } from 'node:fs/promises'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import type { SecurityAssuranceWorkbenchStateV1 } from '../src/client/index.ts'
import {
  decodeWorkbenchRouteStateV1,
  projectWorkbenchRouteStateV1,
  WORKBENCH_INFORMATION_ARCHITECTURE_V1,
} from '../src/client/index.ts'

describe('ADR 0278 low-sensitivity Workbench route state', () => {
  it('admits only a version and reviewed opaque View identifier', () => {
    for (const viewId of WORKBENCH_INFORMATION_ARCHITECTURE_V1) {
      expect(decodeWorkbenchRouteStateV1({ schemaVersion: 1, viewId })).toEqual({
        schemaVersion: 1,
        viewId,
      })
    }

    for (const forbidden of [
      { repositoryPath: 'C:/private/repository' },
      { searchTerms: 'protected source term' },
      { sourceAnchor: { path: 'src/private.ts', line: 1 } },
      { findingDetail: { title: 'sensitive detail' } },
      { riskRationale: 'operator rationale' },
      { transcript: 'private session' },
      { exportDestination: 'C:/private/export.json' },
      { downloadCapability: 'one-use-secret' },
      { credential: 'secret' },
      { authorizationContext: { principalId: 'operator' } },
    ]) {
      expect(decodeWorkbenchRouteStateV1({
        schemaVersion: 1,
        viewId: 'assessment-detail',
        ...forbidden,
      })).toBeNull()
    }
    expect(decodeWorkbenchRouteStateV1({ schemaVersion: 2, viewId: 'overview' })).toBeNull()
    expect(decodeWorkbenchRouteStateV1({ schemaVersion: 1, viewId: 'settings' })).toBeNull()
  })

  it('projects sensitive Controller payloads to a frozen two-field route and never persists them', async () => {
    const route = projectWorkbenchRouteStateV1({
      kind: 'BUNDLE_LOADING',
      assessmentId: 'asm-sensitive',
      downloadCapability: 'not-a-real-state-field',
    } as unknown as SecurityAssuranceWorkbenchStateV1)
    expect(route).toEqual({ schemaVersion: 1, viewId: 'exports' })
    expect(Object.isFrozen(route)).toBe(true)

    const sources = await Promise.all([
      'index.ts',
      'workbench/navigation.ts',
      'workbench/WorkbenchOverlay.tsx',
      'workbench/presentation.ts',
    ].map(file => readFile(join(import.meta.dirname, '..', 'src', 'client', file), 'utf8')))
    expect(sources.join('\n')).not.toMatch(
      /\b(?:localStorage|sessionStorage|indexedDB)\b|history\.(?:pushState|replaceState)/u,
    )
  })
})
