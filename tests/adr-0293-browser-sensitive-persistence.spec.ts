import { readFile } from 'node:fs/promises'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import {
  decodeWorkbenchRouteStateV1,
  projectWorkbenchRouteStateV1,
  type SecurityAssuranceWorkbenchStateV1,
} from '../src/client/index.ts'

const clientFiles = [
  'index.ts',
  'workbench/actions.ts',
  'workbench/finding-triage.ts',
  'workbench/locales.ts',
  'workbench/navigation.ts',
  'workbench/presentation.ts',
  'workbench/progress.ts',
  'workbench/styles.ts',
  'workbench/WorkbenchLauncher.tsx',
  'workbench/WorkbenchOverlay.tsx',
] as const

describe('ADR 0293 browser persistence excludes sensitive Assessment payloads', () => {
  it('uses no browser persistence, navigation state, Service Worker cache, or payload logging seam', async () => {
    const sources = await Promise.all(clientFiles.map(file => (
      readFile(join(import.meta.dirname, '..', 'src', 'client', file), 'utf8')
    )))
    const source = sources.join('\n')

    expect(source).not.toMatch(/\b(?:localStorage|sessionStorage|indexedDB|CacheStorage|serviceWorker)\b/u)
    expect(source).not.toMatch(/\bcaches\.(?:open|match|put|delete|keys)\b/u)
    expect(source).not.toMatch(/history\.(?:pushState|replaceState)|location\.(?:assign|replace)/u)
    expect(source).not.toMatch(/console\.(?:debug|info|log|warn|error)\([^)]*,/u)
    expect(source).toContain("message: 'The Workbench Remote invocation failed.'")
    expect(source).not.toContain('error instanceof Error ? error.message')
  })

  it('projects only versioned view identity and rejects sensitive route material', () => {
    const route = projectWorkbenchRouteStateV1({
      kind: 'READY',
      assessmentId: 'asm-sensitive',
      snapshot: { finding: 'protected' },
      findings: { kind: 'NOT_LOADED', content: 'evidence' },
      assessmentCommand: { rationale: 'operator rationale' },
    } as unknown as SecurityAssuranceWorkbenchStateV1)
    expect(route).toEqual({ schemaVersion: 1, viewId: 'assessment-detail' })
    expect(Object.isFrozen(route)).toBe(true)

    for (const forbidden of [
      { snapshot: { source: 'protected' } },
      { finding: { attackPath: 'protected' } },
      { evidence: { content: 'protected' } },
      { riskDecisionRationale: 'protected' },
      { repositoryPath: 'C:/private/repository' },
      { securityInvocation: 'opaque-authority' },
      { exportCapability: 'one-use-secret' },
    ]) {
      expect(decodeWorkbenchRouteStateV1({
        schemaVersion: 1,
        viewId: 'assessment-detail',
        ...forbidden,
      })).toBeNull()
    }
  })
})
