// @vitest-environment jsdom
import { act, createElement } from 'react'
import { createRoot, type Root } from 'react-dom/client'
import { afterEach, describe, expect, it } from 'vitest'
import type { SecurityAssuranceWorkbenchStateV1 } from '../src/web-client/workbench/controller.ts'
import { en, type WorkbenchKey } from '../src/web-client/workbench/locales.ts'
import { WorkbenchOverlay, type WorkbenchOverlayProps } from '../src/web-client/workbench/WorkbenchOverlay.tsx'

;(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true

let root: Root | undefined

afterEach(() => {
  act(() => { root?.unmount() })
  root = undefined
  document.body.innerHTML = ''
})

function bindings() {
  return {
    policyId: 'security/node-package-lifecycle',
    assessmentProfileId: 'security/standard',
    evidenceProtectionId: 'evidence/local-protected',
    dataEgressPolicyId: 'egress/deny-by-default',
    platform: 'win32',
    deliveryDestinationIds: [],
  }
}

describe('ADR 0328: the Workbench repository list names the launch workspace', () => {
  it('badges the launch workspace first in the Workbench repository list', () => {
    const repository = (repositoryId: string, hostBindingIds?: readonly string[]) => ({
      schemaVersion: 1,
      repositoryId,
      repositoryRevision: 1,
      state: 'ENABLED',
      displayName: 'Current workspace',
      rootIdentityDigest: '0'.repeat(64),
      bindings: bindings(),
      createdAt: '2026-09-28T00:00:00.000Z',
      updatedAt: '2026-09-28T00:00:00.000Z',
      ...hostBindingIds === undefined ? {} : { hostBindingIds },
    })
    const state = {
      kind: 'REPOSITORIES_READY',
      repositories: [repository('repo-41391502-68c9-4da9-8356-9a23f4cf7fb8'), repository('repo-1f438805-cc2a-4c1b-9c41-01b632aa864c', ['current-workspace'])],
      truncated: false,
    } as unknown as SecurityAssuranceWorkbenchStateV1
    const container = document.createElement('div')
    document.body.append(container)
    act(() => {
      root = createRoot(container)
      root.render(createElement(WorkbenchOverlay, {
        t: (key: WorkbenchKey) => en[key],
        usePresentation: <S,>(select: (snapshot: { readonly open: boolean }) => S) => select({ open: true }),
        useAssessment: <S,>(select: (snapshot: SecurityAssuranceWorkbenchStateV1) => S) => select(state),
        closeWorkbench: () => {},
      } as unknown as WorkbenchOverlayProps))
    })

    const items = [...container.querySelectorAll('.dsh-security-repository-list > li')]
    expect(items.map(item => item.querySelector('code')?.textContent)).toEqual([
      'repo-1f438805-cc2a-4c1b-9c41-01b632aa864c @ 1',
      'repo-41391502-68c9-4da9-8356-9a23f4cf7fb8 @ 1',
    ])
    expect(items[0]?.textContent).toContain(en['repositories.launchWorkspace'])
    expect(items[1]?.textContent).not.toContain(en['repositories.launchWorkspace'])
  })
})
