import { readFile } from 'node:fs/promises'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import {
  inject as workbenchClientInject,
  SecurityAssuranceWorkbenchController,
} from '../src/client/index.ts'
import SecurityAssuranceWorkbenchRemote from '../src/workbench-remote.ts'

describe('ADR 0275 Workbench Service Client boundary', () => {
  it('depends on the authenticated Remote and Host presentation seams only', () => {
    expect(workbenchClientInject).toEqual(['remote', 'slots', 'locale'])
    expect(SecurityAssuranceWorkbenchController.inject).toEqual([
      'remote',
      'remote.securityAssuranceWorkbench',
    ])
    expect(SecurityAssuranceWorkbenchRemote.inject).toEqual(['securityAssurance', 'typert'])
  })

  it('keeps authority, persistence, and canonical artifact access out of the browser Client', async () => {
    const clientSource = await readFile(join(import.meta.dirname, '..', 'src', 'client', 'index.ts'), 'utf8')
    expect(clientSource).toContain('this.ownerCtx.remote.securityAssuranceWorkbench')
    expect(clientSource).not.toMatch(/from ['"]node:(?:fs|path|sqlite|child_process)/u)
    expect(clientSource).not.toMatch(/internal\/(?:persistence|sealed-artifacts|authority)/u)
    expect(clientSource).not.toMatch(/\b(?:principalId|permissions|resolveAuthorityContext)\b/u)
  })
})
