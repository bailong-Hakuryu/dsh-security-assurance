import { readFile } from 'node:fs/promises'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { REGISTER_ANALYZER_QUALIFICATION } from '../src/internal/analyzer-qualification-registration.ts'
import {
  createTrustedCallerChannel,
  RESOLVE_TRUSTED_INVOCATION,
  SecurityAuthorityResolver,
} from '../src/internal/authority.ts'
import { LOOKUP_CONTROL_PLANE_ASSESSMENT } from '../src/internal/control-plane-assessment.ts'
import { EXECUTE_CONTROL_PLANE_PROVIDER_OPERATION } from '../src/internal/control-plane-provider-operation.ts'
import { VERIFY_CONTROL_PLANE_REPOSITORY_BINDING } from '../src/internal/control-plane-repository-binding.ts'
import { RECEIVE_HARNESS_VERIFICATION } from '../src/internal/harness-verification.ts'

const protocolSymbols = [
  RESOLVE_TRUSTED_INVOCATION,
  REGISTER_ANALYZER_QUALIFICATION,
  LOOKUP_CONTROL_PLANE_ASSESSMENT,
  EXECUTE_CONTROL_PLANE_PROVIDER_OPERATION,
  VERIFY_CONTROL_PLANE_REPOSITORY_BINDING,
  RECEIVE_HARNESS_VERIFICATION,
] as const

describe('ADR 0302 package-private protocol Symbols have versioned process identities', () => {
  it('uses stable versioned Symbol.for identities across independently bundled entries', () => {
    for (const symbol of protocolSymbols) {
      const key = Symbol.keyFor(symbol)
      expect(key).toMatch(/^dsh-security-assurance(?::|\/internal\/).+\/v\d+$|^dsh-security-assurance:.+:v\d+$/u)
      expect(Symbol.for(key!)).toBe(symbol)
    }
    expect(Symbol.keyFor(EXECUTE_CONTROL_PLANE_PROVIDER_OPERATION)).toBe(
      'dsh-security-assurance/internal/execute-control-plane-provider-operation/v1',
    )
    expect(Symbol.keyFor(RECEIVE_HARNESS_VERIFICATION)).toBe(
      'dsh-security-assurance:receive-harness-verification:v2',
    )
  })

  it('keeps protocol slots absent from public exports and non-authorizing by discovery alone', async () => {
    const packageJson = JSON.parse(await readFile(
      join(import.meta.dirname, '..', 'package.json'),
      'utf8',
    )) as { readonly exports?: Record<string, unknown> }
    const publicEntries = Object.keys(packageJson.exports ?? {})
    const emptyOwner = {}

    expect(publicEntries.some(entry => entry.startsWith('./internal/'))).toBe(false)
    for (const symbol of protocolSymbols) {
      expect(Reflect.get(emptyOwner, symbol)).toBeUndefined()
    }
  })

  it('rejects a structurally forged caller channel even when the resolver slot is discovered', () => {
    const resolver = new SecurityAuthorityResolver()
    expect(() => resolver.resolve({
      kind: 'host-operator',
      principalId: 'forged-operator',
      permissions: ['risk:break-glass'],
    })).toThrow('not issued by a package-owned adapter')

    const channel = createTrustedCallerChannel({
      kind: 'host-operator',
      principalId: 'real-operator',
      permissions: ['risk:break-glass'],
    })
    const invocation = resolver.resolve(channel)
    expect(resolver.authorizes(invocation, 'risk:break-glass')).toBe(true)
    expect(() => resolver.resolve({ ...channel })).toThrow('not issued by a package-owned adapter')
  })
})
