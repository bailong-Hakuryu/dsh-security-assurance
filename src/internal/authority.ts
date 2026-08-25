import type { SecurityInvocation } from '../contracts.ts'

export type SecurityPermission =
  | 'health:read'
  | 'repository:read'
  | 'repository:admin'
  | 'assessment:start'
  | 'assessment:read'
  | 'assessment:resume'
  | 'assessment:cancel'
  | 'evidence:disclose:validation-review'
  | 'assurance-submission:read'
  | 'export:request'
  | 'export:read'
  | 'export:download'
  | 'risk:decide'
  | 'risk:break-glass'
export type SecurityCallerChannelKind = 'harness-session' | 'host-operator' | 'control-plane'

/** Package-private method key that Cordis traceable Service proxies can forward. */
export const RESOLVE_TRUSTED_INVOCATION = Symbol.for(
  'dsh-security-assurance/internal/resolve-trusted-invocation/v1',
)

/**
 * Identity already authenticated by a package-owned trusted channel adapter.
 * This value and the Resolver are deliberately absent from package exports.
 */
export interface TrustedCallerChannel {
  readonly kind: SecurityCallerChannelKind
  readonly principalId: string
  readonly permissions: readonly SecurityPermission[]
}

export interface ResolvedSecurityAuthority {
  readonly kind: SecurityCallerChannelKind
  readonly principalId: string
  readonly permissions: ReadonlySet<SecurityPermission>
}

/** Runtime identity registry for opaque, non-copyable Security Invocations. */
export class SecurityAuthorityResolver {
  readonly #issued = new WeakMap<object, ResolvedSecurityAuthority>()

  resolve(channel: TrustedCallerChannel): SecurityInvocation {
    if (!/^[a-z0-9][a-z0-9._:-]{0,127}$/i.test(channel.principalId)) {
      throw new TypeError('trusted caller channel has an invalid principal identity')
    }
    const known = new Set<SecurityPermission>([
      'health:read',
      'repository:read',
      'repository:admin',
      'assessment:start',
      'assessment:read',
      'assessment:resume',
      'assessment:cancel',
      'evidence:disclose:validation-review',
      'assurance-submission:read',
      'export:request',
      'export:read',
      'export:download',
      'risk:decide',
      'risk:break-glass',
    ])
    if (
      channel.permissions.length === 0
      || new Set(channel.permissions).size !== channel.permissions.length
      || channel.permissions.some(permission => !known.has(permission))
    ) {
      throw new TypeError('trusted caller channel has invalid permissions')
    }

    const token = Object.freeze(Object.create(null)) as object
    this.#issued.set(token, Object.freeze({
      kind: channel.kind,
      principalId: channel.principalId,
      permissions: new Set(channel.permissions),
    }))
    return token as SecurityInvocation
  }

  authorizes(invocation: unknown, permission: SecurityPermission): boolean {
    if ((typeof invocation !== 'object' && typeof invocation !== 'function') || invocation === null) return false
    return this.#issued.get(invocation)?.permissions.has(permission) ?? false
  }

  authority(invocation: unknown): ResolvedSecurityAuthority | undefined {
    if ((typeof invocation !== 'object' && typeof invocation !== 'function') || invocation === null) return undefined
    return this.#issued.get(invocation)
  }
}

type TrustedInvocationIssuer = (channel: TrustedCallerChannel) => SecurityInvocation

/** Resolve a capability through the same internal path used by product adapters. */
export function resolveTrustedInvocation(
  owner: object,
  channel: TrustedCallerChannel,
): SecurityInvocation {
  const issue = Reflect.get(owner, RESOLVE_TRUSTED_INVOCATION) as unknown
  if (typeof issue !== 'function') throw new TypeError('security authority resolver is not installed')
  return (issue as TrustedInvocationIssuer)(channel)
}
