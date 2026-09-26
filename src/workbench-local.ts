import { randomBytes } from 'node:crypto'
import type { Context } from '@deepseek-ai/cordis'
import { Remote, TypertRemoteService } from '@deepseek-ai/dsh-typert-protocol'
import { z } from 'zod'
import SecurityAssuranceWorkbenchRemote, {
  type AuthenticatedWorkbenchOperatorV1,
  type WorkbenchAuthorityContextId,
  type WorkbenchAuthorityContextResolverV1,
  type WorkbenchSecurityPermissionV1,
} from './workbench-remote.ts'

/**
 * Principal of the browser that Harness Web has already authenticated: every
 * `/api` caller passes Harness's Host/Origin fence and login-token cookie, and
 * no Harness configuration turns that authentication off (ADR 0321).
 */
export const LOCAL_WORKBENCH_PRINCIPAL_ID = 'harness-web:local-operator'

/**
 * Exactly the reach the Security model tools already give the same user. Risk
 * Decisions, break-glass, Evidence disclosure, Export download, Assurance
 * Submission reads, and Repository administration stay deployment-granted.
 */
export const LOCAL_WORKBENCH_PERMISSIONS: readonly WorkbenchSecurityPermissionV1[] = Object.freeze([
  'health:read',
  'repository:read',
  'assessment:read',
  'assessment:start',
  'assessment:resume',
  'assessment:cancel',
  'export:request',
  'export:read',
])

/** One issued Workbench authority context, returned only to the authenticated browser. */
export interface LocalWorkbenchContextV1 {
  readonly schemaVersion: 1
  readonly contextId: string
  readonly expiresAt: string
  readonly permissions: readonly WorkbenchSecurityPermissionV1[]
}

/** Strict request for a new local Workbench context. */
export interface OpenLocalWorkbenchContextRequestV1 {
  readonly schemaVersion: 1
}

export interface LocalWorkbenchAuthorityOptions {
  readonly ttlMs?: number
  readonly capacity?: number
  readonly now?: () => number
}

const DEFAULT_CONTEXT_TTL_MS = 8 * 60 * 60 * 1000
const DEFAULT_CONTEXT_CAPACITY = 32

/**
 * In-memory issuer and resolver of opaque, expiring, capacity-bounded
 * contexts. A context never outlives the plugin: disposal revokes them all.
 */
export class LocalWorkbenchAuthority implements WorkbenchAuthorityContextResolverV1 {
  private readonly contexts = new Map<string, number>()
  private readonly ttlMs: number
  private readonly capacity: number
  private readonly now: () => number

  constructor(options: LocalWorkbenchAuthorityOptions = {}) {
    this.ttlMs = options.ttlMs ?? DEFAULT_CONTEXT_TTL_MS
    this.capacity = options.capacity ?? DEFAULT_CONTEXT_CAPACITY
    this.now = options.now ?? Date.now
  }

  issue(): LocalWorkbenchContextV1 {
    const issuedAt = this.now()
    for (const [contextId, expiresAt] of this.contexts) {
      if (issuedAt >= expiresAt) this.contexts.delete(contextId)
    }
    const contextId = `local-workbench-${randomBytes(24).toString('base64url')}`
    const expiresAt = issuedAt + this.ttlMs
    this.contexts.set(contextId, expiresAt)
    while (this.contexts.size > this.capacity) {
      const oldest = this.contexts.keys().next().value
      if (oldest === undefined) break
      this.contexts.delete(oldest)
    }
    return Object.freeze({
      schemaVersion: 1,
      contextId,
      expiresAt: new Date(expiresAt).toISOString(),
      permissions: Object.freeze([...LOCAL_WORKBENCH_PERMISSIONS]),
    })
  }

  resolveAuthorityContext(contextId: WorkbenchAuthorityContextId): AuthenticatedWorkbenchOperatorV1 | undefined {
    const expiresAt = this.contexts.get(contextId)
    if (expiresAt === undefined) return undefined
    if (this.now() >= expiresAt) {
      this.contexts.delete(contextId)
      return undefined
    }
    return Object.freeze({
      principalId: LOCAL_WORKBENCH_PRINCIPAL_ID,
      permissions: Object.freeze([...LOCAL_WORKBENCH_PERMISSIONS]),
    })
  }

  revokeAll(): void {
    this.contexts.clear()
  }
}

const openRequestSchema: z.ZodType<OpenLocalWorkbenchContextRequestV1> = z.strictObject({
  schemaVersion: z.literal(1),
})

/**
 * Remote reachable only through Harness's authenticated transport. It hands
 * the local browser a Workbench context; it takes no identity or permission
 * input from the wire.
 */
export class SecurityAssuranceWorkbenchSession extends TypertRemoteService {
  static inject = ['typert']

  private readonly authority: LocalWorkbenchAuthority

  constructor(ctx: Context, authority: LocalWorkbenchAuthority) {
    super(ctx, 'securityAssuranceWorkbenchSession')
    this.authority = authority
  }

  /** Issue one expiring Workbench context bound to the local operator's fixed permissions. */
  @Remote
  openLocalContext(
    request: OpenLocalWorkbenchContextRequestV1,
    signal: AbortSignal,
  ): Promise<LocalWorkbenchContextV1> {
    openRequestSchema.parse(request)
    signal.throwIfAborted()
    return Promise.resolve(this.authority.issue())
  }
}

export interface Config {
  /** Lifetime of one issued context; defaults to eight hours. */
  readonly contextTtlMinutes?: number | undefined
}

const configSchema: z.ZodType<Config> = z.strictObject({
  contextTtlMinutes: z.number().int().min(1).max(1440).optional(),
})

export const name = 'security-assurance-workbench-local'
export const inject = ['securityAssurance', 'typert']

/** Mount the Workbench Remote under the local authority of an authenticated Harness Web browser. */
export function apply(ctx: Context, config: Config = {}): void {
  const parsed = configSchema.parse(config ?? {})
  const authority = new LocalWorkbenchAuthority(
    parsed.contextTtlMinutes === undefined ? {} : { ttlMs: parsed.contextTtlMinutes * 60_000 },
  )
  ctx.effect(() => () => { authority.revokeAll() }, 'security-assurance-workbench-local: contexts')
  ctx.plugin(SecurityAssuranceWorkbenchSession, authority)
  ctx.plugin(SecurityAssuranceWorkbenchRemote, authority)
}

export default { name, inject, apply }
