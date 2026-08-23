import { Context, Service } from '@deepseek-ai/cordis'
import z from 'zod'
import type {
  RepositoryBindingsV1,
  RepositoryId,
  RepositoryState,
} from './contracts.ts'
import { repositoryBindingsV1Schema } from './contracts.ts'
import { resolveTrustedInvocation } from './internal/authority.ts'
import { deepFreeze } from './internal/freeze.ts'
import type { SecurityAssuranceService } from './index.ts'

const bindingIdSchema = z.string().regex(/^[a-z0-9][a-z0-9._/-]{0,127}$/i)

/** One Host-owned Repository registration applied during Cordis composition. */
export interface HostRepositoryRegistrationV1 {
  readonly schemaVersion: 1
  readonly bindingId: string
  readonly idempotencyKey: string
  readonly root: string
  readonly displayName: string
  readonly bindings: RepositoryBindingsV1
}

const hostRepositoryRegistrationV1Schema: z.ZodType<HostRepositoryRegistrationV1> = z.strictObject({
  schemaVersion: z.literal(1),
  bindingId: bindingIdSchema,
  idempotencyKey: z.string().min(1).max(128).regex(/^[a-zA-Z0-9._:-]+$/),
  root: z.string().min(1).max(4096),
  displayName: z.string().trim().min(1).max(128),
  bindings: repositoryBindingsV1Schema,
})

/** Host composition configuration for Repository registration. */
export interface Config {
  readonly repositories: readonly HostRepositoryRegistrationV1[]
}

const configSchema: z.ZodType<Config> = z.strictObject({
  repositories: z.array(hostRepositoryRegistrationV1Schema).min(1).max(64),
})

/** Path-free result that another trusted Host plugin may bind into its own configuration. */
export interface HostRepositoryBindingV1 {
  readonly schemaVersion: 1
  readonly bindingId: string
  readonly repositoryId: RepositoryId
  readonly repositoryRevision: number
  readonly state: RepositoryState
}

declare module '@deepseek-ai/cordis' {
  interface Context {
    securityAssuranceHostRepositories: SecurityAssuranceHostRepositoryProvider
  }
}

/**
 * Trusted Host Adapter that registers configured roots through the root Security Service.
 * It exposes only path-free registration bindings and never returns a Security Invocation.
 */
export class SecurityAssuranceHostRepositoryProvider extends Service {
  static inject = ['securityAssurance']

  private readonly ready: Promise<void>
  private readonly resolved = new Map<string, HostRepositoryBindingV1>()
  private disposed = false

  constructor(ctx: Context, config: Config) {
    super(ctx, 'securityAssuranceHostRepositories')
    this.ready = this.initialize(ctx.securityAssurance, config)
    void this.ready.catch(() => {})
    ctx.effect(async () => {
      await this.ready
      return () => {
        this.disposed = true
        this.resolved.clear()
      }
    }, 'Security Assurance Host Repository Provider teardown')
  }

  /** Resolve one configured binding after every Host registration has settled. */
  async resolve(bindingId: string): Promise<HostRepositoryBindingV1 | undefined> {
    if (!bindingIdSchema.safeParse(bindingId).success) {
      throw new TypeError('Host Repository binding identity is invalid')
    }
    await this.ready
    if (this.disposed) throw new Error('Security Assurance Host Repository Provider is disposing')
    return this.resolved.get(bindingId)
  }

  private async initialize(service: SecurityAssuranceService, config: Config): Promise<void> {
    const parsed = configSchema.safeParse(config)
    if (!parsed.success) throw new TypeError('Host Repository Provider configuration is invalid')
    const bindingIds = new Set<string>()
    for (const registration of parsed.data.repositories) {
      if (bindingIds.has(registration.bindingId)) {
        throw new TypeError(`Host Repository binding '${registration.bindingId}' is duplicated`)
      }
      bindingIds.add(registration.bindingId)
    }

    const invocation = resolveTrustedInvocation(service, {
      kind: 'host-operator',
      principalId: 'security-assurance-host-repository-provider',
      permissions: ['repository:admin'],
    })
    for (const registration of parsed.data.repositories) {
      const result = await service.registerRepository(invocation, {
        schemaVersion: 1,
        idempotencyKey: registration.idempotencyKey,
        root: registration.root,
        displayName: registration.displayName,
        bindings: registration.bindings,
      })
      if (!result.ok) {
        throw new Error(`Host Repository registration failed with ${result.error.code}`)
      }
      this.resolved.set(registration.bindingId, deepFreeze({
        schemaVersion: 1,
        bindingId: registration.bindingId,
        repositoryId: result.value.repositoryId,
        repositoryRevision: result.value.repositoryRevision,
        state: result.value.acceptedState,
      }))
    }
  }
}

export default SecurityAssuranceHostRepositoryProvider
