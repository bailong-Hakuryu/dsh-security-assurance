import { randomUUID } from 'node:crypto'
import { Context, Service } from '@deepseek-ai/cordis'
import {
  getHealthRequestSchema,
  REQUIRED_NODE_RANGE,
  runtimeHealthSnapshotSchema,
  SECURITY_ASSURANCE_PRODUCT_NAME,
  SECURITY_ASSURANCE_PRODUCT_VERSION,
  TARGET_HARNESS_VERSION,
} from './contracts.ts'
import type {
  GetHealthRequest,
  InvocationOptions,
  PublicSecurityErrorCode,
  RuntimeHealthSnapshot,
  SecurityInvocation,
  SecurityResult,
} from './contracts.ts'
import {
  RESOLVE_TRUSTED_INVOCATION,
  SecurityAuthorityResolver,
} from './internal/authority.ts'
import type { TrustedCallerChannel } from './internal/authority.ts'
import { deepFreeze } from './internal/freeze.ts'

export * from './contracts.ts'

declare module '@deepseek-ai/cordis' {
  interface Context {
    securityAssurance: SecurityAssuranceService
  }
}

function nodeVersionIsSupported(version: string): boolean {
  const match = /^(\d+)\.(\d+)\.(\d+)/.exec(version)
  if (match === null) return false
  const major = Number(match[1])
  const minor = Number(match[2])
  return major >= 24 || (major === 22 && minor >= 19)
}

function failure<T>(
  code: PublicSecurityErrorCode,
  message: string,
  retryable = false,
): SecurityResult<T> {
  return deepFreeze({
    ok: false,
    error: {
      schemaVersion: 1,
      code,
      message,
      retryable,
      correlationId: `sec-${randomUUID()}`,
    },
  })
}

function interruption<T>(options: InvocationOptions): SecurityResult<T> | undefined {
  if (options.signal?.aborted) {
    return failure('CANCELED', 'The Security Assurance operation was canceled.')
  }
  if (options.deadlineEpochMs !== undefined) {
    if (!Number.isSafeInteger(options.deadlineEpochMs) || options.deadlineEpochMs < 0) {
      return failure('INVALID_REQUEST', 'The local invocation deadline is invalid.')
    }
    if (Date.now() >= options.deadlineEpochMs) {
      return failure('DEADLINE_EXCEEDED', 'The Security Assurance operation deadline was exceeded.', true)
    }
  }
  return undefined
}

function buildRuntimeHealth(): RuntimeHealthSnapshot {
  const actualNodeVersion = process.versions.node
  const nodeSupported = nodeVersionIsSupported(actualNodeVersion)
  return runtimeHealthSnapshotSchema.parse({
    schemaVersion: 1,
    product: {
      name: SECURITY_ASSURANCE_PRODUCT_NAME,
      version: SECURITY_ASSURANCE_PRODUCT_VERSION,
    },
    compatibility: {
      targetHarnessVersion: TARGET_HARNESS_VERSION,
      requiredNodeRange: REQUIRED_NODE_RANGE,
      actualNodeVersion,
      harnessVerification: 'PENDING_INVARIANT',
    },
    state: nodeSupported ? 'READY' : 'READ_ONLY_SAFE',
    admission: {
      queries: true,
      mutations: nodeSupported,
      sealedExports: nodeSupported,
    },
    checks: [
      {
        id: 'runtime.node',
        status: nodeSupported ? 'PASS' : 'FAIL',
        required: true,
        message: nodeSupported
          ? `Node ${actualNodeVersion} satisfies ${REQUIRED_NODE_RANGE}.`
          : `Node ${actualNodeVersion} does not satisfy ${REQUIRED_NODE_RANGE}.`,
      },
      {
        id: 'compatibility.harness',
        status: 'NOT_EVALUATED',
        required: false,
        message: 'The dormant invariant entry will verify the exact Harness composition.',
      },
    ],
  })
}

/**
 * Sole public business Interface for Security Assurance.
 * Internal adapters use the hidden Resolver symbol; package consumers cannot
 * mint or deserialize Security Invocations.
 */
export class SecurityAssuranceService extends Service {
  private readonly authorityResolver = new SecurityAuthorityResolver()

  constructor(ctx: Context) {
    super(ctx, 'securityAssurance')
    Object.defineProperty(this, RESOLVE_TRUSTED_INVOCATION, {
      configurable: false,
      enumerable: false,
      writable: false,
      value: (channel: TrustedCallerChannel) => this.authorityResolver.resolve(channel),
    })
  }

  /** Return a bounded authorized Runtime Health Snapshot. */
  async getHealth(
    invocation: SecurityInvocation,
    request: GetHealthRequest,
    options: InvocationOptions = {},
  ): Promise<SecurityResult<RuntimeHealthSnapshot>> {
    try {
      if (!this.authorityResolver.authorizes(invocation, 'health:read')) {
        return failure('UNAUTHORIZED', 'The caller is not authorized to read Security Assurance health.')
      }
      const interrupted = interruption<RuntimeHealthSnapshot>(options)
      if (interrupted !== undefined) return interrupted
      if (!getHealthRequestSchema.safeParse(request).success) {
        return failure('INVALID_REQUEST', 'The request does not match getHealth schema version 1.')
      }
      return deepFreeze({ ok: true, value: buildRuntimeHealth() })
    } catch {
      return failure('INTERNAL', 'Security Assurance could not complete the operation.', true)
    }
  }
}

export default SecurityAssuranceService
