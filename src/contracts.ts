import { z } from 'zod'

/** Public product identity of this development slice. */
export const SECURITY_ASSURANCE_PRODUCT_NAME = 'dsh-security-assurance' as const
export const SECURITY_ASSURANCE_PRODUCT_VERSION = '0.0.0-development' as const
export const TARGET_HARNESS_VERSION = '0.1.1-rc.2' as const
export const REQUIRED_NODE_RANGE = '^22.19.0 || >=24.0.0' as const

declare const securityInvocationBrand: unique symbol

/**
 * Non-serializable authority capability issued from a trusted caller channel.
 * The runtime verifies object identity; a TypeScript cast cannot forge it.
 */
export interface SecurityInvocation {
  readonly [securityInvocationBrand]: never
}

/** Process-local controls that are intentionally separate from request DTOs. */
export interface InvocationOptions {
  readonly signal?: AbortSignal
  readonly deadlineEpochMs?: number
}

/** Stable error codes implemented by the first public contract slice. */
export const publicSecurityErrorCodeSchema = z.enum([
  'UNAUTHORIZED',
  'INVALID_REQUEST',
  'CANCELED',
  'DEADLINE_EXCEEDED',
  'INTERNAL',
])

export type PublicSecurityErrorCode = z.infer<typeof publicSecurityErrorCodeSchema>

/** Redacted failure returned by every asynchronous Service operation. */
export interface PublicSecurityError {
  readonly schemaVersion: 1
  readonly code: PublicSecurityErrorCode
  readonly message: string
  readonly retryable: boolean
  readonly correlationId: string
}

export const publicSecurityErrorSchema: z.ZodType<PublicSecurityError> = z.strictObject({
  schemaVersion: z.literal(1),
  code: publicSecurityErrorCodeSchema,
  message: z.string().min(1).max(512),
  retryable: z.boolean(),
  correlationId: z.string().regex(/^sec-[0-9a-f-]{36}$/),
})

/** One transport-neutral public outcome envelope. */
export type SecurityResult<T> =
  | { readonly ok: true; readonly value: T }
  | { readonly ok: false; readonly error: PublicSecurityError }

/** Versioned, bounded request for Runtime Health. */
export interface GetHealthRequest {
  readonly schemaVersion: 1
}

export const getHealthRequestSchema: z.ZodType<GetHealthRequest> = z.strictObject({
  schemaVersion: z.literal(1),
})

export const runtimeHealthStateSchema = z.enum([
  'READY',
  'READ_ONLY_SAFE',
  'QUIESCING',
  'STOPPED',
])

export type RuntimeHealthState = z.infer<typeof runtimeHealthStateSchema>

export const runtimeHealthCheckStatusSchema = z.enum([
  'PASS',
  'FAIL',
  'NOT_EVALUATED',
])

export type RuntimeHealthCheckStatus = z.infer<typeof runtimeHealthCheckStatusSchema>

/** One bounded, redacted runtime admission check. */
export interface RuntimeHealthCheck {
  readonly id: string
  readonly status: RuntimeHealthCheckStatus
  readonly required: boolean
  readonly message: string
}

export const runtimeHealthCheckSchema: z.ZodType<RuntimeHealthCheck> = z.strictObject({
  id: z.string().regex(/^[a-z][a-z0-9]*(?:[.-][a-z0-9]+)*$/).max(96),
  status: runtimeHealthCheckStatusSchema,
  required: z.boolean(),
  message: z.string().min(1).max(512),
})

/** Immutable, JSON-safe Runtime Health Snapshot schema version 1. */
export interface RuntimeHealthSnapshot {
  readonly schemaVersion: 1
  readonly product: {
    readonly name: typeof SECURITY_ASSURANCE_PRODUCT_NAME
    readonly version: typeof SECURITY_ASSURANCE_PRODUCT_VERSION
  }
  readonly compatibility: {
    readonly targetHarnessVersion: typeof TARGET_HARNESS_VERSION
    readonly requiredNodeRange: typeof REQUIRED_NODE_RANGE
    readonly actualNodeVersion: string
    readonly harnessVerification: 'PENDING_INVARIANT'
  }
  readonly state: RuntimeHealthState
  readonly admission: {
    readonly queries: boolean
    readonly mutations: boolean
    readonly sealedExports: boolean
  }
  readonly checks: readonly RuntimeHealthCheck[]
}

export const runtimeHealthSnapshotSchema: z.ZodType<RuntimeHealthSnapshot> = z.strictObject({
  schemaVersion: z.literal(1),
  product: z.strictObject({
    name: z.literal(SECURITY_ASSURANCE_PRODUCT_NAME),
    version: z.literal(SECURITY_ASSURANCE_PRODUCT_VERSION),
  }),
  compatibility: z.strictObject({
    targetHarnessVersion: z.literal(TARGET_HARNESS_VERSION),
    requiredNodeRange: z.literal(REQUIRED_NODE_RANGE),
    actualNodeVersion: z.string().regex(/^\d+\.\d+\.\d+(?:[-+].+)?$/).max(64),
    harnessVerification: z.literal('PENDING_INVARIANT'),
  }),
  state: runtimeHealthStateSchema,
  admission: z.strictObject({
    queries: z.boolean(),
    mutations: z.boolean(),
    sealedExports: z.boolean(),
  }),
  checks: z.array(runtimeHealthCheckSchema).max(64),
})

/** Runtime schema for the first operation's complete Result. */
export const runtimeHealthResultSchema: z.ZodType<SecurityResult<RuntimeHealthSnapshot>> = z.discriminatedUnion('ok', [
  z.strictObject({
    ok: z.literal(true),
    value: runtimeHealthSnapshotSchema,
  }),
  z.strictObject({
    ok: z.literal(false),
    error: publicSecurityErrorSchema,
  }),
])
