import type { RuntimeHealthCheck } from '../contracts.ts'

/** Runtime state exposed by the public Health snapshot. */
export type HarnessVerificationResult = 'PASS' | 'FAIL' | 'PENDING_INVARIANT'

/** One immutable composition check contributed by the invariant companion. */
export type HarnessVerificationCheck = RuntimeHealthCheck

/** One active, Fiber-owned invariant contribution. */
export interface HarnessVerificationContribution {
  readonly result: Exclude<HarnessVerificationResult, 'PENDING_INVARIANT'>
  readonly checks: readonly HarnessVerificationCheck[]
}

export type HarnessVerificationOwner = object

const verificationOwners = new WeakSet<object>()

/** Create the opaque owner held by the package's invariant companion. */
export function createHarnessVerificationOwner(): HarnessVerificationOwner {
  const owner = Object.freeze(Object.create(null) as object)
  verificationOwners.add(owner)
  return owner
}

export function isHarnessVerificationOwner(value: unknown): value is HarnessVerificationOwner {
  return (typeof value === 'object' && value !== null) || typeof value === 'function'
    ? verificationOwners.has(value)
    : false
}

export type HarnessVerificationReceiver = (
  authority: object,
  owner: HarnessVerificationOwner,
  contribution: HarnessVerificationContribution | undefined,
) => boolean

/**
 * Separate bundles share this private protocol through versioned global slots.
 * The opaque authority prevents callers that merely discover the receiver
 * symbol from replacing or revoking the active contribution.
 */
export const RECEIVE_HARNESS_VERIFICATION = Symbol.for(
  'dsh-security-assurance:receive-harness-verification:v2',
)

const HARNESS_VERIFICATION_AUTHORITY_SLOT = Symbol.for(
  'dsh-security-assurance:harness-verification-authority:v2',
)

const globalProtocol = globalThis as typeof globalThis & {
  [HARNESS_VERIFICATION_AUTHORITY_SLOT]?: object
}

if (globalProtocol[HARNESS_VERIFICATION_AUTHORITY_SLOT] === undefined) {
  Object.defineProperty(globalProtocol, HARNESS_VERIFICATION_AUTHORITY_SLOT, {
    configurable: false,
    enumerable: false,
    writable: false,
    value: Object.freeze(Object.create(null) as object),
  })
}

export const HARNESS_VERIFICATION_AUTHORITY =
  globalProtocol[HARNESS_VERIFICATION_AUTHORITY_SLOT]!
