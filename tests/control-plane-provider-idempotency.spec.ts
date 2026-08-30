import type { RepositoryId } from '../src/contracts.ts'
import {
  controlPlaneOperationIdempotencyKey,
  type ControlPlaneProviderContext,
} from '../src/internal/control-plane-provider-operation.ts'
import { describe, expect, it } from 'vitest'

const context: ControlPlaneProviderContext = {
  invocationId: 'provider-invocation-1',
  missionId: 'mission-1',
  attempt: 1,
  matchesCanonicalRepository: () => true,
}

describe('Control Plane Provider operation identities', () => {
  it('binds Assessment start idempotency to the configured Repository', () => {
    const firstRepository = 'repo-11111111-1111-4111-8111-111111111111' as RepositoryId
    const secondRepository = 'repo-22222222-2222-4222-8222-222222222222' as RepositoryId

    const first = controlPlaneOperationIdempotencyKey('start', context, firstRepository)

    expect(controlPlaneOperationIdempotencyKey('start', context, firstRepository)).toBe(first)
    expect(controlPlaneOperationIdempotencyKey('start', context, secondRepository)).not.toBe(first)
  })

  it('keeps resume and cancellation stable for the immutable invocation', () => {
    expect(controlPlaneOperationIdempotencyKey('resume', context)).toBe(
      controlPlaneOperationIdempotencyKey('resume', context),
    )
    expect(controlPlaneOperationIdempotencyKey('cancel', context)).toBe(
      controlPlaneOperationIdempotencyKey('cancel', context),
    )
  })
})
