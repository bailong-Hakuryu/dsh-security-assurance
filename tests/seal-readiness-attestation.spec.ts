import { describe, expect, it } from 'vitest'

import {
  checkSealReadiness,
  evaluateDeterministicAssessment,
  prepareAssessmentContract,
} from '../src/internal/deterministic-kernel.ts'
import { structuredDigest } from '../src/internal/canonical.ts'

const TARGET_MEDIA_TYPE = 'application/vnd.dsh.security.target-selector+json'

function fixture() {
  const target = { kind: 'repository' as const }
  const targetDigest = structuredDigest(TARGET_MEDIA_TYPE, target)
  const contract = prepareAssessmentContract({
    policyId: 'security/default',
    assessmentMode: 'REPOSITORY',
    assessmentProfileId: 'security/standard',
    target,
    targetDigest,
    requestedStrongerControlIds: [],
  })
  const outcome = evaluateDeterministicAssessment(
    contract,
    '2026-08-30T00:00:00.000Z',
  )
  return { contract, outcome }
}

describe('seal-readiness attestation rechecks', () => {
  it('accepts an evaluator outcome whose coverage and policy trace bind to the contract', () => {
    const { contract, outcome } = fixture()
    expect(checkSealReadiness(contract, outcome)).toEqual({ ready: true })
  })

  it('rejects tampered coverage and evaluation-trace bindings', () => {
    const { contract, outcome } = fixture()
    const tampered = {
      ...outcome,
      coverage: {
        ...outcome.coverage,
        digest: structuredDigest('application/vnd.dsh.security.coverage+json', {
          tampered: true,
        }),
      },
      evaluationTrace: {
        ...(outcome.evaluationTrace as unknown as Record<string, unknown>),
        policyDigest: structuredDigest(TARGET_MEDIA_TYPE, { tampered: true }),
      },
    } as unknown as typeof outcome
    const result = checkSealReadiness(contract, tampered)
    expect(result.ready).toBe(false)
    if (result.ready) throw new Error('tampered outcome was accepted')
    expect(result.violations).toEqual(expect.arrayContaining([
      'coverage_digest_mismatch',
      'evaluation_trace_policy_mismatch',
    ]))
  })
})
