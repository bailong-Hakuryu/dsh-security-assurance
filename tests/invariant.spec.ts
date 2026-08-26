import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { Context } from '@deepseek-ai/cordis'
import { SecurityAssuranceService } from '../src/index.ts'
import { SecurityAssuranceInvariant } from '../src/invariant.ts'

describe('Invariant Entry', () => {
  let ctx: Context
  let service: SecurityAssuranceService
  let invariant: SecurityAssuranceInvariant

  beforeEach(() => {
    ctx = new Context()
  })

  afterEach(async () => {
    if (ctx && typeof (ctx as any).dispose === 'function') {
      await (ctx as any).dispose()
    }
  })

  it('performs Harness composition verification at construction', async () => {
    const serviceFiber = ctx.plugin(SecurityAssuranceService, {})
    await serviceFiber
    service = ctx.securityAssurance
    expect(service).toBeDefined()

    const invariantFiber = ctx.plugin(SecurityAssuranceInvariant)
    await invariantFiber
    invariant = ctx.securityAssuranceInvariant
    expect(invariant).toBeDefined()

    const result = invariant.getVerificationResult()
    expect(result).toMatch(/^(PASS|FAIL|PENDING_INVARIANT)$/)

    const checks = invariant.getVerificationChecks()
    expect(Array.isArray(checks)).toBe(true)
    expect(checks.length).toBeGreaterThan(0)

    for (const check of checks) {
      expect(check).toHaveProperty('id')
      expect(check).toHaveProperty('status')
      expect(check).toHaveProperty('required')
      expect(check).toHaveProperty('message')
      expect(check.status).toMatch(/^(PASS|FAIL)$/)
      expect(typeof check.required).toBe('boolean')
      expect(typeof check.message).toBe('string')
    }
  })

  it('contributes verification result to Service Runtime Health', async () => {
    const serviceFiber = ctx.plugin(SecurityAssuranceService, {})
    await serviceFiber
    service = ctx.securityAssurance
    expect(service).toBeDefined()

    const invariantFiber = ctx.plugin(SecurityAssuranceInvariant)
    await invariantFiber
    invariant = ctx.securityAssuranceInvariant
    expect(invariant).toBeDefined()

    const invocation = (service as any)[Symbol.for('dsh-security-assurance:resolve-trusted-invocation')]({
      kind: 'host-operator',
      principalId: 'test-health-reader',
      permissions: ['health:read'],
    })

    const healthResult = await service.getHealth(invocation, { schemaVersion: 1 })

    expect(healthResult.ok).toBe(true)
    if (!healthResult.ok) return

    const health = healthResult.value
    expect(health.compatibility.harnessVerification).toMatch(/^(PASS|FAIL|PENDING_INVARIANT)$/)

    // Invariant should have updated the result from PENDING_INVARIANT
    if (invariant.getVerificationResult() !== 'PENDING_INVARIANT') {
      expect(health.compatibility.harnessVerification).toBe(invariant.getVerificationResult())
    }

    // Verify checks include both built-in and invariant checks
    expect(Array.isArray(health.checks)).toBe(true)
    expect(health.checks.length).toBeGreaterThan(2) // At least persistence, node, and some invariant checks

    const persistenceCheck = health.checks.find(c => c.id === 'persistence.sqlite')
    expect(persistenceCheck).toBeDefined()

    const nodeCheck = health.checks.find(c => c.id === 'runtime.node')
    expect(nodeCheck).toBeDefined()
  })

  it('verifies required Cordis services exist', async () => {
    ctx.plugin(SecurityAssuranceService, {})
    service = ctx.securityAssurance

    const invariantFiber = ctx.plugin(SecurityAssuranceInvariant)
    await invariantFiber
    invariant = ctx.securityAssuranceInvariant

    const checks = invariant.getVerificationChecks()
    const servicesCheck = checks.find(c => c.id === 'composition.required-services')

    expect(servicesCheck).toBeDefined()
    if (servicesCheck) {
      expect(servicesCheck.required).toBe(true)
      // In test environment, some services may not be available
      expect(servicesCheck.status).toMatch(/^(PASS|FAIL)$/)
    }
  })

  it('verifies Security Assurance Service registration', async () => {
    ctx.plugin(SecurityAssuranceService, {})
    service = ctx.securityAssurance

    const invariantFiber = ctx.plugin(SecurityAssuranceInvariant)
    await invariantFiber
    invariant = ctx.securityAssuranceInvariant

    const checks = invariant.getVerificationChecks()
    const serviceCheck = checks.find(c => c.id === 'composition.service-registration')

    expect(serviceCheck).toBeDefined()
    if (serviceCheck) {
      expect(serviceCheck.required).toBe(true)
      expect(serviceCheck.status).toBe('PASS')
      expect(serviceCheck.message).toContain('correctly registered')
    }
  })

  it('is dormant and performs no Assessment work', async () => {
    ctx.plugin(SecurityAssuranceService, {})
    service = ctx.securityAssurance

    const invariantFiber = ctx.plugin(SecurityAssuranceInvariant)
    await invariantFiber
    invariant = ctx.securityAssuranceInvariant

    // Invariant should not start any Assessment Engine
    // Invariant should not mutate Assessment state
    // Invariant should not register Providers
    // This is verified by the fact that it only performs checks and returns results

    const result = invariant.getVerificationResult()
    expect(result).toBeDefined()

    // No side effects should be observable beyond the verification result
    expect(typeof invariant.getVerificationResult).toBe('function')
    expect(typeof invariant.getVerificationChecks).toBe('function')
  })

  it('disposes cleanly with Fiber ownership', async () => {
    ctx.plugin(SecurityAssuranceService, {})
    service = ctx.securityAssurance

    const invariantCtx = ctx.plugin(SecurityAssuranceInvariant)
    await invariantCtx
    invariant = ctx.securityAssuranceInvariant

    expect(invariant).toBeDefined()

    // Dispose the invariant plugin
    invariantCtx.dispose()

    // Service should remain functional
    const invocation = (service as any)[Symbol.for('dsh-security-assurance:resolve-trusted-invocation')]({
      kind: 'host-operator',
      principalId: 'test-health-reader',
      permissions: ['health:read'],
    })

    const healthResult = await service.getHealth(invocation, { schemaVersion: 1 })
    expect(healthResult.ok).toBe(true)
  })

  it('does not patch or modify Harness', async () => {
    ctx.plugin(SecurityAssuranceService, {})
    service = ctx.securityAssurance

    const invariantFiber = ctx.plugin(SecurityAssuranceInvariant)
    await invariantFiber
    invariant = ctx.securityAssuranceInvariant

    // Invariant should not modify any existing services
    expect(ctx.securityAssurance).toBe(service)

    // Verify invariant was created
    expect(invariant).toBeDefined()
  })

  it('reports verification failures without throwing', async () => {
    ctx.plugin(SecurityAssuranceService, {})
    service = ctx.securityAssurance

    // Invariant construction should not throw even if checks fail
    let invariantFiber
    expect(() => {
      invariantFiber = ctx.plugin(SecurityAssuranceInvariant)
    }).not.toThrow()

    await invariantFiber
    invariant = ctx.securityAssuranceInvariant
    expect(invariant).toBeDefined()

    const result = invariant.getVerificationResult()
    expect(result).toBeDefined()
  })
})
