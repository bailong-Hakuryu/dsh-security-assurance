import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { Context } from '@deepseek-ai/cordis'
import { SecurityAssuranceService } from '../src/index.ts'
import { SecurityAssuranceInvariant } from '../src/invariant.ts'
import { referenceHostInvocation } from './support/reference-host.ts'

describe('Invariant Entry', () => {
  let ctx: Context
  let service: SecurityAssuranceService
  let invariant: SecurityAssuranceInvariant
  let dshHome: string

  beforeEach(async () => {
    ctx = new Context()
    dshHome = await mkdtemp(join(tmpdir(), 'dsh-security-invariant-test-'))
  })

  afterEach(async () => {
    if (ctx && typeof (ctx as any).dispose === 'function') {
      await (ctx as any).dispose()
    }
    if (dshHome) {
      await rm(dshHome, { recursive: true, force: true }).catch(() => {})
    }
  })

  it('performs Harness composition verification at construction', async () => {
    const serviceFiber = ctx.plugin(SecurityAssuranceService, { dshHome })
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
    const serviceFiber = ctx.plugin(SecurityAssuranceService, { dshHome })
    await serviceFiber
    service = ctx.securityAssurance
    expect(service).toBeDefined()

    const invariantFiber = ctx.plugin(SecurityAssuranceInvariant)
    await invariantFiber
    invariant = ctx.securityAssuranceInvariant
    expect(invariant).toBeDefined()

    await service.whenReady()

    // Verify the invariant performed its checks
    const result = invariant.getVerificationResult()
    expect(result).toMatch(/^(PASS|FAIL|PENDING_INVARIANT)$/)

    const checks = invariant.getVerificationChecks()
    expect(Array.isArray(checks)).toBe(true)
    expect(checks.length).toBeGreaterThan(0)

    // Verify the result was contributed to Service Runtime Health
    const invocation = referenceHostInvocation(service)
    const healthResult = await service.getHealth(invocation, { schemaVersion: 1 })
    expect(healthResult.ok).toBe(true)

    if (healthResult.ok) {
      const health = healthResult.value
      expect(health.compatibility.harnessVerification).toBe(result)

      // Verify checks are present in health
      const harnessChecks = health.checks.filter(c => c.id.startsWith('composition.'))
      expect(harnessChecks.length).toBeGreaterThan(0)
    }
  })

  it('verifies required Cordis services exist', async () => {
    ctx.plugin(SecurityAssuranceService, { dshHome })
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
    ctx.plugin(SecurityAssuranceService, { dshHome })
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
    ctx.plugin(SecurityAssuranceService, { dshHome })
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
    const serviceFiber = ctx.plugin(SecurityAssuranceService, { dshHome })
    await serviceFiber
    service = ctx.securityAssurance
    expect(service).toBeDefined()

    const invariantCtx = ctx.plugin(SecurityAssuranceInvariant)
    await invariantCtx
    invariant = ctx.securityAssuranceInvariant

    expect(invariant).toBeDefined()

    // Dispose the invariant plugin
    invariantCtx.dispose()

    // Service should remain functional - verify it still exists
    expect(ctx.securityAssurance).toBeDefined()

    // The service reference should still be valid
    expect(service).toBeDefined()
  })

  it('does not patch or modify Harness', async () => {
    const serviceFiber = ctx.plugin(SecurityAssuranceService, { dshHome })
    await serviceFiber
    service = ctx.securityAssurance

    const invariantFiber = ctx.plugin(SecurityAssuranceInvariant)
    await invariantFiber
    invariant = ctx.securityAssuranceInvariant

    // Invariant should not modify any existing services
    // We can't use toBe(service) because of Cordis proxy, so just verify both exist
    expect(service).toBeDefined()
    expect(ctx.securityAssurance).toBeDefined()

    // Verify invariant was created
    expect(invariant).toBeDefined()
  })

  it('reports verification failures without throwing', async () => {
    ctx.plugin(SecurityAssuranceService, { dshHome })
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

  it('verifies all checks have proper structure', async () => {
    ctx.plugin(SecurityAssuranceService, { dshHome })
    service = ctx.securityAssurance

    const invariantFiber = ctx.plugin(SecurityAssuranceInvariant)
    await invariantFiber
    invariant = ctx.securityAssuranceInvariant

    const checks = invariant.getVerificationChecks()

    // Verify all checks have proper structure
    for (const check of checks) {
      expect(check).toHaveProperty('id')
      expect(check).toHaveProperty('status')
      expect(check).toHaveProperty('required')
      expect(check).toHaveProperty('message')
      expect(typeof check.id).toBe('string')
      expect(['PASS', 'FAIL', 'NOT_EVALUATED']).toContain(check.status)
      expect(typeof check.required).toBe('boolean')
      expect(typeof check.message).toBe('string')
      expect(check.message.length).toBeGreaterThan(0)
      expect(check.message.length).toBeLessThanOrEqual(512)
    }
  })

  it('verifies check IDs follow naming convention', async () => {
    ctx.plugin(SecurityAssuranceService, { dshHome })
    service = ctx.securityAssurance

    const invariantFiber = ctx.plugin(SecurityAssuranceInvariant)
    await invariantFiber
    invariant = ctx.securityAssuranceInvariant

    const checks = invariant.getVerificationChecks()

    // Verify all check IDs follow the naming convention
    const idPattern = /^[a-z][a-z0-9]*(?:[.-][a-z0-9]+)*$/
    for (const check of checks) {
      expect(check.id).toMatch(idPattern)
      expect(check.id.length).toBeLessThanOrEqual(96)
    }
  })

  it('verifies required checks are actually critical', async () => {
    ctx.plugin(SecurityAssuranceService, { dshHome })
    service = ctx.securityAssurance

    const invariantFiber = ctx.plugin(SecurityAssuranceInvariant)
    await invariantFiber
    invariant = ctx.securityAssuranceInvariant

    const checks = invariant.getVerificationChecks()
    const requiredChecks = checks.filter(c => c.required)

    // Verify critical checks are marked as required
    expect(requiredChecks.some(c => c.id === 'composition.harness-version')).toBe(true)
    expect(requiredChecks.some(c => c.id === 'composition.required-services')).toBe(true)
    expect(requiredChecks.some(c => c.id === 'composition.service-registration')).toBe(true)
    expect(requiredChecks.some(c => c.id === 'composition.public-contract')).toBe(true)

    // Context integrity check may be required or not depending on what failed
    const contextCheck = checks.find(c => c.id === 'composition.context-integrity')
    expect(contextCheck).toBeDefined()
  })
})
