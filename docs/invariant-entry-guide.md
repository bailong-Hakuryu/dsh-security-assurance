# Invariant Entry Usage Guide

## Overview

The `./invariant` entry is an optional dormant Cordis Runtime Entry that verifies Harness composition and reports its result into Service health. It performs read-only verification without patching, repairing, or mutating any runtime state.

## When to Use

Use the invariant entry when you need to:

- **Verify Harness composition** - Ensure the exact Harness version matches expectations
- **Validate runtime environment** - Confirm required services and dependencies are available
- **Monitor system health** - Include composition verification in health checks
- **Detect configuration drift** - Identify mismatches between expected and actual runtime
- **Debug integration issues** - Diagnose problems with service registration or dependencies

## Installation

The invariant entry is included in the `dsh-security-assurance` package but remains dormant by default. To activate it, explicitly load it as a Cordis plugin:

```typescript
import { Context } from '@deepseek-ai/cordis'
import SecurityAssuranceService from 'dsh-security-assurance'
import SecurityAssuranceInvariant from 'dsh-security-assurance/invariant'

const ctx = new Context()

// Install the Security Assurance Service
ctx.plugin(SecurityAssuranceService, {
  dshHome: '/path/to/dsh/home'
})

// Activate the invariant entry (optional)
ctx.plugin(SecurityAssuranceInvariant)
```

## Verification Checks

The invariant entry performs 8 comprehensive checks at construction time:

### Required Checks (must pass)

1. **Harness Version** (`composition.harness-version`)
   - Verifies exact `@deepseek-ai/harness` version matches `TARGET_HARNESS_VERSION`
   - Failure indicates version mismatch or missing Harness package

2. **Required Services** (`composition.required-services`)
   - Verifies presence of: `loader`, `logger`, `http`
   - Failure indicates missing critical Cordis services

3. **Service Registration** (`composition.service-registration`)
   - Verifies Security Assurance Service is registered on Context
   - Verifies Service exposes expected public contract
   - Failure indicates incomplete or incorrect service registration

4. **Context Integrity** (`composition.context-integrity`)
   - Verifies Context.plugin method is available
   - Verifies Context.fiber is accessible
   - Failure indicates fundamental Context corruption

5. **Public Contract** (`composition.public-contract`)
   - Verifies Service exposes: `getHealth`, `whenReady`
   - Reports availability of optional methods: `startAssessment`, `getAssessment`, `waitForAssessment`
   - Failure indicates incomplete public API

### Optional Checks (informational)

6. **No Conflicts** (`composition.no-conflicts`)
   - Checks for multiple Security Assurance Service registrations
   - Skipped if reflect service unavailable

7. **Cordis Version** (`composition.cordis-version`)
   - Reports Cordis framework version
   - Helps diagnose framework-related issues

8. **Bundle Dependencies** (`composition.bundle-dependencies`)
   - Verifies critical dependencies: `@deepseek-ai/cordis`, `@deepseek-ai/harness`
   - Helps diagnose missing dependency issues

## Reading Verification Results

### From the Service

Verification results are contributed to the Service's Runtime Health:

```typescript
const service = ctx.securityAssurance
const invocation = /* create trusted invocation */

const healthResult = await service.getHealth(invocation, { schemaVersion: 1 })

if (healthResult.ok) {
  const health = healthResult.value
  
  // Overall verification result
  console.log(health.compatibility.harnessVerification) // "PASS" | "FAIL" | "PENDING_INVARIANT"
  
  // Individual checks
  for (const check of health.checks) {
    console.log(`${check.id}: ${check.status}`)
    console.log(`  Required: ${check.required}`)
    console.log(`  Message: ${check.message}`)
  }
}
```

### Directly from the Invariant

For testing or debugging, you can access results directly:

```typescript
const invariant = ctx.securityAssuranceInvariant

// Get overall result
const result = invariant.getVerificationResult()
console.log(`Verification: ${result}`) // "PASS" | "FAIL" | "PENDING_INVARIANT"

// Get individual checks
const checks = invariant.getVerificationChecks()
for (const check of checks) {
  console.log(`${check.id}: ${check.status} - ${check.message}`)
}
```

## Understanding Results

### PASS
All required checks passed. The runtime composition matches expectations and the Service is correctly registered.

### FAIL
One or more required checks failed. Review the individual check messages to identify the issue:
- Harness version mismatch → Update Harness or adjust expectations
- Missing services → Ensure required Cordis plugins are loaded
- Service not registered → Verify Service plugin loaded before invariant
- Context corruption → Investigate fundamental runtime issues
- Contract incomplete → Service implementation may be outdated

### PENDING_INVARIANT
The invariant entry was not activated. This is the default state when the Service runs without the invariant plugin.

## Best Practices

### 1. Activate Early in Development
Load the invariant entry during development to catch composition issues early:

```typescript
if (process.env.NODE_ENV === 'development') {
  ctx.plugin(SecurityAssuranceInvariant)
}
```

### 2. Use in Integration Tests
Include invariant verification in integration test suites:

```typescript
import { describe, it, expect } from 'vitest'

describe('Security Assurance Integration', () => {
  it('should have valid Harness composition', async () => {
    ctx.plugin(SecurityAssuranceService, { dshHome })
    ctx.plugin(SecurityAssuranceInvariant)
    
    const invariant = ctx.securityAssuranceInvariant
    const result = invariant.getVerificationResult()
    
    expect(result).toBe('PASS')
  })
})
```

### 3. Monitor in Production
Consider activating the invariant in production environments to detect drift:

```typescript
// Activate invariant in all environments
ctx.plugin(SecurityAssuranceInvariant)

// Log verification results
const invariant = ctx.securityAssuranceInvariant
const result = invariant.getVerificationResult()

if (result === 'FAIL') {
  logger.error('Harness composition verification failed', {
    checks: invariant.getVerificationChecks()
  })
}
```

### 4. Don't Use for Runtime Repairs
The invariant is read-only and performs no repairs. If verification fails:
- Fix the underlying issue (version mismatch, missing dependencies, etc.)
- Don't attempt to patch or work around failures
- Treat failures as critical configuration errors

## Performance Considerations

### Overhead
- Verification runs **once at construction time** (synchronous)
- No ongoing overhead after construction
- Typical execution time: < 10ms
- Safe to activate in production

### Disposal
The invariant follows Cordis Fiber lifecycle:
- Disposes cleanly when parent Context disposes
- No manual cleanup required
- Service remains functional after invariant disposal

## Troubleshooting

### "Missing required Cordis services"
**Cause**: Required services (loader, logger, http) not available  
**Fix**: Ensure Harness plugins are loaded before Security Assurance

### "Harness version mismatch"
**Cause**: Installed Harness version doesn't match `TARGET_HARNESS_VERSION`  
**Fix**: Update `@deepseek-ai/harness` to the required version

### "Security Assurance Service not registered"
**Cause**: Service plugin not loaded or loaded after invariant  
**Fix**: Load `SecurityAssuranceService` before `SecurityAssuranceInvariant`

### "Context.plugin method not available"
**Cause**: Fundamental Context corruption  
**Fix**: Verify Cordis installation and Context initialization

### "Service missing required methods"
**Cause**: Service implementation incomplete or outdated  
**Fix**: Verify `dsh-security-assurance` package version and integrity

## API Reference

### SecurityAssuranceInvariant

```typescript
class SecurityAssuranceInvariant extends Service {
  constructor(ctx: Context)
  
  // Public accessors (for testing and debugging)
  getVerificationResult(): HarnessVerificationResult
  getVerificationChecks(): readonly HarnessVerificationCheck[]
}
```

### Types

```typescript
type HarnessVerificationResult = 'PASS' | 'FAIL' | 'PENDING_INVARIANT'

interface HarnessVerificationCheck {
  readonly id: string              // Check identifier (e.g., "composition.harness-version")
  readonly status: 'PASS' | 'FAIL' // Check result
  readonly required: boolean       // Whether check must pass for overall PASS
  readonly message: string         // Human-readable result description
}
```

## Examples

### Basic Activation

```typescript
import { Context } from '@deepseek-ai/cordis'
import SecurityAssuranceService from 'dsh-security-assurance'
import SecurityAssuranceInvariant from 'dsh-security-assurance/invariant'

const ctx = new Context()
ctx.plugin(SecurityAssuranceService, { dshHome: '/var/lib/dsh' })
ctx.plugin(SecurityAssuranceInvariant)

const result = ctx.securityAssuranceInvariant.getVerificationResult()
console.log(`Composition verification: ${result}`)
```

### Health Check Integration

```typescript
async function healthCheck() {
  const service = ctx.securityAssurance
  const invocation = createTrustedInvocation()
  
  const healthResult = await service.getHealth(invocation, { schemaVersion: 1 })
  
  if (!healthResult.ok) {
    return { healthy: false, error: healthResult.error }
  }
  
  const health = healthResult.value
  
  return {
    healthy: health.state === 'READY',
    harnessVerification: health.compatibility.harnessVerification,
    checks: health.checks.filter(c => c.status === 'FAIL')
  }
}
```

### Conditional Activation

```typescript
// Only activate in specific environments
const shouldVerify = process.env.VERIFY_COMPOSITION === 'true'
  || process.env.NODE_ENV === 'test'
  || process.env.NODE_ENV === 'development'

if (shouldVerify) {
  ctx.plugin(SecurityAssuranceInvariant)
  
  const result = ctx.securityAssuranceInvariant.getVerificationResult()
  if (result === 'FAIL') {
    console.error('Composition verification failed - review checks before proceeding')
  }
}
```

## Related Documentation

- [ADR 0253 Compliance Report](./adr-0253-compliance-report.md) - Implementation details
- [Implementation Specification](./implementation-specification.md) - Overall architecture
- [README](../README.md) - Project overview

## Support

For issues or questions about the invariant entry:
1. Review the troubleshooting section above
2. Check verification check messages for specific guidance
3. Consult ADR 0253 for design rationale
4. File an issue with verification results and environment details
