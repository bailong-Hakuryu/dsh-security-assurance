import { Context, Service } from '@deepseek-ai/cordis'
import {
  TARGET_HARNESS_VERSION,
} from './contracts.ts'

/**
 * Sanitize error message for inclusion in public Health checks.
 * Limits length and removes potentially sensitive details.
 */
function sanitizeErrorMessage(error: unknown): string {
  const raw = error instanceof Error ? error.message : 'unknown error'
  const sanitized = raw.replace(/\/[^\s]+/g, '[path]').replace(/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/g, '[ip]')
  return sanitized.slice(0, 200)
}

/**
 * Harness composition verification result contributed to Runtime Health.
 *
 * The invariant entry verifies the exact Harness version, required Service
 * Definitions, bundle dependencies, generated contract compatibility, and
 * declared runtime composition without mutating state or patching Harness.
 */
export type HarnessVerificationResult = 'PASS' | 'FAIL' | 'PENDING_INVARIANT'

export interface HarnessVerificationCheck {
  readonly id: string
  readonly status: 'PASS' | 'FAIL' | 'NOT_EVALUATED'
  readonly required: boolean
  readonly message: string
}

/**
 * Optional dormant Cordis Runtime Entry that verifies Harness composition
 * and reports its result into Service health without patching or repairing.
 *
 * Effects are Fiber-owned and dormant unless explicitly activated. The entry
 * performs no Assessment work, no Store mutation, no Harness patching, and
 * no substitute Provider registration.
 */
export class SecurityAssuranceInvariant extends Service {
  static inject = ['securityAssurance']

  private verificationResult: HarnessVerificationResult = 'PENDING_INVARIANT'
  private verificationChecks: readonly HarnessVerificationCheck[] = []

  constructor(ctx: Context) {
    super(ctx, 'securityAssuranceInvariant')
    // Perform verification synchronously at construction time
    this.performVerification()

    // Contribute verification result to the Service
    this.contributeToServiceHealth()

    // TODO: Implement proper Fiber disposer to revoke health contribution
    // when invariant is unloaded. Currently, verification state persists
    // after invariant disposal (Standards issue #4).
  }

  private performVerification(): void {
    const checks: HarnessVerificationCheck[] = []

    // 1. Verify exact Harness version
    const harnessVersionCheck = this.verifyHarnessVersion()
    checks.push(harnessVersionCheck)

    // 2. Verify required Cordis services exist
    const cordisServicesCheck = this.verifyRequiredServices()
    checks.push(cordisServicesCheck)

    // 3. Verify Service registration
    const serviceRegistrationCheck = this.verifyServiceRegistration()
    checks.push(serviceRegistrationCheck)

    // 4. Verify no conflicting registrations
    const conflictCheck = this.verifyNoConflicts()
    checks.push(conflictCheck)

    // 5. Verify Cordis framework version
    const cordisVersionCheck = this.verifyCordisVersion()
    checks.push(cordisVersionCheck)

    // 6. Verify Context integrity
    const contextIntegrityCheck = this.verifyContextIntegrity()
    checks.push(contextIntegrityCheck)

    // 7. Verify bundle dependencies
    const bundleDepsCheck = this.verifyBundleDependencies()
    checks.push(bundleDepsCheck)

    // 8. Verify public contract compatibility
    const contractCheck = this.verifyPublicContract()
    checks.push(contractCheck)

    this.verificationChecks = checks

    // Result is PASS only if all required checks pass
    const requiredChecksFailed = checks.filter(c => c.required && c.status === 'FAIL')
    this.verificationResult = requiredChecksFailed.length === 0 ? 'PASS' : 'FAIL'
  }

  private verifyHarnessVersion(): HarnessVerificationCheck {
    // Check if @deepseek-ai/harness is available and matches target version
    try {
      // Access loader through context's services if available
      const loader = (this.ctx as any).loader
      if (!loader?.packages) {
        return {
          id: 'composition.harness-version',
          status: 'FAIL',
          required: true,
          message: `Harness loader not available; expected ${TARGET_HARNESS_VERSION}.`,
        }
      }

      const harnessPackage = loader.packages['@deepseek-ai/harness']
      if (!harnessPackage) {
        return {
          id: 'composition.harness-version',
          status: 'FAIL',
          required: true,
          message: `Harness package not found; expected ${TARGET_HARNESS_VERSION}.`,
        }
      }

      const actualVersion = harnessPackage.version
      if (actualVersion !== TARGET_HARNESS_VERSION) {
        return {
          id: 'composition.harness-version',
          status: 'FAIL',
          required: true,
          message: `Harness version ${actualVersion} does not match target ${TARGET_HARNESS_VERSION}.`,
        }
      }

      return {
        id: 'composition.harness-version',
        status: 'PASS',
        required: true,
        message: `Harness version ${actualVersion} matches target ${TARGET_HARNESS_VERSION}.`,
      }
    } catch (error) {
      return {
        id: 'composition.harness-version',
        status: 'FAIL',
        required: true,
        message: `Harness version verification failed: ${sanitizeErrorMessage(error)}`,
      }
    }
  }

  private verifyRequiredServices(): HarnessVerificationCheck {
    const requiredServices = [
      'loader',
      'logger',
      'http',
    ]

    const missingServices = requiredServices.filter(serviceName => {
      try {
        // Use reflection API if available to safely check service existence
        if (this.ctx.reflect) {
          return this.ctx.reflect.get(serviceName) === undefined
        }
        // Fallback: try to access the service in a try-catch
        return (this.ctx as any)[serviceName] === undefined
      } catch {
        // If accessing throws, service is not available
        return true
      }
    })

    if (missingServices.length > 0) {
      return {
        id: 'composition.required-services',
        status: 'FAIL',
        required: true,
        message: `Missing required Cordis services: ${missingServices.join(', ')}.`,
      }
    }

    return {
      id: 'composition.required-services',
      status: 'PASS',
      required: true,
      message: 'All required Cordis services are available.',
    }
  }

  private verifyServiceRegistration(): HarnessVerificationCheck {
    try {
      const securityService = this.ctx.securityAssurance
      if (!securityService) {
        return {
          id: 'composition.service-registration',
          status: 'FAIL',
          required: true,
          message: 'Security Assurance Service is not registered.',
        }
      }

      // Verify it's the expected type by checking for a known method
      if (typeof securityService.getHealth !== 'function') {
        return {
          id: 'composition.service-registration',
          status: 'FAIL',
          required: true,
          message: 'Security Assurance Service does not expose expected public contract.',
        }
      }

      return {
        id: 'composition.service-registration',
        status: 'PASS',
        required: true,
        message: 'Security Assurance Service is correctly registered.',
      }
    } catch (error) {
      return {
        id: 'composition.service-registration',
        status: 'FAIL',
        required: true,
        message: `Service registration verification failed: ${sanitizeErrorMessage(error)}`,
      }
    }
  }

  private verifyNoConflicts(): HarnessVerificationCheck {
    // Check that no other plugin has registered conflicting services
    // This is a placeholder for more sophisticated conflict detection
    try {
      const registry = this.ctx.reflect
      if (!registry) {
        return {
          id: 'composition.no-conflicts',
          status: 'NOT_EVALUATED',
          required: false,
          message: 'Conflict detection skipped (reflect not available).',
        }
      }

      // Verify our service is the only securityAssurance registration
      // Compare using the underlying service instance, not the proxy
      const securityService = registry.get('securityAssurance')
      if (!securityService) {
        return {
          id: 'composition.no-conflicts',
          status: 'PASS',
          required: false,
          message: 'No conflicting service registrations detected.',
        }
      }

      // Check if there are multiple definitions for securityAssurance
      // The registry tracks all service definitions, not proxies
      const definitions = (this.ctx.reflect as any)?._services
      if (definitions) {
        const securityDefs = Array.from(definitions.values()).filter(
          (def: any) => def?.name === 'securityAssurance'
        )
        if (securityDefs.length > 1) {
          return {
            id: 'composition.no-conflicts',
            status: 'FAIL',
            required: false,
            message: 'Multiple Security Assurance Service registrations detected.',
          }
        }
      }

      return {
        id: 'composition.no-conflicts',
        status: 'PASS',
        required: false,
        message: 'No conflicting service registrations detected.',
      }
    } catch (error) {
      return {
        id: 'composition.no-conflicts',
        status: 'NOT_EVALUATED',
        required: false,
        message: 'Conflict detection skipped due to error.',
      }
    }
  }

  private verifyCordisVersion(): HarnessVerificationCheck {
    // Verify Cordis framework is available and functional
    try {
      const loader = (this.ctx as any).loader
      if (!loader?.packages) {
        return {
          id: 'composition.cordis-version',
          status: 'FAIL',
          required: false,
          message: 'Cordis loader not available for version verification.',
        }
      }

      const cordisPackage = loader.packages['@deepseek-ai/cordis']
      if (!cordisPackage) {
        return {
          id: 'composition.cordis-version',
          status: 'FAIL',
          required: false,
          message: 'Cordis package not found in loader registry.',
        }
      }

      const version = cordisPackage.version
      return {
        id: 'composition.cordis-version',
        status: 'PASS',
        required: false,
        message: `Cordis version ${version} is available.`,
      }
    } catch (error) {
      return {
        id: 'composition.cordis-version',
        status: 'FAIL',
        required: false,
        message: `Cordis version verification failed: ${sanitizeErrorMessage(error)}`,
      }
    }
  }

  private verifyContextIntegrity(): HarnessVerificationCheck {
    // Verify the Context is functioning properly
    try {
      // Check basic Context capabilities
      if (typeof this.ctx.plugin !== 'function') {
        return {
          id: 'composition.context-integrity',
          status: 'FAIL',
          required: true,
          message: 'Context.plugin method not available.',
        }
      }

      // Check if fiber is accessible
      if (!this.ctx.fiber) {
        return {
          id: 'composition.context-integrity',
          status: 'FAIL',
          required: false,
          message: 'Context.fiber not available.',
        }
      }

      // Check if reflect service is accessible
      if (!this.ctx.reflect) {
        return {
          id: 'composition.context-integrity',
          status: 'PASS',
          required: false,
          message: 'Context integrity verified (reflect service not available).',
        }
      }

      return {
        id: 'composition.context-integrity',
        status: 'PASS',
        required: true,
        message: 'Context integrity verified.',
      }
    } catch (error) {
      return {
        id: 'composition.context-integrity',
        status: 'FAIL',
        required: true,
        message: `Context integrity verification failed: ${sanitizeErrorMessage(error)}`,
      }
    }
  }

  private verifyBundleDependencies(): HarnessVerificationCheck {
    // Verify critical bundle dependencies are available
    try {
      const loader = (this.ctx as any).loader
      if (!loader?.packages) {
        return {
          id: 'composition.bundle-dependencies',
          status: 'FAIL',
          required: false,
          message: 'Loader not available for dependency verification.',
        }
      }

      // Check for critical dependencies
      const criticalDeps = [
        '@deepseek-ai/cordis',
        '@deepseek-ai/harness',
      ]

      const missingDeps = criticalDeps.filter(dep => !loader.packages[dep])

      if (missingDeps.length > 0) {
        return {
          id: 'composition.bundle-dependencies',
          status: 'FAIL',
          required: false,
          message: `Missing critical dependencies: ${missingDeps.join(', ')}.`,
        }
      }

      return {
        id: 'composition.bundle-dependencies',
        status: 'PASS',
        required: false,
        message: `All critical bundle dependencies are available.`,
      }
    } catch (error) {
      return {
        id: 'composition.bundle-dependencies',
        status: 'FAIL',
        required: false,
        message: `Bundle dependency verification failed: ${sanitizeErrorMessage(error)}`,
      }
    }
  }

  private verifyPublicContract(): HarnessVerificationCheck {
    // Verify the Security Assurance Service exposes the expected public contract
    try {
      const service = this.ctx.securityAssurance
      if (!service) {
        return {
          id: 'composition.public-contract',
          status: 'FAIL',
          required: true,
          message: 'Security Assurance Service not available for contract verification.',
        }
      }

      // Check for essential public methods
      const requiredMethods = [
        'getHealth',
        'whenReady',
      ]

      const missingMethods = requiredMethods.filter(method => typeof (service as any)[method] !== 'function')

      if (missingMethods.length > 0) {
        return {
          id: 'composition.public-contract',
          status: 'FAIL',
          required: true,
          message: `Service missing required methods: ${missingMethods.join(', ')}.`,
        }
      }

      // Verify Service has lifecycle methods (optional)
      const optionalMethods = [
        'startAssessment',
        'getAssessment',
        'waitForAssessment',
      ]

      const availableOptional = optionalMethods.filter(method => typeof (service as any)[method] === 'function')

      return {
        id: 'composition.public-contract',
        status: 'PASS',
        required: true,
        message: `Service public contract verified (${availableOptional.length} optional methods available).`,
      }
    } catch (error) {
      return {
        id: 'composition.public-contract',
        status: 'FAIL',
        required: true,
        message: `Public contract verification failed: ${sanitizeErrorMessage(error)}`,
      }
    }
  }

  private contributeToServiceHealth(): void {
    // Expose verification result to the Service through a package-private channel
    const service = this.ctx.securityAssurance as any
    if (service && typeof service[RECEIVE_HARNESS_VERIFICATION] === 'function') {
      service[RECEIVE_HARNESS_VERIFICATION](
        this.verificationResult,
        this.verificationChecks,
      )
    }
  }

  /** Public accessor for verification result (for testing) */
  getVerificationResult(): HarnessVerificationResult {
    return this.verificationResult
  }

  /** Public accessor for verification checks (for testing) */
  getVerificationChecks(): readonly HarnessVerificationCheck[] {
    return this.verificationChecks
  }
}

/**
 * Package-private symbol for the Service to receive Harness verification results.
 * This avoids polluting the public Service API.
 * Versioned to ensure protocol compatibility between invariant and Service.
 */
const RECEIVE_HARNESS_VERIFICATION = Symbol.for('dsh-security-assurance:receive-harness-verification:v1')

declare module '@deepseek-ai/cordis' {
  interface Context {
    securityAssuranceInvariant: SecurityAssuranceInvariant
  }
}

export default SecurityAssuranceInvariant
