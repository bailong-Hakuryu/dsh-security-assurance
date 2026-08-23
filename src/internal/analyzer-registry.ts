import type {
  AnalyzerContributionV1,
  AnalyzerDescriptorV1,
  AnalyzerFactoryV1,
  AnalyzerInputV1,
  AnalyzerInvocationOptions,
  AnalyzerRegistrationDisposer,
} from '../analyzer.ts'
import {
  analyzerContributionV1Schema,
  analyzerInputV1Schema,
  parseAnalyzerDescriptorV1,
} from '../analyzer.ts'
import type { AssessmentMode } from '../contracts.ts'
import { canonicalJson } from './canonical.ts'
import { deepFreeze } from './freeze.ts'

export type AnalyzerRegistryErrorCode =
  | 'registration_closed'
  | 'duplicate_registration'
  | 'invalid_factory'
  | 'registration_missing'
  | 'invalid_instance'
  | 'invalid_contribution'
  | 'disposal_failed'

export class AnalyzerRegistryError extends Error {
  constructor(readonly code: AnalyzerRegistryErrorCode, message: string, options?: ErrorOptions) {
    super(message, options)
    this.name = 'AnalyzerRegistryError'
  }
}

interface AnalyzerRegistration {
  readonly descriptor: AnalyzerDescriptorV1
  readonly factory: AnalyzerFactoryV1
}

function key(descriptor: Pick<AnalyzerDescriptorV1, 'analyzerId' | 'analyzerVersion'>): string {
  return `${descriptor.analyzerId}@${descriptor.analyzerVersion}`
}

function exactDescriptor(
  left: AnalyzerDescriptorV1,
  right: AnalyzerDescriptorV1,
): boolean {
  return canonicalJson(left) === canonicalJson(right)
}

/**
 * Startup-composed deep Module for local Analyzer registration and Attempt execution.
 * Factory, instance and cancellation handles never cross into durable Assessment state.
 */
export class AnalyzerRegistry {
  private readonly registrations = new Map<string, AnalyzerRegistration>()
  private registrationClosed = false

  register(candidate: unknown, factory: AnalyzerFactoryV1): AnalyzerRegistrationDisposer {
    if (this.registrationClosed) {
      throw new AnalyzerRegistryError(
        'registration_closed',
        'Analyzer registration is closed after Assessment admission began',
      )
    }
    if (typeof factory !== 'function') {
      throw new AnalyzerRegistryError('invalid_factory', 'Analyzer Factory must be callable')
    }
    const descriptor = parseAnalyzerDescriptorV1(candidate)
    const registrationKey = key(descriptor)
    if (this.registrations.has(registrationKey)) {
      throw new AnalyzerRegistryError(
        'duplicate_registration',
        `Analyzer '${registrationKey}' is already registered`,
      )
    }
    const registration = { descriptor, factory }
    this.registrations.set(registrationKey, registration)
    let disposed = false
    return () => {
      if (disposed) return
      disposed = true
      if (this.registrations.get(registrationKey) === registration) {
        this.registrations.delete(registrationKey)
      }
    }
  }

  /** Freeze exact pure-data identities and close further startup composition. */
  freezeSelection(policyId: string, assessmentMode: AssessmentMode): readonly AnalyzerDescriptorV1[] {
    this.registrationClosed = true
    return deepFreeze([...this.registrations.values()]
      .map(registration => registration.descriptor)
      .filter(descriptor => (
        descriptor.supportedPolicyIds.includes(policyId)
        && descriptor.supportedAssessmentModes.includes(assessmentMode)
      ))
      .sort((left, right) => key(left).localeCompare(key(right))))
  }

  /** Resolve the exact frozen registration, create one Attempt instance, validate and dispose it. */
  async execute(
    descriptor: AnalyzerDescriptorV1,
    input: AnalyzerInputV1,
    options: AnalyzerInvocationOptions = {},
  ): Promise<AnalyzerContributionV1> {
    const registration = this.registrations.get(key(descriptor))
    if (registration === undefined || !exactDescriptor(registration.descriptor, descriptor)) {
      throw new AnalyzerRegistryError(
        'registration_missing',
        `Frozen Analyzer '${key(descriptor)}' is unavailable`,
      )
    }
    const normalizedInput = deepFreeze(analyzerInputV1Schema.parse(input))
    const instance = registration.factory(registration.descriptor)
    if (
      typeof instance !== 'object'
      || instance === null
      || !exactDescriptor(instance.descriptor, registration.descriptor)
      || typeof instance.analyze !== 'function'
      || typeof instance.dispose !== 'function'
    ) {
      throw new AnalyzerRegistryError('invalid_instance', 'Analyzer Factory returned an invalid instance')
    }

    let contribution: AnalyzerContributionV1 | undefined
    let executionError: unknown
    try {
      contribution = deepFreeze(analyzerContributionV1Schema.parse(
        await instance.analyze(normalizedInput, options),
      ))
    } catch (error) {
      executionError = error
    }
    try {
      await instance.dispose()
    } catch (error) {
      throw new AnalyzerRegistryError('disposal_failed', 'Analyzer Attempt disposal failed', { cause: error })
    }
    if (executionError !== undefined || contribution === undefined) {
      throw new AnalyzerRegistryError(
        'invalid_contribution',
        'Analyzer returned an invalid Contribution',
        { cause: executionError },
      )
    }
    if (
      canonicalJson(contribution.analyzerIdentity) !== canonicalJson({
        analyzerId: descriptor.analyzerId,
        analyzerVersion: descriptor.analyzerVersion,
        descriptorSchemaVersion: descriptor.descriptorSchemaVersion,
        buildDigest: descriptor.buildDigest,
      })
      || canonicalJson(contribution.subjectDigest) !== canonicalJson(normalizedInput.subject.digest)
      || contribution.coverageClaims.some(claim => (
        !descriptor.coverageObligationIds.includes(claim.obligationId)
        || !normalizedInput.coverageObligationIds.includes(claim.obligationId)
      ))
      || contribution.evidence.some(evidence => !descriptor.evidenceSchemaIds.includes(evidence.schemaId))
    ) {
      throw new AnalyzerRegistryError(
        'invalid_contribution',
        'Analyzer Contribution does not match its frozen Descriptor and Input',
      )
    }
    return contribution
  }
}
