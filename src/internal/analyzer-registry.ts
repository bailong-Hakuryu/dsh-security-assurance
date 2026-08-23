import type {
  AnalyzerContributionV1,
  AnalyzerDescriptorV1,
  AnalyzerFactoryV1,
  AnalyzerInputV1,
  AnalyzerInvocationOptions,
  AnalyzerPortfolioEntryV1,
  AnalyzerQualificationRecordV1,
  AnalyzerQualificationRegistrationDisposer,
  AnalyzerRegistrationDisposer,
} from '../analyzer.ts'
import {
  analyzerContributionV1Schema,
  analyzerInputV1Schema,
  parseAnalyzerDescriptorV1,
  parseAnalyzerQualificationRecordV1,
} from '../analyzer.ts'
import {
  SECURITY_ASSURANCE_PRODUCT_NAME,
} from '../contracts.ts'
import type {
  AssessmentMode,
  RepositoryPlatform,
} from '../contracts.ts'
import { canonicalJson, structuredDigest } from './canonical.ts'
import { deepFreeze } from './freeze.ts'

export type AnalyzerRegistryErrorCode =
  | 'registration_closed'
  | 'duplicate_registration'
  | 'duplicate_qualification'
  | 'invalid_factory'
  | 'invalid_qualification'
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
  private readonly qualifications = new Map<string, AnalyzerQualificationRecordV1>()
  private readonly qualificationIds = new Map<string, AnalyzerQualificationRecordV1>()
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

  registerQualification(candidate: unknown): AnalyzerQualificationRegistrationDisposer {
    if (this.registrationClosed) {
      throw new AnalyzerRegistryError(
        'registration_closed',
        'Analyzer Qualification registration is closed after Assessment admission began',
      )
    }
    const qualification = parseAnalyzerQualificationRecordV1(candidate)
    const { qualificationDigest, ...qualificationCore } = qualification
    const observedDigest = structuredDigest(
      qualificationDigest.mediaType,
      qualificationCore,
    )
    if (
      qualificationDigest.mediaType
        !== 'application/vnd.dsh.security.analyzer-qualification+json'
      || canonicalJson(observedDigest) !== canonicalJson(qualificationDigest)
    ) {
      throw new AnalyzerRegistryError(
        'invalid_qualification',
        'Analyzer Qualification digest does not bind its canonical record',
      )
    }
    const identityKey = canonicalJson(qualification.analyzerIdentity)
    if (
      this.qualifications.has(identityKey)
      || this.qualificationIds.has(qualification.qualificationId)
    ) {
      throw new AnalyzerRegistryError(
        'duplicate_qualification',
        `Analyzer Qualification '${qualification.qualificationId}' conflicts with an existing registration`,
      )
    }
    this.qualifications.set(identityKey, qualification)
    this.qualificationIds.set(qualification.qualificationId, qualification)
    let disposed = false
    return () => {
      if (disposed) return
      disposed = true
      if (this.qualifications.get(identityKey) === qualification) {
        this.qualifications.delete(identityKey)
      }
      if (this.qualificationIds.get(qualification.qualificationId) === qualification) {
        this.qualificationIds.delete(qualification.qualificationId)
      }
    }
  }

  /** Freeze exact identities, Qualification candidates and Kernel-owned eligibility decisions. */
  freezeSelection(
    policyId: string,
    assessmentMode: AssessmentMode,
    platform: RepositoryPlatform,
    evaluatedAt: string,
  ): readonly AnalyzerPortfolioEntryV1[] {
    this.registrationClosed = true
    return deepFreeze([...this.registrations.values()]
      .map(registration => registration.descriptor)
      .filter(descriptor => (
        descriptor.supportedPolicyIds.includes(policyId)
        && descriptor.supportedAssessmentModes.includes(assessmentMode)
      ))
      .sort((left, right) => key(left).localeCompare(key(right)))
      .map(descriptor => {
        const analyzerIdentity = {
          analyzerId: descriptor.analyzerId,
          analyzerVersion: descriptor.analyzerVersion,
          descriptorSchemaVersion: descriptor.descriptorSchemaVersion,
          buildDigest: descriptor.buildDigest,
        }
        const qualification = this.qualifications.get(canonicalJson(analyzerIdentity)) ?? null
        let reason:
          | 'QUALIFICATION_MISSING'
          | 'QUALIFICATION_SCOPE_MISMATCH'
          | 'QUALIFICATION_NOT_YET_VALID'
          | 'QUALIFICATION_EXPIRED'
          | null = null
        if (qualification === null) {
          reason = 'QUALIFICATION_MISSING'
        } else if (Date.parse(evaluatedAt) < Date.parse(qualification.issuedAt)) {
          reason = 'QUALIFICATION_NOT_YET_VALID'
        } else if (Date.parse(evaluatedAt) >= Date.parse(qualification.expiresAt)) {
          reason = 'QUALIFICATION_EXPIRED'
        } else if (
          qualification.executionClass !== descriptor.executionClass
          || qualification.egress !== descriptor.egress
          || qualification.executionBackendId !== 'dsh/security-assurance/in-process-pure-v1'
          || !qualification.providerIds.includes(SECURITY_ASSURANCE_PRODUCT_NAME)
          || !qualification.supportedAssessmentModes.includes(assessmentMode)
          || !qualification.supportedPolicyIds.includes(policyId)
          || !qualification.platforms.includes(platform)
          || descriptor.coverageObligationIds.some(
            obligationId => !qualification.coverageObligationIds.includes(obligationId),
          )
          || descriptor.evidenceSchemaIds.some(
            schemaId => !qualification.evidenceSchemaIds.includes(schemaId),
          )
        ) {
          reason = 'QUALIFICATION_SCOPE_MISMATCH'
        }
        const eligible = reason === null
        return {
          descriptor,
          qualification,
          eligibility: {
            schemaVersion: 1,
            decision: eligible ? 'ELIGIBLE' : 'INELIGIBLE',
            reason,
            evaluatedAt,
            analyzerIdentity,
            qualificationId: qualification?.qualificationId ?? null,
            qualificationDigest: qualification?.qualificationDigest ?? null,
            policyId,
            assessmentMode,
            platform,
          },
        }
      }))
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
      || contribution.candidateFindings.some(candidate => !normalizedInput.subject.textSlices.some(slice => (
        slice.path === candidate.sourceAnchor.path
        && canonicalJson(slice.digest) === canonicalJson(candidate.sourceAnchor.fileDigest)
      )))
    ) {
      throw new AnalyzerRegistryError(
        'invalid_contribution',
        'Analyzer Contribution does not match its frozen Descriptor and Input',
      )
    }
    return contribution
  }
}
