import type {
  AnalyzerQualificationRecordV1,
  AnalyzerQualificationRegistrationDisposer,
} from '../analyzer.ts'

/**
 * Package-private Host composition protocol. The versioned process identity is
 * shared by independently bundled trusted entries without widening the public
 * Security Service Interface.
 */
export const REGISTER_ANALYZER_QUALIFICATION = Symbol.for(
  'dsh-security-assurance/internal/register-analyzer-qualification/v1',
)

type QualificationRegistrar = (
  record: AnalyzerQualificationRecordV1,
) => AnalyzerQualificationRegistrationDisposer

/** Invoke the trusted same-package qualification protocol. */
export function registerAnalyzerQualification(
  service: unknown,
  record: AnalyzerQualificationRecordV1,
): AnalyzerQualificationRegistrationDisposer {
  if (typeof service !== 'object' || service === null) {
    throw new TypeError('Security Assurance qualification composition is unavailable')
  }
  const registrar = (service as Record<PropertyKey, unknown>)[REGISTER_ANALYZER_QUALIFICATION]
  if (typeof registrar !== 'function') {
    throw new TypeError('Security Assurance qualification composition is unavailable')
  }
  return (registrar as QualificationRegistrar)(record)
}
