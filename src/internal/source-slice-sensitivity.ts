import { z } from 'zod'
import type { DigestEnvelopeV1 } from '../contracts.ts'
import { digestEnvelopeV1Schema } from '../contracts.ts'
import { canonicalJson, structuredDigest } from './canonical.ts'
import { deepFreeze } from './freeze.ts'
import {
  parseProtectedSourceSliceRedaction,
  type ProtectedSourceSliceRedactionV1,
} from './source-slice-protection.ts'
import type { ProtectedSourceSliceMaterialV1 } from './subject-freeze.ts'

export const SOURCE_SLICE_SENSITIVITY_CLASSIFICATION_MEDIA_TYPE =
  'application/vnd.dsh.security.source-slice-sensitivity-classification+json'
export const SOURCE_SLICE_SENSITIVITY_CLASSIFIER_ID =
  'security/source-slice-sensitivity-baseline'
export const SOURCE_SLICE_SENSITIVITY_CLASSIFIER_VERSION = '1.0.0'

export type SourceSliceSensitivityCategoryV1 =
  | 'PROTECTED_SOURCE'
  | 'RESTRICTED_SOURCE'
  | 'SECRET_BEARING_SOURCE'

export type SourceSliceSensitivityIndicatorV1 =
  | 'BASELINE_SOURCE_PROTECTION'
  | 'SENSITIVE_PATH'
  | 'HIGH_CONFIDENCE_SECRET_MATCH'

export interface ProtectedSourceSliceSensitivityClassificationCoreV1 {
  readonly schemaVersion: 1
  readonly requestDigest: DigestEnvelopeV1
  readonly subjectDigest: DigestEnvelopeV1
  readonly sourceDigest: DigestEnvelopeV1
  readonly redactionDigest: DigestEnvelopeV1
  readonly path: string
  readonly classifierId: typeof SOURCE_SLICE_SENSITIVITY_CLASSIFIER_ID
  readonly classifierVersion: typeof SOURCE_SLICE_SENSITIVITY_CLASSIFIER_VERSION
  readonly category: SourceSliceSensitivityCategoryV1
  readonly indicatorCodes: readonly SourceSliceSensitivityIndicatorV1[]
  readonly secretFindingCount: number
}

export interface ProtectedSourceSliceSensitivityClassificationV1
  extends ProtectedSourceSliceSensitivityClassificationCoreV1 {
  readonly classificationDigest: DigestEnvelopeV1
}

export interface ProtectedSourceSliceSensitivityInputV1 {
  readonly material: ProtectedSourceSliceMaterialV1
  readonly redaction: ProtectedSourceSliceRedactionV1
}

const subjectRelativePathSchema = z.string().min(1).max(1024).refine(path => (
  !path.startsWith('/')
  && !path.startsWith('\\')
  && !/^[a-z]:/iu.test(path)
  && !path.includes('\\')
  && path.split('/').every(segment => segment.length > 0 && segment !== '.' && segment !== '..')
), 'Source Slice sensitivity classification requires a canonical Subject-relative path')

const classificationV1Schema = z.strictObject({
  schemaVersion: z.literal(1),
  requestDigest: digestEnvelopeV1Schema,
  subjectDigest: digestEnvelopeV1Schema,
  sourceDigest: digestEnvelopeV1Schema,
  redactionDigest: digestEnvelopeV1Schema,
  path: subjectRelativePathSchema,
  classifierId: z.literal(SOURCE_SLICE_SENSITIVITY_CLASSIFIER_ID),
  classifierVersion: z.literal(SOURCE_SLICE_SENSITIVITY_CLASSIFIER_VERSION),
  category: z.enum(['PROTECTED_SOURCE', 'RESTRICTED_SOURCE', 'SECRET_BEARING_SOURCE']),
  indicatorCodes: z.array(z.enum([
    'BASELINE_SOURCE_PROTECTION',
    'SENSITIVE_PATH',
    'HIGH_CONFIDENCE_SECRET_MATCH',
  ])).length(1),
  secretFindingCount: z.number().int().nonnegative().max(4096),
  classificationDigest: digestEnvelopeV1Schema,
})

function sameDigest(left: DigestEnvelopeV1, right: DigestEnvelopeV1): boolean {
  return canonicalJson(left) === canonicalJson(right)
}

function hasSensitivePath(path: string): boolean {
  const segments = path.toLowerCase().split('/')
  const basename = segments.at(-1) ?? ''
  return (
    /^\.env(?:\.|$)/u.test(basename)
    || ['.npmrc', '.pypirc', '.netrc'].includes(basename)
    || /\.(?:key|pem|p12|pfx)$/u.test(basename)
    || /^(?:credentials|secrets)(?:\.|$)/u.test(basename)
    || /^(?:id_rsa|id_ed25519)(?:\.|$)/u.test(basename)
  )
}

export function deriveProtectedSourceSliceSensitivity(
  path: string,
  secretFindingCount: number,
): {
  readonly category: SourceSliceSensitivityCategoryV1
  readonly indicatorCodes: readonly SourceSliceSensitivityIndicatorV1[]
} {
  const canonicalPath = subjectRelativePathSchema.parse(path)
  const count = z.number().int().nonnegative().max(4096).parse(secretFindingCount)
  if (count > 0) {
    return deepFreeze({
      category: 'SECRET_BEARING_SOURCE',
      indicatorCodes: ['HIGH_CONFIDENCE_SECRET_MATCH'],
    })
  }
  if (hasSensitivePath(canonicalPath)) {
    return deepFreeze({ category: 'RESTRICTED_SOURCE', indicatorCodes: ['SENSITIVE_PATH'] })
  }
  return deepFreeze({
    category: 'PROTECTED_SOURCE',
    indicatorCodes: ['BASELINE_SOURCE_PROTECTION'],
  })
}

/** Apply the fixed conservative classifier without making an egress decision. */
export function classifyProtectedSourceSliceSensitivity(
  input: ProtectedSourceSliceSensitivityInputV1,
): ProtectedSourceSliceSensitivityClassificationV1 {
  const redaction = parseProtectedSourceSliceRedaction(input.redaction, input.material)
  const derived = deriveProtectedSourceSliceSensitivity(
    redaction.path,
    redaction.redactions.length,
  )
  const core: ProtectedSourceSliceSensitivityClassificationCoreV1 = {
    schemaVersion: 1,
    requestDigest: redaction.requestDigest,
    subjectDigest: redaction.subjectDigest,
    sourceDigest: redaction.sourceDigest,
    redactionDigest: redaction.redactionDigest,
    path: redaction.path,
    classifierId: SOURCE_SLICE_SENSITIVITY_CLASSIFIER_ID,
    classifierVersion: SOURCE_SLICE_SENSITIVITY_CLASSIFIER_VERSION,
    category: derived.category,
    indicatorCodes: derived.indicatorCodes,
    secretFindingCount: redaction.redactions.length,
  }
  return deepFreeze({
    ...core,
    classificationDigest: structuredDigest(
      SOURCE_SLICE_SENSITIVITY_CLASSIFICATION_MEDIA_TYPE,
      core,
    ),
  })
}

/** Recompute source/redaction bindings and reject even digest-valid classification downgrades. */
export function parseProtectedSourceSliceSensitivity(
  candidate: unknown,
  expected: ProtectedSourceSliceSensitivityInputV1,
): ProtectedSourceSliceSensitivityClassificationV1 {
  const redaction = parseProtectedSourceSliceRedaction(expected.redaction, expected.material)
  const classification = classificationV1Schema.parse(candidate)
  if (
    !sameDigest(classification.requestDigest, redaction.requestDigest)
    || !sameDigest(classification.subjectDigest, redaction.subjectDigest)
    || !sameDigest(classification.sourceDigest, redaction.sourceDigest)
    || !sameDigest(classification.redactionDigest, redaction.redactionDigest)
    || classification.path !== redaction.path
    || classification.secretFindingCount !== redaction.redactions.length
  ) {
    throw new TypeError('Source Slice sensitivity classification does not bind its expected inputs')
  }
  const derived = deriveProtectedSourceSliceSensitivity(
    classification.path,
    classification.secretFindingCount,
  )
  if (
    classification.category !== derived.category
    || canonicalJson(classification.indicatorCodes) !== canonicalJson(derived.indicatorCodes)
  ) {
    throw new TypeError('Source Slice sensitivity classification is not conservatively derived')
  }
  const { classificationDigest, ...core } = classification
  const observedDigest = structuredDigest(
    SOURCE_SLICE_SENSITIVITY_CLASSIFICATION_MEDIA_TYPE,
    core,
  )
  if (!sameDigest(classificationDigest, observedDigest)) {
    throw new TypeError('Source Slice sensitivity classification digest is invalid')
  }
  return deepFreeze({ ...core, classificationDigest })
}
