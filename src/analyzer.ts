import { z } from 'zod'
import {
  assessmentIdSchema,
  assessmentModeSchema,
  digestEnvelopeV1Schema,
  securitySubmissionJsonV1Schema,
} from './contracts.ts'
import type {
  AssessmentId,
  AssessmentMode,
  DigestEnvelopeV1,
  SecuritySubmissionJsonV1,
} from './contracts.ts'

const namespacedIdSchema = z.string()
  .min(3)
  .max(128)
  .regex(/^[a-z0-9][a-z0-9._-]*(?:\/[a-z0-9][a-z0-9._-]*){1,7}$/)
const semanticVersionSchema = z.string()
  .max(128)
  .regex(/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/)
const artifactIdSchema = z.string().regex(/^[a-z0-9][a-z0-9-]{0,127}$/)
const bindingIdSchema = z.string().regex(/^[a-z0-9][a-z0-9._/-]{0,127}$/i)
const mediaTypeSchema = z.string()
  .max(128)
  .regex(/^application\/[a-z0-9.+-]+$|^text\/[a-z0-9.+-]+$/)
const subjectRelativePathSchema = z.string().min(1).max(1024).refine(path => (
  !path.startsWith('/')
  && !path.startsWith('\\')
  && !/^[a-z]:/iu.test(path)
  && !path.includes('\\')
  && path.split('/').every(segment => segment.length > 0 && segment !== '.' && segment !== '..')
), 'Analyzer source slices must use canonical Subject-relative paths')

function unique(values: readonly string[]): boolean {
  return new Set(values).size === values.length
}

function deepFreeze<T>(value: T): T {
  if (typeof value !== 'object' || value === null || Object.isFrozen(value)) return value
  for (const child of Object.values(value)) deepFreeze(child)
  return Object.freeze(value)
}

/** Pure-data declaration admitted during local Host composition. */
export interface AnalyzerDescriptorV1 {
  readonly schemaVersion: 1
  readonly analyzerId: string
  readonly analyzerVersion: string
  readonly descriptorSchemaVersion: 1
  readonly buildDigest: DigestEnvelopeV1
  readonly executionClass: 'PURE'
  readonly supportedAssessmentModes: readonly AssessmentMode[]
  readonly supportedPolicyIds: readonly string[]
  readonly coverageObligationIds: readonly string[]
  readonly evidenceSchemaIds: readonly string[]
  readonly egress: 'NONE'
}

export const analyzerDescriptorV1Schema: z.ZodType<AnalyzerDescriptorV1> = z.strictObject({
  schemaVersion: z.literal(1),
  analyzerId: namespacedIdSchema,
  analyzerVersion: semanticVersionSchema,
  descriptorSchemaVersion: z.literal(1),
  buildDigest: digestEnvelopeV1Schema,
  executionClass: z.literal('PURE'),
  supportedAssessmentModes: z.array(assessmentModeSchema).min(1).max(3),
  supportedPolicyIds: z.array(namespacedIdSchema).min(1).max(32),
  coverageObligationIds: z.array(bindingIdSchema).min(1).max(128),
  evidenceSchemaIds: z.array(namespacedIdSchema).min(1).max(128),
  egress: z.literal('NONE'),
}).superRefine((descriptor, context) => {
  for (const values of [
    descriptor.supportedAssessmentModes,
    descriptor.supportedPolicyIds,
    descriptor.coverageObligationIds,
    descriptor.evidenceSchemaIds,
  ]) {
    if (!unique(values)) context.addIssue({ code: 'custom', message: 'Analyzer Descriptor arrays must be unique' })
  }
})

export interface AnalyzerIdentityV1 {
  readonly analyzerId: string
  readonly analyzerVersion: string
  readonly descriptorSchemaVersion: 1
  readonly buildDigest: DigestEnvelopeV1
}

export const analyzerIdentityV1Schema: z.ZodType<AnalyzerIdentityV1> = z.strictObject({
  analyzerId: namespacedIdSchema,
  analyzerVersion: semanticVersionSchema,
  descriptorSchemaVersion: z.literal(1),
  buildDigest: digestEnvelopeV1Schema,
})

export interface AnalyzerSubjectTextSliceV1 {
  readonly path: string
  readonly mediaType: string
  readonly digest: DigestEnvelopeV1
  readonly text: string
}

const analyzerSubjectTextSliceV1Schema: z.ZodType<AnalyzerSubjectTextSliceV1> = z.strictObject({
  path: subjectRelativePathSchema,
  mediaType: mediaTypeSchema,
  digest: digestEnvelopeV1Schema,
  text: z.string().max(1024 * 1024),
})

/** Immutable, path-free and authority-free input for one Analyzer Attempt. */
export interface AnalyzerInputV1 {
  readonly schemaVersion: 1
  readonly assessmentId: AssessmentId
  readonly attemptId: string
  readonly assessmentMode: AssessmentMode
  readonly subject: {
    readonly digest: DigestEnvelopeV1
    readonly textSlices: readonly AnalyzerSubjectTextSliceV1[]
  }
  readonly policy: {
    readonly policyId: string
    readonly digest: DigestEnvelopeV1
  }
  readonly coverageObligationIds: readonly string[]
}

export const analyzerInputV1Schema: z.ZodType<AnalyzerInputV1> = z.strictObject({
  schemaVersion: z.literal(1),
  assessmentId: assessmentIdSchema,
  attemptId: z.string().min(1).max(384).regex(/^[a-zA-Z0-9._:/-]+$/),
  assessmentMode: assessmentModeSchema,
  subject: z.strictObject({
    digest: digestEnvelopeV1Schema,
    textSlices: z.array(analyzerSubjectTextSliceV1Schema).max(256),
  }),
  policy: z.strictObject({
    policyId: namespacedIdSchema,
    digest: digestEnvelopeV1Schema,
  }),
  coverageObligationIds: z.array(bindingIdSchema).min(1).max(128),
}).superRefine((input, context) => {
  if (!unique(input.coverageObligationIds)) {
    context.addIssue({ code: 'custom', message: 'Analyzer Input obligations must be unique' })
  }
  const totalBytes = input.subject.textSlices.reduce(
    (sum, slice) => sum + new TextEncoder().encode(slice.text).byteLength,
    0,
  )
  if (totalBytes > 4 * 1024 * 1024) {
    context.addIssue({ code: 'custom', message: 'Analyzer Input exceeds the v1 source byte budget' })
  }
})

export interface AnalyzerEvidenceDraftV1 {
  readonly artifactId: string
  readonly schemaId: string
  readonly mediaType: string
  readonly value: SecuritySubmissionJsonV1
}

const analyzerEvidenceDraftV1Schema: z.ZodType<AnalyzerEvidenceDraftV1> = z.strictObject({
  artifactId: artifactIdSchema,
  schemaId: namespacedIdSchema,
  mediaType: mediaTypeSchema,
  value: securitySubmissionJsonV1Schema,
})

export interface AnalyzerContributionV1 {
  readonly schemaVersion: 1
  readonly analyzerIdentity: AnalyzerIdentityV1
  readonly subjectDigest: DigestEnvelopeV1
  readonly completionDisposition: 'COMPLETE' | 'UNSUPPORTED' | 'INCOMPLETE'
  readonly coverageClaims: readonly {
    readonly obligationId: string
    readonly completion: 'COMPLETE'
    readonly evidenceArtifactId: string
  }[]
  readonly candidateFindings: readonly SecuritySubmissionJsonV1[]
  readonly evidence: readonly AnalyzerEvidenceDraftV1[]
  readonly diagnostics: readonly string[]
  readonly resourceUse: {
    readonly filesRead: number
    readonly bytesRead: number
  }
}

export const analyzerContributionV1Schema: z.ZodType<AnalyzerContributionV1> = z.strictObject({
  schemaVersion: z.literal(1),
  analyzerIdentity: analyzerIdentityV1Schema,
  subjectDigest: digestEnvelopeV1Schema,
  completionDisposition: z.enum(['COMPLETE', 'UNSUPPORTED', 'INCOMPLETE']),
  coverageClaims: z.array(z.strictObject({
    obligationId: bindingIdSchema,
    completion: z.literal('COMPLETE'),
    evidenceArtifactId: artifactIdSchema,
  })).max(128),
  candidateFindings: z.array(securitySubmissionJsonV1Schema).max(768),
  evidence: z.array(analyzerEvidenceDraftV1Schema).max(128),
  diagnostics: z.array(z.string().min(1).max(128).regex(/^[A-Z0-9_:-]+$/)).max(256),
  resourceUse: z.strictObject({
    filesRead: z.number().int().nonnegative().max(256),
    bytesRead: z.number().int().nonnegative().max(4 * 1024 * 1024),
  }),
}).superRefine((contribution, context) => {
  const artifactIds = contribution.evidence.map(evidence => evidence.artifactId)
  if (!unique(artifactIds)) {
    context.addIssue({ code: 'custom', message: 'Analyzer Evidence artifact identities must be unique' })
  }
  const artifacts = new Set(artifactIds)
  if (contribution.coverageClaims.some(claim => !artifacts.has(claim.evidenceArtifactId))) {
    context.addIssue({ code: 'custom', message: 'Analyzer Coverage Claims must reference contributed Evidence' })
  }
})

export interface AnalyzerInvocationOptions {
  readonly signal?: AbortSignal
}

export interface AnalyzerInstanceV1 {
  readonly descriptor: AnalyzerDescriptorV1
  analyze(input: AnalyzerInputV1, options?: AnalyzerInvocationOptions): Promise<AnalyzerContributionV1>
  dispose(): Promise<void>
}

export type AnalyzerFactoryV1 = (descriptor: AnalyzerDescriptorV1) => AnalyzerInstanceV1
export type AnalyzerRegistrationDisposer = () => void

/** Validate, detach and recursively freeze one pure-data Descriptor. */
export function parseAnalyzerDescriptorV1(candidate: unknown): AnalyzerDescriptorV1 {
  return deepFreeze(analyzerDescriptorV1Schema.parse(candidate))
}
