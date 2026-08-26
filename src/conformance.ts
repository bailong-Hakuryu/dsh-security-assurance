import { z } from 'zod'
import type {
  AssuranceExecutionContext,
  AssuranceProviderDescriptorV1,
  AssuranceProviderFactoryV1,
  AssuranceSubmissionArtifactDraftV1,
  AssuranceSubmissionV1,
} from 'dsh-engineering-control-plane/assurance-provider'
import {
  analyzerContributionV1Schema,
  analyzerInputV1Schema,
  parseAnalyzerDescriptorV1,
  type AnalyzerContributionV1,
  type AnalyzerDescriptorV1,
  type AnalyzerFactoryV1,
  type AnalyzerInputV1,
  type AnalyzerInvocationOptions,
} from './analyzer.ts'
import type { DigestEnvelopeV1 } from './contracts.ts'

export const ANALYZER_CONTRACT_SUITE_V1 =
  'dsh-security-assurance/analyzer-contract/v1' as const
export const ASSURANCE_PROVIDER_CONTRACT_SUITE_V1 =
  'dsh-security-assurance/assurance-provider-contract/v1' as const

export type ConformanceSuiteIdV1 =
  | typeof ANALYZER_CONTRACT_SUITE_V1
  | typeof ASSURANCE_PROVIDER_CONTRACT_SUITE_V1

export interface ConformanceCheckV1 {
  readonly schemaVersion: 1
  readonly checkId: string
  readonly status: 'PASS' | 'FAIL'
}

export interface ConformanceReportV1 {
  readonly schemaVersion: 1
  readonly suiteId: ConformanceSuiteIdV1
  readonly subjectId: string
  readonly passed: boolean
  readonly checks: readonly ConformanceCheckV1[]
}

export interface AnalyzerConformanceFixtureV1 {
  readonly schemaVersion: 1
  readonly invocation: 'ANALYZE' | 'CANCEL'
  readonly descriptor: AnalyzerDescriptorV1
  readonly input: AnalyzerInputV1
}

export interface AnalyzerConformanceFixtureOptionsV1 {
  readonly invocation?: AnalyzerConformanceFixtureV1['invocation']
}

export interface AnalyzerContractSubjectV1 {
  readonly descriptor: AnalyzerDescriptorV1
  readonly factory: AnalyzerFactoryV1
}

export type ReferenceAnalyzerScenarioV1 =
  | 'SUCCESS'
  | 'FAILURE'
  | 'MALFORMED_OUTPUT'
  | 'DELAY_UNTIL_ABORT'

export interface AssuranceProviderConformanceFixtureV1 {
  readonly schemaVersion: 1
  readonly descriptor: AssuranceProviderDescriptorV1
}

export interface AssuranceProviderCompositionObservationV1 {
  readonly schemaVersion: 1
  readonly descriptor: AssuranceProviderDescriptorV1
  readonly invocationState: 'settled' | 'external_failed'
  readonly outcomeKind: 'sealed_submission' | 'external_failure'
  readonly claimedOutcome: 'satisfied' | 'failed' | 'indeterminate' | null
}

export type AssuranceProviderCompositionAdapterV1 = (
  subject: AssuranceProviderConformanceFixtureV1,
) => Promise<AssuranceProviderCompositionObservationV1>

export type ReferenceAssuranceProviderScenarioV1 =
  | 'SATISFIED'
  | 'FAILED'
  | 'INDETERMINATE'
  | 'EXTERNAL_FAILURE'

const conformanceCheckV1Schema: z.ZodType<ConformanceCheckV1> = z.strictObject({
  schemaVersion: z.literal(1),
  checkId: z.string().min(1).max(128).regex(/^[a-z0-9.-]+$/),
  status: z.enum(['PASS', 'FAIL']),
})

export const conformanceReportV1Schema: z.ZodType<ConformanceReportV1> = z.strictObject({
  schemaVersion: z.literal(1),
  suiteId: z.enum([ANALYZER_CONTRACT_SUITE_V1, ASSURANCE_PROVIDER_CONTRACT_SUITE_V1]),
  subjectId: z.string().min(1).max(384),
  passed: z.boolean(),
  checks: z.array(conformanceCheckV1Schema).min(1).max(64),
}).superRefine((report, context) => {
  if (report.passed !== report.checks.every(check => check.status === 'PASS')) {
    context.addIssue({ code: 'custom', message: 'Conformance report status does not match its checks' })
  }
  if (new Set(report.checks.map(check => check.checkId)).size !== report.checks.length) {
    context.addIssue({ code: 'custom', message: 'Conformance report check identities must be unique' })
  }
})

const DIGEST_ZERO = '0'.repeat(64)
const DIGEST_ONE = '1'.repeat(64)

const assuranceProviderCompositionObservationV1Schema:
z.ZodType<AssuranceProviderCompositionObservationV1> = z.strictObject({
  schemaVersion: z.literal(1),
  descriptor: z.strictObject({
    schemaVersion: z.literal(1),
    providerId: z.string().min(1).max(128),
    providerVersion: z.string().min(1).max(128),
  }),
  invocationState: z.enum(['settled', 'external_failed']),
  outcomeKind: z.enum(['sealed_submission', 'external_failure']),
  claimedOutcome: z.enum(['satisfied', 'failed', 'indeterminate']).nullable(),
}).superRefine((observation, context) => {
  const sealed = observation.outcomeKind === 'sealed_submission'
  if (sealed !== (observation.invocationState === 'settled')) {
    context.addIssue({ code: 'custom', message: 'Provider outcome does not match invocation state' })
  }
  if (sealed !== (observation.claimedOutcome !== null)) {
    context.addIssue({ code: 'custom', message: 'Provider claimed outcome does not match outcome kind' })
  }
})

function digest(value: string, mediaType = 'application/octet-stream'): DigestEnvelopeV1 {
  return {
    schemaVersion: 1,
    algorithm: 'sha256',
    mediaType,
    byteLength: 0,
    canonicalization: 'raw-bytes',
    value,
  }
}

function deepFreeze<T>(value: T): T {
  if (typeof value !== 'object' || value === null || Object.isFrozen(value)) return value
  for (const child of Object.values(value)) deepFreeze(child)
  return Object.freeze(value)
}

function sameValue(left: unknown, right: unknown): boolean {
  return JSON.stringify(left) === JSON.stringify(right)
}

function check(checkId: string, passed: boolean): ConformanceCheckV1 {
  return { schemaVersion: 1, checkId, status: passed ? 'PASS' : 'FAIL' }
}

async function rejectsWithin(promise: Promise<unknown>, timeoutMs: number): Promise<boolean> {
  return await new Promise(resolve => {
    let settled = false
    const finish = (rejected: boolean) => {
      if (settled) return
      settled = true
      clearTimeout(timeout)
      resolve(rejected)
    }
    const timeout = setTimeout(() => finish(false), timeoutMs)
    void promise.then(() => finish(false), () => finish(true))
  })
}

/** Build one deterministic, authority-free Analyzer contract fixture. */
export function createAnalyzerConformanceFixtureV1(
  options: AnalyzerConformanceFixtureOptionsV1 = {},
): AnalyzerConformanceFixtureV1 {
  const descriptor = parseAnalyzerDescriptorV1({
    schemaVersion: 1,
    analyzerId: 'fixture/conformance-analyzer',
    analyzerVersion: '1.0.0',
    descriptorSchemaVersion: 1,
    buildDigest: digest(DIGEST_ZERO),
    executionClass: 'PURE',
    supportedAssessmentModes: ['REPOSITORY'],
    supportedPolicyIds: ['fixture/conformance-policy'],
    coverageObligationIds: ['fixture/conformance-obligation'],
    evidenceSchemaIds: ['fixture/conformance-evidence'],
    egress: 'NONE',
  })
  const input = deepFreeze(analyzerInputV1Schema.parse({
    schemaVersion: 1,
    assessmentId: 'asm-00000000-0000-4000-8000-000000000000',
    attemptId: 'attempt:fixture:1',
    assessmentMode: 'REPOSITORY',
    subject: {
      digest: digest(DIGEST_ONE),
      textSlices: [],
    },
    policy: {
      policyId: 'fixture/conformance-policy',
      digest: digest(DIGEST_ZERO, 'application/json'),
    },
    coverageObligationIds: ['fixture/conformance-obligation'],
  }))
  return deepFreeze({
    schemaVersion: 1,
    invocation: options.invocation ?? 'ANALYZE',
    descriptor,
    input,
  })
}

/** Build one deterministic Provider identity for a supplied public Service composition. */
export function createAssuranceProviderConformanceFixtureV1(): AssuranceProviderConformanceFixtureV1 {
  return deepFreeze({
    schemaVersion: 1,
    descriptor: {
      schemaVersion: 1,
      providerId: 'fixture/conformance-provider',
      providerVersion: '1.0.0',
    },
  })
}

function referenceAssuranceSubmissionV1(
  context: AssuranceExecutionContext,
  descriptor: AssuranceProviderDescriptorV1,
  claimedOutcome: 'satisfied' | 'failed' | 'indeterminate',
  seal: typeof import('dsh-engineering-control-plane/assurance-provider')['sealAssuranceSubmissionV1'],
): AssuranceSubmissionV1 {
  const evidence: readonly AssuranceSubmissionArtifactDraftV1[] = [{
    artifactId: 'reference-conformance-evidence-1',
    schemaId: 'fixture/reference-conformance-evidence',
    schemaVersion: 1,
    value: { schemaVersion: 1, testOnly: true, outcome: claimedOutcome },
  }]
  const draft = {
    schemaVersion: 1 as const,
    binding: {
      invocationId: context.invocationId,
      missionId: context.missionId,
      attempt: context.attempt,
      provider: descriptor,
      subject: context.subject,
      effectivePolicyDigest: context.effectivePolicyDigest,
    },
    externalAssessment: {
      state: 'sealed' as const,
      assessmentId: `reference-conformance-${claimedOutcome}-assessment-1`,
      claimedOutcome,
    },
    providerComposition: {
      artifactId: 'reference-conformance-composition-1',
      schemaId: 'dsh/assurance-provider-composition',
      schemaVersion: 1,
      value: {
        schemaVersion: 1,
        provider: descriptor,
        components: [{ componentId: 'fixture/reference-provider', componentVersion: '1.0.0' }],
      },
    },
    providerPolicy: {
      artifactId: 'reference-conformance-policy-1',
      schemaId: 'dsh/assurance-provider-policy',
      schemaVersion: 1,
      value: { schemaVersion: 1, effectivePolicyDigest: context.effectivePolicyDigest },
    },
    coverage: {
      artifactId: 'reference-conformance-coverage-1',
      schemaId: 'dsh/assurance-provider-coverage',
      schemaVersion: 1,
      value: {
        schemaVersion: 1,
        status: 'complete',
        dimensions: [{ dimensionId: 'fixture/reference-check', status: 'covered' }],
      },
    },
    provenance: {
      artifactId: 'reference-conformance-provenance-1',
      schemaId: 'dsh/assurance-provider-provenance',
      schemaVersion: 1,
      value: {
        schemaVersion: 1,
        assessor: { kind: 'machine_provider', provider: descriptor },
      },
    },
    evidence,
  }
  const provisional = seal({
    ...draft,
    sourceSeal: {
      artifactId: 'reference-conformance-source-seal-1',
      schemaId: 'dsh/assurance-provider-source-seal',
      schemaVersion: 1,
      value: {
        schemaVersion: 1,
        state: 'sealed',
        subject: context.subject,
        evidenceDigests: [],
      },
    },
  })
  return seal({
    ...draft,
    sourceSeal: {
      artifactId: 'reference-conformance-source-seal-1',
      schemaId: 'dsh/assurance-provider-source-seal',
      schemaVersion: 1,
      value: {
        schemaVersion: 1,
        state: 'sealed',
        subject: context.subject,
        evidenceDigests: provisional.payload.evidence.map(item => item.digest.value),
      },
    },
  })
}

/** Build a test-only Provider Factory that can run only with a real Kernel-issued Context. */
export async function createReferenceAssuranceProviderFactoryV1(
  scenario: ReferenceAssuranceProviderScenarioV1 = 'SATISFIED',
): Promise<AssuranceProviderFactoryV1> {
  const {
    parseExternalAssessmentFailureV1,
    sealAssuranceSubmissionV1,
  } = await import(
    'dsh-engineering-control-plane/assurance-provider'
  )
  return descriptor => Object.freeze({
    descriptor,
    async assess(context: AssuranceExecutionContext) {
      if (scenario === 'EXTERNAL_FAILURE') {
        return {
          kind: 'external_failure' as const,
          failure: parseExternalAssessmentFailureV1({
            schemaVersion: 1,
            reason: 'failed',
            code: 'reference_provider_failure',
          }),
        }
      }
      const claimedOutcome = scenario.toLowerCase() as 'satisfied' | 'failed' | 'indeterminate'
      return {
        kind: 'sealed_submission' as const,
        submission: referenceAssuranceSubmissionV1(
          context,
          descriptor,
          claimedOutcome,
          sealAssuranceSubmissionV1,
        ),
      }
    },
  })
}

/** Deterministic successful Analyzer used through exactly the public extension contract. */
export function createReferenceAnalyzerFactoryV1(
  scenario: ReferenceAnalyzerScenarioV1 = 'SUCCESS',
): AnalyzerFactoryV1 {
  return descriptor => {
    const boundDescriptor = parseAnalyzerDescriptorV1(descriptor)
    let disposed = false
    let interruptDelayed: (() => void) | undefined
    return Object.freeze({
      descriptor: boundDescriptor,
      async analyze(
        input: AnalyzerInputV1,
        options: AnalyzerInvocationOptions = {},
      ): Promise<AnalyzerContributionV1> {
        if (disposed) throw new Error('Reference Analyzer is disposed')
        const normalizedInput = analyzerInputV1Schema.parse(input)
        if (scenario === 'MALFORMED_OUTPUT') {
          return deepFreeze({ schemaVersion: 1 }) as unknown as AnalyzerContributionV1
        }
        if (scenario === 'FAILURE') {
          throw new Error('Reference Analyzer deterministic failure')
        }
        if (scenario === 'DELAY_UNTIL_ABORT') {
          return await new Promise<AnalyzerContributionV1>((_resolve, reject) => {
            let interrupted = false
            const interrupt = () => {
              if (interrupted) return
              interrupted = true
              options.signal?.removeEventListener('abort', interrupt)
              interruptDelayed = undefined
              reject(new Error('Reference Analyzer invocation interrupted'))
            }
            interruptDelayed = interrupt
            if (options.signal?.aborted === true) interrupt()
            else options.signal?.addEventListener('abort', interrupt, { once: true })
          })
        }
        const artifactId = 'reference-conformance-evidence'
        return deepFreeze({
          schemaVersion: 1,
          analyzerIdentity: {
            analyzerId: boundDescriptor.analyzerId,
            analyzerVersion: boundDescriptor.analyzerVersion,
            descriptorSchemaVersion: boundDescriptor.descriptorSchemaVersion,
            buildDigest: boundDescriptor.buildDigest,
          },
          subjectDigest: normalizedInput.subject.digest,
          completionDisposition: 'COMPLETE',
          coverageClaims: normalizedInput.coverageObligationIds.map(obligationId => ({
            obligationId,
            completion: 'COMPLETE' as const,
            evidenceArtifactId: artifactId,
          })),
          candidateFindings: [],
          evidence: [{
            artifactId,
            schemaId: 'fixture/conformance-evidence',
            mediaType: 'application/json',
            value: { result: 'reference-pass' },
          }],
          diagnostics: [],
          resourceUse: { filesRead: 0, bytesRead: 0 },
        })
      },
      async dispose(): Promise<void> {
        interruptDelayed?.()
        disposed = true
      },
    })
  }
}

/** Run the versioned Analyzer contract without registration or Host capabilities. */
export async function runAnalyzerContractSuiteV1(
  subject: AnalyzerContractSubjectV1,
  fixture = createAnalyzerConformanceFixtureV1(),
): Promise<ConformanceReportV1> {
  const checks: ConformanceCheckV1[] = []
  let descriptor: AnalyzerDescriptorV1 | undefined
  try {
    descriptor = parseAnalyzerDescriptorV1(subject.descriptor)
    checks.push(check('descriptor.valid', true))
  } catch {
    checks.push(check('descriptor.valid', false))
  }

  let instance: ReturnType<AnalyzerFactoryV1> | undefined
  let contribution: AnalyzerContributionV1 | undefined
  try {
    if (descriptor !== undefined) instance = subject.factory(descriptor)
    checks.push(check(
      'instance.descriptor-bound',
      descriptor !== undefined && instance !== undefined && sameValue(instance.descriptor, descriptor),
    ))
    if (fixture.invocation === 'CANCEL') {
      if (instance === undefined) {
        checks.push(check('analysis.cancellation-observed', false))
      } else {
        const controller = new AbortController()
        const pending = instance.analyze(fixture.input, { signal: controller.signal })
        controller.abort()
        checks.push(check('analysis.cancellation-observed', await rejectsWithin(pending, 1_000)))
      }
    } else {
      if (instance !== undefined) contribution = await instance.analyze(fixture.input)
      const parsed = analyzerContributionV1Schema.safeParse(contribution)
      checks.push(check('analysis.result-valid', parsed.success))
      if (parsed.success && descriptor !== undefined) {
        contribution = parsed.data
        checks.push(check('analysis.identity-bound', sameValue(contribution.analyzerIdentity, {
          analyzerId: descriptor.analyzerId,
          analyzerVersion: descriptor.analyzerVersion,
          descriptorSchemaVersion: descriptor.descriptorSchemaVersion,
          buildDigest: descriptor.buildDigest,
        })))
        checks.push(check('analysis.subject-bound', sameValue(
          contribution.subjectDigest,
          fixture.input.subject.digest,
        )))
        const obligations = new Set(fixture.input.coverageObligationIds)
        checks.push(check('analysis.coverage-bound', contribution.coverageClaims.every(claim => (
          obligations.has(claim.obligationId)
        ))))
      } else {
        checks.push(check('analysis.identity-bound', false))
        checks.push(check('analysis.subject-bound', false))
        checks.push(check('analysis.coverage-bound', false))
      }
    }
  } catch {
    if (!checks.some(item => item.checkId === 'instance.descriptor-bound')) {
      checks.push(check('instance.descriptor-bound', false))
    }
    if (
      fixture.invocation === 'CANCEL'
      && !checks.some(item => item.checkId === 'analysis.cancellation-observed')
    ) {
      checks.push(check('analysis.cancellation-observed', false))
    } else if (!checks.some(item => item.checkId === 'analysis.result-valid')) {
      checks.push(check('analysis.result-valid', false))
      checks.push(check('analysis.identity-bound', false))
      checks.push(check('analysis.subject-bound', false))
      checks.push(check('analysis.coverage-bound', false))
    }
  }

  let disposed = false
  if (instance !== undefined) {
    try {
      await instance.dispose()
      disposed = true
    } catch {}
  }
  checks.push(check('lifecycle.disposed', disposed))

  const report = {
    schemaVersion: 1 as const,
    suiteId: ANALYZER_CONTRACT_SUITE_V1,
    subjectId: descriptor === undefined
      ? 'invalid-analyzer'
      : `${descriptor.analyzerId}@${descriptor.analyzerVersion}`,
    passed: checks.every(item => item.status === 'PASS'),
    checks,
  }
  return deepFreeze(conformanceReportV1Schema.parse(report))
}

/**
 * Run the Provider contract through a caller-supplied public Service composition.
 * The adapter receives no Store, authority constructor, or Kernel callback.
 */
export async function runAssuranceProviderContractSuiteV1(
  subject: AssuranceProviderConformanceFixtureV1,
  adapter: AssuranceProviderCompositionAdapterV1,
): Promise<ConformanceReportV1> {
  const checks: ConformanceCheckV1[] = []
  let descriptor: AssuranceProviderDescriptorV1 | undefined
  try {
    const { parseAssuranceProviderDescriptorV1 } = await import(
      'dsh-engineering-control-plane/assurance-provider'
    )
    descriptor = parseAssuranceProviderDescriptorV1(subject.descriptor)
    checks.push(check('descriptor.valid', true))
  } catch {
    checks.push(check('descriptor.valid', false))
  }

  let observation: AssuranceProviderCompositionObservationV1 | undefined
  if (descriptor !== undefined) {
    try {
      const candidate = await adapter(deepFreeze({
        schemaVersion: 1,
        descriptor,
      }))
      const parsed = assuranceProviderCompositionObservationV1Schema.safeParse(candidate)
      if (parsed.success) observation = parsed.data
    } catch {}
  }

  checks.push(check(
    'composition.descriptor-bound',
    descriptor !== undefined && observation !== undefined && sameValue(observation.descriptor, descriptor),
  ))
  checks.push(check(
    'composition.invocation-settled',
    observation?.invocationState === 'settled' || observation?.invocationState === 'external_failed',
  ))
  checks.push(check(
    'composition.outcome-accepted',
    observation?.outcomeKind === 'sealed_submission' || observation?.outcomeKind === 'external_failure',
  ))

  const report = {
    schemaVersion: 1 as const,
    suiteId: ASSURANCE_PROVIDER_CONTRACT_SUITE_V1,
    subjectId: descriptor === undefined
      ? 'invalid-assurance-provider'
      : `${descriptor.providerId}@${descriptor.providerVersion}`,
    passed: checks.every(item => item.status === 'PASS'),
    checks,
  }
  return deepFreeze(conformanceReportV1Schema.parse(report))
}

/** Throw a stable assertion error when any canonical contract check failed. */
export function assertConformanceReportV1(candidate: unknown): asserts candidate is ConformanceReportV1 {
  const parsed = conformanceReportV1Schema.safeParse(candidate)
  if (!parsed.success) throw new TypeError('Conformance report is invalid')
  if (!parsed.data.passed) {
    const failures = parsed.data.checks.filter(item => item.status === 'FAIL').map(item => item.checkId)
    throw new Error(`Conformance failed: ${failures.join(', ')}`)
  }
}
