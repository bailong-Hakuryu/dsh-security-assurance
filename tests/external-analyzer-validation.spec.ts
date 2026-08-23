import { execFile } from 'node:child_process'
import { mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { promisify } from 'node:util'
import { Context } from '@deepseek-ai/cordis'
import { afterEach, describe, expect, it } from 'vitest'
import SecurityAssuranceService, {
  analyzerContributionV1Schema,
  securitySubmissionJsonV1Schema,
} from '../src/index.ts'
import type {
  AnalyzerDescriptorV1,
  AnalyzerQualificationRecordV1,
  AssessmentId,
  SecurityInvocation,
} from '../src/index.ts'
import { referenceHostInvocation } from './support/reference-host.ts'

const run = promisify(execFile)
const temporaryRoots: string[] = []

afterEach(async () => {
  await Promise.all(temporaryRoots.splice(0).map(path => rm(path, { recursive: true, force: true })))
})

async function validationRepositoryFixture(
  referenceControl: 'VIOLATED' | 'SATISFIED',
): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), 'dsh-security-external-validation-'))
  temporaryRoots.push(root)
  await run('git', ['init', '-b', 'main'], { cwd: root })
  await run('git', ['config', 'user.email', 'fixture@example.invalid'], { cwd: root })
  await run('git', ['config', 'user.name', 'Fixture'], { cwd: root })
  await writeFile(join(root, 'package.json'), `${JSON.stringify({
    name: 'external-validation-fixture',
    version: '1.0.0',
    dshSecurity: { referenceControl },
  }, null, 2)}\n`, 'utf8')
  await run('git', ['add', '.'], { cwd: root })
  await run('git', ['commit', '-m', 'external validation fixture'], { cwd: root })
  return root
}

interface ReferenceValidationScenario<Observation = undefined> {
  readonly id: string
  readonly referenceControl: 'VIOLATED' | 'SATISFIED'
  readonly observedValue: 'VIOLATED' | 'SATISFIED'
  readonly candidateHex: string
  readonly additionalCandidateHexes?: readonly string[]
  readonly additionalObservedValues?: readonly ('VIOLATED' | 'SATISFIED')[]
  readonly inspect?: (
    service: SecurityAssuranceService,
    invocation: SecurityInvocation,
    assessmentId: AssessmentId,
  ) => Promise<Observation>
}

async function waitUntilSealed(
  service: SecurityAssuranceService,
  invocation: SecurityInvocation,
  assessmentId: AssessmentId,
): Promise<void> {
  let revision = 1
  for (let attempt = 0; attempt < 5; attempt += 1) {
    const changed = await service.waitForAssessmentRevision(invocation, {
      schemaVersion: 1,
      assessmentId,
      afterRevision: revision,
      timeoutMs: 5_000,
    })
    if (!changed.ok) throw new Error(`wait failed: ${changed.error.code}`)
    const assessment = await service.getAssessment(invocation, { schemaVersion: 1, assessmentId })
    if (!assessment.ok) throw new Error(`query failed: ${assessment.error.code}`)
    if (assessment.value.state === 'SEALED') return
    if (assessment.value.state === 'BLOCKED') throw new Error('Assessment unexpectedly blocked')
    revision = assessment.value.assessmentRevision
  }
  throw new Error('Assessment did not reach SEALED')
}

async function runReferenceValidationScenario<Observation = undefined>(
  scenario: ReferenceValidationScenario<Observation>,
) {
  const repository = await validationRepositoryFixture(scenario.referenceControl)
  const dshHome = await mkdtemp(join(tmpdir(), 'dsh-security-external-validation-home-'))
  temporaryRoots.push(dshHome)
  const ctx = new Context()
  const fiber = await ctx.plugin(SecurityAssuranceService, { dshHome })
  const descriptor: AnalyzerDescriptorV1 = {
    schemaVersion: 1,
    analyzerId: 'fixture/reference-validator',
    analyzerVersion: '1.0.0',
    descriptorSchemaVersion: 1,
    buildDigest: {
      schemaVersion: 1,
      algorithm: 'sha256',
      mediaType: 'application/vnd.fixture.reference-validator+json',
      byteLength: 1,
      canonicalization: 'dsh-canonical-json-v1',
      value: 'a'.repeat(64),
    },
    executionClass: 'PURE',
    supportedAssessmentModes: ['REPOSITORY'],
    supportedPolicyIds: ['security/reference-validation'],
    coverageObligationIds: ['application-security-analysis'],
    evidenceSchemaIds: ['fixture/reference-validation-evidence'],
    egress: 'NONE',
  }
  const qualification: AnalyzerQualificationRecordV1 = {
    schemaVersion: 1,
    qualificationId: 'fixture/qualification/reference-validator/v1',
    analyzerIdentity: {
      analyzerId: descriptor.analyzerId,
      analyzerVersion: descriptor.analyzerVersion,
      descriptorSchemaVersion: descriptor.descriptorSchemaVersion,
      buildDigest: descriptor.buildDigest,
    },
    issuerId: 'fixture/qualification-authority',
    level: 'HOST_ATTESTED',
    supportedEcosystemIds: ['fixture/reference'],
    supportedAssessmentModes: ['REPOSITORY'],
    supportedPolicyIds: ['security/reference-validation'],
    coverageObligationIds: ['application-security-analysis'],
    evidenceSchemaIds: ['fixture/reference-validation-evidence'],
    executionClass: 'PURE',
    executionBackendId: 'dsh/security-assurance/in-process-pure-v1',
    providerIds: ['dsh-security-assurance'],
    egress: 'NONE',
    platforms: ['win32', 'linux', 'darwin'],
    issuedAt: '2026-01-01T00:00:00.000Z',
    expiresAt: '2099-01-01T00:00:00.000Z',
    evidenceDigests: [{
      schemaVersion: 1,
      algorithm: 'sha256',
      mediaType: 'application/vnd.fixture.validation-qualification-evidence+json',
      byteLength: 1,
      canonicalization: 'dsh-canonical-json-v1',
      value: 'b'.repeat(64),
    }],
    limitations: ['Conformance reference validation only.'],
    qualificationDigest: {
      schemaVersion: 1,
      algorithm: 'sha256',
      mediaType: 'application/vnd.dsh.security.analyzer-qualification+json',
      byteLength: 1375,
      canonicalization: 'dsh-canonical-json-v1',
      value: 'b3a8db649fdeb8269abb8e8624b8df66ae68c7be05c09bda029df0d0e6a57357',
    },
  }
  const candidateIds = [scenario.candidateHex, ...(scenario.additionalCandidateHexes ?? [])]
    .map(value => `candidate-${value.repeat(64)}`)
  const additionalObservedValues = scenario.additionalObservedValues
    ?? (scenario.additionalCandidateHexes ?? []).map(() => scenario.observedValue)
  const observedValues = [scenario.observedValue, ...additionalObservedValues]
  if (observedValues.length !== candidateIds.length) {
    throw new Error('Reference validation scenario Evidence count does not match its Candidates')
  }
  const candidateId = candidateIds[0]
  if (candidateId === undefined) throw new Error('Reference validation scenario has no Candidate')
  const disposeAnalyzer = ctx.securityAssurance.registerAnalyzer(
    descriptor,
    normalizedDescriptor => ({
      descriptor: normalizedDescriptor,
      async analyze(input) {
        const manifest = input.subject.textSlices.find(slice => slice.path === 'package.json')
        if (manifest === undefined) throw new Error('Reference validation manifest is missing')
        const sourceAnchor = {
          path: manifest.path,
          fileDigest: manifest.digest,
          locator: { kind: 'JSON_POINTER' as const, value: '/dshSecurity/referenceControl' },
        }
        return {
          schemaVersion: 1,
          analyzerIdentity: {
            analyzerId: normalizedDescriptor.analyzerId,
            analyzerVersion: normalizedDescriptor.analyzerVersion,
            descriptorSchemaVersion: normalizedDescriptor.descriptorSchemaVersion,
            buildDigest: normalizedDescriptor.buildDigest,
          },
          subjectDigest: input.subject.digest,
          completionDisposition: 'COMPLETE',
          coverageClaims: [{
            obligationId: 'application-security-analysis',
            completion: 'COMPLETE',
            evidenceArtifactId: 'reference-validation-evidence',
          }],
          candidateFindings: candidateIds.map((candidateId, index) => ({
            schemaVersion: 1,
            candidateId,
            weaknessClassification: {
              schemaVersion: 1,
              primary: 'dsh/conformance/reference-control-violation',
              secondary: [],
            },
            affectedControlId: 'dsh/conformance/reference-control',
            securityClaim: 'The conformance reference security control is explicitly violated.',
            sourceAnchor,
            evidenceArtifactIds: [index === 0
              ? 'reference-validation-evidence'
              : `reference-validation-evidence-${index + 1}`],
          })),
          evidence: candidateIds.map((candidateId, index) => ({
            artifactId: index === 0
              ? 'reference-validation-evidence'
              : `reference-validation-evidence-${index + 1}`,
            schemaId: 'fixture/reference-validation-evidence',
            mediaType: 'application/json',
            value: securitySubmissionJsonV1Schema.parse({
              schemaVersion: 1,
              candidateId,
              subjectDigest: input.subject.digest,
              sourceAnchor,
              observedValue: observedValues[index],
            }),
          })),
          diagnostics: [],
          resourceUse: { filesRead: 1, bytesRead: manifest.text.length },
        }
      },
      async dispose() {},
    }),
  )
  const disposeQualification = ctx.securityAssurance.registerAnalyzerQualification(qualification)

  try {
    const invocation = referenceHostInvocation(ctx.securityAssurance)
    const platform = process.platform
    if (platform !== 'win32' && platform !== 'linux' && platform !== 'darwin') {
      throw new Error(`unsupported test platform: ${platform}`)
    }
    const registered = await ctx.securityAssurance.registerRepository(invocation, {
      schemaVersion: 1,
      idempotencyKey: `external-validation-register-${scenario.id}`,
      root: repository,
      displayName: 'External validation fixture',
      bindings: {
        policyId: 'security/reference-validation',
        assessmentProfileId: 'security/standard',
        evidenceProtectionId: 'evidence/local-protected',
        dataEgressPolicyId: 'egress/deny-by-default',
        platform,
        deliveryDestinationIds: [],
      },
    })
    if (!registered.ok) throw new Error(`registration failed: ${registered.error.code}`)
    const started = await ctx.securityAssurance.startAssessment(invocation, {
      schemaVersion: 1,
      idempotencyKey: `external-validation-assessment-${scenario.id}`,
      repositoryId: registered.value.repositoryId,
      subject: { kind: 'workspace_snapshot' },
      assessmentMode: 'REPOSITORY',
      assessmentProfileId: 'security/standard',
      target: { kind: 'repository' },
      requestedStrongerControlIds: [],
    })
    if (!started.ok) throw new Error(`start failed: ${started.error.code}`)
    await waitUntilSealed(ctx.securityAssurance, invocation, started.value.assessmentId)
    const assessment = await ctx.securityAssurance.getAssessment(invocation, {
      schemaVersion: 1,
      assessmentId: started.value.assessmentId,
    })
    if (!assessment.ok) throw new Error(`query failed: ${assessment.error.code}`)
    const submission = await ctx.securityAssurance.getAssuranceSubmission(invocation, {
      schemaVersion: 1,
      assessmentId: started.value.assessmentId,
    })
    if (!submission.ok) throw new Error(`submission failed: ${submission.error.code}`)
    const observation = scenario.inspect === undefined
      ? undefined
      : await scenario.inspect(ctx.securityAssurance, invocation, started.value.assessmentId)
    return { assessment: assessment.value, candidateId, observation, submission: submission.value }
  } finally {
    disposeQualification()
    disposeAnalyzer()
    await fiber.dispose()
  }
}

describe('external Analyzer Candidate validation', () => {
  it('rejects a Candidate that is not bound to contributed Evidence', () => {
    const digest = {
      schemaVersion: 1 as const,
      algorithm: 'sha256' as const,
      mediaType: 'application/json',
      byteLength: 1,
      canonicalization: 'dsh-canonical-json-v1' as const,
      value: 'd'.repeat(64),
    }
    expect(analyzerContributionV1Schema.safeParse({
      schemaVersion: 1,
      analyzerIdentity: {
        analyzerId: 'fixture/reference-validator',
        analyzerVersion: '1.0.0',
        descriptorSchemaVersion: 1,
        buildDigest: digest,
      },
      subjectDigest: digest,
      completionDisposition: 'INCOMPLETE',
      coverageClaims: [],
      candidateFindings: [{
        schemaVersion: 1,
        candidateId: `candidate-${'e'.repeat(64)}`,
        weaknessClassification: {
          schemaVersion: 1,
          primary: 'dsh/conformance/reference-control-violation',
          secondary: [],
        },
        affectedControlId: 'dsh/conformance/reference-control',
        securityClaim: 'The conformance reference security control is explicitly violated.',
        sourceAnchor: {
          path: 'package.json',
          fileDigest: digest,
          locator: { kind: 'JSON_POINTER', value: '/dshSecurity/referenceControl' },
        },
        evidenceArtifactIds: ['missing-validation-evidence'],
      }],
      evidence: [],
      diagnostics: [],
      resourceUse: { filesRead: 1, bytesRead: 1 },
    }).success).toBe(false)
  })

  it('validates a qualified deterministic Candidate into a blocking Finding and FAILED Verdict', async () => {
    const { assessment, candidateId, submission } = await runReferenceValidationScenario({
      id: 'validated-candidate',
      referenceControl: 'VIOLATED',
      observedValue: 'VIOLATED',
      candidateHex: 'c',
    })

    expect(assessment).toMatchObject({
      state: 'SEALED',
      verdict: 'FAILED',
      coverage: { status: 'COMPLETE' },
    })
    expect(submission).toMatchObject({
      payload: {
        assessment: { verdict: 'FAILED' },
        findings: {
          value: {
            findings: [{
              candidateId,
              weaknessClassification: {
                primary: 'dsh/conformance/reference-control-violation',
              },
              validation: {
                state: 'VALIDATED',
                contractId: 'dsh/conformance/reference-control-validation-v1',
              },
              technicalSeverity: {
                value: 'HIGH',
                methodVersion: 'dsh/conformance/reference-control-severity-v1',
              },
              evidenceConfidence: {
                value: 'HIGH',
                methodVersion: 'dsh/conformance/deterministic-evidence-confidence-v1',
              },
              policySignificance: 'BLOCKING',
            }],
          },
        },
        evidence: expect.arrayContaining([
          expect.objectContaining({ schemaId: 'dsh/security-candidate-admission' }),
          expect.objectContaining({ schemaId: 'dsh/security-validation-outcome' }),
          expect.objectContaining({ schemaId: 'dsh/security-validation-evidence-eligibility-decision' }),
        ]),
      },
    })
  })

  it('lists a redacted VALIDATED Finding Summary from a sealed Assessment', async () => {
    const { assessment, candidateId, observation } = await runReferenceValidationScenario({
      id: 'list-validated-finding',
      referenceControl: 'VIOLATED',
      observedValue: 'VIOLATED',
      candidateHex: 'a',
      inspect: (service, invocation, assessmentId) => service.listFindings(invocation, {
        schemaVersion: 1,
        assessmentId,
        limit: 10,
      }),
    })

    expect(observation).toMatchObject({
      ok: true,
      value: {
        schemaVersion: 1,
        assessmentId: assessment.assessmentId,
        assessmentRevision: assessment.assessmentRevision,
        findings: [{
          schemaVersion: 1,
          assessmentId: assessment.assessmentId,
          assessmentRevision: assessment.assessmentRevision,
          recordKind: 'FINDING',
          recordId: expect.stringMatching(/^finding-[0-9a-f]{64}$/),
          candidateId,
          recordRevision: 1,
          validationState: 'VALIDATED',
          validationContractId: 'dsh/conformance/reference-control-validation-v1',
          weaknessClassification: {
            primary: 'dsh/conformance/reference-control-violation',
            secondary: [],
          },
          technicalSeverity: 'HIGH',
          evidenceConfidence: 'HIGH',
          policySignificance: 'BLOCKING',
          hasProtectedDetail: true,
        }],
        nextCursor: null,
      },
    })
    expect(observation).not.toHaveProperty('value.findings.0.sourceAnchor')
    expect(observation).not.toHaveProperty('value.findings.0.securityClaim')
    expect(observation).not.toHaveProperty('value.findings.0.evidence')
  })

  it('paginates Finding Summaries with a stable opaque cursor', async () => {
    const firstCandidateId = `candidate-${'1'.repeat(64)}`
    const secondCandidateId = `candidate-${'2'.repeat(64)}`
    const { observation } = await runReferenceValidationScenario({
      id: 'paginate-validated-findings',
      referenceControl: 'VIOLATED',
      observedValue: 'VIOLATED',
      candidateHex: '1',
      additionalCandidateHexes: ['2'],
      inspect: async (service, invocation, assessmentId) => {
        const first = await service.listFindings(invocation, {
          schemaVersion: 1,
          assessmentId,
          limit: 1,
        })
        if (!first.ok || first.value.nextCursor === null) return { first, second: null }
        const second = await service.listFindings(invocation, {
          schemaVersion: 1,
          assessmentId,
          limit: 1,
          cursor: first.value.nextCursor,
        })
        return { first, second }
      },
    })

    expect(observation).toMatchObject({
      first: {
        ok: true,
        value: {
          findings: [{ candidateId: firstCandidateId }],
          nextCursor: expect.stringMatching(/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/),
        },
      },
      second: {
        ok: true,
        value: {
          findings: [{ candidateId: secondCandidateId }],
          nextCursor: null,
        },
      },
    })
  })

  it('filters Finding Summaries by Validation state before pagination', async () => {
    const unresolvedCandidateId = `candidate-${'6'.repeat(64)}`
    const { observation } = await runReferenceValidationScenario({
      id: 'filter-finding-validation-state',
      referenceControl: 'VIOLATED',
      observedValue: 'VIOLATED',
      candidateHex: '5',
      additionalCandidateHexes: ['6'],
      additionalObservedValues: ['SATISFIED'],
      inspect: (service, invocation, assessmentId) => service.listFindings(invocation, {
        schemaVersion: 1,
        assessmentId,
        limit: 10,
        validationStates: ['UNRESOLVED'],
      }),
    })

    expect(observation).toMatchObject({
      ok: true,
      value: {
        findings: [{
          candidateId: unresolvedCandidateId,
          recordKind: 'UNRESOLVED_CANDIDATE',
          validationState: 'UNRESOLVED',
        }],
        nextCursor: null,
      },
    })
  })

  it('rejects a Finding cursor when its Validation filter changes', async () => {
    const { observation } = await runReferenceValidationScenario({
      id: 'filter-bound-finding-cursor',
      referenceControl: 'VIOLATED',
      observedValue: 'VIOLATED',
      candidateHex: '7',
      additionalCandidateHexes: ['8', '9'],
      additionalObservedValues: ['SATISFIED', 'SATISFIED'],
      inspect: async (service, invocation, assessmentId) => {
        const first = await service.listFindings(invocation, {
          schemaVersion: 1,
          assessmentId,
          limit: 1,
          validationStates: ['VALIDATED', 'UNRESOLVED'],
        })
        if (!first.ok || first.value.nextCursor === null) return { first, replay: null }
        const replay = await service.listFindings(invocation, {
          schemaVersion: 1,
          assessmentId,
          limit: 1,
          cursor: first.value.nextCursor,
          validationStates: ['VALIDATED'],
        })
        return { first, replay }
      },
    })

    expect(observation).toMatchObject({
      first: { ok: true, value: { nextCursor: expect.any(String) } },
      replay: {
        ok: false,
        error: {
          code: 'INVALID_REQUEST',
          retryable: false,
        },
      },
    })
  })

  it('rejects a Finding cursor replayed by another Security Principal', async () => {
    const { observation } = await runReferenceValidationScenario({
      id: 'principal-bound-finding-cursor',
      referenceControl: 'VIOLATED',
      observedValue: 'VIOLATED',
      candidateHex: '3',
      additionalCandidateHexes: ['4'],
      inspect: async (service, invocation, assessmentId) => {
        const first = await service.listFindings(invocation, {
          schemaVersion: 1,
          assessmentId,
          limit: 1,
        })
        if (!first.ok || first.value.nextCursor === null) return { first, replay: null }
        const otherPrincipal = referenceHostInvocation(service, 'other-reference-host-operator')
        const replay = await service.listFindings(otherPrincipal, {
          schemaVersion: 1,
          assessmentId,
          limit: 1,
          cursor: first.value.nextCursor,
        })
        return { first, replay }
      },
    })

    expect(observation).toMatchObject({
      first: { ok: true, value: { nextCursor: expect.any(String) } },
      replay: {
        ok: false,
        error: {
          code: 'INVALID_REQUEST',
          retryable: false,
        },
      },
    })
  })

  it('rejects a Candidate only when eligible Counter-Evidence proves the rejection condition', async () => {
    const { assessment, candidateId, submission } = await runReferenceValidationScenario({
      id: 'counter-evidence',
      referenceControl: 'SATISFIED',
      observedValue: 'SATISFIED',
      candidateHex: 'e',
    })

    expect(assessment).toMatchObject({
      state: 'SEALED',
      verdict: 'SATISFIED',
      coverage: { status: 'COMPLETE' },
    })
    expect(submission).toMatchObject({
      payload: {
        assessment: { verdict: 'SATISFIED' },
        findings: { value: { findings: [] } },
        evidence: expect.arrayContaining([
          expect.objectContaining({
            schemaId: 'dsh/security-validation-evidence-eligibility-decision',
            value: expect.objectContaining({
              candidateId,
              decision: 'ELIGIBLE',
              purpose: 'COUNTER_EVIDENCE',
            }),
          }),
          expect.objectContaining({
            schemaId: 'dsh/security-validation-outcome',
            value: expect.objectContaining({
              candidateId,
              state: 'REJECTED',
              contractId: 'dsh/conformance/reference-control-validation-v1',
              rejectionCondition: 'EXACT_REFERENCE_CONTROL_SATISFIED',
              counterEvidenceArtifactIds: ['reference-validation-evidence'],
              proofGaps: [],
            }),
          }),
        ]),
      },
    })
  })

  it('lists a REJECTED Candidate without presenting it as a Security Finding', async () => {
    const { assessment, candidateId, observation } = await runReferenceValidationScenario({
      id: 'list-rejected-candidate',
      referenceControl: 'SATISFIED',
      observedValue: 'SATISFIED',
      candidateHex: 'b',
      inspect: (service, invocation, assessmentId) => service.listFindings(invocation, {
        schemaVersion: 1,
        assessmentId,
        limit: 10,
      }),
    })

    expect(observation).toMatchObject({
      ok: true,
      value: {
        schemaVersion: 1,
        assessmentId: assessment.assessmentId,
        assessmentRevision: assessment.assessmentRevision,
        findings: [{
          schemaVersion: 1,
          assessmentId: assessment.assessmentId,
          assessmentRevision: assessment.assessmentRevision,
          recordKind: 'REJECTED_CANDIDATE',
          recordId: candidateId,
          candidateId,
          recordRevision: 1,
          validationState: 'REJECTED',
          validationContractId: 'dsh/conformance/reference-control-validation-v1',
          weaknessClassification: {
            primary: 'dsh/conformance/reference-control-violation',
            secondary: [],
          },
          technicalSeverity: null,
          evidenceConfidence: null,
          policySignificance: null,
          hasProtectedDetail: true,
        }],
        nextCursor: null,
      },
    })
  })

  it('keeps a Candidate unresolved when proposed Counter-Evidence contradicts the Subject', async () => {
    const { assessment, candidateId, submission } = await runReferenceValidationScenario({
      id: 'contradictory-counter-evidence',
      referenceControl: 'VIOLATED',
      observedValue: 'SATISFIED',
      candidateHex: 'f',
    })

    expect(assessment).toMatchObject({
      state: 'SEALED',
      verdict: 'INDETERMINATE',
      coverage: { status: 'GAP' },
    })
    expect(submission).toMatchObject({
      payload: {
        assessment: { verdict: 'INDETERMINATE' },
        findings: { value: { findings: [] } },
        evidence: expect.arrayContaining([
          expect.objectContaining({
            schemaId: 'dsh/security-validation-evidence-eligibility-decision',
            value: expect.objectContaining({
              candidateId,
              decision: 'INELIGIBLE',
              purpose: 'COUNTER_EVIDENCE',
              reason: 'VALIDATION_EVIDENCE_CONTRADICTS_SUBJECT',
            }),
          }),
          expect.objectContaining({
            schemaId: 'dsh/security-validation-outcome',
            value: expect.objectContaining({
              candidateId,
              state: 'UNRESOLVED',
              contractId: 'dsh/conformance/reference-control-validation-v1',
              proofGaps: ['VALIDATION_EVIDENCE_CONTRADICTS_SUBJECT'],
            }),
          }),
        ]),
      },
    })
  })

  it('lists an UNRESOLVED Candidate without assigning severity or Policy Significance', async () => {
    const { assessment, candidateId, observation } = await runReferenceValidationScenario({
      id: 'list-unresolved-candidate',
      referenceControl: 'VIOLATED',
      observedValue: 'SATISFIED',
      candidateHex: 'd',
      inspect: (service, invocation, assessmentId) => service.listFindings(invocation, {
        schemaVersion: 1,
        assessmentId,
        limit: 10,
      }),
    })

    expect(observation).toMatchObject({
      ok: true,
      value: {
        schemaVersion: 1,
        assessmentId: assessment.assessmentId,
        assessmentRevision: assessment.assessmentRevision,
        findings: [{
          schemaVersion: 1,
          assessmentId: assessment.assessmentId,
          assessmentRevision: assessment.assessmentRevision,
          recordKind: 'UNRESOLVED_CANDIDATE',
          recordId: candidateId,
          candidateId,
          recordRevision: 1,
          validationState: 'UNRESOLVED',
          validationContractId: 'dsh/conformance/reference-control-validation-v1',
          weaknessClassification: {
            primary: 'dsh/conformance/reference-control-violation',
            secondary: [],
          },
          technicalSeverity: null,
          evidenceConfidence: null,
          policySignificance: null,
          hasProtectedDetail: true,
        }],
        nextCursor: null,
      },
    })
  })
})
