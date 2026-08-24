import { execFile } from 'node:child_process'
import { mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { promisify } from 'node:util'
import { Context } from '@deepseek-ai/cordis'
import { afterEach, describe, expect, it, vi } from 'vitest'
import SecurityAssuranceService, {
  analyzerContributionV1Schema,
  evidenceViewV1Schema,
  riskDecisionRecordV1Schema,
  securityAssuranceSubmissionV1Schema,
  securitySubmissionJsonV1Schema,
} from '../src/index.ts'
import type {
  AnalyzerDescriptorV1,
  AnalyzerQualificationRecordV1,
  AssessmentId,
  SecurityInvocation,
} from '../src/index.ts'
import {
  referenceHostInvocation,
  referenceHostInvocationWithPermissions,
} from './support/reference-host.ts'

const run = promisify(execFile)
const temporaryRoots: string[] = []

afterEach(async () => {
  await Promise.all(temporaryRoots.splice(0).map(path => rm(path, { recursive: true, force: true })))
})

async function validationRepositoryFixture(
  referenceControl: 'VIOLATED' | 'SATISFIED',
  referenceImpact: 'HIGH' | 'CRITICAL' = 'HIGH',
): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), 'dsh-security-external-validation-'))
  temporaryRoots.push(root)
  await run('git', ['init', '-b', 'main'], { cwd: root })
  await run('git', ['config', 'user.email', 'fixture@example.invalid'], { cwd: root })
  await run('git', ['config', 'user.name', 'Fixture'], { cwd: root })
  await writeFile(join(root, 'package.json'), `${JSON.stringify({
    name: 'external-validation-fixture',
    version: '1.0.0',
    dshSecurity: { referenceControl, referenceImpact },
  }, null, 2)}\n`, 'utf8')
  await run('git', ['add', '.'], { cwd: root })
  await run('git', ['commit', '-m', 'external validation fixture'], { cwd: root })
  return root
}

interface ReferenceValidationScenario<Observation = undefined> {
  readonly id: string
  readonly referenceControl: 'VIOLATED' | 'SATISFIED'
  readonly observedValue: 'VIOLATED' | 'SATISFIED'
  readonly technicalSeverity?: 'HIGH' | 'CRITICAL'
  readonly candidateHex: string
  readonly additionalCandidateHexes?: readonly string[]
  readonly additionalObservedValues?: readonly ('VIOLATED' | 'SATISFIED')[]
  readonly evidencePaddingBytes?: number
  readonly evidenceProtectionId?: string
  readonly requestedStrongerControlIds?: readonly string[]
  readonly beforeInspectState?: 'SEALED' | 'BLOCKED'
  readonly skipSubmissionAfterInspect?: boolean
  readonly restartBeforeInspect?: boolean
  readonly beforeRestart?: (
    service: SecurityAssuranceService,
    invocation: SecurityInvocation,
    assessmentId: AssessmentId,
  ) => Promise<unknown>
  readonly inspect?: (
    service: SecurityAssuranceService,
    invocation: SecurityInvocation,
    assessmentId: AssessmentId,
  ) => Promise<Observation>
}

async function waitUntilAssessmentState(
  service: SecurityAssuranceService,
  invocation: SecurityInvocation,
  assessmentId: AssessmentId,
  expectedState: 'SEALED' | 'BLOCKED',
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
    if (assessment.value.state === expectedState) return
    if (assessment.value.state === 'SEALED' || assessment.value.state === 'BLOCKED') {
      throw new Error(`Assessment reached ${assessment.value.state} instead of ${expectedState}`)
    }
    revision = assessment.value.assessmentRevision
  }
  throw new Error(`Assessment did not reach ${expectedState}`)
}

async function runReferenceValidationScenario<Observation = undefined>(
  scenario: ReferenceValidationScenario<Observation>,
) {
  const repository = await validationRepositoryFixture(
    scenario.referenceControl,
    scenario.technicalSeverity,
  )
  const dshHome = await mkdtemp(join(tmpdir(), 'dsh-security-external-validation-home-'))
  temporaryRoots.push(dshHome)
  const ctx = new Context()
  let activeFiber = await ctx.plugin(SecurityAssuranceService, { dshHome })
  let activeService = ctx.securityAssurance
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
              observedImpact: scenario.technicalSeverity ?? 'HIGH',
              ...(scenario.evidencePaddingBytes === undefined
                ? {}
                : { padding: 'x'.repeat(scenario.evidencePaddingBytes) }),
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
  let registrationsDisposed = false

  const disposeRegistrations = () => {
    if (registrationsDisposed) return
    registrationsDisposed = true
    disposeQualification()
    disposeAnalyzer()
  }

  try {
    let invocation = referenceHostInvocation(activeService)
    const platform = process.platform
    if (platform !== 'win32' && platform !== 'linux' && platform !== 'darwin') {
      throw new Error(`unsupported test platform: ${platform}`)
    }
    const registered = await activeService.registerRepository(invocation, {
      schemaVersion: 1,
      idempotencyKey: `external-validation-register-${scenario.id}`,
      root: repository,
      displayName: 'External validation fixture',
      bindings: {
        policyId: 'security/reference-validation',
        assessmentProfileId: 'security/standard',
        evidenceProtectionId: scenario.evidenceProtectionId ?? 'evidence/local-protected',
        dataEgressPolicyId: 'egress/deny-by-default',
        platform,
        deliveryDestinationIds: [],
      },
    })
    if (!registered.ok) throw new Error(`registration failed: ${registered.error.code}`)
    const started = await activeService.startAssessment(invocation, {
      schemaVersion: 1,
      idempotencyKey: `external-validation-assessment-${scenario.id}`,
      repositoryId: registered.value.repositoryId,
      subject: { kind: 'workspace_snapshot' },
      assessmentMode: 'REPOSITORY',
      assessmentProfileId: 'security/standard',
      target: { kind: 'repository' },
      requestedStrongerControlIds: scenario.requestedStrongerControlIds ?? [],
    })
    if (!started.ok) throw new Error(`start failed: ${started.error.code}`)
    await waitUntilAssessmentState(
      activeService,
      invocation,
      started.value.assessmentId,
      scenario.beforeInspectState ?? 'SEALED',
    )
    const beforeRestartObservation = scenario.beforeRestart === undefined
      ? undefined
      : await scenario.beforeRestart(activeService, invocation, started.value.assessmentId)
    if (scenario.restartBeforeInspect === true) {
      disposeRegistrations()
      await activeFiber.dispose()
      const restartedContext = new Context()
      activeFiber = await restartedContext.plugin(SecurityAssuranceService, { dshHome })
      activeService = restartedContext.securityAssurance
      invocation = referenceHostInvocation(activeService)
    }
    const observation = scenario.inspect === undefined
      ? undefined
      : await scenario.inspect(activeService, invocation, started.value.assessmentId)
    const assessment = await activeService.getAssessment(invocation, {
      schemaVersion: 1,
      assessmentId: started.value.assessmentId,
    })
    if (!assessment.ok) throw new Error(`query failed: ${assessment.error.code}`)
    if (scenario.skipSubmissionAfterInspect === true) {
      return {
        assessment: assessment.value,
        candidateId,
        beforeRestartObservation,
        observation,
        submission: undefined,
      }
    }
    const submission = await activeService.getAssuranceSubmission(invocation, {
      schemaVersion: 1,
      assessmentId: started.value.assessmentId,
    })
    if (!submission.ok) throw new Error(`submission failed: ${submission.error.code}`)
    return {
      assessment: assessment.value,
      candidateId,
      beforeRestartObservation,
      observation,
      submission: submission.value,
    }
  } finally {
    disposeRegistrations()
    await activeFiber.dispose()
  }
}

describe('external Analyzer Candidate validation', () => {
  it('parses legacy single-authority Risk Decision v1 records without rewriting canonical fields', () => {
    const legacyRecord = {
      schemaVersion: 1 as const,
      decisionId: 'risk-decision-00000000-0000-4000-8000-000000000001',
      assessmentId: 'asm-00000000-0000-4000-8000-000000000001' as const,
      finding: {
        recordId: `finding-${'d'.repeat(64)}`,
        recordRevision: 1,
      },
      decision: 'ACCEPT' as const,
      resolution: 'ACCEPTED' as const,
      rationale: 'A legacy ordinary acceptance remains readable without canonical field injection.',
      compensatingControls: ['Keep the deployment behind the authenticated internal gateway.'],
      expiresAt: '2026-08-25T00:00:00.000Z',
      decisionMaker: {
        kind: 'host-operator' as const,
        principalId: 'legacy-risk-operator',
      },
      recordedAt: '2026-08-24T00:00:00.000Z',
    }

    const parsed = riskDecisionRecordV1Schema.parse(legacyRecord)

    expect(parsed).toEqual(legacyRecord)
    expect('authorizationMode' in parsed).toBe(false)
    expect('attestations' in parsed).toBe(false)
  })

  it('keeps Submission v1 readable when a pre-Risk-Decision sealed record has no decision artifact', async () => {
    const { submission } = await runReferenceValidationScenario({
      id: 'legacy-submission-without-risk-decisions',
      referenceControl: 'SATISFIED',
      observedValue: 'SATISFIED',
      candidateHex: 'e',
    })
    if (submission === undefined) throw new Error('legacy Submission fixture did not seal')
    const legacySubmission = structuredClone(submission)
    Reflect.deleteProperty(legacySubmission.payload, 'riskDecisions')

    expect(securityAssuranceSubmissionV1Schema.safeParse(legacySubmission).success).toBe(true)
  })

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

  it('opens an explicit pre-Seal Risk Decision Window only when its stronger control is frozen', async () => {
    const { assessment, candidateId, observation, submission } = await runReferenceValidationScenario({
      id: 'risk-decision-window',
      referenceControl: 'VIOLATED',
      observedValue: 'VIOLATED',
      candidateHex: '0',
      requestedStrongerControlIds: ['security/risk-decision-window-v1'],
      beforeInspectState: 'BLOCKED',
      skipSubmissionAfterInspect: true,
      inspect: (service, invocation, assessmentId) => service.listFindings(invocation, {
        schemaVersion: 1,
        assessmentId,
        limit: 10,
      }),
    })

    expect(assessment).toMatchObject({
      assessmentRevision: 3,
      state: 'BLOCKED',
      coverage: { status: 'COMPLETE' },
      verdict: null,
      seal: null,
    })
    expect(observation).toMatchObject({
      ok: true,
      value: {
        assessmentRevision: 3,
        findings: [{
          recordKind: 'FINDING',
          candidateId,
          recordRevision: 1,
          validationState: 'VALIDATED',
          technicalSeverity: 'HIGH',
          policySignificance: 'BLOCKING',
        }],
      },
    })
    expect(submission).toBeUndefined()
  })

  it('opens a Critical Dual Authority window only when break-glass is explicitly frozen', async () => {
    const { assessment, observation } = await runReferenceValidationScenario({
      id: 'critical-break-glass-window',
      referenceControl: 'VIOLATED',
      observedValue: 'VIOLATED',
      technicalSeverity: 'CRITICAL',
      candidateHex: '4',
      requestedStrongerControlIds: [
        'security/risk-decision-window-v1',
        'security/critical-break-glass-v1',
      ],
      beforeInspectState: 'BLOCKED',
      skipSubmissionAfterInspect: true,
      inspect: (service, invocation, assessmentId) => service.listFindings(invocation, {
        schemaVersion: 1,
        assessmentId,
        limit: 10,
      }),
    })

    expect(assessment).toMatchObject({
      assessmentRevision: 3,
      state: 'BLOCKED',
      verdict: null,
      seal: null,
    })
    expect(observation).toMatchObject({
      ok: true,
      value: {
        assessmentRevision: 3,
        findings: [{
          technicalSeverity: 'CRITICAL',
          policySignificance: 'BLOCKING',
        }],
      },
    })
  })

  it('does not admit Critical acceptance under the ordinary Risk Decision control', async () => {
    const { assessment, observation } = await runReferenceValidationScenario({
      id: 'critical-without-break-glass-policy',
      referenceControl: 'VIOLATED',
      observedValue: 'VIOLATED',
      technicalSeverity: 'CRITICAL',
      candidateHex: '8',
      requestedStrongerControlIds: ['security/risk-decision-window-v1'],
      beforeInspectState: 'BLOCKED',
      skipSubmissionAfterInspect: true,
      inspect: async (service, invocation, assessmentId) => {
        const listed = await service.listFindings(invocation, {
          schemaVersion: 1,
          assessmentId,
          limit: 10,
        })
        if (!listed.ok || listed.value.findings[0] === undefined) return { listed }
        const finding = listed.value.findings[0]
        return service.recordRiskDecision(invocation, {
          schemaVersion: 1,
          idempotencyKey: 'critical-without-break-glass-policy-v1',
          assessmentId,
          expectedAssessmentRevision: listed.value.assessmentRevision,
          finding: {
            recordId: finding.recordId,
            recordRevision: finding.recordRevision,
          },
          decision: 'ACCEPT',
          rationale: 'Critical risk cannot be accepted when only the ordinary decision window was frozen.',
          compensatingControls: [
            'Keep the affected deployment isolated from every public ingress.',
            'Require continuous operator monitoring until the emergency window closes.',
          ],
          expiresAt: new Date(Date.now() + 12 * 60 * 60 * 1_000).toISOString(),
        })
      },
    })

    expect(observation).toMatchObject({ ok: false, error: { code: 'CONFLICT' } })
    expect(assessment).toMatchObject({ assessmentRevision: 3, state: 'BLOCKED', seal: null })
  })

  it('allows ordinary Decision Authority to deny Critical risk without break-glass authority', async () => {
    const { assessment, observation } = await runReferenceValidationScenario({
      id: 'critical-denial-without-break-glass',
      referenceControl: 'VIOLATED',
      observedValue: 'VIOLATED',
      technicalSeverity: 'CRITICAL',
      candidateHex: 'b',
      requestedStrongerControlIds: ['security/risk-decision-window-v1'],
      beforeInspectState: 'BLOCKED',
      skipSubmissionAfterInspect: true,
      inspect: async (service, invocation, assessmentId) => {
        const listed = await service.listFindings(invocation, {
          schemaVersion: 1,
          assessmentId,
          limit: 10,
        })
        if (!listed.ok || listed.value.findings[0] === undefined) return { listed }
        const finding = listed.value.findings[0]
        const ordinaryDecisionInvocation = referenceHostInvocationWithPermissions(
          service,
          ['assessment:read', 'risk:decide'],
          'critical-risk-denier',
        )
        const receipt = await service.recordRiskDecision(ordinaryDecisionInvocation, {
          schemaVersion: 1,
          idempotencyKey: 'critical-risk-denial-v1',
          assessmentId,
          expectedAssessmentRevision: listed.value.assessmentRevision,
          finding: { recordId: finding.recordId, recordRevision: finding.recordRevision },
          decision: 'DENY',
          rationale: 'Critical risk is denied and must remain blocking until the affected Subject is remediated.',
          compensatingControls: [],
          expiresAt: null,
        })
        if (!receipt.ok) return { listed, receipt }
        await waitUntilAssessmentState(service, invocation, assessmentId, 'SEALED')
        return {
          listed,
          receipt,
          sealed: await service.getAssessment(invocation, { schemaVersion: 1, assessmentId }),
        }
      },
    })

    expect(observation).toMatchObject({
      receipt: {
        ok: true,
        value: { assessmentRevision: 4, decision: 'DENY', resolution: 'DENIED' },
      },
      sealed: {
        ok: true,
        value: { assessmentRevision: 5, state: 'SEALED', verdict: 'FAILED' },
      },
    })
    expect(assessment).toMatchObject({
      assessmentRevision: 5,
      state: 'SEALED',
      verdict: 'FAILED',
    })
  })

  it('records the first Critical break-glass approval as pending without sealing', async () => {
    const rationale = 'Critical exposure is temporarily accepted only for the isolated emergency recovery window.'
    const controls = [
      'Keep the affected deployment isolated from every public ingress.',
      'Require continuous operator monitoring until the emergency window closes.',
    ]
    const expiresAt = new Date(Date.now() + 12 * 60 * 60 * 1_000).toISOString()
    const { assessment, observation } = await runReferenceValidationScenario({
      id: 'critical-first-attestation',
      referenceControl: 'VIOLATED',
      observedValue: 'VIOLATED',
      technicalSeverity: 'CRITICAL',
      candidateHex: '5',
      requestedStrongerControlIds: [
        'security/risk-decision-window-v1',
        'security/critical-break-glass-v1',
      ],
      beforeInspectState: 'BLOCKED',
      skipSubmissionAfterInspect: true,
      inspect: async (service, invocation, assessmentId) => {
        const listed = await service.listFindings(invocation, {
          schemaVersion: 1,
          assessmentId,
          limit: 10,
        })
        if (!listed.ok || listed.value.findings[0] === undefined) return { listed }
        const finding = listed.value.findings[0]
        const receipt = await service.recordRiskDecision(invocation, {
          schemaVersion: 1,
          idempotencyKey: 'critical-first-attestation-v1',
          assessmentId,
          expectedAssessmentRevision: listed.value.assessmentRevision,
          finding: {
            recordId: finding.recordId,
            recordRevision: finding.recordRevision,
          },
          decision: 'ACCEPT',
          rationale,
          compensatingControls: controls,
          expiresAt,
        })
        const after = await service.getAssessment(invocation, { schemaVersion: 1, assessmentId })
        const afterList = await service.listFindings(invocation, {
          schemaVersion: 1,
          assessmentId,
          limit: 10,
        })
        if (!afterList.ok || afterList.value.findings[0] === undefined) {
          return { listed, receipt, after, afterList }
        }
        const current = afterList.value.findings[0]
        return {
          listed,
          receipt,
          after,
          afterList,
          detail: await service.getFinding(invocation, {
            schemaVersion: 1,
            assessmentId,
            assessmentRevision: afterList.value.assessmentRevision,
            recordId: current.recordId,
            recordRevision: current.recordRevision,
          }),
          submission: await service.getAssuranceSubmission(invocation, {
            schemaVersion: 1,
            assessmentId,
          }),
        }
      },
    })

    expect(observation).toMatchObject({
      receipt: {
        ok: true,
        value: {
          assessmentRevision: 4,
          decision: 'ACCEPT',
          resolution: 'PENDING_DUAL_AUTHORITY',
        },
      },
      after: {
        ok: true,
        value: {
          assessmentRevision: 4,
          state: 'BLOCKED',
          verdict: null,
          seal: null,
        },
      },
      detail: {
        ok: true,
        value: {
          technicalSeverity: { value: 'CRITICAL' },
          policySignificance: 'BLOCKING',
          riskDecision: {
            state: 'PENDING_DUAL_AUTHORITY',
            authorizationMode: 'CRITICAL_DUAL_AUTHORITY',
            rationale,
            compensatingControls: controls,
            expiresAt,
            attestations: [{
              sequence: 1,
              decisionMaker: {
                kind: 'host-operator',
                principalId: 'reference-host-operator',
              },
              authorizationEvidence: {
                permission: 'risk:break-glass',
                invocationClass: 'independently-authenticated',
              },
            }],
          },
        },
      },
      submission: { ok: false, error: { code: 'CONFLICT' } },
    })
    expect(assessment).toMatchObject({
      assessmentRevision: 4,
      state: 'BLOCKED',
      verdict: null,
      seal: null,
    })
  })

  it('accepts Critical risk only after a distinct independently authenticated matching approval', async () => {
    const rationale = 'Critical exposure is temporarily accepted only for the isolated emergency recovery window.'
    const controls = [
      'Keep the affected deployment isolated from every public ingress.',
      'Require continuous operator monitoring until the emergency window closes.',
    ]
    const expiresAt = new Date(Date.now() + 12 * 60 * 60 * 1_000).toISOString()
    const { observation } = await runReferenceValidationScenario({
      id: 'critical-second-attestation',
      referenceControl: 'VIOLATED',
      observedValue: 'VIOLATED',
      technicalSeverity: 'CRITICAL',
      candidateHex: '6',
      requestedStrongerControlIds: [
        'security/risk-decision-window-v1',
        'security/critical-break-glass-v1',
      ],
      beforeInspectState: 'BLOCKED',
      skipSubmissionAfterInspect: true,
      inspect: async (service, firstInvocation, assessmentId) => {
        const initial = await service.listFindings(firstInvocation, {
          schemaVersion: 1,
          assessmentId,
          limit: 10,
        })
        if (!initial.ok || initial.value.findings[0] === undefined) return { initial }
        const finding = initial.value.findings[0]
        const decisionCore = {
          schemaVersion: 1,
          assessmentId,
          finding: {
            recordId: finding.recordId,
            recordRevision: finding.recordRevision,
          },
          decision: 'ACCEPT',
          rationale,
          compensatingControls: controls,
          expiresAt,
        } as const
        const firstRequest = {
          ...decisionCore,
          idempotencyKey: 'critical-dual-first-v1',
          expectedAssessmentRevision: initial.value.assessmentRevision,
        } as const
        const first = await service.recordRiskDecision(firstInvocation, firstRequest)
        if (!first.ok) return { initial, first }
        const pending = await service.listFindings(firstInvocation, {
          schemaVersion: 1,
          assessmentId,
          limit: 10,
        })
        if (!pending.ok) return { initial, first, pending }
        const secondInvocation = referenceHostInvocation(service, 'critical-second-operator')
        const secondRequest = {
          ...decisionCore,
          idempotencyKey: 'critical-dual-second-v1',
          expectedAssessmentRevision: pending.value.assessmentRevision,
        } as const
        const second = await service.recordRiskDecision(secondInvocation, secondRequest)
        if (!second.ok) return { initial, first, pending, second }
        await waitUntilAssessmentState(service, secondInvocation, assessmentId, 'SEALED')
        const firstReplay = await service.recordRiskDecision(firstInvocation, firstRequest)
        const secondReplay = await service.recordRiskDecision(secondInvocation, secondRequest)
        const sealedList = await service.listFindings(secondInvocation, {
          schemaVersion: 1,
          assessmentId,
          limit: 10,
        })
        if (!sealedList.ok || sealedList.value.findings[0] === undefined) {
          return { initial, first, firstReplay, pending, second, secondReplay, sealedList }
        }
        const sealedFinding = sealedList.value.findings[0]
        return {
          initial,
          first,
          firstReplay,
          pending,
          second,
          secondReplay,
          assessment: await service.getAssessment(secondInvocation, {
            schemaVersion: 1,
            assessmentId,
          }),
          detail: await service.getFinding(secondInvocation, {
            schemaVersion: 1,
            assessmentId,
            assessmentRevision: sealedList.value.assessmentRevision,
            recordId: sealedFinding.recordId,
            recordRevision: sealedFinding.recordRevision,
          }),
          submission: await service.getAssuranceSubmission(secondInvocation, {
            schemaVersion: 1,
            assessmentId,
          }),
        }
      },
    })

    expect(observation).toMatchObject({
      first: {
        ok: true,
        value: { assessmentRevision: 4, resolution: 'PENDING_DUAL_AUTHORITY' },
      },
      second: {
        ok: true,
        value: { assessmentRevision: 5, resolution: 'ACCEPTED' },
      },
      firstReplay: { ok: true },
      secondReplay: { ok: true },
      assessment: {
        ok: true,
        value: { assessmentRevision: 6, state: 'SEALED', verdict: 'SATISFIED' },
      },
      detail: {
        ok: true,
        value: {
          technicalSeverity: { value: 'CRITICAL' },
          policySignificance: 'NON_BLOCKING',
          riskDecision: {
            state: 'ACCEPTED',
            authorizationMode: 'CRITICAL_DUAL_AUTHORITY',
            rationale,
            compensatingControls: controls,
            expiresAt,
            decisionMaker: {
              kind: 'host-operator',
              principalId: 'reference-host-operator',
            },
            attestations: [{
              sequence: 1,
              decisionMaker: { principalId: 'reference-host-operator' },
            }, {
              sequence: 2,
              decisionMaker: { principalId: 'critical-second-operator' },
            }],
          },
        },
      },
      submission: {
        ok: true,
        value: {
          payload: {
            assessment: { assessmentRevision: 6, verdict: 'SATISFIED' },
            riskDecisions: {
              value: {
                decisions: [{
                  authorizationMode: 'CRITICAL_DUAL_AUTHORITY',
                  resolution: 'ACCEPTED',
                  attestations: [{
                    sequence: 1,
                    decisionMaker: { principalId: 'reference-host-operator' },
                  }, {
                    sequence: 2,
                    decisionMaker: { principalId: 'critical-second-operator' },
                  }],
                }],
              },
            },
          },
        },
      },
    })
    if (
      observation !== undefined
      && typeof observation === 'object'
      && 'first' in observation
      && 'firstReplay' in observation
      && 'second' in observation
      && 'secondReplay' in observation
    ) {
      expect(observation.firstReplay).toEqual(observation.first)
      expect(observation.secondReplay).toEqual(observation.second)
    }
  })

  it('does not confuse repeated sessions, mismatched forms, or weak controls with Dual Authority', async () => {
    const rationale = 'Critical exposure is temporarily accepted only for the isolated emergency recovery window.'
    const controls = [
      'Keep the affected deployment isolated from every public ingress.',
      'Require continuous operator monitoring until the emergency window closes.',
    ]
    const expiresAt = new Date(Date.now() + 12 * 60 * 60 * 1_000).toISOString()
    const { assessment, observation } = await runReferenceValidationScenario({
      id: 'critical-dual-authority-boundaries',
      referenceControl: 'VIOLATED',
      observedValue: 'VIOLATED',
      technicalSeverity: 'CRITICAL',
      candidateHex: '7',
      requestedStrongerControlIds: [
        'security/risk-decision-window-v1',
        'security/critical-break-glass-v1',
      ],
      beforeInspectState: 'BLOCKED',
      skipSubmissionAfterInspect: true,
      inspect: async (service, firstInvocation, assessmentId) => {
        const initial = await service.listFindings(firstInvocation, {
          schemaVersion: 1,
          assessmentId,
          limit: 10,
        })
        if (!initial.ok || initial.value.findings[0] === undefined) return { initial }
        const finding = initial.value.findings[0]
        const decisionCore = {
          schemaVersion: 1,
          assessmentId,
          expectedAssessmentRevision: initial.value.assessmentRevision,
          finding: {
            recordId: finding.recordId,
            recordRevision: finding.recordRevision,
          },
          decision: 'ACCEPT',
          rationale,
          compensatingControls: controls,
          expiresAt,
        } as const
        const weakControls = await service.recordRiskDecision(firstInvocation, {
          ...decisionCore,
          idempotencyKey: 'critical-weak-controls-v1',
          compensatingControls: ['Keep the affected deployment isolated from every public ingress.'],
        })
        const excessiveExpiry = await service.recordRiskDecision(firstInvocation, {
          ...decisionCore,
          idempotencyKey: 'critical-excessive-expiry-v1',
          expiresAt: new Date(Date.now() + 25 * 60 * 60 * 1_000).toISOString(),
        })
        const firstRequest = {
          ...decisionCore,
          idempotencyKey: 'critical-boundary-first-v1',
        }
        const first = await service.recordRiskDecision(firstInvocation, firstRequest)
        if (!first.ok) return { initial, weakControls, excessiveExpiry, first }
        const firstReplay = await service.recordRiskDecision(firstInvocation, firstRequest)
        const pending = await service.listFindings(firstInvocation, {
          schemaVersion: 1,
          assessmentId,
          limit: 10,
        })
        if (!pending.ok) {
          return { initial, weakControls, excessiveExpiry, first, firstReplay, pending }
        }
        const secondCore = {
          ...decisionCore,
          expectedAssessmentRevision: pending.value.assessmentRevision,
        }
        const samePrincipalNewInvocation = referenceHostInvocation(
          service,
          'reference-host-operator',
        )
        const repeatedPrincipal = await service.recordRiskDecision(samePrincipalNewInvocation, {
          ...secondCore,
          idempotencyKey: 'critical-repeated-principal-v1',
        })
        const distinctInvocation = referenceHostInvocation(service, 'critical-distinct-operator')
        const mismatch = await service.recordRiskDecision(distinctInvocation, {
          ...secondCore,
          idempotencyKey: 'critical-mismatched-form-v1',
          rationale: 'A different rationale cannot complete the pending Critical acceptance decision.',
        })
        const unqualifiedInvocation = referenceHostInvocationWithPermissions(
          service,
          ['assessment:read', 'risk:decide'],
          'critical-unqualified-operator',
        )
        const unqualified = await service.recordRiskDecision(unqualifiedInvocation, {
          ...secondCore,
          idempotencyKey: 'critical-unqualified-second-v1',
        })
        return {
          initial,
          weakControls,
          excessiveExpiry,
          first,
          firstReplay,
          repeatedPrincipal,
          mismatch,
          unqualified,
          after: await service.getAssessment(firstInvocation, { schemaVersion: 1, assessmentId }),
        }
      },
    })

    expect(observation).toMatchObject({
      weakControls: { ok: false, error: { code: 'CONFLICT' } },
      excessiveExpiry: { ok: false, error: { code: 'CONFLICT' } },
      first: {
        ok: true,
        value: { assessmentRevision: 4, resolution: 'PENDING_DUAL_AUTHORITY' },
      },
      firstReplay: { ok: true },
      repeatedPrincipal: { ok: false, error: { code: 'CONFLICT' } },
      mismatch: { ok: false, error: { code: 'CONFLICT' } },
      unqualified: { ok: false, error: { code: 'UNAUTHORIZED' } },
      after: {
        ok: true,
        value: { assessmentRevision: 4, state: 'BLOCKED', verdict: null, seal: null },
      },
    })
    if (
      observation !== undefined
      && typeof observation === 'object'
      && 'first' in observation
      && 'firstReplay' in observation
    ) expect(observation.firstReplay).toEqual(observation.first)
    expect(assessment).toMatchObject({
      assessmentRevision: 4,
      state: 'BLOCKED',
      verdict: null,
      seal: null,
    })
  })

  it('leaves an expired first Critical attestation pending and auditable', async () => {
    const expiresAt = new Date(Date.now() + 60 * 60 * 1_000).toISOString()
    const { assessment, observation } = await runReferenceValidationScenario({
      id: 'critical-expired-first-attestation',
      referenceControl: 'VIOLATED',
      observedValue: 'VIOLATED',
      technicalSeverity: 'CRITICAL',
      candidateHex: '9',
      requestedStrongerControlIds: [
        'security/risk-decision-window-v1',
        'security/critical-break-glass-v1',
      ],
      beforeInspectState: 'BLOCKED',
      skipSubmissionAfterInspect: true,
      inspect: async (service, firstInvocation, assessmentId) => {
        const listed = await service.listFindings(firstInvocation, {
          schemaVersion: 1,
          assessmentId,
          limit: 10,
        })
        if (!listed.ok || listed.value.findings[0] === undefined) return { listed }
        const finding = listed.value.findings[0]
        const decisionCore = {
          schemaVersion: 1,
          assessmentId,
          finding: { recordId: finding.recordId, recordRevision: finding.recordRevision },
          decision: 'ACCEPT',
          rationale: 'Critical exposure is temporarily accepted only for the isolated emergency recovery window.',
          compensatingControls: [
            'Keep the affected deployment isolated from every public ingress.',
            'Require continuous operator monitoring until the emergency window closes.',
          ],
          expiresAt,
        } as const
        const first = await service.recordRiskDecision(firstInvocation, {
          ...decisionCore,
          idempotencyKey: 'critical-expired-first-v1',
          expectedAssessmentRevision: listed.value.assessmentRevision,
        })
        if (!first.ok) return { listed, first }
        const secondInvocation = referenceHostInvocation(service, 'critical-late-second-operator')
        vi.useFakeTimers()
        try {
          vi.setSystemTime(new Date(Date.parse(expiresAt) + 1_000))
          const second = await service.recordRiskDecision(secondInvocation, {
            ...decisionCore,
            idempotencyKey: 'critical-expired-second-v1',
            expectedAssessmentRevision: first.value.assessmentRevision,
          })
          return {
            listed,
            first,
            second,
            after: await service.getAssessment(firstInvocation, { schemaVersion: 1, assessmentId }),
          }
        } finally {
          vi.useRealTimers()
        }
      },
    })

    expect(observation).toMatchObject({
      first: { ok: true, value: { resolution: 'PENDING_DUAL_AUTHORITY' } },
      second: { ok: false, error: { code: 'CONFLICT' } },
      after: {
        ok: true,
        value: { assessmentRevision: 4, state: 'BLOCKED', verdict: null, seal: null },
      },
    })
    expect(assessment).toMatchObject({ assessmentRevision: 4, state: 'BLOCKED', seal: null })
  })

  it('recovers a pending Critical attestation across Service restart before the second approval', async () => {
    const rationale = 'Critical exposure is temporarily accepted only for the isolated emergency recovery window.'
    const controls = [
      'Keep the affected deployment isolated from every public ingress.',
      'Require continuous operator monitoring until the emergency window closes.',
    ]
    const expiresAt = new Date(Date.now() + 12 * 60 * 60 * 1_000).toISOString()
    const { assessment, beforeRestartObservation, observation } = await runReferenceValidationScenario({
      id: 'critical-pending-restart',
      referenceControl: 'VIOLATED',
      observedValue: 'VIOLATED',
      technicalSeverity: 'CRITICAL',
      candidateHex: 'a',
      requestedStrongerControlIds: [
        'security/risk-decision-window-v1',
        'security/critical-break-glass-v1',
      ],
      beforeInspectState: 'BLOCKED',
      restartBeforeInspect: true,
      skipSubmissionAfterInspect: true,
      beforeRestart: async (service, invocation, assessmentId) => {
        const listed = await service.listFindings(invocation, {
          schemaVersion: 1,
          assessmentId,
          limit: 10,
        })
        if (!listed.ok || listed.value.findings[0] === undefined) return { listed }
        const finding = listed.value.findings[0]
        return service.recordRiskDecision(invocation, {
          schemaVersion: 1,
          idempotencyKey: 'critical-restart-first-v1',
          assessmentId,
          expectedAssessmentRevision: listed.value.assessmentRevision,
          finding: { recordId: finding.recordId, recordRevision: finding.recordRevision },
          decision: 'ACCEPT',
          rationale,
          compensatingControls: controls,
          expiresAt,
        })
      },
      inspect: async (service, _restartedInvocation, assessmentId) => {
        const secondInvocation = referenceHostInvocation(service, 'critical-restart-second-operator')
        const pending = await service.listFindings(secondInvocation, {
          schemaVersion: 1,
          assessmentId,
          limit: 10,
        })
        if (!pending.ok || pending.value.findings[0] === undefined) return { pending }
        const finding = pending.value.findings[0]
        const second = await service.recordRiskDecision(secondInvocation, {
          schemaVersion: 1,
          idempotencyKey: 'critical-restart-second-v1',
          assessmentId,
          expectedAssessmentRevision: pending.value.assessmentRevision,
          finding: { recordId: finding.recordId, recordRevision: finding.recordRevision },
          decision: 'ACCEPT',
          rationale,
          compensatingControls: controls,
          expiresAt,
        })
        if (!second.ok) return { pending, second }
        await waitUntilAssessmentState(service, secondInvocation, assessmentId, 'SEALED')
        return {
          pending,
          second,
          sealed: await service.getAssessment(secondInvocation, { schemaVersion: 1, assessmentId }),
          submission: await service.getAssuranceSubmission(secondInvocation, {
            schemaVersion: 1,
            assessmentId,
          }),
        }
      },
    })

    expect(beforeRestartObservation).toMatchObject({
      ok: true,
      value: { assessmentRevision: 4, resolution: 'PENDING_DUAL_AUTHORITY' },
    })
    expect(observation).toMatchObject({
      pending: {
        ok: true,
        value: {
          assessmentRevision: 4,
          findings: [{ technicalSeverity: 'CRITICAL', policySignificance: 'BLOCKING' }],
        },
      },
      second: {
        ok: true,
        value: { assessmentRevision: 5, resolution: 'ACCEPTED' },
      },
      sealed: {
        ok: true,
        value: { assessmentRevision: 6, state: 'SEALED', verdict: 'SATISFIED' },
      },
      submission: {
        ok: true,
        value: {
          payload: {
            riskDecisions: {
              value: {
                decisions: [{
                  resolution: 'ACCEPTED',
                  attestations: [{ sequence: 1 }, { sequence: 2 }],
                }],
              },
            },
          },
        },
      },
    })
    expect(assessment).toMatchObject({
      assessmentRevision: 6,
      state: 'SEALED',
      verdict: 'SATISFIED',
    })
  })

  it('fails closed at every Risk Decision authority, schema, revision, scope, and lifecycle boundary', async () => {
    const { assessment, observation } = await runReferenceValidationScenario({
      id: 'risk-decision-boundaries',
      referenceControl: 'VIOLATED',
      observedValue: 'VIOLATED',
      candidateHex: '1',
      requestedStrongerControlIds: ['security/risk-decision-window-v1'],
      beforeInspectState: 'BLOCKED',
      skipSubmissionAfterInspect: true,
      inspect: async (service, invocation, assessmentId) => {
        const listed = await service.listFindings(invocation, {
          schemaVersion: 1,
          assessmentId,
          limit: 10,
        })
        if (!listed.ok || listed.value.findings[0] === undefined) return { listed }
        const finding = listed.value.findings[0]
        const request = {
          schemaVersion: 1,
          idempotencyKey: 'risk-decision-boundaries-v1',
          assessmentId,
          expectedAssessmentRevision: listed.value.assessmentRevision,
          finding: {
            recordId: finding.recordId,
            recordRevision: finding.recordRevision,
          },
          decision: 'DENY',
          rationale: 'This denial is valid in shape but must only be accepted by Risk Decision Authority.',
          compensatingControls: [],
          expiresAt: null,
        } as const
        const unauthorizedInvocation = referenceHostInvocationWithPermissions(
          service,
          ['assessment:read'],
          'read-only-reviewer',
        )
        const unauthorized = await service.recordRiskDecision(unauthorizedInvocation, request)
        const forgedRequest: unknown = {
          ...request,
          idempotencyKey: 'risk-decision-forged-maker-v1',
          decisionMaker: { kind: 'host-operator', principalId: 'forged-principal' },
        }
        const forged = await service.recordRiskDecision(
          invocation,
          forgedRequest as Parameters<SecurityAssuranceService['recordRiskDecision']>[1],
        )
        const stale = await service.recordRiskDecision(invocation, {
          ...request,
          idempotencyKey: 'risk-decision-stale-v1',
          expectedAssessmentRevision: listed.value.assessmentRevision - 1,
        })
        const wrongFinding = await service.recordRiskDecision(invocation, {
          ...request,
          idempotencyKey: 'risk-decision-wrong-finding-v1',
          finding: {
            recordId: `finding-${'f'.repeat(64)}`,
            recordRevision: 1,
          },
        })
        const missingControls = await service.recordRiskDecision(invocation, {
          ...request,
          idempotencyKey: 'risk-decision-missing-controls-v1',
          decision: 'ACCEPT',
          expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1_000).toISOString(),
        })
        const overCeiling = await service.recordRiskDecision(invocation, {
          ...request,
          idempotencyKey: 'risk-decision-over-ceiling-v1',
          decision: 'ACCEPT',
          compensatingControls: ['Restrict deployment to the authenticated internal gateway.'],
          expiresAt: new Date(Date.now() + 8 * 24 * 60 * 60 * 1_000).toISOString(),
        })
        const resume = await service.resumeAssessment(invocation, {
          schemaVersion: 1,
          assessmentId,
          expectedAssessmentRevision: listed.value.assessmentRevision,
          idempotencyKey: 'resume-risk-decision-window-v1',
          reason: {
            code: 'HOST_RECONCILIATION',
            summary: 'An active Risk Decision Window cannot be bypassed through resume.',
          },
        })
        return {
          listed,
          unauthorized,
          forged,
          stale,
          wrongFinding,
          missingControls,
          overCeiling,
          resume,
          after: await service.getAssessment(invocation, { schemaVersion: 1, assessmentId }),
        }
      },
    })

    expect(observation).toMatchObject({
      unauthorized: { ok: false, error: { code: 'UNAUTHORIZED' } },
      forged: { ok: false, error: { code: 'INVALID_REQUEST' } },
      stale: { ok: false, error: { code: 'CONFLICT' } },
      wrongFinding: { ok: false, error: { code: 'NOT_FOUND' } },
      missingControls: { ok: false, error: { code: 'INVALID_REQUEST' } },
      overCeiling: { ok: false, error: { code: 'CONFLICT' } },
      resume: { ok: false, error: { code: 'CONFLICT' } },
      after: {
        ok: true,
        value: { assessmentRevision: 3, state: 'BLOCKED', verdict: null, seal: null },
      },
    })
    expect(assessment).toMatchObject({
      assessmentRevision: 3,
      state: 'BLOCKED',
      verdict: null,
      seal: null,
    })
  })

  it('records an immutable authorized DENY decision before sealing the original FAILED Verdict', async () => {
    const rationale = 'The validated High risk is denied and must be remediated before approval.'
    const { assessment, observation, submission } = await runReferenceValidationScenario({
      id: 'deny-risk-decision',
      referenceControl: 'VIOLATED',
      observedValue: 'VIOLATED',
      candidateHex: '2',
      requestedStrongerControlIds: ['security/risk-decision-window-v1'],
      beforeInspectState: 'BLOCKED',
      inspect: async (service, invocation, assessmentId) => {
        const listed = await service.listFindings(invocation, {
          schemaVersion: 1,
          assessmentId,
          limit: 10,
        })
        if (!listed.ok || listed.value.findings[0] === undefined) return { listed }
        const summary = listed.value.findings[0]
        const request = {
          schemaVersion: 1,
          idempotencyKey: 'deny-risk-decision-v1',
          assessmentId,
          expectedAssessmentRevision: listed.value.assessmentRevision,
          finding: {
            recordId: summary.recordId,
            recordRevision: summary.recordRevision,
          },
          decision: 'DENY',
          rationale,
          compensatingControls: [],
          expiresAt: null,
        } as const
        const receipt = await service.recordRiskDecision(invocation, request)
        if (!receipt.ok) return { listed, receipt }
        await waitUntilAssessmentState(service, invocation, assessmentId, 'SEALED')
        const replay = await service.recordRiskDecision(invocation, request)
        const conflictingReplay = await service.recordRiskDecision(invocation, {
          ...request,
          rationale: 'A materially different denial rationale cannot reuse the same idempotency key.',
        })
        const sealedList = await service.listFindings(invocation, {
          schemaVersion: 1,
          assessmentId,
          limit: 10,
        })
        if (!sealedList.ok || sealedList.value.findings[0] === undefined) {
          return { listed, receipt, replay, conflictingReplay, sealedList }
        }
        const sealedSummary = sealedList.value.findings[0]
        return {
          listed,
          receipt,
          replay,
          conflictingReplay,
          sealedList,
          detail: await service.getFinding(invocation, {
            schemaVersion: 1,
            assessmentId,
            assessmentRevision: sealedList.value.assessmentRevision,
            recordId: sealedSummary.recordId,
            recordRevision: sealedSummary.recordRevision,
          }),
        }
      },
    })

    expect(observation).toMatchObject({
      receipt: {
        ok: true,
        value: {
          schemaVersion: 1,
          operation: 'record_risk_decision',
          assessmentId: assessment.assessmentId,
          assessmentRevision: 4,
          acceptedState: 'BLOCKED',
          decisionId: expect.stringMatching(/^risk-decision-[0-9a-f-]{36}$/),
          finding: {
            recordId: expect.stringMatching(/^finding-[0-9a-f]{64}$/),
            recordRevision: 1,
          },
          decision: 'DENY',
          resolution: 'DENIED',
          idempotencyKey: 'deny-risk-decision-v1',
          recordedAt: expect.any(String),
          correlationId: expect.stringMatching(/^sec-[0-9a-f-]{36}$/),
        },
      },
      replay: { ok: true },
      conflictingReplay: {
        ok: false,
        error: { code: 'IDEMPOTENCY_CONFLICT' },
      },
      sealedList: {
        ok: true,
        value: { assessmentRevision: 5 },
      },
      detail: {
        ok: true,
        value: {
          technicalSeverity: { value: 'HIGH' },
          policySignificance: 'BLOCKING',
          riskDecision: {
            state: 'DENIED',
            decisionId: expect.stringMatching(/^risk-decision-[0-9a-f-]{36}$/),
            rationale,
            compensatingControls: [],
            expiresAt: null,
            decisionMaker: {
              kind: 'host-operator',
              principalId: 'reference-host-operator',
            },
            recordedAt: expect.any(String),
          },
        },
      },
    })
    if (
      observation !== undefined
      && typeof observation === 'object'
      && 'receipt' in observation
      && 'replay' in observation
    ) expect(observation.replay).toEqual(observation.receipt)
    expect(assessment).toMatchObject({
      assessmentRevision: 5,
      state: 'SEALED',
      verdict: 'FAILED',
    })
    expect(submission).toMatchObject({
      payload: {
        assessment: { assessmentRevision: 5, verdict: 'FAILED' },
        riskDecisions: {
          value: {
            decisions: [{
              decision: 'DENY',
              rationale,
              decisionMaker: {
                kind: 'host-operator',
                principalId: 'reference-host-operator',
              },
            }],
          },
        },
      },
    })
  })

  it('accepts eligible High risk with controls and short expiry without changing Technical Severity', async () => {
    const rationale = 'The bounded deployment accepts this High risk while the compensating control is enforced.'
    const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1_000).toISOString()
    const { observation } = await runReferenceValidationScenario({
      id: 'accept-high-risk-decision',
      referenceControl: 'VIOLATED',
      observedValue: 'VIOLATED',
      candidateHex: '3',
      requestedStrongerControlIds: ['security/risk-decision-window-v1'],
      beforeInspectState: 'BLOCKED',
      skipSubmissionAfterInspect: true,
      inspect: async (service, invocation, assessmentId) => {
        const listed = await service.listFindings(invocation, {
          schemaVersion: 1,
          assessmentId,
          limit: 10,
        })
        if (!listed.ok || listed.value.findings[0] === undefined) return { listed }
        const summary = listed.value.findings[0]
        const receipt = await service.recordRiskDecision(invocation, {
          schemaVersion: 1,
          idempotencyKey: 'accept-high-risk-decision-v1',
          assessmentId,
          expectedAssessmentRevision: listed.value.assessmentRevision,
          finding: {
            recordId: summary.recordId,
            recordRevision: summary.recordRevision,
          },
          decision: 'ACCEPT',
          rationale,
          compensatingControls: ['Deploy only behind the authenticated internal gateway.'],
          expiresAt,
        })
        if (!receipt.ok) return { listed, receipt }
        await waitUntilAssessmentState(service, invocation, assessmentId, 'SEALED')
        const sealedAssessment = await service.getAssessment(invocation, {
          schemaVersion: 1,
          assessmentId,
        })
        const sealedList = await service.listFindings(invocation, {
          schemaVersion: 1,
          assessmentId,
          limit: 10,
        })
        if (!sealedList.ok || sealedList.value.findings[0] === undefined) {
          return { listed, receipt, sealedAssessment, sealedList }
        }
        const sealedSummary = sealedList.value.findings[0]
        return {
          listed,
          receipt,
          sealedAssessment,
          sealedList,
          detail: await service.getFinding(invocation, {
            schemaVersion: 1,
            assessmentId,
            assessmentRevision: sealedList.value.assessmentRevision,
            recordId: sealedSummary.recordId,
            recordRevision: sealedSummary.recordRevision,
          }),
          submission: await service.getAssuranceSubmission(invocation, {
            schemaVersion: 1,
            assessmentId,
          }),
        }
      },
    })

    expect(observation).toMatchObject({
      receipt: {
        ok: true,
        value: {
          assessmentRevision: 4,
          decision: 'ACCEPT',
          resolution: 'ACCEPTED',
        },
      },
      sealedAssessment: {
        ok: true,
        value: {
          assessmentRevision: 5,
          state: 'SEALED',
          verdict: 'SATISFIED',
        },
      },
      sealedList: {
        ok: true,
        value: {
          findings: [{
            technicalSeverity: 'HIGH',
            policySignificance: 'NON_BLOCKING',
          }],
        },
      },
      detail: {
        ok: true,
        value: {
          technicalSeverity: { value: 'HIGH' },
          policySignificance: 'NON_BLOCKING',
          riskDecision: {
            state: 'ACCEPTED',
            rationale,
            compensatingControls: ['Deploy only behind the authenticated internal gateway.'],
            expiresAt,
            decisionMaker: {
              kind: 'host-operator',
              principalId: 'reference-host-operator',
            },
          },
        },
      },
      submission: {
        ok: true,
        value: {
          payload: {
            assessment: { verdict: 'SATISFIED' },
            findings: {
              value: {
                findings: [{
                  technicalSeverity: { value: 'HIGH' },
                  policySignificance: 'NON_BLOCKING',
                }],
              },
            },
            riskDecisions: {
              value: {
                decisions: [{
                  decision: 'ACCEPT',
                  resolution: 'ACCEPTED',
                  expiresAt,
                }],
              },
            },
          },
        },
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

  it('returns a revision-bound VALIDATED Finding Detail View without Evidence payload', async () => {
    const { assessment, candidateId, observation } = await runReferenceValidationScenario({
      id: 'get-validated-finding-detail',
      referenceControl: 'VIOLATED',
      observedValue: 'VIOLATED',
      candidateHex: 'c',
      inspect: async (service, invocation, assessmentId) => {
        const listed = await service.listFindings(invocation, {
          schemaVersion: 1,
          assessmentId,
          limit: 10,
        })
        if (!listed.ok || listed.value.findings[0] === undefined) return { listed, detail: null }
        const summary = listed.value.findings[0]
        const detail = await service.getFinding(invocation, {
          schemaVersion: 1,
          assessmentId,
          assessmentRevision: summary.assessmentRevision,
          recordId: summary.recordId,
          recordRevision: summary.recordRevision,
        })
        const staleAssessmentRevision = await service.getFinding(invocation, {
          schemaVersion: 1,
          assessmentId,
          assessmentRevision: summary.assessmentRevision + 1,
          recordId: summary.recordId,
          recordRevision: summary.recordRevision,
        })
        const staleRecordRevision = await service.getFinding(invocation, {
          schemaVersion: 1,
          assessmentId,
          assessmentRevision: summary.assessmentRevision,
          recordId: summary.recordId,
          recordRevision: summary.recordRevision + 1,
        })
        const missingRecord = await service.getFinding(invocation, {
          schemaVersion: 1,
          assessmentId,
          assessmentRevision: summary.assessmentRevision,
          recordId: `finding-${'0'.repeat(64)}`,
          recordRevision: 1,
        })
        return { listed, detail, staleAssessmentRevision, staleRecordRevision, missingRecord }
      },
    })

    expect(observation).toMatchObject({
      detail: {
        ok: true,
        value: {
          schemaVersion: 1,
          assessmentId: assessment.assessmentId,
          assessmentRevision: assessment.assessmentRevision,
          recordKind: 'FINDING',
          recordId: expect.stringMatching(/^finding-[0-9a-f]{64}$/),
          candidateId,
          recordRevision: 1,
          revisionChain: [{
            recordRevision: 1,
            supersedesRecordRevision: null,
            isCurrent: true,
          }],
          weaknessClassification: {
            primary: 'dsh/conformance/reference-control-violation',
            secondary: [],
          },
          affectedControlId: 'dsh/conformance/reference-control',
          sourceAnchor: {
            path: 'package.json',
            fileDigest: { algorithm: 'sha256' },
            locator: {
              kind: 'JSON_POINTER',
              value: '/dshSecurity/referenceControl',
            },
          },
          validation: {
            state: 'VALIDATED',
            contractId: 'dsh/conformance/reference-control-validation-v1',
            contractVersion: 1,
            outcomeArtifactId: 'validation-outcome-cccccccccccccccc',
            rejectionCondition: null,
            proofGaps: [],
            negativeControls: [
              'verified-subject-digest',
              'exact-source-file-digest',
              'unique-json-security-keys',
              'exact-json-pointer',
              'exact-reference-control-marker',
              'observed-value-matches-subject',
            ],
          },
          technicalSeverity: {
            value: 'HIGH',
            methodVersion: 'dsh/conformance/reference-control-severity-v1',
            inputs: [
              { dimension: 'affectedScope', value: 'APPLICATION' },
              { dimension: 'impact', value: 'SECURITY_CONTROL_BYPASS' },
              { dimension: 'reachability', value: 'DIRECT' },
            ],
          },
          evidenceConfidence: {
            value: 'HIGH',
            methodVersion: 'dsh/conformance/deterministic-evidence-confidence-v1',
            rubric: [
              { dimension: 'negativeControls', value: 'PASS' },
              { dimension: 'producerQualification', value: 'PASS' },
              { dimension: 'proofGaps', value: 0 },
              { dimension: 'reproducibility', value: 'PASS' },
              { dimension: 'subjectBinding', value: 'PASS' },
            ],
          },
          policySignificance: 'BLOCKING',
          coverageRelations: [{
            obligationId: 'application-security-analysis',
            state: 'SATISFIED',
            reason: 'ELIGIBLE_EVIDENCE',
          }],
          riskDecision: { state: 'NOT_RECORDED' },
          evidenceLinks: [{
            artifactId: 'reference-validation-evidence',
            schemaId: 'fixture/reference-validation-evidence',
            digest: { algorithm: 'sha256' },
            purpose: 'VALIDATION_EVIDENCE',
            eligibilityDecision: 'ELIGIBLE',
            eligibilityDecisionArtifactId: 'validation-eligibility-cccccccccccccccc',
          }],
          attackPath: { state: 'NOT_AVAILABLE' },
        },
      },
      staleAssessmentRevision: {
        ok: false,
        error: { code: 'CONFLICT' },
      },
      staleRecordRevision: {
        ok: false,
        error: { code: 'CONFLICT' },
      },
      missingRecord: {
        ok: false,
        error: { code: 'NOT_FOUND' },
      },
    })
    expect(observation).not.toHaveProperty('detail.value.evidenceLinks.0.value')
    expect(JSON.stringify(observation)).not.toContain('"observedValue":"VIOLATED"')
  })

  it('returns a metadata-only Evidence View bound to one exact Finding revision', async () => {
    const { assessment, observation } = await runReferenceValidationScenario({
      id: 'get-evidence-metadata-view',
      referenceControl: 'VIOLATED',
      observedValue: 'VIOLATED',
      candidateHex: '4',
      inspect: async (service, invocation, assessmentId) => {
        const listed = await service.listFindings(invocation, {
          schemaVersion: 1,
          assessmentId,
          limit: 10,
        })
        if (!listed.ok || listed.value.findings[0] === undefined) return { listed, view: null }
        const summary = listed.value.findings[0]
        const detail = await service.getFinding(invocation, {
          schemaVersion: 1,
          assessmentId,
          assessmentRevision: summary.assessmentRevision,
          recordId: summary.recordId,
          recordRevision: summary.recordRevision,
        })
        if (!detail.ok || detail.value.evidenceLinks[0] === undefined) return { listed, detail, view: null }
        const link = detail.value.evidenceLinks[0]
        return {
          listed,
          detail,
          view: await service.getEvidenceView(invocation, {
            schemaVersion: 1,
            assessmentId,
            assessmentRevision: summary.assessmentRevision,
            context: {
              kind: 'finding',
              recordId: summary.recordId,
              recordRevision: summary.recordRevision,
            },
            evidenceArtifactId: link.artifactId,
            evidenceDigest: link.digest,
            purpose: 'FINDING_TRIAGE',
            viewProfileId: 'security/evidence-view/metadata-only-v1',
          }),
        }
      },
    })

    expect(observation).toMatchObject({
      view: {
        ok: true,
        value: {
          schemaVersion: 1,
          assessmentId: assessment.assessmentId,
          assessmentRevision: assessment.assessmentRevision,
          context: {
            kind: 'finding',
            recordId: expect.stringMatching(/^finding-[0-9a-f]{64}$/),
            recordRevision: 1,
          },
          evidence: {
            artifactId: 'reference-validation-evidence',
            schemaId: 'fixture/reference-validation-evidence',
            digest: { algorithm: 'sha256' },
            classification: 'CONTROL_PLANE',
          },
          link: {
            purpose: 'VALIDATION_EVIDENCE',
            eligibilityDecision: 'ELIGIBLE',
            eligibilityDecisionArtifactId: 'validation-eligibility-4444444444444444',
          },
          purpose: 'FINDING_TRIAGE',
          viewProfileId: 'security/evidence-view/metadata-only-v1',
          protection: {
            policyId: 'evidence/local-protected',
            status: 'AVAILABLE',
          },
          retention: { status: 'RETAINED' },
          egress: {
            policyId: 'egress/deny-by-default',
            status: 'LOCAL_ONLY',
          },
          content: {
            kind: 'REDACTED',
            reason: 'PROFILE_METADATA_ONLY',
          },
        },
      },
    })
    expect(JSON.stringify(observation)).not.toContain('"observedValue":"VIOLATED"')
    expect(JSON.stringify(observation)).not.toMatch(/evidence[\\/]asm-/i)
    expect(observation).not.toHaveProperty('view.value.path')
    expect(observation).not.toHaveProperty('view.value.key')
  })

  it('requires separate disclosure authority and a validation purpose for bounded Evidence content', async () => {
    const { observation } = await runReferenceValidationScenario({
      id: 'get-evidence-bounded-view',
      referenceControl: 'VIOLATED',
      observedValue: 'VIOLATED',
      candidateHex: '5',
      inspect: async (service, invocation, assessmentId) => {
        const listed = await service.listFindings(invocation, {
          schemaVersion: 1,
          assessmentId,
          limit: 10,
        })
        if (!listed.ok || listed.value.findings[0] === undefined) return { listed }
        const summary = listed.value.findings[0]
        const detail = await service.getFinding(invocation, {
          schemaVersion: 1,
          assessmentId,
          assessmentRevision: summary.assessmentRevision,
          recordId: summary.recordId,
          recordRevision: summary.recordRevision,
        })
        if (!detail.ok || detail.value.evidenceLinks[0] === undefined) return { listed, detail }
        const link = detail.value.evidenceLinks[0]
        const base = {
          schemaVersion: 1 as const,
          assessmentId,
          assessmentRevision: summary.assessmentRevision,
          context: {
            kind: 'finding' as const,
            recordId: summary.recordId,
            recordRevision: summary.recordRevision,
          },
          evidenceArtifactId: link.artifactId,
          evidenceDigest: link.digest,
          purpose: 'VALIDATION_REVIEW' as const,
          viewProfileId: 'security/evidence-view/bounded-json-v1' as const,
        }
        const metadataOnlyAuthority = referenceHostInvocationWithPermissions(
          service,
          ['assessment:read'],
          'metadata-only-reviewer',
        )
        const noReadAuthority = referenceHostInvocationWithPermissions(
          service,
          ['health:read'],
          'health-only-operator',
        )
        return {
          bounded: await service.getEvidenceView(invocation, base),
          withoutDisclosureAuthority: await service.getEvidenceView(metadataOnlyAuthority, base),
          wrongPurpose: await service.getEvidenceView(invocation, {
            ...base,
            purpose: 'FINDING_TRIAGE',
          }),
          metadataWithReadAuthority: await service.getEvidenceView(metadataOnlyAuthority, {
            ...base,
            purpose: 'FINDING_TRIAGE',
            viewProfileId: 'security/evidence-view/metadata-only-v1',
          }),
          submissionByMetadataAuthority: await service.getAssuranceSubmission(
            metadataOnlyAuthority,
            { schemaVersion: 1, assessmentId },
          ),
          withoutReadAuthority: await service.getEvidenceView(noReadAuthority, base),
        }
      },
    })

    expect(observation).toMatchObject({
      bounded: {
        ok: true,
        value: {
          purpose: 'VALIDATION_REVIEW',
          viewProfileId: 'security/evidence-view/bounded-json-v1',
          content: {
            kind: 'BOUNDED_JSON',
            byteLength: expect.any(Number),
            value: {
              schemaVersion: 1,
              observedValue: 'VIOLATED',
            },
          },
        },
      },
      withoutDisclosureAuthority: {
        ok: true,
        value: { content: { kind: 'REDACTED', reason: 'DISCLOSURE_NOT_AUTHORIZED' } },
      },
      wrongPurpose: {
        ok: true,
        value: { content: { kind: 'REDACTED', reason: 'PURPOSE_NOT_AUTHORIZED' } },
      },
      metadataWithReadAuthority: {
        ok: true,
        value: { content: { kind: 'REDACTED', reason: 'PROFILE_METADATA_ONLY' } },
      },
      submissionByMetadataAuthority: {
        ok: false,
        error: { code: 'UNAUTHORIZED' },
      },
      withoutReadAuthority: {
        ok: false,
        error: { code: 'UNAUTHORIZED' },
      },
    })
    expect(observation?.bounded).not.toHaveProperty('value.path')
    expect(observation?.bounded).not.toHaveProperty('value.key')
    if (observation?.bounded?.ok && observation.bounded.value.content.kind === 'BOUNDED_JSON') {
      expect(evidenceViewV1Schema.safeParse({
        ...observation.bounded.value,
        content: {
          ...observation.bounded.value.content,
          byteLength: observation.bounded.value.content.byteLength + 1,
        },
      }).success).toBe(false)
    }
  })

  it('fails closed for stale, cross-Finding, and mismatched Evidence identities', async () => {
    const { observation } = await runReferenceValidationScenario({
      id: 'reject-mismatched-evidence-view',
      referenceControl: 'VIOLATED',
      observedValue: 'VIOLATED',
      candidateHex: '6',
      additionalCandidateHexes: ['7'],
      inspect: async (service, invocation, assessmentId) => {
        const listed = await service.listFindings(invocation, {
          schemaVersion: 1,
          assessmentId,
          limit: 10,
        })
        if (!listed.ok || listed.value.findings.length !== 2) return { listed }
        const first = listed.value.findings[0]
        const second = listed.value.findings[1]
        if (first === undefined || second === undefined) return { listed }
        const detail = await service.getFinding(invocation, {
          schemaVersion: 1,
          assessmentId,
          assessmentRevision: first.assessmentRevision,
          recordId: first.recordId,
          recordRevision: first.recordRevision,
        })
        if (!detail.ok || detail.value.evidenceLinks[0] === undefined) return { listed, detail }
        const link = detail.value.evidenceLinks[0]
        const base = {
          schemaVersion: 1 as const,
          assessmentId,
          assessmentRevision: first.assessmentRevision,
          context: {
            kind: 'finding' as const,
            recordId: first.recordId,
            recordRevision: first.recordRevision,
          },
          evidenceArtifactId: link.artifactId,
          evidenceDigest: link.digest,
          purpose: 'FINDING_TRIAGE' as const,
          viewProfileId: 'security/evidence-view/metadata-only-v1' as const,
        }
        return {
          wrongDigest: await service.getEvidenceView(invocation, {
            ...base,
            evidenceDigest: { ...link.digest, value: 'f'.repeat(64) },
          }),
          wrongArtifact: await service.getEvidenceView(invocation, {
            ...base,
            evidenceArtifactId: 'reference-validation-evidence-9',
          }),
          crossFinding: await service.getEvidenceView(invocation, {
            ...base,
            context: {
              kind: 'finding',
              recordId: second.recordId,
              recordRevision: second.recordRevision,
            },
          }),
          staleAssessment: await service.getEvidenceView(invocation, {
            ...base,
            assessmentRevision: first.assessmentRevision + 1,
          }),
          staleFinding: await service.getEvidenceView(invocation, {
            ...base,
            context: { ...base.context, recordRevision: first.recordRevision + 1 },
          }),
          unknownProfile: await service.getEvidenceView(invocation, {
            ...base,
            viewProfileId: 'security/evidence-view/unrestricted-v1',
          } as never),
        }
      },
    })

    expect(observation).toMatchObject({
      wrongDigest: { ok: false, error: { code: 'NOT_FOUND' } },
      wrongArtifact: { ok: false, error: { code: 'NOT_FOUND' } },
      crossFinding: { ok: false, error: { code: 'NOT_FOUND' } },
      staleAssessment: { ok: false, error: { code: 'CONFLICT' } },
      staleFinding: { ok: false, error: { code: 'CONFLICT' } },
      unknownProfile: { ok: false, error: { code: 'INVALID_REQUEST' } },
    })
  })

  it('redacts content that exceeds the bounded-json Profile byte limit', async () => {
    const { observation } = await runReferenceValidationScenario({
      id: 'redact-oversized-evidence-view',
      referenceControl: 'VIOLATED',
      observedValue: 'VIOLATED',
      candidateHex: '8',
      evidencePaddingBytes: 33 * 1024,
      inspect: async (service, invocation, assessmentId) => {
        const listed = await service.listFindings(invocation, {
          schemaVersion: 1,
          assessmentId,
          limit: 10,
        })
        if (!listed.ok || listed.value.findings[0] === undefined) return listed
        const summary = listed.value.findings[0]
        const detail = await service.getFinding(invocation, {
          schemaVersion: 1,
          assessmentId,
          assessmentRevision: summary.assessmentRevision,
          recordId: summary.recordId,
          recordRevision: summary.recordRevision,
        })
        if (!detail.ok || detail.value.evidenceLinks[0] === undefined) return detail
        const link = detail.value.evidenceLinks[0]
        return service.getEvidenceView(invocation, {
          schemaVersion: 1,
          assessmentId,
          assessmentRevision: summary.assessmentRevision,
          context: {
            kind: 'finding',
            recordId: summary.recordId,
            recordRevision: summary.recordRevision,
          },
          evidenceArtifactId: link.artifactId,
          evidenceDigest: link.digest,
          purpose: 'VALIDATION_REVIEW',
          viewProfileId: 'security/evidence-view/bounded-json-v1',
        })
      },
    })

    expect(observation).toMatchObject({
      ok: true,
      value: {
        content: { kind: 'REDACTED', reason: 'PROFILE_BYTE_LIMIT' },
      },
    })
    expect(JSON.stringify(observation)).not.toContain('x'.repeat(128))
  })

  it('re-evaluates the frozen Evidence protection policy before content disclosure', async () => {
    const { observation } = await runReferenceValidationScenario({
      id: 'unavailable-evidence-protection',
      referenceControl: 'VIOLATED',
      observedValue: 'VIOLATED',
      candidateHex: '9',
      evidenceProtectionId: 'evidence/external-key-provider',
      inspect: async (service, invocation, assessmentId) => {
        const listed = await service.listFindings(invocation, {
          schemaVersion: 1,
          assessmentId,
          limit: 10,
        })
        if (!listed.ok || listed.value.findings[0] === undefined) return listed
        const summary = listed.value.findings[0]
        const detail = await service.getFinding(invocation, {
          schemaVersion: 1,
          assessmentId,
          assessmentRevision: summary.assessmentRevision,
          recordId: summary.recordId,
          recordRevision: summary.recordRevision,
        })
        if (!detail.ok || detail.value.evidenceLinks[0] === undefined) return detail
        const link = detail.value.evidenceLinks[0]
        return service.getEvidenceView(invocation, {
          schemaVersion: 1,
          assessmentId,
          assessmentRevision: summary.assessmentRevision,
          context: {
            kind: 'finding',
            recordId: summary.recordId,
            recordRevision: summary.recordRevision,
          },
          evidenceArtifactId: link.artifactId,
          evidenceDigest: link.digest,
          purpose: 'VALIDATION_REVIEW',
          viewProfileId: 'security/evidence-view/bounded-json-v1',
        })
      },
    })

    expect(observation).toMatchObject({
      ok: true,
      value: {
        protection: {
          policyId: 'evidence/external-key-provider',
          status: 'UNAVAILABLE',
        },
        content: { kind: 'REDACTED', reason: 'PROTECTION_UNAVAILABLE' },
      },
    })
    expect(JSON.stringify(observation)).not.toContain('"observedValue":"VIOLATED"')
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

  it('returns REJECTED Candidate detail with eligible Counter-Evidence metadata', async () => {
    const { assessment, candidateId, observation } = await runReferenceValidationScenario({
      id: 'get-rejected-candidate-detail',
      referenceControl: 'SATISFIED',
      observedValue: 'SATISFIED',
      candidateHex: 'b',
      inspect: async (service, invocation, assessmentId) => {
        const listed = await service.listFindings(invocation, {
          schemaVersion: 1,
          assessmentId,
          limit: 10,
        })
        if (!listed.ok || listed.value.findings[0] === undefined) return { listed, detail: null }
        const summary = listed.value.findings[0]
        return {
          listed,
          detail: await service.getFinding(invocation, {
            schemaVersion: 1,
            assessmentId,
            assessmentRevision: summary.assessmentRevision,
            recordId: summary.recordId,
            recordRevision: summary.recordRevision,
          }),
        }
      },
    })

    expect(observation).toMatchObject({
      detail: {
        ok: true,
        value: {
          assessmentId: assessment.assessmentId,
          assessmentRevision: assessment.assessmentRevision,
          recordKind: 'REJECTED_CANDIDATE',
          recordId: candidateId,
          candidateId,
          recordRevision: 1,
          weaknessClassification: {
            primary: 'dsh/conformance/reference-control-violation',
            secondary: [],
          },
          affectedControlId: 'dsh/conformance/reference-control',
          sourceAnchor: {
            path: 'package.json',
            locator: { kind: 'JSON_POINTER', value: '/dshSecurity/referenceControl' },
          },
          validation: {
            state: 'REJECTED',
            contractId: 'dsh/conformance/reference-control-validation-v1',
            contractVersion: 1,
            outcomeArtifactId: 'validation-outcome-bbbbbbbbbbbbbbbb',
            rejectionCondition: 'EXACT_REFERENCE_CONTROL_SATISFIED',
            proofGaps: [],
            negativeControls: [
              'verified-subject-digest',
              'exact-source-file-digest',
              'unique-json-security-keys',
              'exact-json-pointer',
              'exact-reference-control-marker',
              'observed-value-matches-subject',
            ],
          },
          technicalSeverity: null,
          evidenceConfidence: null,
          policySignificance: null,
          coverageRelations: [{
            obligationId: 'application-security-analysis',
            state: 'SATISFIED',
            reason: 'ELIGIBLE_EVIDENCE',
          }],
          riskDecision: { state: 'NOT_RECORDED' },
          evidenceLinks: [{
            artifactId: 'reference-validation-evidence',
            schemaId: 'fixture/reference-validation-evidence',
            purpose: 'COUNTER_EVIDENCE',
            eligibilityDecision: 'ELIGIBLE',
            eligibilityDecisionArtifactId: 'validation-eligibility-bbbbbbbbbbbbbbbb',
          }],
          attackPath: { state: 'NOT_AVAILABLE' },
        },
      },
    })
    expect(observation).not.toHaveProperty('detail.value.evidenceLinks.0.value')
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

  it('returns UNRESOLVED Candidate detail with its exact Contract and Proof Gap', async () => {
    const { assessment, candidateId, observation } = await runReferenceValidationScenario({
      id: 'get-unresolved-candidate-detail',
      referenceControl: 'VIOLATED',
      observedValue: 'SATISFIED',
      candidateHex: 'd',
      inspect: async (service, invocation, assessmentId) => {
        const listed = await service.listFindings(invocation, {
          schemaVersion: 1,
          assessmentId,
          limit: 10,
        })
        if (!listed.ok || listed.value.findings[0] === undefined) return { listed, detail: null }
        const summary = listed.value.findings[0]
        return {
          listed,
          detail: await service.getFinding(invocation, {
            schemaVersion: 1,
            assessmentId,
            assessmentRevision: summary.assessmentRevision,
            recordId: summary.recordId,
            recordRevision: summary.recordRevision,
          }),
        }
      },
    })

    expect(observation).toMatchObject({
      detail: {
        ok: true,
        value: {
          assessmentId: assessment.assessmentId,
          assessmentRevision: assessment.assessmentRevision,
          recordKind: 'UNRESOLVED_CANDIDATE',
          recordId: candidateId,
          candidateId,
          recordRevision: 1,
          validation: {
            state: 'UNRESOLVED',
            contractId: 'dsh/conformance/reference-control-validation-v1',
            contractVersion: 1,
            outcomeArtifactId: 'validation-outcome-dddddddddddddddd',
            rejectionCondition: null,
            proofGaps: ['VALIDATION_EVIDENCE_CONTRADICTS_SUBJECT'],
          },
          technicalSeverity: null,
          evidenceConfidence: null,
          policySignificance: null,
          coverageRelations: [{
            obligationId: 'application-security-analysis',
            state: 'GAP',
            reason: 'EVIDENCE_INELIGIBLE',
          }],
          evidenceLinks: [{
            artifactId: 'reference-validation-evidence',
            purpose: 'COUNTER_EVIDENCE',
            eligibilityDecision: 'INELIGIBLE',
            eligibilityDecisionArtifactId: 'validation-eligibility-dddddddddddddddd',
          }],
        },
      },
    })
    expect(observation).not.toHaveProperty('detail.value.evidenceLinks.0.value')
  })
})
