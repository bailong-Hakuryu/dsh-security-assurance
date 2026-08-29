// @vitest-environment jsdom
import { createHash } from 'node:crypto'
import { act, cleanup, fireEvent, waitFor } from '@testing-library/react'
import TypertRegistry from '@deepseek-ai/dsh-typert-registry'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { SlotTestRuntime } from '@deepseek-ai/dsh-client-test-runtime'
import {
  apply as applyClientRemote,
  inject as clientRemoteInject,
} from '../../deepseek-harness-master/packages/api/gateway/lib/types/client/index.js'
import { LocaleRuntime } from '@deepseek-ai/dsh-client-locale/client'
import type {} from '@deepseek-ai/dsh-client-ui-layout/client'
import type {} from '@deepseek-ai/dsh-client-ui-sidebar/client'
import type {
  AssessmentId,
  AssessmentListItemV1,
  AssessmentSnapshotV1,
  FindingDetailViewV1,
  FindingSummaryV1,
} from '../src/contracts.ts'
import {
  apply as applyWorkbenchClient,
  inject as workbenchClientInject,
  type SecurityAssuranceWorkbenchController,
  type WorkbenchAuthorityContextId,
} from '../src/client/index.ts'
import type {
  WorkbenchEvidenceDisclosureViewV1,
  WorkbenchEvidenceMetadataViewV1,
} from '../src/workbench-remote.ts'

afterEach(() => {
  cleanup()
  vi.useRealTimers()
})

async function bench(call: (
  path: string,
  endpoint: string,
  payload: unknown,
  signal: AbortSignal,
) => Promise<unknown> = () => Promise.reject(new Error('The empty Workbench must not call Remote.'))) {
  const runtime = await SlotTestRuntime.create()
  await runtime.ctx.plugin(TypertRegistry)
  runtime.provide('connection', {
    rpc: {
      call,
    },
  } as never)
  const gateway = await runtime.mount({ inject: clientRemoteInject, apply: applyClientRemote })

  const locale = new LocaleRuntime(runtime.ctx)
  locale.setLocale('zh')
  runtime.provide('locale', locale)
  runtime.slots.installLocale(locale)
  await runtime.declare({
    'sidebar.footer.action': { kind: 'list', scope: 'root' },
    'shell.overlay': { kind: 'list', scope: 'root' },
  })
  const feature = await runtime.mount({
    inject: [...workbenchClientInject],
    apply: applyWorkbenchClient,
  })
  return {
    runtime,
    locale,
    feature,
    gateway,
    controller: runtime.ctx.get('securityAssuranceWorkbench') as SecurityAssuranceWorkbenchController,
  }
}

function assessmentId(value: string): AssessmentId {
  return value as AssessmentId
}

function authorityContextId(value: string): WorkbenchAuthorityContextId {
  return value as WorkbenchAuthorityContextId
}

function readySnapshot(id: AssessmentId): AssessmentSnapshotV1 {
  const digest = {
    schemaVersion: 1 as const,
    algorithm: 'sha256' as const,
    mediaType: 'application/vnd.dsh.canonical-json',
    byteLength: 1,
    canonicalization: 'dsh-canonical-json-v1' as const,
    value: 'a'.repeat(64),
  }
  return {
    schemaVersion: 1,
    assessmentId: id,
    assessmentRevision: 7,
    state: 'BLOCKED',
    repository: {
      repositoryId: 'repo-00000000-0000-0000-0000-000000000007',
      repositoryRevision: 3,
    },
    subject: { kind: 'workspace_snapshot', digest },
    contract: {
      schemaVersion: 1,
      assessmentMode: 'REPOSITORY',
      assessmentProfileId: 'security/standard',
      target: { kind: 'repository' },
      targetDigest: digest,
      requestedStrongerControlIds: [],
    },
    policy: { policyId: 'security/standard', digest },
    coverage: {
      status: 'GAP',
      mandatoryObligations: 2,
      satisfiedObligations: 0,
      gapObligations: 2,
      resolutions: [
        { obligationId: 'security/sast', state: 'GAP', reason: 'ANALYZER_INCOMPLETE' },
        { obligationId: 'security/secrets', state: 'GAP', reason: 'EVIDENCE_INELIGIBLE' },
      ],
      digest,
    },
    blockedRecovery: {
      schemaVersion: 1,
      blocker: {
        code: 'ASSESSMENT_EXECUTION_FAILED',
        phase: 'ASSESSMENT_EXECUTION',
        interruption: 'FAILED',
        affectedObligations: [
          { obligationId: 'security/sast', reason: 'ANALYZER_INCOMPLETE' },
          { obligationId: 'security/secrets', reason: 'EVIDENCE_INELIGIBLE' },
        ],
      },
      attempt: {
        status: 'IDENTIFIED',
        attemptId: `${id}:assessment-execution:6`,
        attemptKind: 'ASSESSMENT_EXECUTION',
        lifecycleState: 'FAILED',
      },
      evidence: { status: 'RETAINED', publishedArtifactCount: null },
      recovery: {
        requiredCondition: 'EXPLICIT_RESUME_REQUIRED',
        remainingExecutionBudget: { status: 'NOT_REPORTED' },
        remainingEligibility: {
          status: 'ELIGIBLE_FOR_CALLER',
          actionKinds: ['RESUME_ASSESSMENT', 'CANCEL_ASSESSMENT'],
        },
        coverageReconciliation: { required: true, possibleVerdict: 'INDETERMINATE' },
      },
    },
    availableActions: [
      { kind: 'RESUME_ASSESSMENT', expectedAssessmentRevision: 7 },
      { kind: 'CANCEL_ASSESSMENT', expectedAssessmentRevision: 7 },
    ],
    roleCards: [{
      schemaVersion: 1,
      roleDefinition: {
        roleId: 'validation-analyst',
        roleVersion: '1.0.0',
        definitionDigest: digest,
        independenceClass: 'DISTINCT_ATTEMPT',
      },
      attempt: {
        attemptId: 'role-attempt-00000000-0000-0000-0000-000000000007',
        parentAttemptId: null,
        lifecycleState: 'BLOCKED',
        startedAt: '2026-08-24T00:01:00.000Z',
        completedAt: null,
      },
      provider: {
        providerId: 'provider/reference',
        modelId: 'model/reference-v1',
        movingProvider: false,
      },
      budget: {
        status: 'REPORTED',
        requestLimit: 4,
        requestsUsed: 2,
        tokenLimit: 8_000,
        tokensUsed: 3_200,
      },
      milestones: [{
        milestoneId: 'INITIAL_CONTRIBUTION_FROZEN',
        state: 'REACHED',
        recordedAt: '2026-08-24T00:02:00.000Z',
      }],
      evidenceCount: 3,
      candidateCount: 1,
      completionDisposition: 'NOT_AVAILABLE',
      challengeRelations: [{
        relatedAttemptId: 'role-attempt-00000000-0000-0000-0000-000000000008',
        relation: 'CHALLENGED_BY',
      }],
    }, {
      schemaVersion: 1,
      roleDefinition: {
        roleId: 'attack-path-analyst',
        roleVersion: '1.0.0',
        definitionDigest: digest,
        independenceClass: 'DISTINCT_PROVIDER_OR_MODEL_FAMILY',
      },
      attempt: {
        attemptId: 'role-attempt-00000000-0000-0000-0000-000000000009',
        parentAttemptId: null,
        lifecycleState: 'COMPLETED',
        startedAt: '2026-08-24T00:01:00.000Z',
        completedAt: '2026-08-24T00:06:00.000Z',
      },
      provider: {
        providerId: 'provider/deep-reference',
        modelId: 'model/deep-reference-v1',
        movingProvider: false,
      },
      budget: {
        status: 'REPORTED',
        requestLimit: 6,
        requestsUsed: 5,
        tokenLimit: 12_000,
        tokensUsed: 9_500,
      },
      milestones: [{
        milestoneId: 'INITIAL_CONTRIBUTION_FROZEN',
        state: 'REACHED',
        recordedAt: '2026-08-24T00:03:00.000Z',
      }],
      evidenceCount: 2,
      candidateCount: 1,
      completionDisposition: 'COMPLETE',
      challengeRelations: [{
        relatedAttemptId: 'role-attempt-00000000-0000-0000-0000-000000000007',
        relation: 'CHALLENGES',
      }],
      analysisLane: {
        kind: 'DEEP_INDEPENDENT',
        passId: 'deep-pass-reference-v1',
        initialContributionState: 'FROZEN',
        executionPeerVisibility: 'FROZEN_CONTRIBUTIONS_ONLY',
        currentPhase: 'EVIDENCE_CONVERGENCE',
      },
      detail: {
        schemaVersion: 1,
        status: 'PUBLISHED',
        contribution: {
          contributionId: 'role-contribution-00000000-0000-0000-0000-000000000009',
          contributionVersion: 1,
          hypotheses: ['Untrusted template output reaches an executable browser context.'],
          candidateIds: [`candidate-${'9'.repeat(64)}`],
          coverageObservations: [{ obligationId: 'security/sast', state: 'GAP' }],
          evidenceArtifactIds: ['evidence-deep-reference'],
          evidenceRequestIds: ['request-template-context'],
          challenges: [{ challengeId: 'challenge-template-context', disposition: 'PROOF_GAP' }],
          uncertainty: ['The final rendering context remains unproven.'],
          limitations: ['No production request corpus was available.'],
          resourceUse: { status: 'REPORTED', requests: 5, tokens: 9_500 },
          completionDisposition: 'COMPLETE',
        },
        followUpRequests: [{
          requestId: 'follow-up-00000000-0000-0000-0000-000000000009',
          unresolvedObligationId: 'security/template-context',
          requestedRoleId: 'validation-analyst',
          requiredCapabilityId: 'capability/render-context-proof',
          evidenceArtifactIds: ['evidence-deep-reference'],
          reason: 'Validate the final browser rendering context.',
          disposition: 'ADMITTED',
          childAttemptId: 'role-attempt-00000000-0000-0000-0000-000000000010',
        }],
        challengePackages: [{
          packageId: 'challenge-package-00000000-0000-0000-0000-000000000009',
          targetAttemptId: 'role-attempt-00000000-0000-0000-0000-000000000007',
          state: 'RESPONDED',
          questionCount: 2,
          response: {
            status: 'ADMITTED',
            attemptId: 'role-attempt-00000000-0000-0000-0000-000000000007',
            disposition: 'PROOF_GAP',
          },
        }],
        evidenceConvergence: {
          status: 'IN_PROGRESS',
          resolvedCandidateCount: 0,
          unresolvedCandidateCount: 1,
        },
        transcript: { status: 'PROTECTED_EVIDENCE', artifactId: 'transcript-deep-reference' },
      },
    }],
    verdict: null,
    seal: null,
    createdAt: '2026-08-24T00:00:00.000Z',
    updatedAt: '2026-08-24T00:07:00.000Z',
  }
}

function selectionItem(id: AssessmentId, ordinal: number): AssessmentListItemV1 {
  return {
    schemaVersion: 1,
    assessmentId: id,
    assessmentRevision: ordinal,
    state: 'SEALED',
    repository: {
      repositoryId: `repo-00000000-0000-0000-0000-${String(ordinal).padStart(12, '0')}`,
      repositoryRevision: 1,
    } as AssessmentListItemV1['repository'],
    subjectKind: 'workspace_snapshot',
    policyId: 'security/standard',
    coverageStatus: 'COMPLETE',
    verdict: 'SATISFIED',
    createdAt: `2026-08-24T00:0${ordinal}:00.000Z`,
    updatedAt: `2026-08-24T00:0${ordinal}:30.000Z`,
  }
}

function findingSummaryItem(id: AssessmentId): FindingSummaryV1 {
  return {
    schemaVersion: 1,
    assessmentId: id,
    assessmentRevision: 7,
    recordKind: 'FINDING',
    recordId: `finding-${'f'.repeat(64)}`,
    candidateId: `candidate-${'f'.repeat(64)}`,
    recordRevision: 1,
    validationState: 'VALIDATED',
    validationContractId: 'security/validation/reference-v1',
    weaknessClassification: { primary: 'cwe/79', secondary: [] },
    technicalSeverity: 'HIGH',
    evidenceConfidence: 'HIGH',
    policySignificance: 'BLOCKING',
    component: 'src',
    sensitivity: 'PROTECTED_DETAIL',
    coverageRelations: [{ obligationId: 'security/output-encoding', state: 'SATISFIED' }],
    hasProtectedDetail: true,
  }
}

function findingDetailView(summary: FindingSummaryV1): FindingDetailViewV1 {
  const digest = {
    schemaVersion: 1 as const,
    algorithm: 'sha256' as const,
    mediaType: 'application/vnd.dsh.canonical-json',
    byteLength: 42,
    canonicalization: 'dsh-canonical-json-v1' as const,
    value: 'e'.repeat(64),
  }
  return {
    schemaVersion: 1,
    assessmentId: summary.assessmentId,
    assessmentRevision: summary.assessmentRevision,
    recordKind: summary.recordKind,
    recordId: summary.recordId,
    candidateId: summary.candidateId,
    recordRevision: summary.recordRevision,
    revisionChain: [{ recordRevision: 1, supersedesRecordRevision: null, isCurrent: true }],
    weaknessClassification: summary.weaknessClassification,
    affectedControlId: 'security/control/output-encoding',
    sourceAnchor: {
      path: 'src/render.ts',
      fileDigest: digest,
      locator: { kind: 'JSON_POINTER', value: '/render/html' },
    },
    validation: {
      state: 'VALIDATED',
      contractId: 'security/validation/reference-v1',
      contractVersion: 1,
      outcomeArtifactId: 'validation/outcome/reference',
      rejectionCondition: null,
      proofGaps: [],
      negativeControls: ['security/negative-control/encoded-output'],
    },
    technicalSeverity: {
      value: 'HIGH',
      methodVersion: 'security/severity/v1',
      inputs: [{ dimension: 'impact', value: 'account-takeover' }],
    },
    evidenceConfidence: {
      value: 'HIGH',
      methodVersion: 'security/confidence/v1',
      rubric: [{ dimension: 'reproducible', value: true }],
    },
    policySignificance: 'BLOCKING',
    coverageRelations: [{
      obligationId: 'security/output-encoding',
      state: 'SATISFIED',
      reason: 'ELIGIBLE_EVIDENCE',
    }],
    riskDecision: { state: 'NOT_RECORDED' },
    evidenceLinks: [{
      artifactId: 'evidence/reference-output-encoding',
      schemaId: 'security/evidence/reference-v1',
      digest,
      purpose: 'VALIDATION_EVIDENCE',
      eligibilityDecision: 'ELIGIBLE',
      eligibilityDecisionArtifactId: 'eligibility/reference-output-encoding',
    }],
    attackPath: { state: 'NOT_AVAILABLE' },
  }
}

function evidenceMetadataView(detail: FindingDetailViewV1): WorkbenchEvidenceMetadataViewV1 {
  const link = detail.evidenceLinks[0]
  if (link === undefined) throw new Error('Finding Detail fixture has no Evidence Link')
  return {
    schemaVersion: 1,
    assessmentId: detail.assessmentId,
    assessmentRevision: detail.assessmentRevision,
    context: {
      kind: 'finding',
      recordId: detail.recordId,
      recordRevision: detail.recordRevision,
    },
    evidence: {
      artifactId: link.artifactId,
      schemaId: link.schemaId,
      digest: link.digest,
      classification: 'CONTROL_PLANE',
    },
    link: {
      purpose: link.purpose,
      eligibilityDecision: link.eligibilityDecision,
      eligibilityDecisionArtifactId: link.eligibilityDecisionArtifactId,
    },
    producerLineage: {
      status: 'VERIFIED',
      producer: {
        analyzerId: 'security/reference-analyzer',
        analyzerVersion: '1.0.0',
        buildDigest: { ...link.digest, value: 'b'.repeat(64) },
      },
      lineageArtifactId: link.eligibilityDecisionArtifactId,
    },
    redactedSummary: {
      kind: 'SCHEMA_METADATA',
      byteLength: link.digest.byteLength,
      contentStatus: 'REDACTED',
    },
    purpose: 'FINDING_TRIAGE',
    viewProfileId: 'security/evidence-view/metadata-only-v1',
    protection: { policyId: 'evidence/local-protected', status: 'AVAILABLE' },
    retention: { status: 'RETAINED' },
    egress: { policyId: 'egress/deny-by-default', status: 'LOCAL_ONLY' },
    content: { kind: 'REDACTED', reason: 'PROFILE_METADATA_ONLY' },
  }
}

function evidenceDisclosureView(
  detail: FindingDetailViewV1,
  expiresAt: string,
): WorkbenchEvidenceDisclosureViewV1 {
  const metadata = evidenceMetadataView(detail)
  const value = { schemaVersion: 1, proof: 'bounded-ui-secret' }
  return {
    ...metadata,
    purpose: 'VALIDATION_REVIEW',
    viewProfileId: 'security/evidence-view/bounded-json-v1',
    content: {
      kind: 'BOUNDED_JSON',
      byteLength: JSON.stringify(value).length,
      expiresAt,
      value,
    },
  }
}

describe('Security Assurance Workbench UI', () => {
  it('renders bilingual metadata-only Evidence and returns to Finding Detail', async () => {
    const id = assessmentId('asm-00000000-0000-0000-0000-000000000072')
    const snapshot: AssessmentSnapshotV1 = {
      ...readySnapshot(id),
      state: 'SEALED',
      blockedRecovery: null,
      availableActions: [],
      verdict: 'FAILED',
    }
    const summary = findingSummaryItem(id)
    const detail = findingDetailView(summary)
    const view = evidenceMetadataView(detail)
    const authorityId = authorityContextId('workbench-session-evidence-ui')
    let disclosureCalls = 0
    const b = await bench((_path, endpoint) => {
      if (endpoint === 'securityAssuranceWorkbench/getAssessment') {
        return Promise.resolve({ ok: true, value: { ok: true, value: snapshot } })
      }
      if (endpoint === 'securityAssuranceWorkbench/listFindings') {
        return Promise.resolve({
          ok: true,
          value: {
            ok: true,
            value: {
              schemaVersion: 1,
              assessmentId: id,
              assessmentRevision: 7,
              findings: [summary],
              nextCursor: null,
            },
          },
        })
      }
      if (endpoint === 'securityAssuranceWorkbench/getFinding') {
        return Promise.resolve({ ok: true, value: { ok: true, value: detail } })
      }
      if (endpoint === 'securityAssuranceWorkbench/getEvidenceView') {
        return Promise.resolve({ ok: true, value: { ok: true, value: view } })
      }
      if (endpoint === 'securityAssuranceWorkbench/discloseEvidence') {
        disclosureCalls += 1
        const disclosure = evidenceDisclosureView(
          detail,
          new Date(Date.now() + 1_000).toISOString(),
        )
        return Promise.resolve({
          ok: true,
          value: {
            ok: true,
            value: disclosureCalls === 3
              ? {
                  ...disclosure,
                  content: {
                    kind: 'REDACTED',
                    reason: 'DISCLOSURE_NOT_AUTHORIZED',
                  },
                }
              : disclosure,
          },
        })
      }
      return Promise.reject(new Error(`Unexpected endpoint: ${endpoint}`))
    })
    const launcher = b.runtime.renderSlot('sidebar.footer.action', { wide: true })
    const overlay = b.runtime.renderSlot('shell.overlay', {})
    await act(async () => {
      fireEvent.click(launcher.view.getByRole('button', { name: '打开安全保障工作台' }))
      await b.controller.openAssessment({
        securityAssuranceWorkbenchContextId: authorityId,
        assessmentId: id,
      })
      await b.controller.openFindings()
      await b.controller.selectFinding(summary.recordId)
    })

    const evidenceLink = overlay.view.getByRole('button', {
      name: `查看 Evidence 元数据 ${view.evidence.artifactId}`,
    })
    evidenceLink.focus()
    expect(document.activeElement).toBe(evidenceLink)
    await act(async () => { fireEvent.click(evidenceLink) })
    expect(overlay.view.getByRole('heading', { name: 'Evidence 元数据' })).toBeTruthy()
    expect(document.activeElement).toBe(overlay.view.getByRole('button', {
      name: '返回 Finding 详情',
    }))
    expect(overlay.view.getAllByText(view.evidence.artifactId).length).toBeGreaterThanOrEqual(2)
    expect(overlay.view.getByText(view.evidence.schemaId)).toBeTruthy()
    expect(overlay.view.getByText(view.evidence.digest.value)).toBeTruthy()
    expect(overlay.view.getByText(view.evidence.digest.algorithm)).toBeTruthy()
    expect(overlay.view.getByText(view.evidence.digest.mediaType)).toBeTruthy()
    expect(overlay.view.getAllByText(String(view.evidence.digest.byteLength)).length).toBeGreaterThanOrEqual(2)
    expect(overlay.view.getByText(view.evidence.digest.canonicalization)).toBeTruthy()
    expect(overlay.view.getByText('CONTROL_PLANE')).toBeTruthy()
    expect(overlay.view.getByText('VALIDATION_EVIDENCE')).toBeTruthy()
    expect(overlay.view.getByText('ELIGIBLE')).toBeTruthy()
    expect(overlay.view.getByText('evidence/local-protected')).toBeTruthy()
    expect(overlay.view.getByText('RETAINED')).toBeTruthy()
    expect(overlay.view.getByText('egress/deny-by-default')).toBeTruthy()
    expect(overlay.view.getByText('LOCAL_ONLY')).toBeTruthy()
    expect(overlay.view.getByText('FINDING_TRIAGE')).toBeTruthy()
    expect(overlay.view.getByText('security/evidence-view/metadata-only-v1')).toBeTruthy()
    expect(overlay.view.getByText('REDACTED')).toBeTruthy()
    expect(overlay.view.getByText('PROFILE_METADATA_ONLY')).toBeTruthy()
    expect(overlay.view.queryByText('raw-evidence-value')).toBeNull()
    expect(overlay.view.queryByText('storagePath')).toBeNull()
    expect(overlay.view.queryByText(authorityId)).toBeNull()

    const disclose = overlay.view.getByRole('button', {
      name: '显式查看敏感 Evidence 内容',
    })
    disclose.focus()
    await act(async () => { fireEvent.click(disclose) })
    expect(overlay.view.getByRole('heading', { name: '敏感 Evidence 内容' })).toBeTruthy()
    expect(overlay.view.getByText(
      '此内容敏感、限时、仅用于 VALIDATION_REVIEW；关闭、隐藏、失去权限或到期后立即丢弃。',
    )).toBeTruthy()
    expect(overlay.view.getByText('VALIDATION_REVIEW')).toBeTruthy()
    expect(overlay.view.getByText('security/evidence-view/bounded-json-v1')).toBeTruthy()
    expect(overlay.view.getByText(/bounded-ui-secret/)).toBeTruthy()
    const hide = overlay.view.getByRole('button', { name: '隐藏并丢弃敏感内容' })
    expect(document.activeElement).toBe(hide)

    act(() => { b.locale.setLocale('en') })
    expect(overlay.view.getByRole('heading', { name: 'Sensitive Evidence content' })).toBeTruthy()
    expect(overlay.view.getByText(
      'This content is sensitive, time-limited, and restricted to VALIDATION_REVIEW; it is discarded on close, hide, authority loss, or expiry.',
    )).toBeTruthy()
    await act(async () => {
      fireEvent.click(overlay.view.getByRole('button', {
        name: 'Hide and discard sensitive content',
      }))
    })
    expect(overlay.view.queryByText(/bounded-ui-secret/)).toBeNull()
    expect(overlay.view.getByRole('heading', { name: 'Evidence metadata' })).toBeTruthy()
    expect(document.activeElement).toBe(overlay.view.getByRole('button', {
      name: 'Explicitly view sensitive Evidence content',
    }))
    expect(overlay.view.getByText('Digest schema version')).toBeTruthy()
    expect(overlay.view.getByText('Digest algorithm')).toBeTruthy()
    expect(overlay.view.getByText('Digest media type')).toBeTruthy()
    expect(overlay.view.getByText('Digest byte length')).toBeTruthy()
    expect(overlay.view.getByText('Digest canonicalization')).toBeTruthy()

    vi.useFakeTimers()
    await act(async () => {
      fireEvent.click(overlay.view.getByRole('button', {
        name: 'Explicitly view sensitive Evidence content',
      }))
    })
    expect(overlay.view.getByText(/bounded-ui-secret/)).toBeTruthy()
    await act(async () => { await vi.advanceTimersByTimeAsync(1_000) })
    expect(overlay.view.queryByText(/bounded-ui-secret/)).toBeNull()
    expect(overlay.view.getByText(
      'Sensitive content expired and was discarded from memory. Reauthorize to review it again.',
    )).toBeTruthy()
    await act(async () => {
      fireEvent.click(overlay.view.getByRole('button', {
        name: 'Explicitly view sensitive Evidence content',
      }))
    })
    expect(overlay.view.getByText('Security Service denied sensitive content disclosure.')).toBeTruthy()
    expect(overlay.view.getByText('DISCLOSURE_NOT_AUTHORIZED')).toBeTruthy()
    expect(overlay.view.queryByText(/bounded-ui-secret/)).toBeNull()
    await act(async () => {
      fireEvent.click(overlay.view.getByRole('button', {
        name: 'Hide and discard sensitive content',
      }))
    })
    await act(async () => {
      fireEvent.click(overlay.view.getByRole('button', { name: 'Back to Finding detail' }))
    })
    expect(overlay.view.getByRole('heading', { name: 'Finding Detail' })).toBeTruthy()
    expect(overlay.view.queryByRole('heading', { name: 'Evidence metadata' })).toBeNull()
    expect(document.activeElement).toBe(overlay.view.getByRole('button', {
      name: `View Evidence metadata ${view.evidence.artifactId}`,
    }))

    await b.feature.dispose()
    await b.gateway.dispose()
    await b.runtime.dispose()
  })

  it('navigates from multidimensional Finding triage to revision-bound Detail and back', async () => {
    const id = assessmentId('asm-00000000-0000-0000-0000-000000000071')
    const snapshot = readySnapshot(id)
    const summary = findingSummaryItem(id)
    const unresolved: FindingSummaryV1 = {
      ...summary,
      recordKind: 'UNRESOLVED_CANDIDATE',
      recordId: `candidate-${'1'.repeat(64)}`,
      candidateId: `candidate-${'1'.repeat(64)}`,
      validationState: 'UNRESOLVED',
      technicalSeverity: null,
      evidenceConfidence: 'LOW',
      policySignificance: null,
      hasProtectedDetail: false,
    }
    const detail = findingDetailView(summary)
    let findingPage = 0
    const b = await bench((_path, endpoint, _payload, signal) => {
      if (endpoint === 'securityAssuranceWorkbench/getAssessment') {
        return Promise.resolve({ ok: true, value: { ok: true, value: snapshot } })
      }
      if (endpoint === 'securityAssuranceWorkbench/waitForAssessmentRevision') {
        return new Promise(resolve => {
          signal.addEventListener('abort', () => {
            resolve({ ok: false, error: { code: 'aborted' } })
          }, { once: true })
        })
      }
      if (endpoint === 'securityAssuranceWorkbench/listFindings') {
        findingPage += 1
        return Promise.resolve({
          ok: true,
          value: {
            ok: true,
            value: {
              schemaVersion: 1,
              assessmentId: id,
              assessmentRevision: 7,
              findings: [findingPage === 1 ? summary : unresolved],
              nextCursor: findingPage === 1 ? 'finding.cursor' : null,
            },
          },
        })
      }
      if (endpoint === 'securityAssuranceWorkbench/getFinding') {
        return Promise.resolve({ ok: true, value: { ok: true, value: detail } })
      }
      return Promise.reject(new Error(`Unexpected endpoint: ${endpoint}`))
    })
    const launcher = b.runtime.renderSlot('sidebar.footer.action', { wide: true })
    const overlay = b.runtime.renderSlot('shell.overlay', {})
    await act(async () => {
      fireEvent.click(launcher.view.getByRole('button', { name: '打开安全保障工作台' }))
      await b.controller.openAssessment({
        securityAssuranceWorkbenchContextId: authorityContextId('workbench-session-finding-ui'),
        assessmentId: id,
      })
    })

    await act(async () => {
      fireEvent.click(overlay.view.getByRole('button', { name: '查看 Findings' }))
    })
    expect(overlay.view.getByRole('heading', { name: 'Findings' })).toBeTruthy()
    expect(overlay.view.getAllByText('cwe/79').length).toBeGreaterThanOrEqual(2)
    expect(overlay.view.getAllByText('HIGH').length).toBeGreaterThanOrEqual(2)
    expect(overlay.view.getAllByText('BLOCKING').length).toBeGreaterThanOrEqual(2)
    expect(overlay.view.getAllByText('VALIDATED').length).toBeGreaterThanOrEqual(2)
    expect(overlay.view.getByText('包含受保护详情')).toBeTruthy()
    expect(overlay.view.queryByText('src/render.ts')).toBeNull()

    await act(async () => {
      fireEvent.click(overlay.view.getByRole('button', { name: '加载更多 Findings' }))
    })
    expect(overlay.view.getByText(unresolved.recordId)).toBeTruthy()
    expect(overlay.view.getByText('UNRESOLVED_CANDIDATE')).toBeTruthy()
    expect(overlay.view.getAllByText('UNRESOLVED').length).toBeGreaterThanOrEqual(2)
    expect(overlay.view.queryByRole('button', { name: '加载更多 Findings' })).toBeNull()

    fireEvent.change(overlay.view.getByLabelText('验证结论'), { target: { value: 'UNRESOLVED' } })
    expect(overlay.view.queryByText(summary.recordId)).toBeNull()
    expect(overlay.view.getByText(unresolved.recordId)).toBeTruthy()
    fireEvent.change(overlay.view.getByLabelText('验证结论'), { target: { value: '' } })

    await act(async () => {
      fireEvent.click(overlay.view.getByRole('button', {
        name: `打开 Finding ${summary.recordId}`,
      }))
    })
    expect(overlay.view.getByRole('heading', { name: 'Finding 详情' })).toBeTruthy()
    expect(overlay.view.getByText('src/render.ts')).toBeTruthy()
    expect(overlay.view.getByText('/render/html')).toBeTruthy()
    expect(overlay.view.getByText('evidence/reference-output-encoding')).toBeTruthy()
    expect(overlay.view.getByText('NOT_RECORDED')).toBeTruthy()
    expect(overlay.view.queryByText('contentBase64')).toBeNull()

    await act(async () => {
      fireEvent.click(overlay.view.getByRole('button', { name: '返回 Finding 列表' }))
    })
    expect(overlay.view.getByRole('button', {
      name: `打开 Finding ${summary.recordId}`,
    })).toBeTruthy()

    await b.feature.dispose()
    await b.gateway.dispose()
    await b.runtime.dispose()
  })

  it('loads the next Assessment page once without rendering authority or cursor material', async () => {
    const firstId = assessmentId('asm-00000000-0000-0000-0000-000000000051')
    const secondId = assessmentId('asm-00000000-0000-0000-0000-000000000052')
    let calls = 0
    let resolveContinuation: ((value: unknown) => void) | undefined
    const b = await bench((_path, endpoint) => {
      if (endpoint !== 'securityAssuranceWorkbench/listAssessments') {
        return Promise.reject(new Error(`Unexpected endpoint: ${endpoint}`))
      }
      calls += 1
      if (calls === 1) {
        return Promise.resolve({
          ok: true,
          value: {
            ok: true,
            value: {
              schemaVersion: 1,
              consistencyWatermark: 'stable.signature',
              assessments: [selectionItem(firstId, 1)],
              nextCursor: 'cursor.signature',
            },
          },
        })
      }
      return new Promise(resolve => { resolveContinuation = resolve })
    })
    const launcher = b.runtime.renderSlot('sidebar.footer.action', { wide: true })
    const overlay = b.runtime.renderSlot('shell.overlay', {})
    const authorityId = authorityContextId('workbench-session-pagination-ui')
    await act(async () => {
      await b.controller.openAssessmentSelection({
        securityAssuranceWorkbenchContextId: authorityId,
      })
      fireEvent.click(launcher.view.getByRole('button', { name: '打开安全保障工作台' }))
    })

    expect(overlay.view.getByText(firstId)).toBeTruthy()
    const loadMore = overlay.view.getByRole('button', { name: '加载更多 Assessment' })
    await act(async () => { fireEvent.click(loadMore) })
    expect(overlay.view.getByRole<HTMLButtonElement>(
      'button',
      { name: '正在加载更多 Assessment' },
    ).disabled).toBe(true)
    expect(calls).toBe(2)

    await act(async () => {
      resolveContinuation?.({
        ok: true,
        value: {
          ok: true,
          value: {
            schemaVersion: 1,
            consistencyWatermark: 'stable.signature',
            assessments: [selectionItem(secondId, 2)],
            nextCursor: null,
          },
        },
      })
      await Promise.resolve()
    })
    expect(overlay.view.getByText(firstId)).toBeTruthy()
    expect(overlay.view.getByText(secondId)).toBeTruthy()
    expect(overlay.view.queryByRole('button', { name: '加载更多 Assessment' })).toBeNull()
    expect(overlay.view.queryByText('cursor.signature')).toBeNull()
    expect(overlay.view.queryByText(authorityId)).toBeNull()

    await b.feature.dispose()
    await b.gateway.dispose()
    await b.runtime.dispose()
  })

  it('renders an authority-scoped Assessment selector without credential inputs', async () => {
    const id = assessmentId('asm-00000000-0000-0000-0000-000000000011')
    const snapshot = readySnapshot(id)
    const b = await bench((_path, endpoint, _payload, signal) => {
      if (endpoint === 'securityAssuranceWorkbench/listAssessments') {
        return Promise.resolve({
          ok: true,
          value: {
            ok: true,
            value: {
              schemaVersion: 1,
              consistencyWatermark: 'watermark.signature',
              assessments: [{
                schemaVersion: 1,
                assessmentId: id,
                assessmentRevision: snapshot.assessmentRevision,
                state: snapshot.state,
                repository: snapshot.repository,
                subjectKind: snapshot.subject.kind,
                policyId: snapshot.policy.policyId,
                coverageStatus: snapshot.coverage.status,
                verdict: snapshot.verdict,
                createdAt: snapshot.createdAt,
                updatedAt: snapshot.updatedAt,
              }],
              nextCursor: null,
            },
          },
        })
      }
      if (endpoint === 'securityAssuranceWorkbench/getAssessment') {
        return Promise.resolve({ ok: true, value: { ok: true, value: snapshot } })
      }
      if (endpoint === 'securityAssuranceWorkbench/waitForAssessmentRevision') {
        return new Promise(resolve => {
          signal.addEventListener('abort', () => {
            resolve({ ok: false, error: { code: 'aborted' } })
          }, { once: true })
        })
      }
      return Promise.reject(new Error(`Unexpected endpoint: ${endpoint}`))
    })
    const launcher = b.runtime.renderSlot('sidebar.footer.action', { wide: true })
    const overlay = b.runtime.renderSlot('shell.overlay', {})
    await act(async () => {
      await b.controller.openAssessmentSelection({
        securityAssuranceWorkbenchContextId: authorityContextId('workbench-session-selector'),
      })
      fireEvent.click(launcher.view.getByRole('button', { name: '打开安全保障工作台' }))
    })

    const overviewHeading = overlay.view.getByRole('heading', { name: '概览' })
    expect(overviewHeading).toBeTruthy()
    expect(overviewHeading.closest('[data-workbench-view]')?.getAttribute('data-workbench-view')).toBe('overview')
    expect(overlay.view.getByText(id)).toBeTruthy()
    expect(overlay.view.queryByRole('textbox')).toBeNull()
    expect(overlay.view.queryByText('workbench-session-selector')).toBeNull()
    const selectionButton = overlay.view.getByRole('button', { name: `打开 ${id}` })
    fireEvent.keyDown(overlay.view.getByRole('dialog'), { key: 'Tab', shiftKey: true })
    expect(document.activeElement).toBe(selectionButton)
    await act(async () => {
      fireEvent.click(selectionButton)
    })
    expect(overlay.view.getByText('security/standard')).toBeTruthy()
    await act(async () => {
      fireEvent.click(overlay.view.getByRole('button', { name: '关闭工作台' }))
    })
    expect(b.controller.getState()).toEqual({ kind: 'CLOSED' })
    expect(overlay.view.queryByRole('dialog')).toBeNull()

    await b.feature.dispose()
    await b.gateway.dispose()
    await b.runtime.dispose()
  })

  it('renders bilingual Service-owned Runtime Health without repair or bypass controls', async () => {
    const health = {
      schemaVersion: 1,
      product: { name: 'dsh-security-assurance', version: '0.0.0-development' },
      compatibility: {
        targetHarnessVersion: '0.1.1-rc.2',
        requiredNodeRange: '^22.19.0 || >=24.0.0',
        actualNodeVersion: '22.19.0',
        harnessVerification: 'PENDING_INVARIANT',
      },
      state: 'READ_ONLY_SAFE',
      admission: { queries: true, mutations: false, sealedExports: false },
      checks: [
        { id: 'persistence.sqlite', status: 'FAIL', required: true, message: 'SQLite persistence is unavailable; configuration details are redacted.' },
        { id: 'runtime.node', status: 'PASS', required: true, message: 'Node.js runtime satisfies the required range.' },
        { id: 'compatibility.harness', status: 'NOT_EVALUATED', required: false, message: 'Harness compatibility remains a pending invariant.' },
      ],
    }
    const endpoints: string[] = []
    const b = await bench((_path, endpoint) => {
      endpoints.push(endpoint)
      if (endpoint === 'securityAssuranceWorkbench/listAssessments') {
        return Promise.resolve({
          ok: true,
          value: { ok: true, value: {
            schemaVersion: 1,
            consistencyWatermark: 'runtime-health.signature',
            assessments: [],
            nextCursor: null,
          } },
        })
      }
      if (endpoint === 'securityAssuranceWorkbench/getHealth') {
        return Promise.resolve({ ok: true, value: { ok: true, value: health } })
      }
      return Promise.reject(new Error(`Unexpected endpoint: ${endpoint}`))
    })
    const launcher = b.runtime.renderSlot('sidebar.footer.action', { wide: true })
    const overlay = b.runtime.renderSlot('shell.overlay', {})
    await act(async () => {
      await b.controller.openAssessmentSelection({
        securityAssuranceWorkbenchContextId: authorityContextId('workbench-session-health-ui'),
      })
      fireEvent.click(launcher.view.getByRole('button', { name: '打开安全保障工作台' }))
    })
    await act(async () => {
      fireEvent.click(overlay.view.getByRole('button', { name: 'Runtime Health' }))
    })

    expect(overlay.view.getByRole('heading', { name: 'Runtime Health' })).toBeTruthy()
    expect(overlay.view.getAllByText('READ_ONLY_SAFE').length).toBeGreaterThan(0)
    expect(overlay.view.getByText('dsh-security-assurance')).toBeTruthy()
    expect(overlay.view.getByText('0.0.0-development')).toBeTruthy()
    expect(overlay.view.getByRole('heading', { name: '操作准入' })).toBeTruthy()
    expect(overlay.view.getAllByText('false')).toHaveLength(2)
    expect(overlay.view.getByText('SQLite persistence is unavailable; configuration details are redacted.')).toBeTruthy()
    expect(overlay.view.getByText('Harness compatibility remains a pending invariant.')).toBeTruthy()
    expect(overlay.view.queryByRole('button', { name: /修复|绕过/u })).toBeNull()
    expect(endpoints).toEqual([
      'securityAssuranceWorkbench/listAssessments',
      'securityAssuranceWorkbench/getHealth',
    ])

    act(() => { b.locale.setLocale('en') })
    expect(overlay.view.getByRole('heading', { name: 'Operation admission' })).toBeTruthy()
    expect(overlay.view.getByText(/neither infers health nor offers browser-side repair or bypass actions/u)).toBeTruthy()
    expect(overlay.view.getByRole('button', { name: 'Reauthorize and refresh' })).toBeTruthy()

    await b.feature.dispose()
    await b.gateway.dispose()
    await b.runtime.dispose()
  })

  it('renders a bilingual Service-owned Export loop and consumes one digest-bound browser download', async () => {
    const id = assessmentId('asm-00000000-0000-0000-0000-0000000000c1')
    const digest = {
      schemaVersion: 1 as const,
      algorithm: 'sha256' as const,
      mediaType: 'application/vnd.dsh.security.bundle-manifest+json',
      byteLength: 128,
      canonicalization: 'dsh-canonical-json-v1' as const,
      value: 'c'.repeat(64),
    }
    const seal = {
      schemaVersion: 1 as const,
      sealId: 'seal-00000000-0000-0000-0000-0000000000c1',
      assessmentRevision: 8,
      verdict: 'SATISFIED' as const,
      digest,
      sealedAt: '2026-08-25T00:08:00.000Z',
    }
    const snapshot: AssessmentSnapshotV1 = {
      ...readySnapshot(id),
      assessmentRevision: 8,
      state: 'SEALED',
      blockedRecovery: null,
      availableActions: [],
      verdict: 'SATISFIED',
      seal,
    }
    const manifest = {
      schemaVersion: 1,
      assessmentId: id,
      assessmentRevision: 8,
      verdict: 'SATISFIED',
      seal,
      records: [{
        recordId: 'bundle/finding-set',
        schemaId: 'security/finding-set',
        schemaVersion: 1,
        classification: 'INTERNAL',
        digest,
      }],
      omissions: [{ schemaId: 'security/threat-model', reason: 'NO_ELIGIBLE_ANALYZER' }],
      digest,
    }
    const exportId = `export-${'e'.repeat(64)}`
    const exportBytes = Buffer.from(JSON.stringify({ schemaVersion: 1, source: { assessmentId: id } }), 'utf8')
    const exportDigestValue = createHash('sha256').update(exportBytes).digest('hex')
    const exportDigest = {
      ...digest,
      mediaType: 'application/vnd.dsh.security.export+json',
      byteLength: exportBytes.byteLength,
      canonicalization: 'raw-bytes' as const,
      value: exportDigestValue,
    }
    let exportStatusReads = 0
    const exportPreview = {
      schemaVersion: 1,
      kind: 'PREVIEW',
      assessmentId: id,
      assessmentRevision: 8,
      sealId: seal.sealId,
      profile: {
        exportProfileId: 'security/export/internal-json-v1',
        audience: 'INTERNAL',
        artifactFormat: 'JSON',
        mediaType: 'application/vnd.dsh.security.export+json',
        includedCategories: ['SUBJECT', 'FINDINGS', 'EVIDENCE', 'SEAL'],
        redactions: ['ORIGINAL_CREDENTIAL_VALUES', 'HOST_CREDENTIALS', 'PRIVATE_STORE_PATHS'],
      },
      destination: {
        deliveryDestinationId: 'delivery/local-audit',
        kind: 'HOST_REGISTERED_LOCAL_AUDIT',
        summary: 'Host-registered local audit delivery',
      },
      expiresAfterSeconds: 86_400,
      warnings: ['No private Store path or credential is disclosed.'],
    }
    const endpoints: string[] = []
    const b = await bench((_path, endpoint, payload) => {
      endpoints.push(endpoint)
      if (endpoint === 'securityAssuranceWorkbench/getAssessment') {
        return Promise.resolve({ ok: true, value: { ok: true, value: snapshot } })
      }
      if (endpoint === 'securityAssuranceWorkbench/getBundleManifest') {
        return Promise.resolve({ ok: true, value: { ok: true, value: manifest } })
      }
      if (endpoint === 'securityAssuranceWorkbench/getRepository') {
        return Promise.resolve({ ok: true, value: { ok: true, value: {
          schemaVersion: 1,
          repositoryId: snapshot.repository.repositoryId,
          repositoryRevision: snapshot.repository.repositoryRevision,
          state: 'ENABLED',
          displayName: 'Sealed repository',
          rootIdentityDigest: `sha256:${'d'.repeat(64)}`,
          bindings: {
            policyId: 'security/standard',
            assessmentProfileId: 'security/standard',
            evidenceProtectionId: 'evidence/local-protected',
            dataEgressPolicyId: 'egress/deny-by-default',
            platform: 'win32',
            deliveryDestinationIds: ['delivery/local-audit', 'delivery/team-report'],
          },
          createdAt: '2026-08-25T00:00:00.000Z',
          updatedAt: '2026-08-25T00:00:00.000Z',
        } } })
      }
      if (endpoint === 'securityAssuranceWorkbench/getExport') {
        const request = (payload as {
          readonly args: { readonly request: { readonly kind: 'PREVIEW' | 'STATUS' | 'DOWNLOAD' } }
        }).args.request
        if (request.kind === 'PREVIEW') {
          return Promise.resolve({ ok: true, value: { ok: true, value: exportPreview } })
        }
        if (request.kind === 'DOWNLOAD') {
          return Promise.resolve({ ok: true, value: { ok: true, value: {
            schemaVersion: 1,
            kind: 'DOWNLOAD',
            exportId,
            assessmentId: id,
            assessmentRevision: 8,
            artifactId: `${exportId}/artifact`,
            fileName: 'dsh-security-export.json',
            mediaType: 'application/vnd.dsh.security.export+json',
            byteLength: exportBytes.byteLength,
            digest: exportDigest,
            capability: {
              kind: 'CONSUMED_ONE_USE',
              issuedAt: '2026-08-25T00:09:02.000Z',
              expiresAt: '2026-08-25T00:10:02.000Z',
              consumedAt: '2026-08-25T00:09:02.001Z',
            },
            content: { encoding: 'base64', value: exportBytes.toString('base64') },
          } } })
        }
        exportStatusReads += 1
        const pending = exportStatusReads === 1
        const expired = exportStatusReads >= 3
        return Promise.resolve({ ok: true, value: { ok: true, value: {
          schemaVersion: 1,
          kind: 'STATUS',
          exportId,
          assessmentId: id,
          assessmentRevision: 8,
          status: pending ? 'PENDING' : expired ? 'EXPIRED' : 'DELIVERED',
          profile: exportPreview.profile,
          destination: exportPreview.destination,
          artifact: pending || expired ? null : { artifactId: `${exportId}/artifact`, digest: exportDigest },
          expiresAt: pending ? null : '2026-08-26T00:09:00.000Z',
          retention: pending
            ? { status: 'NOT_RETAINED' }
            : expired
              ? {
                  status: 'PURGED',
                  tombstone: {
                    artifactId: `${exportId}/artifact`,
                    digest: exportDigest,
                    expiredAt: '2026-08-26T00:09:00.000Z',
                    deletionAuthority: 'SECURITY_SERVICE_RETENTION',
                    reason: 'ARTIFACT_EXPIRED',
                  },
                  purgeRequestedAt: '2026-08-26T00:09:00.001Z',
                  purgedAt: '2026-08-26T00:09:00.002Z',
                }
              : { status: 'RETAINED' },
          delivery: {
            attemptCount: pending ? 1 : 2,
            lastAttemptAt: pending ? '2026-08-25T00:09:01.000Z' : '2026-08-25T00:09:02.000Z',
            lastFailureAt: '2026-08-25T00:09:01.000Z',
            lastFailureCode: 'ARTIFACT_IO_ERROR',
            nextRetryAt: pending ? '2026-08-25T00:09:02.000Z' : null,
          },
          accessAction: pending
            ? { kind: 'NONE', reason: 'DELIVERY_PENDING' }
            : expired
              ? { kind: 'NONE', reason: 'ARTIFACT_EXPIRED' }
            : {
                kind: 'ONE_USE_DOWNLOAD',
                action: 'REQUEST_ONE_USE_DOWNLOAD',
                capabilityExpiresAfterSeconds: 60,
                maxByteLength: 16 * 1024 * 1024,
              },
          failure: null,
          createdAt: '2026-08-25T00:09:00.000Z',
          updatedAt: pending
            ? '2026-08-25T00:09:01.000Z'
            : expired
              ? '2026-08-26T00:09:00.002Z'
              : '2026-08-25T00:09:02.000Z',
        } } })
      }
      if (endpoint === 'securityAssuranceWorkbench/requestExport') {
        const idempotencyKey = (payload as {
          readonly args: { readonly request: { readonly idempotencyKey: string } }
        }).args.request.idempotencyKey
        return Promise.resolve({ ok: true, value: { ok: true, value: {
          schemaVersion: 1,
          operation: 'request_export',
          exportId,
          assessmentId: id,
          assessmentRevision: 8,
          idempotencyKey,
          acceptedState: 'PENDING',
          acceptedAt: '2026-08-25T00:09:00.000Z',
          correlationId: 'sec-00000000-0000-0000-0000-0000000000e1',
        } } })
      }
      return Promise.reject(new Error(`Unexpected endpoint: ${endpoint}`))
    })
    const launcher = b.runtime.renderSlot('sidebar.footer.action', { wide: true })
    const overlay = b.runtime.renderSlot('shell.overlay', {})
    await act(async () => {
      await b.controller.openAssessment({
        securityAssuranceWorkbenchContextId: authorityContextId('workbench-session-bundle-ui'),
        assessmentId: id,
      })
      fireEvent.click(launcher.view.getByRole('button', { name: '打开安全保障工作台' }))
    })
    await act(async () => {
      fireEvent.click(overlay.view.getByRole('button', { name: '查看 Bundle 与 Export Readiness' }))
    })

    expect(overlay.view.getByRole('heading', { name: 'Bundle 与 Export Readiness' })).toBeTruthy()
    expect(overlay.view.getByText('bundle/finding-set')).toBeTruthy()
    expect(overlay.view.getByText('security/finding-set@1')).toBeTruthy()
    expect(overlay.view.getByText('NO_ELIGIBLE_ANALYZER')).toBeTruthy()
    expect(overlay.view.getByText('delivery/local-audit')).toBeTruthy()
    expect(overlay.view.getByText('delivery/team-report')).toBeTruthy()
    expect(overlay.view.queryByRole('button', { name: /下载/u })).toBeNull()
    expect(overlay.view.queryByText(/^[A-Z]:\\/u)).toBeNull()
    expect(endpoints).toEqual([
      'securityAssuranceWorkbench/getAssessment',
      'securityAssuranceWorkbench/getBundleManifest',
      'securityAssuranceWorkbench/getRepository',
    ])

    await act(async () => {
      fireEvent.click(overlay.view.getAllByRole('button', { name: '预览 Export' })[0]!)
    })
    expect(endpoints.at(-1)).toBe('securityAssuranceWorkbench/getExport')
    expect(overlay.view.getByRole('heading', { name: 'Export Preview 与 Delivery' })).toBeTruthy()
    expect(overlay.view.getByText('security/export/internal-json-v1')).toBeTruthy()
    expect(overlay.view.getByText('ORIGINAL_CREDENTIAL_VALUES')).toBeTruthy()
    expect(overlay.view.getByText('PRIVATE_STORE_PATHS')).toBeTruthy()
    expect(overlay.view.queryByText(/^[A-Z]:\\/u)).toBeNull()

    await act(async () => {
      fireEvent.click(overlay.view.getByRole('button', { name: '请求并交付 Export' }))
    })
    expect(overlay.view.getByText(exportId)).toBeTruthy()
    expect(overlay.view.getAllByText('PENDING').length).toBeGreaterThan(0)
    expect(overlay.view.getByText('NOT_RETAINED')).toBeTruthy()
    expect(overlay.view.getByText('ARTIFACT_IO_ERROR')).toBeTruthy()
    expect(overlay.view.getAllByText('2026-08-25T00:09:02.000Z').length).toBeGreaterThan(0)
    expect(overlay.view.getByRole('button', { name: '刷新 Delivery 状态' })).toBeTruthy()
    expect(overlay.view.queryByRole('button', { name: '授权并下载一次' })).toBeNull()
    expect(endpoints.slice(-3)).toEqual([
      'securityAssuranceWorkbench/getExport',
      'securityAssuranceWorkbench/requestExport',
      'securityAssuranceWorkbench/getExport',
    ])

    await act(async () => {
      fireEvent.click(overlay.view.getByRole('button', { name: '刷新 Delivery 状态' }))
    })
    expect(overlay.view.getAllByText('DELIVERED').length).toBeGreaterThan(0)
    expect(overlay.view.getByText('RETAINED')).toBeTruthy()
    expect(overlay.view.getByText('sec-00000000-0000-0000-0000-0000000000e1')).toBeTruthy()
    expect(overlay.view.getByText(exportDigestValue)).toBeTruthy()
    expect(overlay.view.getByRole('button', { name: '授权并下载一次' })).toBeTruthy()
    expect(endpoints.at(-1)).toBe('securityAssuranceWorkbench/getExport')

    const createObjectURL = vi.fn(() => 'blob:dsh-security-one-use')
    const revokeObjectURL = vi.fn()
    Object.defineProperty(globalThis.URL, 'createObjectURL', { configurable: true, value: createObjectURL })
    Object.defineProperty(globalThis.URL, 'revokeObjectURL', { configurable: true, value: revokeObjectURL })
    const anchorClick = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {})
    await act(async () => {
      fireEvent.click(overlay.view.getByRole('button', { name: '授权并下载一次' }))
    })
    expect(endpoints.at(-1)).toBe('securityAssuranceWorkbench/getExport')
    expect(createObjectURL).toHaveBeenCalledOnce()
    expect(anchorClick).toHaveBeenCalledOnce()
    expect(overlay.view.getByRole('status').textContent).toContain('一次性下载已完成')
    expect(overlay.view.getByText('dsh-security-export.json')).toBeTruthy()
    expect(JSON.stringify(b.controller.getState())).not.toContain(exportBytes.toString('base64'))
    expect(window.location.href).not.toContain('blob:dsh-security-one-use')
    await waitFor(() => { expect(revokeObjectURL).toHaveBeenCalledWith('blob:dsh-security-one-use') })
    anchorClick.mockRestore()
    delete (globalThis.URL as { createObjectURL?: unknown }).createObjectURL
    delete (globalThis.URL as { revokeObjectURL?: unknown }).revokeObjectURL

    await act(async () => {
      fireEvent.click(overlay.view.getByRole('button', { name: '刷新 Delivery 状态' }))
    })
    expect(overlay.view.getAllByText('EXPIRED').length).toBeGreaterThan(0)
    expect(overlay.view.getByText('PURGED')).toBeTruthy()
    expect(overlay.view.getByText('ARTIFACT_EXPIRED')).toBeTruthy()
    expect(overlay.view.getByText(exportDigestValue)).toBeTruthy()
    expect(overlay.view.queryByRole('button', { name: '授权并下载一次' })).toBeNull()

    act(() => { b.locale.setLocale('en') })
    expect(overlay.view.getByRole('heading', { name: 'Bundle and Export Readiness' })).toBeTruthy()
    expect(overlay.view.getByText(/no path, credential, or preloaded artifact bytes enter the browser/u)).toBeTruthy()
    await act(async () => {
      fireEvent.click(overlay.view.getByRole('button', { name: 'Back to Assessment detail' }))
    })
    expect(overlay.view.getAllByText('SEALED').length).toBeGreaterThan(0)

    await b.feature.dispose()
    await b.gateway.dispose()
    await b.runtime.dispose()
  })

  it('renders a bilingual Catalog-only New Assessment wizard and immutable preflight', async () => {
    const repository = {
      schemaVersion: 1 as const,
      repositoryId: 'repo-00000000-0000-0000-0000-000000000021' as const,
      repositoryRevision: 4,
      state: 'ENABLED' as const,
      displayName: '支付服务',
      rootIdentityDigest: `sha256:${'2'.repeat(64)}`,
      bindings: {
        policyId: 'security/node-package-lifecycle',
        assessmentProfileId: 'security/standard',
        evidenceProtectionId: 'evidence/local-protected',
        dataEgressPolicyId: 'egress/deny-by-default',
        platform: 'win32' as const,
        deliveryDestinationIds: [],
      },
      createdAt: '2026-08-24T00:00:00.000Z',
      updatedAt: '2026-08-24T00:04:00.000Z',
    }
    const proposalDigest = {
      schemaVersion: 1 as const,
      algorithm: 'sha256' as const,
      mediaType: 'application/vnd.dsh.security.start-preflight+json',
      byteLength: 1,
      canonicalization: 'dsh-canonical-json-v1' as const,
      value: 'e'.repeat(64),
    }
    const baseCatalog = {
      schemaVersion: 1 as const,
      repository,
      assessmentModes: [{
        assessmentMode: 'REPOSITORY' as const,
        label: { en: 'Repository', zhCN: '完整仓库' },
        targetKind: 'repository' as const,
        subjectKinds: ['workspace_snapshot'] as const,
        support: 'SUPPORTED' as const,
        limitations: ['Only package lifecycle policy is evaluated.'],
      }],
      assessmentProfiles: [{
        assessmentProfileId: 'security/standard',
        label: { en: 'Standard', zhCN: '标准' },
        maximumBudget: { status: 'NOT_REPORTED' as const },
        limitations: ['No numeric budget is reported.'],
      }],
      strongerControls: [{
        controlId: 'security/risk-decision-window-v1',
        label: { en: 'Risk decision window', zhCN: '风险决策窗口' },
        requiresControlIds: [],
      }],
      supportedEcosystemIds: ['node-package-manifest'],
      supportedPlatforms: ['win32', 'linux', 'darwin'] as const,
      supportMatrixReferences: ['dsh-security-assurance/support-matrix/v0.1-development'],
      startPreflight: null,
    }
    const b = await bench((_path, endpoint, payload) => {
      if (endpoint === 'securityAssuranceWorkbench/listAssessments') {
        return Promise.resolve({
          ok: true,
          value: { ok: true, value: {
            schemaVersion: 1,
            consistencyWatermark: 'wizard.signature',
            assessments: [],
            nextCursor: null,
          } },
        })
      }
      if (endpoint === 'securityAssuranceWorkbench/listRepositories') {
        return Promise.resolve({
          ok: true,
          value: { ok: true, value: { schemaVersion: 1, repositories: [repository], truncated: false } },
        })
      }
      if (endpoint === 'securityAssuranceWorkbench/getCatalog') {
        const request = (payload as {
          readonly args: { readonly request: { readonly proposedStart?: import('../src/contracts.ts').StartAssessmentSelectionV1 } }
        }).args.request
        if (request.proposedStart === undefined) {
          return Promise.resolve({ ok: true, value: { ok: true, value: baseCatalog } })
        }
        return Promise.resolve({
          ok: true,
          value: { ok: true, value: {
            ...baseCatalog,
            startPreflight: {
              schemaVersion: 1,
              repository: {
                repositoryId: repository.repositoryId,
                repositoryRevision: repository.repositoryRevision,
                displayName: repository.displayName,
              },
              selection: request.proposedStart,
              effectivePolicyId: repository.bindings.policyId,
              effectiveProfileId: repository.bindings.assessmentProfileId,
              providerComposition: [{
                providerId: 'dsh-security-assurance',
                analyzerId: 'dsh/builtin-node-package-lifecycle',
                analyzerVersion: '1.0.0',
                executionClass: 'PURE',
                eligibility: 'ELIGIBLE',
                reason: null,
                supportedEcosystemIds: ['node-package-manifest'],
                supportedPlatforms: ['win32', 'linux', 'darwin'],
                coverageObligationIds: ['node-package-install-lifecycle-policy'],
              }],
              dataEgress: {
                policyId: repository.bindings.dataEgressPolicyId,
                destinationIds: [],
                categories: ['NONE'],
              },
              evidenceProtection: { policyId: repository.bindings.evidenceProtectionId },
              maximumBudget: { status: 'NOT_REPORTED' },
              unsupportedConditions: [],
              claimLimitations: ['Only package lifecycle policy is evaluated.'],
              coverageLimitations: ['Only package lifecycle policy is evaluated.'],
              admissible: true,
              proposalDigest,
            },
          } },
        })
      }
      return Promise.reject(new Error(`Unexpected endpoint: ${endpoint}`))
    })
    const launcher = b.runtime.renderSlot('sidebar.footer.action', { wide: true })
    const overlay = b.runtime.renderSlot('shell.overlay', {})
    await act(async () => {
      await b.controller.openAssessmentSelection({
        securityAssuranceWorkbenchContextId: authorityContextId('workbench-session-wizard-ui'),
      })
      fireEvent.click(launcher.view.getByRole('button', { name: '打开安全保障工作台' }))
    })
    await waitFor(() => {
      expect(overlay.view.getByRole('button', { name: 'Repositories 与新建 Assessment' })).toBeTruthy()
    })
    await act(async () => {
      fireEvent.click(overlay.view.getByRole('button', { name: 'Repositories 与新建 Assessment' }))
    })
    await waitFor(() => {
      expect(overlay.view.getByRole('heading', { name: 'Repositories' })).toBeTruthy()
    })
    expect(overlay.view.getByText('支付服务')).toBeTruthy()
    expect(overlay.view.queryByLabelText('Repository root')).toBeNull()

    await act(async () => {
      fireEvent.click(overlay.view.getByRole('button', { name: '新建 Assessment' }))
    })
    await waitFor(() => {
      expect(overlay.view.getByRole('heading', { name: '新建 Assessment' })).toBeTruthy()
    })
    expect(overlay.view.getByRole<HTMLSelectElement>('combobox', { name: 'Assessment Mode' }).value).toBe('REPOSITORY')
    expect(overlay.view.getByText('完整仓库 (REPOSITORY)')).toBeTruthy()
    expect(overlay.view.getByText('标准 (security/standard)')).toBeTruthy()
    expect(overlay.view.queryByLabelText('Provider')).toBeNull()
    expect(overlay.view.queryByLabelText('Analyzer')).toBeNull()
    expect(overlay.view.queryByLabelText('Policy')).toBeNull()

    await act(async () => {
      fireEvent.click(overlay.view.getByRole('button', { name: '生成并复核预检' }))
    })
    await waitFor(() => {
      expect(overlay.view.getByRole('heading', { name: 'Start Preflight' })).toBeTruthy()
    })
    expect(overlay.view.getByText('dsh/builtin-node-package-lifecycle@1.0.0')).toBeTruthy()
    expect(overlay.view.getByText('egress/deny-by-default / NONE')).toBeTruthy()
    expect(overlay.view.getByText('evidence/local-protected')).toBeTruthy()
    expect(overlay.view.getByText('NOT_REPORTED')).toBeTruthy()
    expect(overlay.view.getByText('e'.repeat(64))).toBeTruthy()
    expect(overlay.view.getByRole('button', { name: '确认并启动 Assessment' })).toBeTruthy()

    act(() => { b.locale.setLocale('en') })
    expect(overlay.view.getByText('Every value below is resolved by the Security Service. Confirmation accepts only this digest-bound proposal; changing a selection requires a new preflight.')).toBeTruthy()

    await b.feature.dispose()
    await b.gateway.dispose()
    await b.runtime.dispose()
  })

  it('opens a bilingual empty dialog from the additive Host slots and returns focus on close', async () => {
    const b = await bench()
    const launcher = b.runtime.renderSlot('sidebar.footer.action', { wide: true })
    const overlay = b.runtime.renderSlot('shell.overlay', {})

    const open = launcher.view.getByRole('button', { name: '打开安全保障工作台' })
    open.focus()
    await act(async () => { fireEvent.click(open) })
    expect(overlay.view.getByRole('dialog', { name: '安全保障工作台' })).toBeTruthy()
    expect(overlay.view.getByText('尚未选择评估')).toBeTruthy()
    expect(overlay.view.getByText('请通过已认证的宿主集成打开一个 Assessment。')).toBeTruthy()

    act(() => { b.locale.setLocale('en') })
    expect(overlay.view.getByRole('dialog', { name: 'Security Assurance Workbench' })).toBeTruthy()
    expect(overlay.view.getByText('No assessment selected')).toBeTruthy()

    const close = overlay.view.getByRole('button', { name: 'Close Workbench' })
    expect(document.activeElement).toBe(close)
    await act(async () => { fireEvent.click(close) })
    expect(overlay.view.queryByRole('dialog')).toBeNull()
    expect(document.activeElement).toBe(open)
    expect(b.controller.getState()).toEqual({ kind: 'CLOSED' })

    await b.feature.dispose()
    expect(b.runtime.slots.entries('sidebar.footer.action')).toHaveLength(0)
    expect(b.runtime.slots.entries('shell.overlay')).toHaveLength(0)
    await b.gateway.dispose()
    await b.runtime.dispose()
  })

  it('renders the Controller Snapshot and service-projected actions without exposing mutations', async () => {
    const id = assessmentId('asm-00000000-0000-0000-0000-000000000007')
    const snapshot = readySnapshot(id)
    const resumed: AssessmentSnapshotV1 = {
      ...snapshot,
      assessmentRevision: 8,
      state: 'CREATED',
      blockedRecovery: null,
      availableActions: [],
      updatedAt: '2026-08-24T00:08:00.000Z',
    }
    const resumePayloads: unknown[] = []
    let assessmentReads = 0
    const b = await bench((_path, endpoint, payload, signal) => {
      if (endpoint === 'securityAssuranceWorkbench/getAssessment') {
        assessmentReads += 1
        return Promise.resolve({
          ok: true,
          value: { ok: true, value: assessmentReads === 1 ? snapshot : resumed },
        })
      }
      if (endpoint === 'securityAssuranceWorkbench/waitForAssessmentRevision') {
        return new Promise(resolve => {
          signal.addEventListener('abort', () => { resolve({ ok: false, error: { code: 'aborted' } }) }, { once: true })
        })
      }
      if (endpoint === 'securityAssuranceWorkbench/resumeAssessment') {
        resumePayloads.push(payload)
        const idempotencyKey = (payload as {
          readonly args: { readonly request: { readonly idempotencyKey: string } }
        }).args.request.idempotencyKey
        return Promise.resolve({
          ok: true,
          value: {
            ok: true,
            value: {
              schemaVersion: 1,
              operation: 'resume_assessment',
              assessmentId: id,
              assessmentRevision: 8,
              state: 'CREATED',
              idempotencyKey,
              acceptedAt: '2026-08-24T00:08:00.000Z',
              correlationId: 'sec-00000000-0000-0000-0000-000000000007',
            },
          },
        })
      }
      return Promise.reject(new Error(`Unexpected endpoint: ${endpoint}`))
    })
    const launcher = b.runtime.renderSlot('sidebar.footer.action', { wide: true })
    const overlay = b.runtime.renderSlot('shell.overlay', {})
    await act(async () => {
      fireEvent.click(launcher.view.getByRole('button', { name: '打开安全保障工作台' }))
      await b.controller.openAssessment({
        securityAssuranceWorkbenchContextId: authorityContextId('workbench-session-reviewer'),
        assessmentId: id,
      })
    })

    expect(b.controller.getState()).toMatchObject({
      kind: 'READY',
      snapshot: {
        roleCards: [{}, {
          detail: { status: 'PUBLISHED' },
          analysisLane: { kind: 'DEEP_INDEPENDENT' },
        }],
      },
    })
    expect(overlay.view.getByText(id)).toBeTruthy()
    expect(overlay.view.getAllByText('BLOCKED').length).toBeGreaterThanOrEqual(2)
    expect(overlay.view.getAllByText('GAP').length).toBeGreaterThanOrEqual(1)
    expect(overlay.view.getByText('0 / 2')).toBeTruthy()
    expect(overlay.view.getByText('security/standard')).toBeTruthy()
    expect(overlay.view.getAllByText('尚未生成')).toHaveLength(2)
    expect(overlay.view.getAllByText('RESUME_ASSESSMENT').length).toBeGreaterThanOrEqual(1)
    expect(overlay.view.getAllByText('CANCEL_ASSESSMENT').length).toBeGreaterThanOrEqual(1)
    expect(overlay.view.getByRole('heading', { name: '阻塞恢复' })).toBeTruthy()
    expect(overlay.view.getAllByText('ASSESSMENT_EXECUTION_FAILED').length).toBeGreaterThanOrEqual(1)
    expect(overlay.view.getByText('EXPLICIT_RESUME_REQUIRED')).toBeTruthy()
    expect(overlay.view.getAllByText('NOT_REPORTED').length).toBeGreaterThanOrEqual(1)
    expect(overlay.view.getByText('INDETERMINATE')).toBeTruthy()
    expect(overlay.view.getAllByText('ANALYZER_INCOMPLETE').length).toBeGreaterThanOrEqual(1)
    expect(overlay.view.getByRole('heading', { name: '修订绑定的评估进度' })).toBeTruthy()
    expect(overlay.view.getByText('SUBJECT_FREEZE')).toBeTruthy()
    expect(overlay.view.getByRole('heading', { name: '角色卡' })).toBeTruthy()
    expect(overlay.view.getByText('validation-analyst@1.0.0')).toBeTruthy()
    expect(overlay.view.getByText('CHALLENGED_BY')).toBeTruthy()
    const roleDetail = overlay.view.getByText('不可变 Role Detail').closest('.dsh-security-role-detail')
    expect(roleDetail).toBeTruthy()
    expect(roleDetail?.textContent).toContain('Deep 独立分析通道')
    expect(roleDetail?.textContent).toContain('初始 Contributions')
    expect(roleDetail?.textContent).toContain('Challenge Packages')
    expect(roleDetail?.textContent).toContain('Evidence Convergence')
    expect(roleDetail?.textContent).toContain('role-contribution-00000000-0000-0000-0000-000000000009')
    expect(roleDetail?.textContent).toContain('follow-up-00000000-0000-0000-0000-000000000009')
    expect(roleDetail?.textContent).toContain('challenge-package-00000000-0000-0000-0000-000000000009')
    expect(roleDetail?.textContent).toContain('transcript-deep-reference')
    expect(roleDetail?.querySelector('button,input,textarea,select')).toBeNull()
    expect(overlay.view.getByText(`${id}:assessment-execution:6`)).toBeTruthy()
    expect(overlay.view.getByText('ELIGIBLE_FOR_CALLER')).toBeTruthy()
    expect(overlay.view.getAllByText('EVIDENCE_INELIGIBLE').length).toBeGreaterThanOrEqual(1)
    expect(overlay.view.getByText('操作入口严格来自 Security Service 快照；仅已实现的治理表单可提交。')).toBeTruthy()
    expect(overlay.view.getByRole('button', { name: '查看 Findings' })).toBeTruthy()
    const resume = overlay.view.getByRole('button', { name: '恢复 Assessment' })
    const cancel = overlay.view.getByRole('button', { name: '请求取消 Assessment' })
    expect((resume as HTMLButtonElement).disabled).toBe(true)
    expect((cancel as HTMLButtonElement).disabled).toBe(true)

    fireEvent.change(overlay.view.getByRole('textbox', { name: '操作原因代码' }), {
      target: { value: 'OPERATOR_RETRY' },
    })
    fireEvent.change(overlay.view.getByRole('textbox', { name: '操作原因说明' }), {
      target: { value: 'Retry the frozen contract after restoring the analyzer host.' },
    })
    expect((resume as HTMLButtonElement).disabled).toBe(false)
    await act(async () => { fireEvent.click(resume) })
    await waitFor(() => {
      expect(b.controller.getState()).toMatchObject({
        kind: 'READY',
        snapshot: { assessmentRevision: 8, state: 'CREATED', blockedRecovery: null },
        assessmentCommand: { kind: 'IDLE' },
      })
    })
    expect(resumePayloads).toHaveLength(1)
    expect(resumePayloads[0]).toMatchObject({
      args: {
        securityAssuranceWorkbenchContextId: 'workbench-session-reviewer',
        request: {
          schemaVersion: 1,
          contractVersion: 1,
          assessmentId: id,
          expectedAssessmentRevision: 7,
          idempotencyKey: expect.stringMatching(/^workbench-resume:[0-9a-f-]{36}$/),
          reason: {
            code: 'OPERATOR_RETRY',
            summary: 'Retry the frozen contract after restoring the analyzer host.',
          },
        },
      },
    })
    expect(JSON.stringify(resumePayloads[0])).not.toContain('principalId')
    expect(overlay.view.queryByRole('heading', { name: '阻塞恢复' })).toBeNull()

    await b.feature.dispose()
    await b.gateway.dispose()
    await b.runtime.dispose()
  })

  it('submits a governed Risk Decision without accepting browser-authored authority', async () => {
    const id = assessmentId('asm-00000000-0000-0000-0000-000000000082')
    const summary = findingSummaryItem(id)
    const detail = findingDetailView(summary)
    const snapshot: AssessmentSnapshotV1 = {
      ...readySnapshot(id),
      availableActions: [{
        kind: 'RECORD_RISK_DECISION',
        expectedAssessmentRevision: 7,
        finding: {
          recordId: summary.recordId,
          recordRevision: summary.recordRevision,
        },
        options: [{
          decision: 'DENY',
          consequence: 'KEEPS_FINDING_BLOCKING',
        }],
      }],
    }
    const committed: AssessmentSnapshotV1 = {
      ...snapshot,
      assessmentRevision: 8,
      state: 'SEALED',
      blockedRecovery: null,
      availableActions: [],
      verdict: 'FAILED',
      updatedAt: '2026-08-24T00:08:00.000Z',
    }
    const riskPayloads: unknown[] = []
    let assessmentReads = 0
    const b = await bench((_path, endpoint, payload, signal) => {
      if (endpoint === 'securityAssuranceWorkbench/getAssessment') {
        assessmentReads += 1
        return Promise.resolve({
          ok: true,
          value: { ok: true, value: assessmentReads === 1 ? snapshot : committed },
        })
      }
      if (endpoint === 'securityAssuranceWorkbench/waitForAssessmentRevision') {
        return new Promise(resolve => {
          signal.addEventListener('abort', () => {
            resolve({ ok: false, error: { code: 'aborted' } })
          }, { once: true })
        })
      }
      if (endpoint === 'securityAssuranceWorkbench/listFindings') {
        return Promise.resolve({
          ok: true,
          value: {
            ok: true,
            value: {
              schemaVersion: 1,
              assessmentId: id,
              assessmentRevision: 7,
              findings: [summary],
              nextCursor: null,
            },
          },
        })
      }
      if (endpoint === 'securityAssuranceWorkbench/getFinding') {
        return Promise.resolve({ ok: true, value: { ok: true, value: detail } })
      }
      if (endpoint === 'securityAssuranceWorkbench/recordRiskDecision') {
        riskPayloads.push(payload)
        const idempotencyKey = (payload as {
          readonly args: { readonly request: { readonly idempotencyKey: string } }
        }).args.request.idempotencyKey
        return Promise.resolve({
          ok: true,
          value: {
            ok: true,
            value: {
              schemaVersion: 1,
              operation: 'record_risk_decision',
              assessmentId: id,
              assessmentRevision: 8,
              acceptedState: 'BLOCKED',
              decisionId: 'risk-decision-00000000-0000-0000-0000-000000000082',
              finding: {
                recordId: summary.recordId,
                recordRevision: summary.recordRevision,
              },
              decision: 'DENY',
              resolution: 'DENIED',
              idempotencyKey,
              recordedAt: '2026-08-24T00:08:00.000Z',
              correlationId: 'sec-00000000-0000-0000-0000-000000000082',
            },
          },
        })
      }
      return Promise.reject(new Error(`Unexpected endpoint: ${endpoint}`))
    })
    const launcher = b.runtime.renderSlot('sidebar.footer.action', { wide: true })
    const overlay = b.runtime.renderSlot('shell.overlay', {})
    const authorityId = authorityContextId('workbench-session-risk-decision-ui')
    await act(async () => {
      fireEvent.click(launcher.view.getByRole('button', { name: '打开安全保障工作台' }))
      await b.controller.openAssessment({
        securityAssuranceWorkbenchContextId: authorityId,
        assessmentId: id,
      })
      await b.controller.openFindings()
      await b.controller.selectFinding(summary.recordId)
    })

    expect(overlay.view.getByRole('heading', { name: '风险决策' })).toBeTruthy()
    expect(overlay.view.getAllByText('KEEPS_FINDING_BLOCKING')).toHaveLength(2)
    expect(overlay.view.getByText('由当前宿主认证上下文派生')).toBeTruthy()
    expect(overlay.view.queryByLabelText('决策者身份')).toBeNull()
    const rationale = overlay.view.getByRole('textbox', { name: '理由' })
    fireEvent.change(rationale, {
      target: { value: 'The validated risk must remain blocking for this release.' },
    })
    await act(async () => {
      fireEvent.click(overlay.view.getByRole('button', { name: '记录风险决策' }))
    })

    expect(riskPayloads).toHaveLength(1)
    expect(riskPayloads[0]).toMatchObject({
      args: {
        request: {
          decision: 'DENY',
          expectedAssessmentRevision: 7,
          rationale: 'The validated risk must remain blocking for this release.',
          compensatingControls: [],
          expiresAt: null,
        },
      },
    })
    expect(JSON.stringify(riskPayloads[0])).not.toContain('principalId')
    expect(overlay.view.queryByRole('heading', { name: '风险决策' })).toBeNull()
    expect(overlay.view.queryByText('The validated risk must remain blocking for this release.')).toBeNull()
    expect(overlay.view.getByRole('button', { name: '查看 Findings' })).toBeTruthy()

    await b.feature.dispose()
    await b.gateway.dispose()
    await b.runtime.dispose()
  })

  it('completes Critical Dual Authority only with the exact prior attestation fields', async () => {
    const id = assessmentId('asm-00000000-0000-0000-0000-000000000083')
    const summary: FindingSummaryV1 = {
      ...findingSummaryItem(id),
      technicalSeverity: 'CRITICAL',
    }
    const snapshot: AssessmentSnapshotV1 = {
      ...readySnapshot(id),
      availableActions: [{
        kind: 'RECORD_RISK_DECISION',
        expectedAssessmentRevision: 7,
        finding: {
          recordId: summary.recordId,
          recordRevision: summary.recordRevision,
        },
        options: [{
          decision: 'ACCEPT',
          consequence: 'MAKES_FINDING_NON_BLOCKING',
          authorizationMode: 'CRITICAL_DUAL_AUTHORITY',
          minimumCompensatingControls: 2,
          maximumLifetimeSeconds: 86_400,
          requiredAttestations: 2,
          completedAttestations: 1,
          exactMatchRequired: true,
        }],
      }],
    }
    const rationale = 'Two independent operators attest to this bounded critical exception.'
    const compensatingControls = [
      'Disable the affected route at the edge.',
      'Monitor every attempted invocation.',
    ]
    const expiresAt = '2026-08-25T00:00:00.000Z'
    const detail: FindingDetailViewV1 = {
      ...findingDetailView(summary),
      riskDecision: {
        state: 'PENDING_DUAL_AUTHORITY',
        decisionId: 'risk-decision-00000000-0000-0000-0000-000000000083',
        authorizationMode: 'CRITICAL_DUAL_AUTHORITY',
        rationale,
        compensatingControls,
        expiresAt,
        decisionMaker: { kind: 'host-operator', principalId: 'operator-first' },
        scope: {
          subjectDigest: snapshot.subject.digest,
          policyDigest: snapshot.policy.digest,
        },
        attestations: [{
          sequence: 1,
          decisionMaker: { kind: 'host-operator', principalId: 'operator-first' },
          authorizationEvidence: {
            permission: 'risk:break-glass',
            invocationClass: 'independently-authenticated',
          },
          attestedAt: '2026-08-24T23:30:00.000Z',
        }],
        recordedAt: '2026-08-24T23:30:00.000Z',
      },
    }
    const committed: AssessmentSnapshotV1 = {
      ...snapshot,
      assessmentRevision: 8,
      state: 'SEALED',
      blockedRecovery: null,
      availableActions: [],
      verdict: 'FAILED',
      updatedAt: '2026-08-24T23:31:00.000Z',
    }
    const riskPayloads: unknown[] = []
    let assessmentReads = 0
    const b = await bench((_path, endpoint, payload, signal) => {
      if (endpoint === 'securityAssuranceWorkbench/getAssessment') {
        assessmentReads += 1
        return Promise.resolve({
          ok: true,
          value: { ok: true, value: assessmentReads === 1 ? snapshot : committed },
        })
      }
      if (endpoint === 'securityAssuranceWorkbench/waitForAssessmentRevision') {
        return new Promise(resolve => {
          signal.addEventListener('abort', () => {
            resolve({ ok: false, error: { code: 'aborted' } })
          }, { once: true })
        })
      }
      if (endpoint === 'securityAssuranceWorkbench/listFindings') {
        return Promise.resolve({
          ok: true,
          value: {
            ok: true,
            value: {
              schemaVersion: 1,
              assessmentId: id,
              assessmentRevision: 7,
              findings: [summary],
              nextCursor: null,
            },
          },
        })
      }
      if (endpoint === 'securityAssuranceWorkbench/getFinding') {
        return Promise.resolve({ ok: true, value: { ok: true, value: detail } })
      }
      if (endpoint === 'securityAssuranceWorkbench/recordRiskDecision') {
        riskPayloads.push(payload)
        const idempotencyKey = (payload as {
          readonly args: { readonly request: { readonly idempotencyKey: string } }
        }).args.request.idempotencyKey
        return Promise.resolve({
          ok: true,
          value: {
            ok: true,
            value: {
              schemaVersion: 1,
              operation: 'record_risk_decision',
              assessmentId: id,
              assessmentRevision: 8,
              acceptedState: 'BLOCKED',
              decisionId: 'risk-decision-00000000-0000-0000-0000-000000000083',
              finding: {
                recordId: summary.recordId,
                recordRevision: summary.recordRevision,
              },
              decision: 'ACCEPT',
              resolution: 'ACCEPTED',
              idempotencyKey,
              recordedAt: '2026-08-24T23:31:00.000Z',
              correlationId: 'sec-00000000-0000-0000-0000-000000000083',
            },
          },
        })
      }
      return Promise.reject(new Error(`Unexpected endpoint: ${endpoint}`))
    })
    const launcher = b.runtime.renderSlot('sidebar.footer.action', { wide: true })
    const overlay = b.runtime.renderSlot('shell.overlay', {})
    await act(async () => {
      fireEvent.click(launcher.view.getByRole('button', { name: '打开安全保障工作台' }))
      await b.controller.openAssessment({
        securityAssuranceWorkbenchContextId: authorityContextId('workbench-session-critical-second'),
        assessmentId: id,
      })
      await b.controller.openFindings()
      await b.controller.selectFinding(summary.recordId)
    })

    expect(overlay.view.getByRole('heading', { name: '已记录的风险决策' })).toBeTruthy()
    expect(overlay.view.getByText('operator-first')).toBeTruthy()
    expect(overlay.view.getByText('1 / 2')).toBeTruthy()
    expect(overlay.view.getByText('必须精确匹配首次证明')).toBeTruthy()
    expect(overlay.view.getByRole<HTMLInputElement>('radio').matches(':disabled')).toBe(true)
    expect(overlay.view.getByRole<HTMLTextAreaElement>('textbox', { name: '理由' }).readOnly).toBe(true)
    expect(overlay.view.getByRole<HTMLTextAreaElement>('textbox', { name: /^补偿控制/u }).readOnly).toBe(true)
    expect(overlay.view.queryByLabelText('决策者身份')).toBeNull()
    await act(async () => {
      fireEvent.click(overlay.view.getByRole('button', { name: '提交第二次独立证明' }))
    })

    expect(riskPayloads).toHaveLength(1)
    expect(riskPayloads[0]).toMatchObject({
      args: {
        request: {
          decision: 'ACCEPT',
          rationale,
          compensatingControls,
          expiresAt,
        },
      },
    })
    expect(JSON.stringify(riskPayloads[0])).not.toContain('principalId')
    expect(overlay.view.queryByRole('heading', { name: '风险决策' })).toBeNull()

    await b.feature.dispose()
    await b.gateway.dispose()
    await b.runtime.dispose()
  })
})
