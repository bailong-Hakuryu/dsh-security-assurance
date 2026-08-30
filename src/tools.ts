import type { Context } from '@deepseek-ai/cordis'
import type {} from '@deepseek-ai/dsh-agent'
import { HarnessError } from '@deepseek-ai/dsh-llm'
import { defineTool, type GenericCallView, type ToolRunContext } from '@deepseek-ai/dsh-tools'
import {
  cancelAssessmentRequestSchema,
  getCatalogRequestSchema,
  getAssessmentRequestSchema,
  listRepositoriesRequestSchema,
  listFindingsRequestSchema,
  requestExportRequestSchema,
  resumeAssessmentRequestSchema,
  startAssessmentRequestSchema,
  type AssessmentId,
  type AssessmentCancellationReceiptV1,
  type AssessmentReceiptV1,
  type AssessmentResumeReceiptV1,
  type AssessmentSnapshotV1,
  type AssessmentState,
  type FindingListPageV1,
  type FindingSummaryV1,
  type ExportRequestReceiptV1,
  type RepositoryListSnapshotV1,
  type SecurityCatalogSnapshotV1,
  type SecurityInvocation,
  type SecurityVerdict,
} from './contracts.ts'
import type { SecurityAssuranceService } from './index.ts'
import {
  createTrustedCallerChannel,
  resolveTrustedInvocation,
  type SecurityPermission,
} from './internal/authority.ts'

/** Model-safe projection of one accepted Assessment start. */
export interface SecurityAssessmentStartReceiptV1 {
  readonly schemaVersion: 1
  readonly operation: 'start_assessment'
  readonly assessmentId: AssessmentId
  readonly assessmentRevision: 1
  readonly state: 'CREATED'
  readonly idempotencyKey: string
}

/** Model-safe projection of one accepted Assessment resume. */
export interface SecurityAssessmentResumeReceiptV1 {
  readonly schemaVersion: 1
  readonly operation: 'resume_assessment'
  readonly assessmentId: AssessmentId
  readonly assessmentRevision: number
  readonly state: 'CREATED'
  readonly idempotencyKey: string
}

/** Model-safe projection of one durable Assessment cancellation request. */
export interface SecurityAssessmentCancellationReceiptV1 {
  readonly schemaVersion: 1
  readonly operation: 'cancel_assessment'
  readonly assessmentId: AssessmentId
  readonly assessmentRevision: number
  readonly acceptedState: 'CREATED' | 'RUNNING' | 'BLOCKED'
  readonly idempotencyKey: string
}

/** Model-safe projection of one accepted official Export request. */
export interface SecurityAssessmentExportReceiptV1 {
  readonly schemaVersion: 1
  readonly operation: 'request_export'
  readonly exportId: string
  readonly assessmentId: AssessmentId
  readonly assessmentRevision: number
  readonly idempotencyKey: string
  readonly acceptedState: 'PENDING'
}

/** Model-safe projection of one current Assessment revision. */
export interface SecurityAssessmentStatusV1 {
  readonly schemaVersion: 1
  readonly assessmentId: AssessmentId
  readonly assessmentRevision: number
  readonly state: AssessmentState
  readonly coverage: {
    readonly status: AssessmentSnapshotV1['coverage']['status']
    readonly mandatoryObligations: number
    readonly satisfiedObligations: number
    readonly gapObligations: number
  }
  /** Present only as a non-null value after the Service has sealed the Assessment. */
  readonly verdict: SecurityVerdict | null
}

/** Model-safe page of Service-redacted Finding Summaries. */
export interface SecurityAssessmentFindingSummaryV1 {
  readonly schemaVersion: 1
  readonly assessmentId: AssessmentId
  readonly assessmentRevision: number
  readonly recordKind: FindingSummaryV1['recordKind']
  readonly recordId: string
  readonly candidateId: string
  readonly recordRevision: number
  readonly validationState: FindingSummaryV1['validationState']
  readonly validationContractId: string | null
  readonly weaknessClassification: {
    readonly primary: string
    readonly secondary: string[]
  }
  readonly technicalSeverity: FindingSummaryV1['technicalSeverity']
  readonly evidenceConfidence: FindingSummaryV1['evidenceConfidence']
  readonly policySignificance: FindingSummaryV1['policySignificance']
  readonly component: string
  readonly sensitivity: FindingSummaryV1['sensitivity']
  readonly coverageRelations: {
    readonly obligationId: string
    readonly state: 'SATISFIED' | 'GAP'
  }[]
  readonly hasProtectedDetail: boolean
}

export interface SecurityAssessmentFindingsV1 {
  readonly schemaVersion: 1
  readonly assessmentId: AssessmentId
  readonly assessmentRevision: number
  readonly findings: SecurityAssessmentFindingSummaryV1[]
  readonly nextCursor: string | null
}

/** Model-safe Repository selection list with no root or root-identity digest. */
export interface SecurityRepositorySelectionV1 {
  readonly schemaVersion: 1
  readonly repositories: {
    readonly repositoryId: string
    readonly repositoryRevision: number
    readonly state: 'ENABLED' | 'DISABLED'
    readonly displayName: string
    readonly policyId: string
    readonly assessmentProfileId: string
    readonly platform: 'win32' | 'linux' | 'darwin'
  }[]
  readonly truncated: boolean
}

/** Model-safe effective choices needed to construct an Assessment start request. */
export interface SecurityAssessmentCatalogV1 {
  readonly schemaVersion: 1
  readonly repository: null | {
    readonly repositoryId: string
    readonly repositoryRevision: number
    readonly state: 'ENABLED' | 'DISABLED'
    readonly displayName: string
  }
  readonly assessmentModes: {
    readonly assessmentMode: 'REPOSITORY' | 'CHANGE' | 'TARGETED'
    readonly targetKind: 'repository' | 'change' | 'targeted'
    readonly subjectKinds: ('git_revision' | 'change' | 'workspace_snapshot')[]
    readonly support: 'SUPPORTED' | 'UNSUPPORTED'
    readonly limitations: string[]
  }[]
  readonly assessmentProfiles: {
    readonly assessmentProfileId: string
    readonly limitations: string[]
  }[]
  readonly strongerControls: {
    readonly controlId: string
    readonly requiresControlIds: string[]
  }[]
  readonly supportedEcosystemIds: string[]
  readonly supportedPlatforms: ('win32' | 'linux' | 'darwin')[]
}

const REPOSITORIES_OUTPUT = {
  schema: {
    type: 'object',
    additionalProperties: false,
    properties: {
      schemaVersion: { type: 'integer', const: 1, required: true },
      repositories: {
        type: 'array',
        required: true,
        items: {
          type: 'object',
          additionalProperties: false,
          properties: {
            repositoryId: { type: 'string', required: true },
            repositoryRevision: { type: 'integer', required: true },
            state: { type: 'string', enum: ['ENABLED', 'DISABLED'], required: true },
            displayName: { type: 'string', required: true },
            policyId: { type: 'string', required: true },
            assessmentProfileId: { type: 'string', required: true },
            platform: { type: 'string', enum: ['win32', 'linux', 'darwin'], required: true },
          },
        },
      },
      truncated: { type: 'boolean', required: true },
    },
  },
  render: (_args: unknown, value: SecurityRepositorySelectionV1) => ([{
    type: 'text' as const,
    text: JSON.stringify(value),
  }]),
} as const

const CATALOG_OUTPUT = {
  schema: {
    type: 'object',
    additionalProperties: false,
    properties: {
      schemaVersion: { type: 'integer', const: 1, required: true },
      repository: {
        required: true,
        oneOf: [{ type: 'null' }, {
          type: 'object',
          additionalProperties: false,
          properties: {
            repositoryId: { type: 'string', required: true },
            repositoryRevision: { type: 'integer', required: true },
            state: { type: 'string', enum: ['ENABLED', 'DISABLED'], required: true },
            displayName: { type: 'string', required: true },
          },
        }],
      },
      assessmentModes: {
        type: 'array', required: true, items: {
          type: 'object', additionalProperties: false, properties: {
            assessmentMode: { type: 'string', enum: ['REPOSITORY', 'CHANGE', 'TARGETED'], required: true },
            targetKind: { type: 'string', enum: ['repository', 'change', 'targeted'], required: true },
            subjectKinds: { type: 'array', items: { type: 'string', enum: ['git_revision', 'change', 'workspace_snapshot'] }, required: true },
            support: { type: 'string', enum: ['SUPPORTED', 'UNSUPPORTED'], required: true },
            limitations: { type: 'array', items: { type: 'string' }, required: true },
          },
        },
      },
      assessmentProfiles: {
        type: 'array', required: true, items: {
          type: 'object', additionalProperties: false, properties: {
            assessmentProfileId: { type: 'string', required: true },
            limitations: { type: 'array', items: { type: 'string' }, required: true },
          },
        },
      },
      strongerControls: {
        type: 'array', required: true, items: {
          type: 'object', additionalProperties: false, properties: {
            controlId: { type: 'string', required: true },
            requiresControlIds: { type: 'array', items: { type: 'string' }, required: true },
          },
        },
      },
      supportedEcosystemIds: { type: 'array', items: { type: 'string' }, required: true },
      supportedPlatforms: { type: 'array', items: { type: 'string', enum: ['win32', 'linux', 'darwin'] }, required: true },
    },
  },
  render: (_args: unknown, value: SecurityAssessmentCatalogV1) => ([{
    type: 'text' as const,
    text: JSON.stringify(value),
  }]),
} as const

const START_OUTPUT = {
  schema: {
    type: 'object',
    additionalProperties: false,
    properties: {
      schemaVersion: { type: 'integer', const: 1, required: true },
      operation: { type: 'string', const: 'start_assessment', required: true },
      assessmentId: { type: 'string', required: true },
      assessmentRevision: { type: 'integer', const: 1, required: true },
      state: { type: 'string', const: 'CREATED', required: true },
      idempotencyKey: { type: 'string', required: true },
    },
  },
  render: (_args: unknown, value: SecurityAssessmentStartReceiptV1) => ([{
    type: 'text' as const,
    text: JSON.stringify(value),
  }]),
} as const

const RESUME_OUTPUT = {
  schema: {
    type: 'object',
    additionalProperties: false,
    properties: {
      schemaVersion: { type: 'integer', const: 1, required: true },
      operation: { type: 'string', const: 'resume_assessment', required: true },
      assessmentId: { type: 'string', required: true },
      assessmentRevision: { type: 'integer', required: true },
      state: { type: 'string', const: 'CREATED', required: true },
      idempotencyKey: { type: 'string', required: true },
    },
  },
  render: (_args: unknown, value: SecurityAssessmentResumeReceiptV1) => ([{
    type: 'text' as const,
    text: JSON.stringify(value),
  }]),
} as const

const CANCEL_OUTPUT = {
  schema: {
    type: 'object',
    additionalProperties: false,
    properties: {
      schemaVersion: { type: 'integer', const: 1, required: true },
      operation: { type: 'string', const: 'cancel_assessment', required: true },
      assessmentId: { type: 'string', required: true },
      assessmentRevision: { type: 'integer', required: true },
      acceptedState: {
        type: 'string',
        enum: ['CREATED', 'RUNNING', 'BLOCKED'],
        required: true,
      },
      idempotencyKey: { type: 'string', required: true },
    },
  },
  render: (_args: unknown, value: SecurityAssessmentCancellationReceiptV1) => ([{
    type: 'text' as const,
    text: JSON.stringify(value),
  }]),
} as const

const EXPORT_OUTPUT = {
  schema: {
    type: 'object',
    additionalProperties: false,
    properties: {
      schemaVersion: { type: 'integer', const: 1, required: true },
      operation: { type: 'string', const: 'request_export', required: true },
      exportId: { type: 'string', required: true },
      assessmentId: { type: 'string', required: true },
      assessmentRevision: { type: 'integer', required: true },
      idempotencyKey: { type: 'string', required: true },
      acceptedState: { type: 'string', const: 'PENDING', required: true },
    },
  },
  render: (_args: unknown, value: SecurityAssessmentExportReceiptV1) => ([{
    type: 'text' as const,
    text: JSON.stringify(value),
  }]),
} as const

const STATUS_OUTPUT = {
  schema: {
    type: 'object',
    additionalProperties: false,
    properties: {
      schemaVersion: { type: 'integer', const: 1, required: true },
      assessmentId: { type: 'string', required: true },
      assessmentRevision: { type: 'integer', required: true },
      state: {
        type: 'string',
        enum: ['CREATED', 'RUNNING', 'BLOCKED', 'SEALED', 'CANCELED'],
        required: true,
      },
      coverage: {
        type: 'object',
        additionalProperties: false,
        required: true,
        properties: {
          status: {
            type: 'string',
            enum: ['PENDING', 'COMPLETE', 'GAP'],
            required: true,
          },
          mandatoryObligations: { type: 'integer', required: true },
          satisfiedObligations: { type: 'integer', required: true },
          gapObligations: { type: 'integer', required: true },
        },
      },
      verdict: {
        oneOf: [
          { type: 'string', enum: ['SATISFIED', 'FAILED', 'INDETERMINATE'] },
          { type: 'null' },
        ],
        required: true,
      },
    },
  },
  render: (_args: unknown, value: SecurityAssessmentStatusV1) => ([{
    type: 'text' as const,
    text: JSON.stringify(value),
  }]),
} as const

const FINDINGS_OUTPUT = {
  schema: {
    type: 'object',
    additionalProperties: false,
    properties: {
      schemaVersion: { type: 'integer', const: 1, required: true },
      assessmentId: { type: 'string', required: true },
      assessmentRevision: { type: 'integer', required: true },
      findings: {
        type: 'array',
        required: true,
        items: {
          type: 'object',
          additionalProperties: false,
          properties: {
            schemaVersion: { type: 'integer', const: 1, required: true },
            assessmentId: { type: 'string', required: true },
            assessmentRevision: { type: 'integer', required: true },
            recordKind: {
              type: 'string',
              enum: ['FINDING', 'REJECTED_CANDIDATE', 'UNRESOLVED_CANDIDATE'],
              required: true,
            },
            recordId: { type: 'string', required: true },
            candidateId: { type: 'string', required: true },
            recordRevision: { type: 'integer', required: true },
            validationState: {
              type: 'string',
              enum: ['VALIDATED', 'REJECTED', 'UNRESOLVED'],
              required: true,
            },
            validationContractId: {
              oneOf: [{ type: 'string' }, { type: 'null' }],
              required: true,
            },
            weaknessClassification: {
              type: 'object',
              additionalProperties: false,
              required: true,
              properties: {
                primary: { type: 'string', required: true },
                secondary: {
                  type: 'array',
                  items: { type: 'string' },
                  required: true,
                },
              },
            },
            technicalSeverity: {
              oneOf: [
                {
                  type: 'string',
                  enum: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL'],
                },
                { type: 'null' },
              ],
              required: true,
            },
            evidenceConfidence: {
              oneOf: [
                { type: 'string', enum: ['HIGH', 'MEDIUM', 'LOW'] },
                { type: 'null' },
              ],
              required: true,
            },
            policySignificance: {
              oneOf: [
                { type: 'string', enum: ['BLOCKING', 'NON_BLOCKING', 'ADVISORY'] },
                { type: 'null' },
              ],
              required: true,
            },
            component: { type: 'string', required: true },
            sensitivity: {
              type: 'string',
              const: 'PROTECTED_DETAIL',
              required: true,
            },
            coverageRelations: {
              type: 'array',
              required: true,
              items: {
                type: 'object',
                additionalProperties: false,
                properties: {
                  obligationId: { type: 'string', required: true },
                  state: {
                    type: 'string',
                    enum: ['SATISFIED', 'GAP'],
                    required: true,
                  },
                },
              },
            },
            hasProtectedDetail: { type: 'boolean', required: true },
          },
        },
      },
      nextCursor: {
        oneOf: [{ type: 'string' }, { type: 'null' }],
        required: true,
      },
    },
  },
  render: (_args: unknown, value: SecurityAssessmentFindingsV1) => ([{
    type: 'text' as const,
    text: JSON.stringify(value),
  }]),
} as const

function reject(message: string, code: string): never {
  throw new HarnessError(message, code)
}

/** A model tool may act only for the exact live Agent inside its open driver turn. */
function requireHarnessSession(ctx: Context, exec: ToolRunContext): string {
  const agent = exec.agent
  if (agent === undefined) {
    return reject('security tools require a calling Harness session', 'SECURITY_TOOL_AGENT_REQUIRED')
  }
  if (
    ctx.agents.get(agent.id) !== agent
    || agent.status !== 'running'
    || ctx.agents.currentInitiator() !== agent
  ) {
    return reject(
      'security tools require the exact live calling session inside its active driver',
      'SECURITY_TOOL_DRIVER_REQUIRED',
    )
  }
  for (let index = agent.session.events.length - 1; index >= 0; index -= 1) {
    const boundary = agent.session.events[index]
    if (boundary?.type === 'turn/end') {
      return reject('security tools require an open model turn', 'SECURITY_TOOL_DRIVER_REQUIRED')
    }
    if (boundary?.type === 'turn/start') return String(agent.id)
  }
  return reject('security tools require an open model turn', 'SECURITY_TOOL_DRIVER_REQUIRED')
}

/** Mint exactly one operation permission from the authenticated live Session. */
function harnessSessionInvocation(
  ctx: Context,
  exec: ToolRunContext,
  permission: SecurityPermission,
): SecurityInvocation {
  return resolveTrustedInvocation(ctx.securityAssurance as SecurityAssuranceService, createTrustedCallerChannel({
    kind: 'harness-session',
    principalId: requireHarnessSession(ctx, exec),
    permissions: [permission],
  }))
}

function startReceiptValue(receipt: AssessmentReceiptV1): SecurityAssessmentStartReceiptV1 {
  return {
    schemaVersion: 1,
    operation: receipt.operation,
    assessmentId: receipt.assessmentId,
    assessmentRevision: receipt.assessmentRevision,
    state: receipt.state,
    idempotencyKey: receipt.idempotencyKey,
  }
}

function resumeReceiptValue(
  receipt: AssessmentResumeReceiptV1,
): SecurityAssessmentResumeReceiptV1 {
  return {
    schemaVersion: 1,
    operation: receipt.operation,
    assessmentId: receipt.assessmentId,
    assessmentRevision: receipt.assessmentRevision,
    state: receipt.state,
    idempotencyKey: receipt.idempotencyKey,
  }
}

function cancellationReceiptValue(
  receipt: AssessmentCancellationReceiptV1,
): SecurityAssessmentCancellationReceiptV1 {
  return {
    schemaVersion: 1,
    operation: receipt.operation,
    assessmentId: receipt.assessmentId,
    assessmentRevision: receipt.assessmentRevision,
    acceptedState: receipt.acceptedState,
    idempotencyKey: receipt.idempotencyKey,
  }
}

function exportReceiptValue(receipt: ExportRequestReceiptV1): SecurityAssessmentExportReceiptV1 {
  return {
    schemaVersion: 1,
    operation: receipt.operation,
    exportId: receipt.exportId,
    assessmentId: receipt.assessmentId,
    assessmentRevision: receipt.assessmentRevision,
    idempotencyKey: receipt.idempotencyKey,
    acceptedState: receipt.acceptedState,
  }
}

function statusValue(snapshot: AssessmentSnapshotV1): SecurityAssessmentStatusV1 {
  return {
    schemaVersion: 1,
    assessmentId: snapshot.assessmentId,
    assessmentRevision: snapshot.assessmentRevision,
    state: snapshot.state,
    coverage: {
      status: snapshot.coverage.status,
      mandatoryObligations: snapshot.coverage.mandatoryObligations,
      satisfiedObligations: snapshot.coverage.satisfiedObligations,
      gapObligations: snapshot.coverage.gapObligations,
    },
    verdict: snapshot.verdict,
  }
}

function findingSummaryValue(summary: FindingSummaryV1): SecurityAssessmentFindingSummaryV1 {
  return {
    schemaVersion: 1,
    assessmentId: summary.assessmentId,
    assessmentRevision: summary.assessmentRevision,
    recordKind: summary.recordKind,
    recordId: summary.recordId,
    candidateId: summary.candidateId,
    recordRevision: summary.recordRevision,
    validationState: summary.validationState,
    validationContractId: summary.validationContractId,
    weaknessClassification: {
      primary: summary.weaknessClassification.primary,
      secondary: [...summary.weaknessClassification.secondary],
    },
    technicalSeverity: summary.technicalSeverity,
    evidenceConfidence: summary.evidenceConfidence,
    policySignificance: summary.policySignificance,
    component: summary.component,
    sensitivity: summary.sensitivity,
    coverageRelations: summary.coverageRelations.map(relation => ({ ...relation })),
    hasProtectedDetail: summary.hasProtectedDetail,
  }
}

function findingsValue(page: FindingListPageV1): SecurityAssessmentFindingsV1 {
  return {
    schemaVersion: 1,
    assessmentId: page.assessmentId,
    assessmentRevision: page.assessmentRevision,
    findings: page.findings.map(findingSummaryValue),
    nextCursor: page.nextCursor,
  }
}

function repositoriesValue(snapshot: RepositoryListSnapshotV1): SecurityRepositorySelectionV1 {
  return {
    schemaVersion: 1,
    repositories: snapshot.repositories.map(repository => ({
      repositoryId: repository.repositoryId,
      repositoryRevision: repository.repositoryRevision,
      state: repository.state,
      displayName: repository.displayName,
      policyId: repository.bindings.policyId,
      assessmentProfileId: repository.bindings.assessmentProfileId,
      platform: repository.bindings.platform,
    })),
    truncated: snapshot.truncated,
  }
}

function catalogValue(snapshot: SecurityCatalogSnapshotV1): SecurityAssessmentCatalogV1 {
  return {
    schemaVersion: 1,
    repository: snapshot.repository === null
      ? null
      : {
          repositoryId: snapshot.repository.repositoryId,
          repositoryRevision: snapshot.repository.repositoryRevision,
          state: snapshot.repository.state,
          displayName: snapshot.repository.displayName,
        },
    assessmentModes: snapshot.assessmentModes.map(mode => ({
      assessmentMode: mode.assessmentMode,
      targetKind: mode.targetKind,
      subjectKinds: [...mode.subjectKinds],
      support: mode.support,
      limitations: [...mode.limitations],
    })),
    assessmentProfiles: snapshot.assessmentProfiles.map(profile => ({
      assessmentProfileId: profile.assessmentProfileId,
      limitations: [...profile.limitations],
    })),
    strongerControls: snapshot.strongerControls.map(control => ({
      controlId: control.controlId,
      requiresControlIds: [...control.requiresControlIds],
    })),
    supportedEcosystemIds: [...snapshot.supportedEcosystemIds],
    supportedPlatforms: [...snapshot.supportedPlatforms],
  }
}

function presentRepositories(): GenericCallView {
  return {
    card: 'generic',
    title: 'List security repositories',
    kind: 'read',
  }
}

function presentCatalog(args: { readonly repository_id?: string }): GenericCallView {
  return {
    card: 'generic',
    title: 'Read security assessment catalog',
    kind: 'read',
    rawInput: args.repository_id,
  }
}

function presentStatus(args: { readonly assessment_id: string }): GenericCallView {
  return {
    card: 'generic',
    title: 'Read security assessment status',
    kind: 'read',
    rawInput: args.assessment_id,
  }
}

function presentStart(args: { readonly repository_id: string }): GenericCallView {
  return {
    card: 'generic',
    title: 'Start security assessment',
    kind: 'other',
    rawInput: args.repository_id,
  }
}

function presentFindings(args: { readonly assessment_id: string }): GenericCallView {
  return {
    card: 'generic',
    title: 'List security assessment findings',
    kind: 'read',
    rawInput: args.assessment_id,
  }
}

function presentResume(args: { readonly assessment_id: string }): GenericCallView {
  return {
    card: 'generic',
    title: 'Resume security assessment',
    kind: 'other',
    rawInput: args.assessment_id,
  }
}

function presentCancel(args: { readonly assessment_id: string }): GenericCallView {
  return {
    card: 'generic',
    title: 'Cancel security assessment',
    kind: 'other',
    rawInput: args.assessment_id,
  }
}

function presentExport(args: { readonly assessment_id: string }): GenericCallView {
  return {
    card: 'generic',
    title: 'Request security assessment export',
    kind: 'other',
    rawInput: args.assessment_id,
  }
}

/** Independently activatable model-facing Consumer over the root Security Service. */
const SecurityAssuranceTools = {
  name: 'dsh-security-assurance-tools',
  inject: ['agents', 'securityAssurance', 'tools'],
  apply(ctx: Context): void {
    ctx.tools.register(defineTool({
      name: 'security_repositories',
      description: 'List the bounded, path-free Security Repository choices visible to the calling Harness '
        + 'session. Use an ENABLED repositoryId from this result with security_catalog and '
        + 'security_assessment_start. This tool never returns repository roots, root digests, credentials, '
        + 'authority metadata, or storage handles.',
      parameters: {
        limit: {
          type: 'integer',
          required: true,
          description: 'Maximum repositories to return, from 1 through 100.',
        },
        state: {
          type: 'string',
          enum: ['ENABLED', 'DISABLED'],
          description: 'Optional Repository state filter.',
        },
      },
      output: REPOSITORIES_OUTPUT,
      async execute(args, exec) {
        const parsed = listRepositoriesRequestSchema.safeParse({
          schemaVersion: 1,
          limit: args.limit,
          ...args.state === undefined ? {} : { state: args.state },
        })
        if (!parsed.success) {
          return reject(
            'security_repositories arguments do not match the Repository list contract',
            'SECURITY_INVALID_REQUEST',
          )
        }
        const result = await ctx.securityAssurance.listRepositories(
          harnessSessionInvocation(ctx, exec, 'repository:read'),
          parsed.data,
          { signal: exec.signal },
        )
        if (!result.ok) return reject(result.error.message, `SECURITY_${result.error.code}`)
        return repositoriesValue(result.value)
      },
      isConcurrencySafe: () => true,
      presentCall: presentRepositories,
    }))

    ctx.tools.register(defineTool({
      name: 'security_catalog',
      description: 'Read the effective Security Assessment modes, profiles, target/subject kinds, stronger '
        + 'controls, ecosystems, and platforms. Pass an exact repositoryId from security_repositories to '
        + 'obtain repository-specific choices before security_assessment_start. This tool returns no paths, '
        + 'Evidence, provider credentials, authority metadata, or mutable registry handles.',
      parameters: {
        repository_id: {
          type: 'string',
          description: 'Optional exact registered Repository id from security_repositories.',
        },
      },
      output: CATALOG_OUTPUT,
      async execute(args, exec) {
        const parsed = getCatalogRequestSchema.safeParse({
          schemaVersion: 1,
          ...args.repository_id === undefined ? {} : { repositoryId: args.repository_id },
        })
        if (!parsed.success) {
          return reject(
            'security_catalog arguments do not match the Security Catalog contract',
            'SECURITY_INVALID_REQUEST',
          )
        }
        const result = await ctx.securityAssurance.getCatalog(
          harnessSessionInvocation(ctx, exec, 'repository:read'),
          parsed.data,
          { signal: exec.signal },
        )
        if (!result.ok) return reject(result.error.message, `SECURITY_${result.error.code}`)
        return catalogValue(result.value)
      },
      isConcurrencySafe: () => true,
      presentCall: presentCatalog,
    }))

    ctx.tools.register(defineTool({
      name: 'security_assessment_start',
      description: 'Start one durable Security Assessment against an already registered Repository. Use only '
        + 'Repository, profile, mode, Subject, target, stronger-control, and optional Start Preflight values '
        + 'obtained from trusted Security selection surfaces. Supply a stable idempotency_key and reuse it only '
        + 'for the exact same request. This tool never accepts repository paths, Principal, permissions, Policy '
        + 'content, credentials, or Risk Acceptance decisions.',
      parameters: {
        idempotency_key: {
          type: 'string',
          required: true,
          description: 'Stable key for replaying this exact start request; 1-128 letters, digits, dot, underscore, colon, or hyphen.',
        },
        repository_id: {
          type: 'string',
          required: true,
          description: 'Exact registered Repository id from a trusted Security selection surface.',
        },
        subject: {
          required: true,
          oneOf: [
            {
              type: 'object',
              additionalProperties: false,
              properties: {
                kind: { type: 'string', const: 'git_revision', required: true },
                commit: { type: 'string', required: true },
              },
            },
            {
              type: 'object',
              additionalProperties: false,
              properties: {
                kind: { type: 'string', const: 'change', required: true },
                base_commit: { type: 'string', required: true },
                head_commit: { type: 'string', required: true },
              },
            },
            {
              type: 'object',
              additionalProperties: false,
              properties: {
                kind: { type: 'string', const: 'workspace_snapshot', required: true },
              },
            },
          ],
        },
        assessment_mode: {
          type: 'string',
          enum: ['REPOSITORY', 'CHANGE', 'TARGETED'],
          required: true,
          description: 'Assessment mode selected from the effective Security Catalog.',
        },
        assessment_profile_id: {
          type: 'string',
          required: true,
          description: 'Exact Assessment Profile bound to the selected Repository.',
        },
        target: {
          required: true,
          oneOf: [
            {
              type: 'object',
              additionalProperties: false,
              properties: {
                kind: { type: 'string', const: 'repository', required: true },
              },
            },
            {
              type: 'object',
              additionalProperties: false,
              properties: {
                kind: { type: 'string', const: 'change', required: true },
                base_commit: { type: 'string', required: true },
                head_commit: { type: 'string', required: true },
                impact_cone: { type: 'string', const: 'POLICY_DEFAULT', required: true },
              },
            },
            {
              type: 'object',
              additionalProperties: false,
              properties: {
                kind: { type: 'string', const: 'targeted', required: true },
                relative_paths: {
                  type: 'array',
                  items: { type: 'string' },
                  required: true,
                },
              },
            },
          ],
        },
        requested_stronger_control_ids: {
          type: 'array',
          items: { type: 'string' },
          required: true,
          description: 'Exact stronger Control ids selected from the Catalog; use an empty array for none.',
        },
        start_preflight_digest: {
          type: 'object',
          additionalProperties: false,
          properties: {
            schema_version: { type: 'integer', const: 1, required: true },
            algorithm: { type: 'string', const: 'sha256', required: true },
            media_type: { type: 'string', required: true },
            byte_length: { type: 'integer', required: true },
            canonicalization: {
              type: 'string',
              enum: ['raw-bytes', 'dsh-canonical-json-v1'],
              required: true,
            },
            value: { type: 'string', required: true },
          },
          description: 'Optional exact proposalDigest from a fresh Start Preflight.',
        },
      },
      output: START_OUTPUT,
      async execute(args, exec) {
        const subject = args.subject.kind === 'git_revision'
          ? { kind: args.subject.kind, commit: args.subject.commit }
          : args.subject.kind === 'change'
            ? {
                kind: args.subject.kind,
                baseCommit: args.subject.base_commit,
                headCommit: args.subject.head_commit,
              }
            : { kind: args.subject.kind }
        const target = args.target.kind === 'repository'
          ? { kind: args.target.kind }
          : args.target.kind === 'change'
            ? {
                kind: args.target.kind,
                baseCommit: args.target.base_commit,
                headCommit: args.target.head_commit,
                impactCone: args.target.impact_cone,
              }
            : { kind: args.target.kind, relativePaths: args.target.relative_paths }
        const parsed = startAssessmentRequestSchema.safeParse({
          schemaVersion: 1,
          contractVersion: 1,
          idempotencyKey: args.idempotency_key,
          repositoryId: args.repository_id,
          subject,
          assessmentMode: args.assessment_mode,
          assessmentProfileId: args.assessment_profile_id,
          target,
          requestedStrongerControlIds: args.requested_stronger_control_ids,
          ...args.start_preflight_digest === undefined ? {} : {
            startPreflightDigest: {
              schemaVersion: args.start_preflight_digest.schema_version,
              algorithm: args.start_preflight_digest.algorithm,
              mediaType: args.start_preflight_digest.media_type,
              byteLength: args.start_preflight_digest.byte_length,
              canonicalization: args.start_preflight_digest.canonicalization,
              value: args.start_preflight_digest.value,
            },
          },
        })
        if (!parsed.success) {
          return reject(
            'security_assessment_start arguments do not match the Security start contract',
            'SECURITY_INVALID_REQUEST',
          )
        }
        const result = await ctx.securityAssurance.startAssessment(
          harnessSessionInvocation(ctx, exec, 'assessment:start'),
          parsed.data,
          { signal: exec.signal },
        )
        if (!result.ok) return reject(result.error.message, `SECURITY_${result.error.code}`)
        return startReceiptValue(result.value)
      },
      presentCall: presentStart,
    }))

    ctx.tools.register(defineTool({
      name: 'security_assessment_status',
      description: 'Read one Security Assessment current revision, lifecycle state, bounded coverage counts, '
        + 'and its Verdict only after sealing. This tool never returns repository bindings, subject or policy '
        + 'digests, Evidence, Findings, attack paths, export locations, or authority metadata.',
      parameters: {
        assessment_id: {
          type: 'string',
          required: true,
          description: 'Exact Assessment id returned by a Security Assessment receipt.',
        },
      },
      output: STATUS_OUTPUT,
      async execute(args, exec) {
        const parsed = getAssessmentRequestSchema.safeParse({
          schemaVersion: 1,
          assessmentId: args.assessment_id,
        })
        if (!parsed.success) {
          return reject(
            'assessment_id does not match the Security Assessment identifier contract',
            'SECURITY_INVALID_REQUEST',
          )
        }
        const result = await ctx.securityAssurance.getAssessment(
          harnessSessionInvocation(ctx, exec, 'assessment:read'),
          parsed.data,
          { signal: exec.signal },
        )
        if (!result.ok) {
          return reject(result.error.message, `SECURITY_${result.error.code}`)
        }
        return statusValue(result.value)
      },
      isConcurrencySafe: () => true,
      presentCall: presentStatus,
    }))

    ctx.tools.register(defineTool({
      name: 'security_assessment_findings',
      description: 'List one bounded page of Service-redacted Finding Summaries for a Security Assessment. '
        + 'Use nextCursor only with the exact same Assessment, Validation-state filter, page limit, and live '
        + 'Harness session that received it. This tool never returns Finding Detail, source anchors, Evidence '
        + 'content or links, attack paths, Risk Decisions, repository bindings, credentials, or authority metadata.',
      parameters: {
        assessment_id: {
          type: 'string',
          required: true,
          description: 'Exact Assessment id returned by a Security Assessment receipt.',
        },
        limit: {
          type: 'integer',
          required: true,
          description: 'Page size from 1 through 100; the Security Service enforces the bound.',
        },
        cursor: {
          type: 'string',
          description: 'Opaque nextCursor from the preceding page for this exact query and live session.',
        },
        validation_states: {
          type: 'array',
          items: {
            type: 'string',
            enum: ['VALIDATED', 'REJECTED', 'UNRESOLVED'],
          },
          description: 'Optional unique non-empty subset of Finding validation states.',
        },
      },
      output: FINDINGS_OUTPUT,
      async execute(args, exec) {
        const parsed = listFindingsRequestSchema.safeParse({
          schemaVersion: 1,
          assessmentId: args.assessment_id,
          limit: args.limit,
          ...args.cursor === undefined ? {} : { cursor: args.cursor },
          ...args.validation_states === undefined
            ? {}
            : { validationStates: args.validation_states },
        })
        if (!parsed.success) {
          return reject(
            'security_assessment_findings arguments do not match the Finding list contract',
            'SECURITY_INVALID_REQUEST',
          )
        }
        const result = await ctx.securityAssurance.listFindings(
          harnessSessionInvocation(ctx, exec, 'assessment:read'),
          parsed.data,
          { signal: exec.signal },
        )
        if (!result.ok) return reject(result.error.message, `SECURITY_${result.error.code}`)
        return findingsValue(result.value)
      },
      isConcurrencySafe: () => true,
      presentCall: presentFindings,
    }))

    ctx.tools.register(defineTool({
      name: 'security_assessment_resume',
      description: 'Resume one exact BLOCKED Security Assessment revision under its original frozen contract. '
        + 'Supply a fresh idempotency_key and a bounded operator reason. This tool never accepts a Subject, '
        + 'Policy, Coverage Plan, Provider or Analyzer selection, budget, state override, Risk Acceptance, '
        + 'Principal, permissions, repository path, or retry instruction outside the Service contract.',
      parameters: {
        assessment_id: {
          type: 'string',
          required: true,
          description: 'Exact BLOCKED Assessment id from a current Security status result.',
        },
        expected_assessment_revision: {
          type: 'integer',
          required: true,
          description: 'Exact current revision projected for the resumable BLOCKED Assessment.',
        },
        idempotency_key: {
          type: 'string',
          required: true,
          description: 'Stable key for replaying this exact resume request; 1-128 bounded key characters.',
        },
        reason: {
          type: 'object',
          additionalProperties: false,
          required: true,
          properties: {
            code: {
              type: 'string',
              required: true,
              description: 'Uppercase operator reason code from the controlling workflow.',
            },
            summary: {
              type: 'string',
              required: true,
              description: 'Bounded non-empty operator explanation, at most 512 characters.',
            },
          },
        },
      },
      output: RESUME_OUTPUT,
      async execute(args, exec) {
        const parsed = resumeAssessmentRequestSchema.safeParse({
          schemaVersion: 1,
          contractVersion: 1,
          assessmentId: args.assessment_id,
          expectedAssessmentRevision: args.expected_assessment_revision,
          idempotencyKey: args.idempotency_key,
          reason: args.reason,
        })
        if (!parsed.success) {
          return reject(
            'security_assessment_resume arguments do not match the Assessment resume contract',
            'SECURITY_INVALID_REQUEST',
          )
        }
        const result = await ctx.securityAssurance.resumeAssessment(
          harnessSessionInvocation(ctx, exec, 'assessment:resume'),
          parsed.data,
          { signal: exec.signal },
        )
        if (!result.ok) return reject(result.error.message, `SECURITY_${result.error.code}`)
        return resumeReceiptValue(result.value)
      },
      presentCall: presentResume,
    }))

    ctx.tools.register(defineTool({
      name: 'security_assessment_cancel',
      description: 'Request cancellation of one exact nonterminal Security Assessment revision. Supply a fresh '
        + 'idempotency_key and a bounded operator reason. The returned Receipt records accepted cancellation '
        + 'intent and never claims terminal CANCELED state; query status for committed truth. This tool never '
        + 'accepts force-complete, skip-cleanup, Evidence deletion, Verdict, state override, Principal, '
        + 'permissions, repository path, or arbitrary cancellation policy.',
      parameters: {
        assessment_id: {
          type: 'string',
          required: true,
          description: 'Exact nonterminal Assessment id from a current Security status result.',
        },
        expected_assessment_revision: {
          type: 'integer',
          required: true,
          description: 'Exact current revision projected for the Assessment to cancel.',
        },
        idempotency_key: {
          type: 'string',
          required: true,
          description: 'Stable key for replaying this exact cancellation request.',
        },
        reason: {
          type: 'object',
          additionalProperties: false,
          required: true,
          properties: {
            code: {
              type: 'string',
              required: true,
              description: 'Uppercase operator reason code from the controlling workflow.',
            },
            summary: {
              type: 'string',
              required: true,
              description: 'Bounded non-empty operator explanation, at most 512 characters.',
            },
          },
        },
      },
      output: CANCEL_OUTPUT,
      async execute(args, exec) {
        const parsed = cancelAssessmentRequestSchema.safeParse({
          schemaVersion: 1,
          contractVersion: 1,
          assessmentId: args.assessment_id,
          expectedAssessmentRevision: args.expected_assessment_revision,
          idempotencyKey: args.idempotency_key,
          reason: args.reason,
        })
        if (!parsed.success) {
          return reject(
            'security_assessment_cancel arguments do not match the Assessment cancellation contract',
            'SECURITY_INVALID_REQUEST',
          )
        }
        const result = await ctx.securityAssurance.cancelAssessment(
          harnessSessionInvocation(ctx, exec, 'assessment:cancel'),
          parsed.data,
          { signal: exec.signal },
        )
        if (!result.ok) return reject(result.error.message, `SECURITY_${result.error.code}`)
        return cancellationReceiptValue(result.value)
      },
      presentCall: presentCancel,
    }))

    ctx.tools.register(defineTool({
      name: 'security_assessment_export',
      description: 'Request one official Export for an exact SEALED Security Assessment revision through a '
        + 'Host-registered Delivery Destination. Supply the fixed supported Export Profile and a fresh '
        + 'idempotency_key. This tool returns only a durable PENDING Receipt and never returns preview content, '
        + 'artifact bytes or digest, private paths, URLs, credentials, download capabilities, destination '
        + 'options, Principal, permissions, or arbitrary output locations.',
      parameters: {
        assessment_id: {
          type: 'string',
          required: true,
          description: 'Exact SEALED Assessment id from a current Security status result.',
        },
        expected_assessment_revision: {
          type: 'integer',
          required: true,
          description: 'Exact SEALED Assessment revision bound to the official Export.',
        },
        idempotency_key: {
          type: 'string',
          required: true,
          description: 'Stable key for replaying this exact Export request.',
        },
        export_profile_id: {
          type: 'string',
          const: 'security/export/internal-json-v1',
          required: true,
          description: 'Exact supported audience-specific Export Profile.',
        },
        delivery_destination_id: {
          type: 'string',
          required: true,
          description: 'Host-registered Delivery Destination frozen into the Assessment contract.',
        },
      },
      output: EXPORT_OUTPUT,
      async execute(args, exec) {
        const parsed = requestExportRequestSchema.safeParse({
          schemaVersion: 1,
          contractVersion: 1,
          idempotencyKey: args.idempotency_key,
          assessmentId: args.assessment_id,
          expectedAssessmentRevision: args.expected_assessment_revision,
          exportProfileId: args.export_profile_id,
          deliveryDestinationId: args.delivery_destination_id,
        })
        if (!parsed.success) {
          return reject(
            'security_assessment_export arguments do not match the official Export request contract',
            'SECURITY_INVALID_REQUEST',
          )
        }
        const result = await ctx.securityAssurance.requestExport(
          harnessSessionInvocation(ctx, exec, 'export:request'),
          parsed.data,
          { signal: exec.signal },
        )
        if (!result.ok) return reject(result.error.message, `SECURITY_${result.error.code}`)
        return exportReceiptValue(result.value)
      },
      presentCall: presentExport,
    }))
  },
}

export default SecurityAssuranceTools
