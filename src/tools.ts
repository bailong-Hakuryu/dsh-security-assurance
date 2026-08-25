import type { Context } from '@deepseek-ai/cordis'
import type {} from '@deepseek-ai/dsh-agent'
import { HarnessError } from '@deepseek-ai/dsh-llm'
import { defineTool, type GenericCallView, type ToolRunContext } from '@deepseek-ai/dsh-tools'
import {
  getAssessmentRequestSchema,
  startAssessmentRequestSchema,
  type AssessmentId,
  type AssessmentReceiptV1,
  type AssessmentSnapshotV1,
  type AssessmentState,
  type SecurityInvocation,
  type SecurityVerdict,
} from './contracts.ts'
import type { SecurityAssuranceService } from './index.ts'
import {
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
  return resolveTrustedInvocation(ctx.securityAssurance as SecurityAssuranceService, {
    kind: 'harness-session',
    principalId: requireHarnessSession(ctx, exec),
    permissions: [permission],
  })
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

/** Independently activatable model-facing Consumer over the root Security Service. */
const SecurityAssuranceTools = {
  name: 'dsh-security-assurance-tools',
  inject: ['agents', 'securityAssurance', 'tools'],
  apply(ctx: Context): void {
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
  },
}

export default SecurityAssuranceTools
