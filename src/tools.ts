import type { Context } from '@deepseek-ai/cordis'
import type {} from '@deepseek-ai/dsh-agent'
import { HarnessError } from '@deepseek-ai/dsh-llm'
import { defineTool, type GenericCallView, type ToolRunContext } from '@deepseek-ai/dsh-tools'
import {
  getAssessmentRequestSchema,
  type AssessmentId,
  type AssessmentSnapshotV1,
  type AssessmentState,
  type SecurityVerdict,
} from './contracts.ts'
import type { SecurityAssuranceService } from './index.ts'
import { resolveTrustedInvocation } from './internal/authority.ts'

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

/** Independently activatable model-facing Consumer over the root Security Service. */
const SecurityAssuranceTools = {
  name: 'dsh-security-assurance-tools',
  inject: ['agents', 'securityAssurance', 'tools'],
  apply(ctx: Context): void {
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
        const principalId = requireHarnessSession(ctx, exec)
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
        const invocation = resolveTrustedInvocation(ctx.securityAssurance as SecurityAssuranceService, {
          kind: 'harness-session',
          principalId,
          permissions: ['assessment:read'],
        })
        const result = await ctx.securityAssurance.getAssessment(
          invocation,
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
