import type { Context } from '@deepseek-ai/cordis'
import {
  Remote,
  TypertRemoteService,
  type TypertLookup,
} from '@deepseek-ai/dsh-typert-protocol'
import type {
  AssessmentRevisionSignalV1,
  AssessmentListPageV1,
  AssessmentSnapshotV1,
  FindingDetailViewV1,
  FindingListPageV1,
  GetAssessmentRequest,
  GetFindingRequest,
  ListFindingsRequest,
  ListAssessmentsRequest,
  RecordRiskDecisionRequest,
  RiskDecisionReceiptV1,
  SecurityInvocation,
  SecurityResult,
  WaitForAssessmentRevisionRequest,
} from './contracts.ts'
import type { SecurityAssuranceService } from './index.ts'
import { resolveTrustedInvocation } from './internal/authority.ts'

declare const workbenchAuthorityContextIdBrand: unique symbol

/**
 * Opaque identity of one Host-authenticated Workbench authority context.
 * The browser may carry it in memory but cannot derive a Principal or permissions from it.
 */
export type WorkbenchAuthorityContextId = string & {
  readonly [workbenchAuthorityContextIdBrand]: never
}

/** Permissions an authenticated Host integration may bind to one Workbench operator. */
export type WorkbenchSecurityPermissionV1 =
  | 'health:read'
  | 'repository:read'
  | 'repository:admin'
  | 'assessment:start'
  | 'assessment:read'
  | 'assessment:resume'
  | 'assessment:cancel'
  | 'evidence:disclose:validation-review'
  | 'assurance-submission:read'
  | 'risk:decide'
  | 'risk:break-glass'

/** Host-authenticated operator facts returned outside the browser wire contract. */
export interface AuthenticatedWorkbenchOperatorV1 {
  readonly principalId: string
  readonly permissions: readonly WorkbenchSecurityPermissionV1[]
}

/** Host authentication seam consumed independently for every Remote invocation. */
export interface WorkbenchAuthorityContextResolverV1 {
  /** Resolve one opaque context to current authenticated operator facts, or fail closed. */
  resolveAuthorityContext(
    contextId: WorkbenchAuthorityContextId,
  ): AuthenticatedWorkbenchOperatorV1 | undefined | Promise<AuthenticatedWorkbenchOperatorV1 | undefined>
}

const WORKBENCH_AUTHORITY_CONTEXT_PATTERN = /^[A-Za-z0-9_-]{16,256}$/

declare module '@deepseek-ai/dsh-typert-protocol' {
  interface TypertLookupMap {
    securityAssuranceWorkbenchContext: TypertLookup<SecurityInvocation, WorkbenchAuthorityContextId>
  }
}

/**
 * Package-owned Workbench Host adapter. It translates an authenticated Host
 * context into an opaque Security Invocation and delegates domain behavior to
 * {@link SecurityAssuranceService}.
 */
export class SecurityAssuranceWorkbenchRemote extends TypertRemoteService {
  static inject = ['securityAssurance', 'typert']

  constructor(ctx: Context, resolver: WorkbenchAuthorityContextResolverV1) {
    super(ctx, 'securityAssuranceWorkbench')
    if (resolver === undefined || typeof resolver.resolveAuthorityContext !== 'function') {
      throw new TypeError('Security Assurance Workbench Remote requires a Host authority resolver')
    }
    ctx.typert.lookups.register('securityAssuranceWorkbenchContext', {
      parameter: 'securityAssuranceWorkbenchContext',
      wire: 'securityAssuranceWorkbenchContextId',
      hostTypeSymbol: 'dsh-security-assurance#SecurityInvocation',
      wireTypeSymbol: 'dsh-security-assurance/workbench-remote#WorkbenchAuthorityContextId',
      resolve: async contextId => {
        if (!WORKBENCH_AUTHORITY_CONTEXT_PATTERN.test(contextId)) return undefined
        const operator = await resolver.resolveAuthorityContext(contextId)
        if (operator === undefined) return undefined
        return resolveTrustedInvocation(ctx.securityAssurance, {
          kind: 'host-operator',
          principalId: operator.principalId,
          permissions: operator.permissions,
        })
      },
    })
  }

  /** List authority-visible redacted Assessment identities for Host selection surfaces. */
  @Remote
  listAssessments(
    securityAssuranceWorkbenchContext: SecurityInvocation,
    request: ListAssessmentsRequest,
    signal: AbortSignal,
  ): Promise<SecurityResult<AssessmentListPageV1>> {
    return this.ctx.securityAssurance.listAssessments(
      securityAssuranceWorkbenchContext,
      request,
      { signal },
    )
  }

  /** Read one authority-projected Assessment Snapshot. */
  @Remote
  getAssessment(
    securityAssuranceWorkbenchContext: SecurityInvocation,
    request: GetAssessmentRequest,
    signal: AbortSignal,
  ): Promise<SecurityResult<AssessmentSnapshotV1>> {
    return this.ctx.securityAssurance.getAssessment(securityAssuranceWorkbenchContext, request, { signal })
  }

  /** List redacted Finding Summaries without Source Anchors or Evidence payloads. */
  @Remote
  listFindings(
    securityAssuranceWorkbenchContext: SecurityInvocation,
    request: ListFindingsRequest,
    signal: AbortSignal,
  ): Promise<SecurityResult<FindingListPageV1>> {
    return this.ctx.securityAssurance.listFindings(
      securityAssuranceWorkbenchContext,
      request,
      { signal },
    )
  }

  /** Read one exact revision-bound Finding Detail without Evidence payloads. */
  @Remote
  getFinding(
    securityAssuranceWorkbenchContext: SecurityInvocation,
    request: GetFindingRequest,
    signal: AbortSignal,
  ): Promise<SecurityResult<FindingDetailViewV1>> {
    return this.ctx.securityAssurance.getFinding(
      securityAssuranceWorkbenchContext,
      request,
      { signal },
    )
  }

  /** Wait for one later committed Assessment revision without holding a Store transaction. */
  @Remote
  waitForAssessmentRevision(
    securityAssuranceWorkbenchContext: SecurityInvocation,
    request: WaitForAssessmentRevisionRequest,
    signal: AbortSignal,
  ): Promise<SecurityResult<AssessmentRevisionSignalV1>> {
    return this.ctx.securityAssurance.waitForAssessmentRevision(
      securityAssuranceWorkbenchContext,
      request,
      { signal },
    )
  }

  /** Submit one catalogued, revision-bound Risk Decision command. */
  @Remote
  recordRiskDecision(
    securityAssuranceWorkbenchContext: SecurityInvocation,
    request: RecordRiskDecisionRequest,
    signal: AbortSignal,
  ): Promise<SecurityResult<RiskDecisionReceiptV1>> {
    return this.ctx.securityAssurance.recordRiskDecision(
      securityAssuranceWorkbenchContext,
      request,
      { signal },
    )
  }
}

export default SecurityAssuranceWorkbenchRemote
