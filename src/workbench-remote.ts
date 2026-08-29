import type { Context } from '@deepseek-ai/cordis'
import {
  Remote,
  TypertRemoteService,
  type TypertLookup,
} from '@deepseek-ai/dsh-typert-protocol'
import type {
  AssessmentId,
  AssessmentCancellationReceiptV1,
  AssessmentResumeReceiptV1,
  AssessmentRevisionSignalV1,
  AssessmentListPageV1,
  AssessmentSnapshotV1,
  BundleManifestV1,
  DigestEnvelopeV1,
  EvidenceViewV1,
  ExportRequestReceiptV1,
  ExportViewV1,
  FindingDetailViewV1,
  FindingListPageV1,
  GetCatalogRequest,
  GetBundleManifestRequest,
  GetHealthRequest,
  GetAssessmentRequest,
  GetRepositoryRequest,
  GetFindingRequest,
  GetExportRequest,
  ListFindingsRequest,
  ListAssessmentsRequest,
  ListRepositoriesRequest,
  CancelAssessmentRequest,
  RecordRiskDecisionRequest,
  RequestExportRequest,
  ResumeAssessmentRequest,
  RiskDecisionReceiptV1,
  RepositoryListSnapshotV1,
  RepositorySnapshotV1,
  RuntimeHealthSnapshot,
  SecurityCatalogSnapshotV1,
  SecurityInvocation,
  SecurityResult,
  StartAssessmentRequest,
  AssessmentReceiptV1,
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
  | 'export:request'
  | 'export:read'
  | 'export:download'
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

/** Workbench confirmation always carries the exact Service-derived proposal digest. */
export type WorkbenchStartAssessmentRequestV1 = StartAssessmentRequest & {
  readonly startPreflightDigest: NonNullable<StartAssessmentRequest['startPreflightDigest']>
}

/** Strict browser request for the metadata-only Evidence disclosure slice. */
export interface WorkbenchEvidenceMetadataRequestV1 {
  readonly schemaVersion: 1
  readonly assessmentId: AssessmentId
  readonly assessmentRevision: number
  readonly context: {
    readonly kind: 'finding'
    readonly recordId: string
    readonly recordRevision: number
  }
  readonly evidenceArtifactId: string
  readonly evidenceDigest: DigestEnvelopeV1
  readonly purpose: 'FINDING_TRIAGE'
  readonly viewProfileId: 'security/evidence-view/metadata-only-v1'
}

/** Strict metadata-only Evidence projection; bounded content is not part of this Remote face. */
export interface WorkbenchEvidenceMetadataViewV1 {
  readonly schemaVersion: 1
  readonly assessmentId: AssessmentId
  readonly assessmentRevision: number
  readonly context: {
    readonly kind: 'finding'
    readonly recordId: string
    readonly recordRevision: number
  }
  readonly evidence: {
    readonly artifactId: string
    readonly schemaId: string
    readonly digest: DigestEnvelopeV1
    readonly classification: 'INTERNAL' | 'CONTROL_PLANE'
  }
  readonly link: {
    readonly purpose: 'VALIDATION_EVIDENCE' | 'COUNTER_EVIDENCE'
    readonly eligibilityDecision: 'ELIGIBLE' | 'INELIGIBLE'
    readonly eligibilityDecisionArtifactId: string
  }
  readonly producerLineage:
    | {
        readonly status: 'VERIFIED'
        readonly producer: {
          readonly analyzerId: string
          readonly analyzerVersion: string
          readonly buildDigest: DigestEnvelopeV1
        }
        readonly lineageArtifactId: string
      }
    | {
        readonly status: 'NOT_AVAILABLE'
        readonly reason: 'PRODUCER_IDENTITY_NOT_RECORDED'
        readonly lineageArtifactId: string
      }
  readonly redactedSummary: {
    readonly kind: 'SCHEMA_METADATA'
    readonly byteLength: number
    readonly contentStatus: 'REDACTED'
  }
  readonly purpose: 'FINDING_TRIAGE'
  readonly viewProfileId: 'security/evidence-view/metadata-only-v1'
  readonly protection: {
    readonly policyId: string
    readonly status: 'AVAILABLE' | 'UNAVAILABLE'
  }
  readonly retention: { readonly status: 'RETAINED' }
  readonly egress: {
    readonly policyId: string
    readonly status: 'LOCAL_ONLY'
  }
  readonly content: {
    readonly kind: 'REDACTED'
    readonly reason: 'PROFILE_METADATA_ONLY'
  }
}

/** Package-owned recursive JSON value admitted by the bounded Workbench Remote face. */
export type WorkbenchBoundedJsonV1 =
  | null
  | boolean
  | number
  | string
  | WorkbenchBoundedJsonV1[]
  | { [key: string]: WorkbenchBoundedJsonV1 }

/** Strict browser request for one explicit validation-review disclosure action. */
export interface WorkbenchEvidenceDisclosureRequestV1 {
  readonly schemaVersion: 1
  readonly assessmentId: AssessmentId
  readonly assessmentRevision: number
  readonly context: {
    readonly kind: 'finding'
    readonly recordId: string
    readonly recordRevision: number
  }
  readonly evidenceArtifactId: string
  readonly evidenceDigest: DigestEnvelopeV1
  readonly purpose: 'VALIDATION_REVIEW'
  readonly viewProfileId: 'security/evidence-view/bounded-json-v1'
}

/** Purpose-bound bounded disclosure or a structured Service redaction. */
export interface WorkbenchEvidenceDisclosureViewV1 {
  readonly schemaVersion: 1
  readonly assessmentId: AssessmentId
  readonly assessmentRevision: number
  readonly context: {
    readonly kind: 'finding'
    readonly recordId: string
    readonly recordRevision: number
  }
  readonly evidence: {
    readonly artifactId: string
    readonly schemaId: string
    readonly digest: DigestEnvelopeV1
    readonly classification: 'INTERNAL' | 'CONTROL_PLANE'
  }
  readonly link: {
    readonly purpose: 'VALIDATION_EVIDENCE' | 'COUNTER_EVIDENCE'
    readonly eligibilityDecision: 'ELIGIBLE' | 'INELIGIBLE'
    readonly eligibilityDecisionArtifactId: string
  }
  readonly producerLineage: WorkbenchEvidenceMetadataViewV1['producerLineage']
  readonly redactedSummary: WorkbenchEvidenceMetadataViewV1['redactedSummary']
  readonly purpose: 'VALIDATION_REVIEW'
  readonly viewProfileId: 'security/evidence-view/bounded-json-v1'
  readonly protection: {
    readonly policyId: string
    readonly status: 'AVAILABLE' | 'UNAVAILABLE'
  }
  readonly retention: { readonly status: 'RETAINED' }
  readonly egress: {
    readonly policyId: string
    readonly status: 'LOCAL_ONLY'
  }
  readonly content:
    | {
        readonly kind: 'REDACTED'
        readonly reason:
          | 'DISCLOSURE_NOT_AUTHORIZED'
          | 'PURPOSE_NOT_AUTHORIZED'
          | 'PROTECTION_UNAVAILABLE'
          | 'SCHEMA_NOT_DISCLOSABLE'
          | 'PROFILE_BYTE_LIMIT'
      }
    | {
        readonly kind: 'BOUNDED_JSON'
        readonly byteLength: number
        readonly expiresAt: string
        readonly value: WorkbenchBoundedJsonV1
      }
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

  /** Read the bounded Runtime Health projection through current Host authority. */
  @Remote
  getHealth(
    securityAssuranceWorkbenchContext: SecurityInvocation,
    request: GetHealthRequest,
    signal: AbortSignal,
  ): Promise<SecurityResult<RuntimeHealthSnapshot>> {
    return this.ctx.securityAssurance.getHealth(
      securityAssuranceWorkbenchContext,
      request,
      { signal },
    )
  }

  /** Read one integrity-verified SEALED Bundle Manifest through current Host authority. */
  @Remote
  getBundleManifest(
    securityAssuranceWorkbenchContext: SecurityInvocation,
    request: GetBundleManifestRequest,
    signal: AbortSignal,
  ): Promise<SecurityResult<BundleManifestV1>> {
    return this.ctx.securityAssurance.getBundleManifest(
      securityAssuranceWorkbenchContext,
      request,
      { signal },
    )
  }

  /** Preview, inspect, or explicitly consume one authorized Export download through fresh Host authority. */
  @Remote
  getExport(
    securityAssuranceWorkbenchContext: SecurityInvocation,
    request: GetExportRequest,
    signal: AbortSignal,
  ): Promise<SecurityResult<ExportViewV1>> {
    return this.ctx.securityAssurance.getExport(
      securityAssuranceWorkbenchContext,
      request,
      { signal },
    )
  }

  /** Request one idempotent registered-destination Export through current Host authority. */
  @Remote
  requestExport(
    securityAssuranceWorkbenchContext: SecurityInvocation,
    request: RequestExportRequest,
    signal: AbortSignal,
  ): Promise<SecurityResult<ExportRequestReceiptV1>> {
    return this.ctx.securityAssurance.requestExport(
      securityAssuranceWorkbenchContext,
      request,
      { signal },
    )
  }

  /** Read one path-free Repository binding projection through current Host authority. */
  @Remote
  getRepository(
    securityAssuranceWorkbenchContext: SecurityInvocation,
    request: GetRepositoryRequest,
    signal: AbortSignal,
  ): Promise<SecurityResult<RepositorySnapshotV1>> {
    return this.ctx.securityAssurance.getRepository(
      securityAssuranceWorkbenchContext,
      request,
      { signal },
    )
  }

  /** List authority-visible path-free Repository Registry entries. */
  @Remote
  listRepositories(
    securityAssuranceWorkbenchContext: SecurityInvocation,
    request: ListRepositoriesRequest,
    signal: AbortSignal,
  ): Promise<SecurityResult<RepositoryListSnapshotV1>> {
    return this.ctx.securityAssurance.listRepositories(
      securityAssuranceWorkbenchContext,
      request,
      { signal },
    )
  }

  /** Resolve Catalog choices and an optional immutable Start Preflight proposal. */
  @Remote
  getCatalog(
    securityAssuranceWorkbenchContext: SecurityInvocation,
    request: GetCatalogRequest,
    signal: AbortSignal,
  ): Promise<SecurityResult<SecurityCatalogSnapshotV1>> {
    return this.ctx.securityAssurance.getCatalog(
      securityAssuranceWorkbenchContext,
      request,
      { signal },
    )
  }

  /** Confirm one exact digest-bound Start Preflight through the root Service. */
  @Remote
  startAssessment(
    securityAssuranceWorkbenchContext: SecurityInvocation,
    request: WorkbenchStartAssessmentRequestV1,
    signal: AbortSignal,
  ): Promise<SecurityResult<AssessmentReceiptV1>> {
    return this.ctx.securityAssurance.startAssessment(
      securityAssuranceWorkbenchContext,
      request,
      { signal },
    )
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

  /** Read one purpose/profile-bound Evidence View without exposing Store authority. */
  @Remote
  async getEvidenceView(
    securityAssuranceWorkbenchContext: SecurityInvocation,
    request: WorkbenchEvidenceMetadataRequestV1,
    signal: AbortSignal,
  ): Promise<SecurityResult<WorkbenchEvidenceMetadataViewV1>> {
    const result = await this.ctx.securityAssurance.getEvidenceView(
      securityAssuranceWorkbenchContext,
      request,
      { signal },
    )
    if (!result.ok) return result
    if (!isMetadataOnlyEvidenceView(result.value)) {
      throw new TypeError('Security Service returned a non-metadata Evidence View')
    }
    return { ok: true, value: result.value }
  }

  /** Explicitly reauthorize and disclose one expiring validation-review View. */
  @Remote
  async discloseEvidence(
    securityAssuranceWorkbenchContext: SecurityInvocation,
    request: WorkbenchEvidenceDisclosureRequestV1,
    signal: AbortSignal,
  ): Promise<SecurityResult<WorkbenchEvidenceDisclosureViewV1>> {
    const result = await this.ctx.securityAssurance.getEvidenceView(
      securityAssuranceWorkbenchContext,
      request,
      { signal },
    )
    if (!result.ok) return result
    if (!isValidationReviewEvidenceView(result.value)) {
      throw new TypeError('Security Service returned a non-disclosure Evidence View')
    }
    return { ok: true, value: result.value }
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

  /** Resume only the frozen Assessment contract named by a Service-projected action. */
  @Remote
  resumeAssessment(
    securityAssuranceWorkbenchContext: SecurityInvocation,
    request: ResumeAssessmentRequest,
    signal: AbortSignal,
  ): Promise<SecurityResult<AssessmentResumeReceiptV1>> {
    return this.ctx.securityAssurance.resumeAssessment(
      securityAssuranceWorkbenchContext,
      request,
      { signal },
    )
  }

  /** Request cancellation without implying that terminal quiescence is already proven. */
  @Remote
  cancelAssessment(
    securityAssuranceWorkbenchContext: SecurityInvocation,
    request: CancelAssessmentRequest,
    signal: AbortSignal,
  ): Promise<SecurityResult<AssessmentCancellationReceiptV1>> {
    return this.ctx.securityAssurance.cancelAssessment(
      securityAssuranceWorkbenchContext,
      request,
      { signal },
    )
  }
}

export default SecurityAssuranceWorkbenchRemote

function isMetadataOnlyEvidenceView(
  view: EvidenceViewV1,
): view is WorkbenchEvidenceMetadataViewV1 {
  return view.purpose === 'FINDING_TRIAGE'
    && view.viewProfileId === 'security/evidence-view/metadata-only-v1'
    && view.content.kind === 'REDACTED'
    && view.content.reason === 'PROFILE_METADATA_ONLY'
}

function isValidationReviewEvidenceView(
  view: EvidenceViewV1,
): view is WorkbenchEvidenceDisclosureViewV1 {
  if (
    view.purpose !== 'VALIDATION_REVIEW'
    || view.viewProfileId !== 'security/evidence-view/bounded-json-v1'
  ) return false
  if (view.content.kind === 'BOUNDED_JSON') return true
  return view.content.reason !== 'PROFILE_METADATA_ONLY'
}
