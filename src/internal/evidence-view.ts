import { z } from 'zod'
import {
  digestEnvelopeV1Schema,
  EVIDENCE_VIEW_METADATA_ONLY_PROFILE_ID,
  evidenceViewV1Schema,
} from '../contracts.ts'
import type {
  BundleManifestV1,
  EvidenceViewContentV1,
  EvidenceProducerLineageV1,
  EvidenceViewV1,
  FindingDetailViewV1,
  GetEvidenceViewRequest,
  RepositoryBindingsV1,
  SecurityAssuranceSubmissionV1,
  SecuritySubmissionArtifactV1,
} from '../contracts.ts'
import { canonicalJson } from './canonical.ts'

const BOUNDED_JSON_BYTE_LIMIT = 32 * 1024
const locallyAvailableProtectionPolicies = new Set(['evidence/local-protected'])
const boundedJsonSchemas = new Set([
  'fixture/reference-validation-evidence',
  'dsh/security-node-package-manifest-evidence',
])

export class EvidenceViewNotFoundError extends Error {}

export interface EvidenceViewAuthority {
  readonly canDiscloseValidationReview: boolean
}

export interface EvidenceViewPolicies {
  readonly evidenceProtectionId: RepositoryBindingsV1['evidenceProtectionId']
  readonly dataEgressPolicyId: RepositoryBindingsV1['dataEgressPolicyId']
}

const analyzerIdentityProjectionSchema = z.object({
  analyzerId: z.string().min(1).max(128),
  analyzerVersion: z.string().min(1).max(128),
  buildDigest: digestEnvelopeV1Schema,
})

const evidenceProducerSourceSchema = z.object({
  analyzerIdentity: analyzerIdentityProjectionSchema.optional(),
  producerEligibility: z.object({
    analyzerIdentity: analyzerIdentityProjectionSchema,
  }).optional(),
})

function sameDigest(
  left: GetEvidenceViewRequest['evidenceDigest'],
  right: GetEvidenceViewRequest['evidenceDigest'],
): boolean {
  return canonicalJson(left) === canonicalJson(right)
}

function boundedContent(
  request: GetEvidenceViewRequest,
  artifact: SecuritySubmissionArtifactV1,
  classification: 'INTERNAL' | 'CONTROL_PLANE',
  authority: EvidenceViewAuthority,
  protectionAvailable: boolean,
  expiresAt: string,
): EvidenceViewContentV1 {
  if (request.viewProfileId === EVIDENCE_VIEW_METADATA_ONLY_PROFILE_ID) {
    return { kind: 'REDACTED', reason: 'PROFILE_METADATA_ONLY' }
  }
  if (request.purpose !== 'VALIDATION_REVIEW') {
    return { kind: 'REDACTED', reason: 'PURPOSE_NOT_AUTHORIZED' }
  }
  if (!authority.canDiscloseValidationReview) {
    return { kind: 'REDACTED', reason: 'DISCLOSURE_NOT_AUTHORIZED' }
  }
  if (!protectionAvailable) {
    return { kind: 'REDACTED', reason: 'PROTECTION_UNAVAILABLE' }
  }
  if (classification !== 'CONTROL_PLANE' || !boundedJsonSchemas.has(artifact.schemaId)) {
    return { kind: 'REDACTED', reason: 'SCHEMA_NOT_DISCLOSABLE' }
  }
  const byteLength = Buffer.byteLength(canonicalJson(artifact.value), 'utf8')
  if (byteLength > BOUNDED_JSON_BYTE_LIMIT) {
    return { kind: 'REDACTED', reason: 'PROFILE_BYTE_LIMIT' }
  }
  return {
    kind: 'BOUNDED_JSON',
    byteLength,
    expiresAt,
    value: artifact.value,
  }
}

function producerLineage(
  submission: SecurityAssuranceSubmissionV1,
  lineageArtifactId: string,
): EvidenceProducerLineageV1 {
  const lineageArtifact = submission.payload.evidence.find(candidate => (
    candidate.artifactId === lineageArtifactId
  ))
  if (lineageArtifact === undefined) {
    throw new TypeError('Evidence Link lineage artifact is missing from the sealed Submission')
  }
  const parsed = evidenceProducerSourceSchema.safeParse(lineageArtifact.value)
  const producer = parsed.success
    ? parsed.data.analyzerIdentity ?? parsed.data.producerEligibility?.analyzerIdentity
    : undefined
  return producer === undefined
    ? {
        status: 'NOT_AVAILABLE',
        reason: 'PRODUCER_IDENTITY_NOT_RECORDED',
        lineageArtifactId,
      }
    : {
        status: 'VERIFIED',
        producer,
        lineageArtifactId,
      }
}

/**
 * Deep Module owning Evidence identity binding and the complete named-profile
 * disclosure policy. It only projects from an already integrity-verified seal.
 */
export class EvidenceViewModule {
  get(
    submission: SecurityAssuranceSubmissionV1,
    manifest: BundleManifestV1,
    finding: FindingDetailViewV1,
    request: GetEvidenceViewRequest,
    policies: EvidenceViewPolicies,
    authority: EvidenceViewAuthority,
    boundedJsonExpiresAt: string,
  ): EvidenceViewV1 {
    const links = finding.evidenceLinks.filter(candidate => (
      candidate.artifactId === request.evidenceArtifactId
      && sameDigest(candidate.digest, request.evidenceDigest)
    ))
    const link = links[0]
    if (link === undefined) {
      throw new EvidenceViewNotFoundError('Evidence is not linked to the consuming Finding revision')
    }
    if (links.length !== 1) throw new TypeError('Finding has an ambiguous Evidence Link identity')
    const artifacts = submission.payload.evidence.filter(candidate => (
      candidate.artifactId === request.evidenceArtifactId
      && candidate.schemaId === link.schemaId
      && sameDigest(candidate.digest, request.evidenceDigest)
    ))
    const artifact = artifacts[0]
    if (artifact === undefined) {
      throw new TypeError('Finding Evidence Link target does not match the sealed Submission')
    }
    if (artifacts.length !== 1) throw new TypeError('Sealed Submission has an ambiguous Evidence identity')
    const descriptors = manifest.records.filter(candidate => (
      candidate.recordId === artifact.artifactId
      && candidate.schemaId === artifact.schemaId
      && sameDigest(candidate.digest, artifact.digest)
    ))
    const descriptor = descriptors[0]
    if (descriptor === undefined) {
      throw new TypeError('Evidence record does not match the sealed Bundle Manifest')
    }
    if (descriptors.length !== 1) throw new TypeError('Bundle Manifest has an ambiguous Evidence identity')
    const protectionAvailable = locallyAvailableProtectionPolicies.has(policies.evidenceProtectionId)
    return evidenceViewV1Schema.parse({
      schemaVersion: 1,
      assessmentId: request.assessmentId,
      assessmentRevision: request.assessmentRevision,
      context: request.context,
      evidence: {
        artifactId: artifact.artifactId,
        schemaId: artifact.schemaId,
        digest: artifact.digest,
        classification: descriptor.classification,
      },
      link: {
        purpose: link.purpose,
        eligibilityDecision: link.eligibilityDecision,
        eligibilityDecisionArtifactId: link.eligibilityDecisionArtifactId,
      },
      producerLineage: producerLineage(
        submission,
        link.eligibilityDecisionArtifactId,
      ),
      redactedSummary: {
        kind: 'SCHEMA_METADATA',
        byteLength: artifact.digest.byteLength,
        contentStatus: 'REDACTED',
      },
      purpose: request.purpose,
      viewProfileId: request.viewProfileId,
      protection: {
        policyId: policies.evidenceProtectionId,
        status: protectionAvailable ? 'AVAILABLE' : 'UNAVAILABLE',
      },
      retention: { status: 'RETAINED' },
      egress: {
        policyId: policies.dataEgressPolicyId,
        status: 'LOCAL_ONLY',
      },
      content: boundedContent(
        request,
        artifact,
        descriptor.classification,
        authority,
        protectionAvailable,
        boundedJsonExpiresAt,
      ),
    })
  }
}
