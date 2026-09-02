import { z } from 'zod'
import type {
  AnalyzerContributionV1,
  AnalyzerDescriptorV1,
  AnalyzerFactoryV1,
  AnalyzerQualificationRecordV1,
} from '../analyzer.ts'
import { analyzerContributionV1Schema } from '../analyzer.ts'
import {
  digestEnvelopeV1Schema,
  SECURITY_ASSURANCE_PRODUCT_NAME,
} from '../contracts.ts'
import type { DigestEnvelopeV1 } from '../contracts.ts'
import { canonicalJson, sha256Hex, structuredDigest } from './canonical.ts'
import { deepFreeze } from './freeze.ts'

/**
 * External Analyzer Normalization Contract v1 — npm audit binding.
 *
 * The external tool (npm audit) runs OUTSIDE the Pure Analyzer boundary: a
 * CI job or the operator executes `npm audit --json > npm-audit.json` and the
 * report is frozen with the Subject. This PURE normalizer converts the
 * verified report slice into Candidate Findings, Coverage and Evidence.
 * Report freshness is a Host concern; the Assessment binds the exact frozen
 * report bytes, never a live registry response.
 */
export const NPM_AUDIT_NORMALIZATION_CONTRACT_ID = 'dsh/security/npm-audit-normalization/v1' as const
export const NPM_AUDIT_ANALYZER_ID = 'dsh/external-npm-audit' as const
export const NPM_AUDIT_ANALYZER_VERSION = '1.0.0' as const
export const NPM_AUDIT_POLICY_ID = 'security/npm-dependency-audit' as const
export const NPM_AUDIT_REPORT_BASE_NAME = 'npm-audit.json' as const
export const NPM_AUDIT_WEAKNESS_ID = 'dsh/npm-audit/vulnerable-dependency' as const
export const NPM_AUDIT_SECONDARY_WEAKNESS_ID = 'cwe/1395' as const
export const NPM_AUDIT_CONTROL_ID = 'dsh/npm-audit/dependency-integrity' as const
export const NPM_AUDIT_EVIDENCE_SCHEMA_ID = 'dsh/security-npm-audit-report-evidence' as const
export const NPM_AUDIT_COVERAGE_OBLIGATION_ID = 'application-security-analysis' as const
export const NPM_AUDIT_REPORT_MEDIA_TYPE = 'application/vnd.dsh.security.npm-audit-report-evidence+json' as const
const NPM_AUDIT_ANALYZER_METHOD = {
  schemaVersion: 1,
  contractId: NPM_AUDIT_NORMALIZATION_CONTRACT_ID,
  analyzerId: NPM_AUDIT_ANALYZER_ID,
  analyzerVersion: NPM_AUDIT_ANALYZER_VERSION,
  methodVersion: 'dsh-npm-audit-normalization-v1',
  input: 'verified npm-audit.json report slices frozen with the Subject',
  rule: 'every vulnerabilities record entry becomes one Candidate anchored by JSON Pointer',
  exclusions: 'live npm audit execution, registry access and lockfile resolution stay outside the Pure boundary',
} as const

export const NPM_AUDIT_DESCRIPTOR: AnalyzerDescriptorV1 = deepFreeze({
  schemaVersion: 1 as const,
  analyzerId: NPM_AUDIT_ANALYZER_ID,
  analyzerVersion: NPM_AUDIT_ANALYZER_VERSION,
  descriptorSchemaVersion: 1 as const,
  buildDigest: structuredDigest('application/vnd.dsh.security.analyzer-method+json', NPM_AUDIT_ANALYZER_METHOD),
  executionClass: 'PURE' as const,
  supportedAssessmentModes: ['REPOSITORY', 'CHANGE'] as const,
  supportedPolicyIds: [NPM_AUDIT_POLICY_ID] as const,
  coverageObligationIds: [NPM_AUDIT_COVERAGE_OBLIGATION_ID] as const,
  evidenceSchemaIds: [NPM_AUDIT_EVIDENCE_SCHEMA_ID] as const,
  egress: 'NONE' as const,
})

const NPM_AUDIT_QUALIFICATION_CORE = {
  schemaVersion: 1 as const,
  qualificationId: 'dsh/qualification/external-npm-audit/v1' as const,
  analyzerIdentity: {
    analyzerId: NPM_AUDIT_DESCRIPTOR.analyzerId,
    analyzerVersion: NPM_AUDIT_DESCRIPTOR.analyzerVersion,
    descriptorSchemaVersion: NPM_AUDIT_DESCRIPTOR.descriptorSchemaVersion,
    buildDigest: NPM_AUDIT_DESCRIPTOR.buildDigest,
  },
  issuerId: 'dsh/security-assurance-development' as const,
  level: 'HOST_ATTESTED' as const,
  supportedEcosystemIds: ['node-npm-audit-report'] as const,
  supportedAssessmentModes: ['REPOSITORY', 'CHANGE'] as const,
  supportedPolicyIds: [NPM_AUDIT_POLICY_ID] as const,
  coverageObligationIds: [NPM_AUDIT_COVERAGE_OBLIGATION_ID] as const,
  evidenceSchemaIds: [NPM_AUDIT_EVIDENCE_SCHEMA_ID] as const,
  executionClass: 'PURE' as const,
  executionBackendId: 'dsh/security-assurance/in-process-pure-v1' as const,
  providerIds: [SECURITY_ASSURANCE_PRODUCT_NAME] as const,
  egress: 'NONE' as const,
  platforms: ['win32', 'linux', 'darwin'] as const,
  issuedAt: '2026-01-01T00:00:00.000Z' as const,
  expiresAt: '2099-01-01T00:00:00.000Z' as const,
  evidenceDigests: [NPM_AUDIT_DESCRIPTOR.buildDigest] as const,
  limitations: [
    'Only the frozen npm-audit.json report is evaluated; report freshness is the Host responsibility.',
    'CHANGE mode evaluates the report frozen in the complete head tree for an exact committed base-to-head pair.',
    'This qualification does not claim general dependency, license, or reachability analysis coverage.',
  ] as const,
}

export const NPM_AUDIT_QUALIFICATION: AnalyzerQualificationRecordV1 = deepFreeze({
  ...NPM_AUDIT_QUALIFICATION_CORE,
  qualificationDigest: structuredDigest(
    'application/vnd.dsh.security.analyzer-qualification+json',
    NPM_AUDIT_QUALIFICATION_CORE,
  ),
})

export const npmAuditSeveritySchema = z.enum(['critical', 'high', 'moderate', 'low', 'info'])
export type NpmAuditSeverity = z.infer<typeof npmAuditSeveritySchema>

export const evaluationSeverityFromNpmAudit = {
  critical: 'CRITICAL',
  high: 'HIGH',
  moderate: 'MEDIUM',
  low: 'LOW',
  info: 'INFORMATIONAL',
} as const satisfies Record<NpmAuditSeverity, string>

const npmAuditViaString = z.string().max(512)
const npmAuditViaAdvisorySchema = z.strictObject({
  source: z.number().int().nonnegative().optional(),
  name: z.string().max(512).optional(),
  dependency: z.string().max(512).optional(),
  title: z.string().max(1024).optional(),
  url: z.string().max(2048).optional(),
  severity: npmAuditSeveritySchema.optional(),
  range: z.string().max(1024).optional(),
})
const npmAuditVulnerabilitySchema = z.strictObject({
  name: z.string().min(1).max(512).optional(),
  severity: npmAuditSeveritySchema,
  isDirect: z.boolean().optional(),
  via: z.array(z.union([npmAuditViaString, npmAuditViaAdvisorySchema])).max(256).optional(),
  effects: z.array(z.string().max(512)).max(256).optional(),
  range: z.string().max(1024).optional(),
  nodes: z.array(z.string().max(1024)).max(256).optional(),
  fixAvailable: z.union([z.boolean(), z.strictObject({
    name: z.string().max(512),
    version: z.string().max(128),
    isSemVerMajor: z.boolean(),
  })]).optional(),
}).loose()
const npmAuditReportSchema = z.strictObject({
  auditReportVersion: z.number().int().min(1).max(16).optional(),
  vulnerabilities: z.record(z.string().max(512), npmAuditVulnerabilitySchema).optional(),
  metadata: z.record(z.string().max(128), z.unknown()).optional(),
}).loose()

export const npmAuditFindingEvidenceEntryV1Schema = z.strictObject({
  candidateId: z.string().regex(/^candidate-[0-9a-f]{64}$/),
  name: z.string().min(1).max(512),
  severity: z.enum(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL']),
  title: z.string().max(1024).nullable(),
  url: z.string().max(2048).nullable(),
  range: z.string().max(1024).nullable(),
  fixAvailable: z.boolean().nullable(),
  isDirect: z.boolean().nullable(),
  sourceAnchor: z.strictObject({
    path: z.string().min(1).max(1024),
    fileDigest: digestEnvelopeV1Schema,
    locator: z.strictObject({
      kind: z.literal('JSON_POINTER'),
      value: z.string().min(1).max(1024),
    }),
  }),
})
export type NpmAuditFindingEvidenceEntryV1 = z.infer<typeof npmAuditFindingEvidenceEntryV1Schema>

export const npmAuditReportEvidenceV1Schema = z.strictObject({
  schemaVersion: z.literal(1),
  contractId: z.literal(NPM_AUDIT_NORMALIZATION_CONTRACT_ID),
  analyzerIdentity: z.strictObject({
    analyzerId: z.literal(NPM_AUDIT_ANALYZER_ID),
    analyzerVersion: z.literal(NPM_AUDIT_ANALYZER_VERSION),
    descriptorSchemaVersion: z.literal(1),
    buildDigest: digestEnvelopeV1Schema,
  }),
  subjectDigest: digestEnvelopeV1Schema,
  reportPath: z.string().min(1).max(1024),
  reportDigest: digestEnvelopeV1Schema,
  auditReportVersion: z.number().int().min(1).max(16).nullable(),
  totals: z.strictObject({
    CRITICAL: z.number().int().nonnegative(),
    HIGH: z.number().int().nonnegative(),
    MEDIUM: z.number().int().nonnegative(),
    LOW: z.number().int().nonnegative(),
    INFORMATIONAL: z.number().int().nonnegative(),
  }),
  entries: z.array(npmAuditFindingEvidenceEntryV1Schema).max(768),
})
export type NpmAuditReportEvidenceV1 = z.infer<typeof npmAuditReportEvidenceV1Schema>

export function escapeJsonPointerSegment(segment: string): string {
  return segment.replaceAll('~', '~0').replaceAll('/', '~1')
}

export function unescapeJsonPointerSegment(segment: string): string {
  return segment.replaceAll('~1', '/').replaceAll('~0', '~')
}

function analyzerIdentity(): {
  readonly analyzerId: typeof NPM_AUDIT_ANALYZER_ID
  readonly analyzerVersion: typeof NPM_AUDIT_ANALYZER_VERSION
  readonly descriptorSchemaVersion: 1
  readonly buildDigest: DigestEnvelopeV1
} {
  return {
    analyzerId: NPM_AUDIT_ANALYZER_ID,
    analyzerVersion: NPM_AUDIT_ANALYZER_VERSION,
    descriptorSchemaVersion: 1,
    buildDigest: NPM_AUDIT_DESCRIPTOR.buildDigest,
  }
}

type NpmAuditDiagnostic =
  | 'NPM_AUDIT_REPORT_MISSING'
  | 'NPM_AUDIT_REPORT_LIMIT'
  | 'NPM_AUDIT_REPORT_INVALID_JSON'
  | 'NPM_AUDIT_REPORT_INVALID_SHAPE'
  | 'NPM_AUDIT_CANDIDATE_LIMIT'

const MAX_REPORT_SLICES = 127
const MAX_CANDIDATES = 768

interface NormalizedCandidate {
  readonly candidateId: string
  readonly name: string
  readonly severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFORMATIONAL'
  readonly title: string | null
  readonly url: string | null
  readonly range: string | null
  readonly fixAvailable: boolean | null
  readonly isDirect: boolean | null
  readonly securityClaim: string
  readonly sourceAnchor: {
    readonly path: string
    readonly fileDigest: DigestEnvelopeV1
    readonly locator: { readonly kind: 'JSON_POINTER'; readonly value: string }
  }
  readonly evidenceArtifactId: string
}

function firstAdvisory(
  via: readonly (string | z.infer<typeof npmAuditViaAdvisorySchema>)[] | undefined,
): { readonly title: string | null; readonly url: string | null } {
  if (via === undefined) return { title: null, url: null }
  for (const entry of via) {
    if (typeof entry === 'object' && entry.title !== undefined) {
      return { title: entry.title, url: entry.url ?? null }
    }
  }
  return { title: null, url: null }
}

function buildSecurityClaim(candidate: {
  readonly name: string
  readonly severity: string
  readonly title: string | null
  readonly url: string | null
}): string {
  const title = candidate.title === null ? '' : `: ${candidate.title.slice(0, 512)}`
  const url = candidate.url === null ? '' : ` (${candidate.url.slice(0, 512)})`
  const claim = `Dependency '${candidate.name}' has a known ${candidate.severity.toLowerCase()}-severity vulnerability reported by npm audit${title}${url}.`
  return claim.length > 2048 ? claim.slice(0, 2048) : claim
}

/**
 * Pure npm audit normalization: verified report slices in, deterministic
 * Analyzer Contribution out. No filesystem, process, network, model, clock,
 * or Store authority.
 */
export function analyzeNpmAuditReport(input: {
  readonly subjectDigest: DigestEnvelopeV1
  readonly slices: readonly {
    readonly path: string
    readonly digest: DigestEnvelopeV1
    readonly text: string
  }[]
}): AnalyzerContributionV1 {
  const diagnostics = new Set<NpmAuditDiagnostic>()
  const reportSlices = [...input.slices].sort((left, right) => left.path.localeCompare(right.path))
  if (reportSlices.length === 0) diagnostics.add('NPM_AUDIT_REPORT_MISSING')
  const boundedSlices = reportSlices.slice(0, MAX_REPORT_SLICES)
  if (reportSlices.length > boundedSlices.length) diagnostics.add('NPM_AUDIT_REPORT_LIMIT')

  const candidates: NormalizedCandidate[] = []
  const evidence: {
    readonly artifactId: string
    readonly schemaId: string
    readonly mediaType: string
    readonly value: NpmAuditReportEvidenceV1
  }[] = []
  let bytesRead = 0
  let incomplete = false

  for (const [index, slice] of boundedSlices.entries()) {
    bytesRead += Buffer.byteLength(slice.text, 'utf8')
    const artifactId = index === 0 ? 'npm-audit-report' : `npm-audit-report-${index + 1}`
    let parsed: unknown
    try {
      parsed = JSON.parse(slice.text)
    } catch {
      diagnostics.add('NPM_AUDIT_REPORT_INVALID_JSON')
      incomplete = true
      continue
    }
    const report = npmAuditReportSchema.safeParse(parsed)
    if (!report.success) {
      diagnostics.add('NPM_AUDIT_REPORT_INVALID_SHAPE')
      incomplete = true
      continue
    }
    const vulnerabilities = report.data.vulnerabilities ?? {}
    const totals = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFORMATIONAL: 0 }
    const entries: NpmAuditFindingEvidenceEntryV1[] = []
    for (const key of Object.keys(vulnerabilities).sort()) {
      const vulnerability = vulnerabilities[key]!
      const severity = evaluationSeverityFromNpmAudit[vulnerability.severity]
      totals[severity] += 1
      if (candidates.length >= MAX_CANDIDATES) {
        diagnostics.add('NPM_AUDIT_CANDIDATE_LIMIT')
        incomplete = true
        break
      }
      const name = vulnerability.name ?? key
      const advisory = firstAdvisory(vulnerability.via)
      const range = vulnerability.range ?? null
      const fixAvailable = typeof vulnerability.fixAvailable === 'boolean'
        ? vulnerability.fixAvailable
        : vulnerability.fixAvailable === undefined ? null : true
      const isDirect = vulnerability.isDirect ?? null
      const sourceAnchor = {
        path: slice.path,
        fileDigest: slice.digest,
        locator: {
          kind: 'JSON_POINTER' as const,
          value: `/vulnerabilities/${escapeJsonPointerSegment(key)}`,
        },
      }
      const candidateId = `candidate-${sha256Hex(canonicalJson({
        analyzerIdentity: analyzerIdentity(),
        subjectDigest: input.subjectDigest,
        name: key,
        severity,
        sourceAnchor,
      }))}`
      const securityClaim = buildSecurityClaim({ name, severity, ...advisory })
      candidates.push({
        candidateId,
        name,
        severity,
        title: advisory.title,
        url: advisory.url,
        range,
        fixAvailable,
        isDirect,
        securityClaim,
        sourceAnchor,
        evidenceArtifactId: artifactId,
      })
      entries.push({
        candidateId,
        name,
        severity,
        title: advisory.title,
        url: advisory.url,
        range,
        fixAvailable,
        isDirect,
        sourceAnchor: {
          path: sourceAnchor.path,
          fileDigest: sourceAnchor.fileDigest,
          locator: { kind: 'JSON_POINTER', value: sourceAnchor.locator.value },
        },
      })
    }
    evidence.push({
      artifactId,
      schemaId: NPM_AUDIT_EVIDENCE_SCHEMA_ID,
      mediaType: NPM_AUDIT_REPORT_MEDIA_TYPE,
      value: {
        schemaVersion: 1,
        contractId: NPM_AUDIT_NORMALIZATION_CONTRACT_ID,
        analyzerIdentity: analyzerIdentity(),
        subjectDigest: input.subjectDigest,
        reportPath: slice.path,
        reportDigest: slice.digest,
        auditReportVersion: report.data.auditReportVersion ?? null,
        totals,
        entries,
      },
    })
  }

  const complete = reportSlices.length > 0 && !incomplete
  const contribution = analyzerContributionV1Schema.parse({
    schemaVersion: 1,
    analyzerIdentity: analyzerIdentity(),
    subjectDigest: input.subjectDigest,
    completionDisposition: reportSlices.length === 0
      ? 'UNSUPPORTED'
      : complete ? 'COMPLETE' : 'INCOMPLETE',
    coverageClaims: complete && evidence.length > 0 ? [{
      obligationId: NPM_AUDIT_COVERAGE_OBLIGATION_ID,
      completion: 'COMPLETE',
      evidenceArtifactId: evidence[0]!.artifactId,
    }] : [],
    candidateFindings: candidates.map(candidate => ({
      schemaVersion: 1,
      candidateId: candidate.candidateId,
      weaknessClassification: {
        schemaVersion: 1,
        primary: NPM_AUDIT_WEAKNESS_ID,
        secondary: [NPM_AUDIT_SECONDARY_WEAKNESS_ID],
      },
      affectedControlId: NPM_AUDIT_CONTROL_ID,
      securityClaim: candidate.securityClaim,
      sourceAnchor: candidate.sourceAnchor,
      evidenceArtifactIds: [candidate.evidenceArtifactId],
    })),
    evidence,
    diagnostics: [...diagnostics].sort(),
    resourceUse: {
      filesRead: boundedSlices.length,
      bytesRead,
    },
  })
  return deepFreeze(contribution)
}

/** Factory producing one Attempt instance per frozen Descriptor. */
export const createNpmAuditAnalyzer: AnalyzerFactoryV1 = descriptor => ({
  descriptor,
  async analyze(analyzerInput) {
    return analyzeNpmAuditReport({
      subjectDigest: analyzerInput.subject.digest,
      slices: analyzerInput.subject.textSlices.filter(slice => (
        slice.path.split('/').at(-1) === NPM_AUDIT_REPORT_BASE_NAME
      )),
    })
  },
  async dispose() {},
})
