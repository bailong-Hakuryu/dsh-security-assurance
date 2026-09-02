import { z } from 'zod'
import type {
  AnalyzerCandidateFindingV1,
  AnalyzerContributionV1,
  AnalyzerPortfolioEntryV1,
} from '../analyzer.ts'
import type {
  DigestEnvelopeV1,
  SecuritySubmissionJsonV1,
} from '../contracts.ts'
import {
  digestEnvelopeV1Schema,
  securitySubmissionJsonV1Schema,
} from '../contracts.ts'
import { canonicalJson, sha256Hex } from './canonical.ts'
import type { EvidencePublicationInputV1 } from './evidence-persistence.ts'
import {
  GITLEAKS_ANALYZER_ID,
  GITLEAKS_ANALYZER_VERSION,
  GITLEAKS_CONTROL_ID,
  GITLEAKS_COVERAGE_OBLIGATION_ID,
  GITLEAKS_DESCRIPTOR,
  GITLEAKS_DROPPED_REPORT_FIELDS,
  GITLEAKS_EVIDENCE_SCHEMA_ID,
  GITLEAKS_NORMALIZATION_CONTRACT_ID,
  GITLEAKS_POLICY_ID,
  GITLEAKS_QUALIFICATION,
  GITLEAKS_REPORT_BASE_NAME,
  GITLEAKS_REPORT_MEDIA_TYPE,
  GITLEAKS_SECONDARY_WEAKNESS_ID,
  GITLEAKS_WEAKNESS_ID,
  gitleaksReportEvidenceV1Schema,
} from './gitleaks-analyzer.ts'
import {
  evaluationSeverityFromNpmAudit,
  escapeJsonPointerSegment,
  NPM_AUDIT_CONTROL_ID,
  NPM_AUDIT_DESCRIPTOR,
  NPM_AUDIT_EVIDENCE_SCHEMA_ID,
  NPM_AUDIT_POLICY_ID,
  NPM_AUDIT_QUALIFICATION,
  NPM_AUDIT_REPORT_BASE_NAME,
  NPM_AUDIT_REPORT_MEDIA_TYPE,
  NPM_AUDIT_SECONDARY_WEAKNESS_ID,
  NPM_AUDIT_WEAKNESS_ID,
  npmAuditReportEvidenceV1Schema,
  npmAuditSeveritySchema,
  unescapeJsonPointerSegment,
} from './npm-audit-analyzer.ts'
import type { VerifiedSubjectTextSliceV1 } from './subject-freeze.ts'

const VALIDATION_CONTRACT_ID = 'dsh/conformance/reference-control-validation-v1'
const WEAKNESS_ID = 'dsh/conformance/reference-control-violation'
const CONTROL_ID = 'dsh/conformance/reference-control'
const SECURITY_CLAIM = 'The conformance reference security control is explicitly violated.'
const EVIDENCE_SCHEMA_ID = 'fixture/reference-validation-evidence'
const JSON_POINTER = '/dshSecurity/referenceControl'

const sourceAnchorSchema = z.strictObject({
  path: z.literal('package.json'),
  fileDigest: digestEnvelopeV1Schema,
  locator: z.strictObject({
    kind: z.literal('JSON_POINTER'),
    value: z.literal(JSON_POINTER),
  }),
})

const referenceValidationEvidenceV1Schema = z.strictObject({
  schemaVersion: z.literal(1),
  candidateId: z.string().regex(/^candidate-[0-9a-f]{64}$/),
  subjectDigest: digestEnvelopeV1Schema,
  sourceAnchor: sourceAnchorSchema,
  observedValue: z.enum(['VIOLATED', 'SATISFIED']),
  observedImpact: z.enum(['HIGH', 'CRITICAL']).default('HIGH'),
})

export interface CandidateValidationInputV1 {
  readonly portfolioEntry: AnalyzerPortfolioEntryV1
  readonly contribution: AnalyzerContributionV1
  readonly subjectSlices: readonly VerifiedSubjectTextSliceV1[]
  readonly policyId: string
  readonly policyDigest: DigestEnvelopeV1
}

export interface CandidateValidationResultV1 {
  readonly findings: readonly NonNullable<SecuritySubmissionJsonV1>[]
  readonly evidence: readonly EvidencePublicationInputV1[]
  readonly unresolvedCandidateIds: readonly string[]
}

function json(value: unknown): NonNullable<SecuritySubmissionJsonV1> {
  const normalized = securitySubmissionJsonV1Schema.parse(value)
  if (normalized === null) throw new TypeError('Candidate validation artifact must be an object')
  return normalized
}

function referenceControlState(
  slice: VerifiedSubjectTextSliceV1,
): {
  readonly value: 'VIOLATED' | 'SATISFIED'
  readonly impact: 'HIGH' | 'CRITICAL'
} | undefined {
  if ((slice.text.match(/"dshSecurity"\s*:/gu) ?? []).length !== 1) return undefined
  if ((slice.text.match(/"referenceControl"\s*:/gu) ?? []).length !== 1) return undefined
  try {
    const parsed: unknown = JSON.parse(slice.text)
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) return undefined
    const dshSecurity = (parsed as Record<string, unknown>).dshSecurity
    if (typeof dshSecurity !== 'object' || dshSecurity === null || Array.isArray(dshSecurity)) {
      return undefined
    }
    const value = (dshSecurity as Record<string, unknown>).referenceControl
    const impact = (dshSecurity as Record<string, unknown>).referenceImpact ?? 'HIGH'
    return (value === 'VIOLATED' || value === 'SATISFIED')
      && (impact === 'HIGH' || impact === 'CRITICAL')
      ? { value, impact }
      : undefined
  } catch {
    return undefined
  }
}

function candidatePrefix(candidateId: string): string {
  return candidateId.slice('candidate-'.length, 'candidate-'.length + 16)
}

const GITLEAKS_VALIDATION_CONTRACT_ID = 'dsh/security/gitleaks-validation/v1'
const GITLEAKS_NEGATIVE_CONTROLS = [
  'verified-subject-digest',
  'exact-report-slice-digest',
  'exact-array-index-pointer',
  'report-entry-rule-match',
  'report-entry-path-match',
  'report-entry-location-match',
  'candidate-identity-rederived',
  'candidate-security-claim-match',
  'candidate-evidence-binding',
  'sensitive-report-fields-not-retained',
] as const

const gitleaksValidationLocationValue = z.number().int().nonnegative().max(2_147_483_647)
const gitleaksValidationAffectedPathSchema = z.string().min(1).max(1024).transform((value, context) => {
  const canonical = value.normalize('NFC').replaceAll('\\', '/').replace(/^\.\//u, '')
  const segments = canonical.split('/')
  const reserved = /^(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\..*)?$/iu
  if (
    canonical.length === 0
    || canonical.startsWith('/')
    || /^[a-z]:/iu.test(canonical)
    || canonical.includes('\0')
    || Array.from(canonical).some(character => (character.codePointAt(0) ?? 0) <= 0x1f)
    || segments.some(segment => (
      segment.length === 0
      || segment === '.'
      || segment === '..'
      || segment.toLowerCase() === '.git'
      || segment.endsWith('.')
      || segment.endsWith(' ')
      || segment.includes(':')
      || reserved.test(segment)
    ))
  ) {
    context.addIssue({ code: 'custom', message: 'Gitleaks File must identify a portable Subject-relative path' })
    return z.NEVER
  }
  return canonical
})
const gitleaksValidationFindingSchema = z.strictObject({
  RuleID: z.string().min(1).max(256),
  File: gitleaksValidationAffectedPathSchema,
  StartLine: gitleaksValidationLocationValue,
  EndLine: gitleaksValidationLocationValue,
  StartColumn: gitleaksValidationLocationValue,
  EndColumn: gitleaksValidationLocationValue,
}).loose().superRefine((finding, context) => {
  if (finding.EndLine < finding.StartLine) {
    context.addIssue({ code: 'custom', message: 'Gitleaks end line precedes start line' })
  }
  if (finding.StartLine === finding.EndLine && finding.EndColumn < finding.StartColumn) {
    context.addIssue({ code: 'custom', message: 'Gitleaks end column precedes start column' })
  }
})
const gitleaksValidationReportSchema = z.array(gitleaksValidationFindingSchema).max(768)

interface IndependentlyObservedGitleaksEntry {
  readonly ruleId: string
  readonly affectedPath: string
  readonly startLine: number
  readonly endLine: number
  readonly startColumn: number
  readonly endColumn: number
  readonly securityClaim: string
}

function independentlyDerivedGitleaksSecurityClaim(entry: {
  readonly ruleId: string
  readonly affectedPath: string
  readonly startLine: number
}): string {
  const claim = `Gitleaks reported rule '${entry.ruleId}' at '${entry.affectedPath}:${entry.startLine}'. Sensitive match content was discarded during normalization.`
  return claim.length > 2048 ? claim.slice(0, 2048) : claim
}

function resolveGitleaksReportEntry(
  slice: VerifiedSubjectTextSliceV1,
  pointer: string,
): IndependentlyObservedGitleaksEntry | undefined {
  if (!/^\/(?:0|[1-9][0-9]*)$/u.test(pointer)) return undefined
  const index = Number(pointer.slice(1))
  if (!Number.isSafeInteger(index)) return undefined
  try {
    const report = gitleaksValidationReportSchema.safeParse(JSON.parse(slice.text))
    const raw = report.success ? report.data[index] : undefined
    if (raw === undefined) return undefined
    const observed = {
      ruleId: raw.RuleID,
      affectedPath: raw.File,
      startLine: raw.StartLine,
      endLine: raw.EndLine,
      startColumn: raw.StartColumn,
      endColumn: raw.EndColumn,
    }
    return {
      ...observed,
      securityClaim: independentlyDerivedGitleaksSecurityClaim(observed),
    }
  } catch {
    return undefined
  }
}

function expectedGitleaksCandidateId(input: {
  readonly contribution: AnalyzerContributionV1
  readonly slice: VerifiedSubjectTextSliceV1
  readonly pointer: string
  readonly observed: IndependentlyObservedGitleaksEntry
}): string {
  return `candidate-${sha256Hex(canonicalJson({
    analyzerIdentity: input.contribution.analyzerIdentity,
    subjectDigest: input.contribution.subjectDigest,
    projected: {
      ruleId: input.observed.ruleId,
      affectedPath: input.observed.affectedPath,
      startLine: input.observed.startLine,
      endLine: input.observed.endLine,
      startColumn: input.observed.startColumn,
      endColumn: input.observed.endColumn,
    },
    sourceAnchor: {
      path: input.slice.path,
      fileDigest: input.slice.digest,
      locator: { kind: 'JSON_POINTER', value: input.pointer },
    },
  }))}`
}

/**
 * Re-derive every Gitleaks report entry from the exact frozen Subject bytes.
 * This validator deliberately does not use the normalizer's report parser.
 */
export function gitleaksCoverageIsIndependentlyVerified(
  input: CandidateValidationInputV1,
): boolean {
  const { descriptor, qualification } = input.portfolioEntry
  const expectedIdentity = {
    analyzerId: GITLEAKS_ANALYZER_ID,
    analyzerVersion: GITLEAKS_ANALYZER_VERSION,
    descriptorSchemaVersion: GITLEAKS_DESCRIPTOR.descriptorSchemaVersion,
    buildDigest: GITLEAKS_DESCRIPTOR.buildDigest,
  }
  if (
    input.policyId !== GITLEAKS_POLICY_ID
    || canonicalJson(descriptor) !== canonicalJson(GITLEAKS_DESCRIPTOR)
    || qualification === null
    || qualification.qualificationId !== GITLEAKS_QUALIFICATION.qualificationId
    || canonicalJson(qualification.qualificationDigest)
      !== canonicalJson(GITLEAKS_QUALIFICATION.qualificationDigest)
    || canonicalJson(input.contribution.analyzerIdentity) !== canonicalJson(expectedIdentity)
    || input.contribution.completionDisposition !== 'COMPLETE'
    || input.contribution.diagnostics.length !== 0
    || input.contribution.coverageClaims.length !== 1
    || input.contribution.coverageClaims[0]?.obligationId !== GITLEAKS_COVERAGE_OBLIGATION_ID
  ) return false

  const reportSlices = input.subjectSlices.filter(slice => (
    slice.path.split('/').at(-1) === GITLEAKS_REPORT_BASE_NAME
  ))
  if (reportSlices.length === 0 || input.contribution.evidence.length !== reportSlices.length) {
    return false
  }
  const evidenceByPath = new Map<string, {
    readonly artifactId: string
    readonly value: z.infer<typeof gitleaksReportEvidenceV1Schema>
  }>()
  for (const artifact of input.contribution.evidence) {
    if (
      artifact.schemaId !== GITLEAKS_EVIDENCE_SCHEMA_ID
      || artifact.mediaType !== GITLEAKS_REPORT_MEDIA_TYPE
    ) return false
    const evidence = gitleaksReportEvidenceV1Schema.safeParse(artifact.value)
    if (
      !evidence.success
      || evidence.data.contractId !== GITLEAKS_NORMALIZATION_CONTRACT_ID
      || canonicalJson(evidence.data.analyzerIdentity) !== canonicalJson(expectedIdentity)
      || canonicalJson(evidence.data.subjectDigest)
        !== canonicalJson(input.contribution.subjectDigest)
      || canonicalJson(evidence.data.redaction.droppedFields)
        !== canonicalJson(GITLEAKS_DROPPED_REPORT_FIELDS)
      || evidenceByPath.has(evidence.data.reportPath)
    ) return false
    evidenceByPath.set(evidence.data.reportPath, {
      artifactId: artifact.artifactId,
      value: evidence.data,
    })
  }
  const coverageArtifactId = input.contribution.coverageClaims[0]?.evidenceArtifactId
  if (!input.contribution.evidence.some(artifact => artifact.artifactId === coverageArtifactId)) {
    return false
  }
  const candidatesById = new Map(input.contribution.candidateFindings.map(candidate => (
    [candidate.candidateId, candidate] as const
  )))
  if (candidatesById.size !== input.contribution.candidateFindings.length) return false
  const coveredCandidateIds = new Set<string>()
  for (const slice of reportSlices) {
    let report: z.infer<typeof gitleaksValidationReportSchema>
    try {
      const parsed = gitleaksValidationReportSchema.safeParse(JSON.parse(slice.text))
      if (!parsed.success) return false
      report = parsed.data
    } catch {
      return false
    }
    const evidence = evidenceByPath.get(slice.path)
    if (
      evidence === undefined
      || canonicalJson(evidence.value.reportDigest) !== canonicalJson(slice.digest)
      || evidence.value.findingsCount !== report.length
      || evidence.value.entries.length !== report.length
    ) return false
    const entriesByPointer = new Map(evidence.value.entries.map(entry => (
      [entry.sourceAnchor.locator.value, entry] as const
    )))
    if (entriesByPointer.size !== evidence.value.entries.length) return false
    for (const [index] of report.entries()) {
      const pointer = `/${index}`
      const observed = resolveGitleaksReportEntry(slice, pointer)
      const entry = entriesByPointer.get(pointer)
      if (
        observed === undefined
        || entry === undefined
        || entry.ruleId !== observed.ruleId
        || entry.affectedPath !== observed.affectedPath
        || entry.location.startLine !== observed.startLine
        || entry.location.endLine !== observed.endLine
        || entry.location.startColumn !== observed.startColumn
        || entry.location.endColumn !== observed.endColumn
        || entry.sourceAnchor.path !== slice.path
        || canonicalJson(entry.sourceAnchor.fileDigest) !== canonicalJson(slice.digest)
        || entry.candidateId !== expectedGitleaksCandidateId({
          contribution: input.contribution,
          slice,
          pointer,
          observed,
        })
      ) return false
      const candidate = candidatesById.get(entry.candidateId)
      if (
        candidate === undefined
        || coveredCandidateIds.has(entry.candidateId)
        || candidate.weaknessClassification.primary !== GITLEAKS_WEAKNESS_ID
        || candidate.weaknessClassification.secondary.length !== 1
        || candidate.weaknessClassification.secondary[0] !== GITLEAKS_SECONDARY_WEAKNESS_ID
        || candidate.affectedControlId !== GITLEAKS_CONTROL_ID
        || candidate.evidenceArtifactIds.length !== 1
        || candidate.evidenceArtifactIds[0] !== evidence.artifactId
        || canonicalJson(candidate.sourceAnchor) !== canonicalJson(entry.sourceAnchor)
        || candidate.securityClaim !== observed.securityClaim
      ) return false
      coveredCandidateIds.add(entry.candidateId)
    }
  }
  return coveredCandidateIds.size === candidatesById.size
}

const NPM_AUDIT_VALIDATION_CONTRACT_ID = 'dsh/security/npm-audit-validation/v1'
const NPM_AUDIT_NEGATIVE_CONTROLS = [
  'verified-subject-digest',
  'exact-report-slice-digest',
  'exact-json-pointer',
  'report-entry-name-match',
  'report-entry-severity-match',
  'report-entry-detail-match',
  'candidate-security-claim-match',
  'candidate-evidence-binding',
] as const

function npmAuditReportIndex(slice: VerifiedSubjectTextSliceV1): {
  readonly auditReportVersion: number | null
  readonly pointers: readonly string[]
} | undefined {
  try {
    const parsed: unknown = JSON.parse(slice.text)
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) return undefined
    const record = parsed as Record<string, unknown>
    const auditReportVersion = record.auditReportVersion
    if (
      auditReportVersion !== undefined
      && (typeof auditReportVersion !== 'number'
        || !Number.isInteger(auditReportVersion)
        || auditReportVersion < 1
        || auditReportVersion > 16)
    ) return undefined
    const vulnerabilities = record.vulnerabilities
    if (vulnerabilities === undefined) {
      return { auditReportVersion: auditReportVersion ?? null, pointers: [] }
    }
    if (
      typeof vulnerabilities !== 'object'
      || vulnerabilities === null
      || Array.isArray(vulnerabilities)
    ) return undefined
    return {
      auditReportVersion: auditReportVersion ?? null,
      pointers: Object.keys(vulnerabilities).sort().map(key => (
        `/vulnerabilities/${escapeJsonPointerSegment(key)}`
      )),
    }
  } catch {
    return undefined
  }
}

/**
 * Independently re-bind npm audit Coverage to every verified report slice.
 * Structural Coverage alone is not sufficient: only the package-owned
 * Analyzer and Qualification with a complete entry-for-Candidate projection
 * over the exact frozen reports can satisfy the npm dependency-audit Policy.
 */
export function npmAuditCoverageIsIndependentlyVerified(
  input: CandidateValidationInputV1,
): boolean {
  const { descriptor, qualification } = input.portfolioEntry
  const expectedIdentity = {
    analyzerId: NPM_AUDIT_DESCRIPTOR.analyzerId,
    analyzerVersion: NPM_AUDIT_DESCRIPTOR.analyzerVersion,
    descriptorSchemaVersion: NPM_AUDIT_DESCRIPTOR.descriptorSchemaVersion,
    buildDigest: NPM_AUDIT_DESCRIPTOR.buildDigest,
  }
  if (
    input.policyId !== NPM_AUDIT_POLICY_ID
    || canonicalJson(descriptor) !== canonicalJson(NPM_AUDIT_DESCRIPTOR)
    || qualification === null
    || qualification.qualificationId !== NPM_AUDIT_QUALIFICATION.qualificationId
    || canonicalJson(qualification.qualificationDigest)
      !== canonicalJson(NPM_AUDIT_QUALIFICATION.qualificationDigest)
    || canonicalJson(input.contribution.analyzerIdentity) !== canonicalJson(expectedIdentity)
    || input.contribution.completionDisposition !== 'COMPLETE'
    || input.contribution.diagnostics.length !== 0
    || input.contribution.coverageClaims.length !== 1
  ) return false

  const reportSlices = input.subjectSlices.filter(slice => (
    slice.path.split('/').at(-1) === NPM_AUDIT_REPORT_BASE_NAME
  ))
  if (reportSlices.length === 0 || input.contribution.evidence.length !== reportSlices.length) {
    return false
  }
  const evidenceByPath = new Map<string, {
    readonly artifactId: string
    readonly value: z.infer<typeof npmAuditReportEvidenceV1Schema>
  }>()
  for (const artifact of input.contribution.evidence) {
    if (
      artifact.schemaId !== NPM_AUDIT_EVIDENCE_SCHEMA_ID
      || artifact.mediaType !== NPM_AUDIT_REPORT_MEDIA_TYPE
    ) return false
    const evidence = npmAuditReportEvidenceV1Schema.safeParse(artifact.value)
    if (
      !evidence.success
      || canonicalJson(evidence.data.analyzerIdentity) !== canonicalJson(expectedIdentity)
      || canonicalJson(evidence.data.subjectDigest)
        !== canonicalJson(input.contribution.subjectDigest)
      || evidenceByPath.has(evidence.data.reportPath)
    ) return false
    evidenceByPath.set(evidence.data.reportPath, {
      artifactId: artifact.artifactId,
      value: evidence.data,
    })
  }
  const candidatesById = new Map(input.contribution.candidateFindings.map(candidate => (
    [candidate.candidateId, candidate] as const
  )))
  const coveredCandidateIds = new Set<string>()
  for (const slice of reportSlices) {
    const report = npmAuditReportIndex(slice)
    const evidence = evidenceByPath.get(slice.path)
    if (
      report === undefined
      || evidence === undefined
      || canonicalJson(evidence.value.reportDigest) !== canonicalJson(slice.digest)
      || evidence.value.auditReportVersion !== report.auditReportVersion
      || evidence.value.entries.length !== report.pointers.length
    ) return false
    const entriesByPointer = new Map(evidence.value.entries.map(entry => (
      [entry.sourceAnchor.locator.value, entry] as const
    )))
    if (entriesByPointer.size !== evidence.value.entries.length) return false
    const totals = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFORMATIONAL: 0 }
    for (const pointer of report.pointers) {
      const observed = resolveReportEntry(slice, pointer)
      const entry = entriesByPointer.get(pointer)
      if (
        observed === undefined
        || entry === undefined
        || entry.sourceAnchor.path !== slice.path
        || canonicalJson(entry.sourceAnchor.fileDigest) !== canonicalJson(slice.digest)
        || entry.name !== observed.name
        || entry.severity !== observed.severity
        || entry.title !== observed.title
        || entry.url !== observed.url
        || entry.range !== observed.range
        || entry.fixAvailable !== observed.fixAvailable
        || entry.isDirect !== observed.isDirect
      ) return false
      totals[observed.severity] += 1
      const candidate = candidatesById.get(entry.candidateId)
      if (
        candidate === undefined
        || coveredCandidateIds.has(entry.candidateId)
        || candidate.evidenceArtifactIds.length !== 1
        || candidate.evidenceArtifactIds[0] !== evidence.artifactId
        || canonicalJson(candidate.sourceAnchor) !== canonicalJson(entry.sourceAnchor)
        || candidate.securityClaim !== observed.securityClaim
      ) return false
      coveredCandidateIds.add(entry.candidateId)
    }
    if (canonicalJson(evidence.value.totals) !== canonicalJson(totals)) return false
  }
  return coveredCandidateIds.size === candidatesById.size
}

const npmAuditValidationViaAdvisorySchema = z.strictObject({
  title: z.string().max(1024).optional(),
  url: z.string().max(2048).optional(),
}).loose()

const npmAuditValidationEntrySchema = z.strictObject({
  name: z.string().min(1).max(512).optional(),
  severity: npmAuditSeveritySchema,
  isDirect: z.boolean().optional(),
  via: z.array(z.union([
    z.string().max(512),
    npmAuditValidationViaAdvisorySchema,
  ])).max(256).optional(),
  range: z.string().max(1024).optional(),
  fixAvailable: z.union([z.boolean(), z.strictObject({
    name: z.string().max(512),
    version: z.string().max(128),
    isSemVerMajor: z.boolean(),
  })]).optional(),
}).loose()

function independentlyDerivedSecurityClaim(candidate: {
  readonly name: string
  readonly severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFORMATIONAL'
  readonly title: string | null
  readonly url: string | null
}): string {
  const title = candidate.title === null ? '' : `: ${candidate.title.slice(0, 512)}`
  const url = candidate.url === null ? '' : ` (${candidate.url.slice(0, 512)})`
  const claim = `Dependency '${candidate.name}' has a known ${candidate.severity.toLowerCase()}-severity vulnerability reported by npm audit${title}${url}.`
  return claim.length > 2048 ? claim.slice(0, 2048) : claim
}

function resolveReportEntry(
  slice: VerifiedSubjectTextSliceV1,
  pointer: string,
): {
  readonly name: string
  readonly severity: string
  readonly title: string | null
  readonly url: string | null
  readonly range: string | null
  readonly fixAvailable: boolean | null
  readonly isDirect: boolean | null
  readonly securityClaim: string
} | undefined {
  if (!pointer.startsWith('/vulnerabilities/')) return undefined
  const encodedSegments = pointer.split('/').slice(1)
  if (encodedSegments.some(segment => /~(?:[^01]|$)/u.test(segment))) return undefined
  const segments = encodedSegments.map(unescapeJsonPointerSegment)
  if (segments.length !== 2 || segments[0] !== 'vulnerabilities') return undefined
  const name = segments[1]
  if (name === undefined || name.length === 0) return undefined
  try {
    const parsed: unknown = JSON.parse(slice.text)
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) return undefined
    const vulnerabilities = (parsed as Record<string, unknown>).vulnerabilities
    if (typeof vulnerabilities !== 'object' || vulnerabilities === null || Array.isArray(vulnerabilities)) {
      return undefined
    }
    const entry = npmAuditValidationEntrySchema.safeParse(
      (vulnerabilities as Record<string, unknown>)[name],
    )
    if (!entry.success) return undefined
    let title: string | null = null
    let url: string | null = null
    for (const via of entry.data.via ?? []) {
      if (typeof via === 'object' && via.title !== undefined) {
        title = via.title
        url = via.url ?? null
        break
      }
    }
    const normalized = {
      name: entry.data.name ?? name,
      severity: evaluationSeverityFromNpmAudit[entry.data.severity],
      title,
      url,
      range: entry.data.range ?? null,
      fixAvailable: typeof entry.data.fixAvailable === 'boolean'
        ? entry.data.fixAvailable
        : entry.data.fixAvailable === undefined ? null : true,
      isDirect: entry.data.isDirect ?? null,
    }
    return { ...normalized, securityClaim: independentlyDerivedSecurityClaim(normalized) }
  } catch {
    return undefined
  }
}

function validateNpmAuditCandidate(
  input: CandidateValidationInputV1,
  candidate: AnalyzerCandidateFindingV1,
): {
  readonly finding?: NonNullable<SecuritySubmissionJsonV1>
  readonly evidence: readonly EvidencePublicationInputV1[]
  readonly unresolved: boolean
} {
  const prefix = candidatePrefix(candidate.candidateId)
  const admissionArtifactId = `candidate-admission-${prefix}`
  const resolutionArtifactId = `validation-contract-${prefix}`
  const eligibilityArtifactId = `validation-eligibility-${prefix}`
  const outcomeArtifactId = `validation-outcome-${prefix}`
  const contractResolved = input.policyId === NPM_AUDIT_POLICY_ID
    && candidate.weaknessClassification.primary === NPM_AUDIT_WEAKNESS_ID
    && candidate.weaknessClassification.secondary.length === 1
    && candidate.weaknessClassification.secondary[0] === NPM_AUDIT_SECONDARY_WEAKNESS_ID
    && candidate.affectedControlId === NPM_AUDIT_CONTROL_ID
    && candidate.sourceAnchor.locator.kind === 'JSON_POINTER'
    && candidate.sourceAnchor.locator.value.startsWith('/vulnerabilities/')
  const sourceSlice = input.subjectSlices.find(slice => (
    slice.path === candidate.sourceAnchor.path
    && canonicalJson(slice.digest) === canonicalJson(candidate.sourceAnchor.fileDigest)
  ))
  const referencedEvidence = candidate.evidenceArtifactIds.length === 1
    ? input.contribution.evidence.find(evidence => (
        evidence.artifactId === candidate.evidenceArtifactIds[0]
        && evidence.schemaId === NPM_AUDIT_EVIDENCE_SCHEMA_ID
      ))
    : undefined
  const parsedEvidence = npmAuditReportEvidenceV1Schema.safeParse(referencedEvidence?.value)
  const evidenceEntry = parsedEvidence.success
    ? parsedEvidence.data.entries.find(entry => entry.candidateId === candidate.candidateId)
    : undefined
  const evidenceBound = parsedEvidence.success
    && sourceSlice !== undefined
    && evidenceEntry !== undefined
    && canonicalJson(parsedEvidence.data.analyzerIdentity)
      === canonicalJson(input.contribution.analyzerIdentity)
    && canonicalJson(parsedEvidence.data.subjectDigest) === canonicalJson(input.contribution.subjectDigest)
    && parsedEvidence.data.reportPath === sourceSlice.path
    && canonicalJson(parsedEvidence.data.reportDigest) === canonicalJson(sourceSlice.digest)
    && canonicalJson(evidenceEntry.sourceAnchor) === canonicalJson(candidate.sourceAnchor)
  const reportEntry = sourceSlice === undefined
    ? undefined
    : resolveReportEntry(sourceSlice, candidate.sourceAnchor.locator.value)
  const observedMatch = evidenceBound
    && reportEntry !== undefined
    && evidenceEntry !== undefined
    && reportEntry.name === evidenceEntry.name
    && reportEntry.severity === evidenceEntry.severity
    && reportEntry.title === evidenceEntry.title
    && reportEntry.url === evidenceEntry.url
    && reportEntry.range === evidenceEntry.range
    && reportEntry.fixAvailable === evidenceEntry.fixAvailable
    && reportEntry.isDirect === evidenceEntry.isDirect
    && reportEntry.securityClaim === candidate.securityClaim
  const evidenceEligible = input.portfolioEntry.eligibility.decision === 'ELIGIBLE'
    && contractResolved
    && sourceSlice !== undefined
    && evidenceBound
    && observedMatch
  const unresolvedReason = input.portfolioEntry.eligibility.reason
    ?? (!contractResolved
      ? 'VALIDATION_CONTRACT_UNAVAILABLE'
      : sourceSlice === undefined
        ? 'SOURCE_ANCHOR_UNBOUND'
        : !evidenceBound
          ? 'VALIDATION_EVIDENCE_INELIGIBLE'
          : !observedMatch
            ? 'VALIDATION_EVIDENCE_CONTRADICTS_SUBJECT'
            : null)
  const commonEvidence: EvidencePublicationInputV1[] = [{
    artifactId: admissionArtifactId,
    schemaId: 'dsh/security-candidate-admission',
    mediaType: 'application/vnd.dsh.security.candidate-admission+json',
    value: json({
      schemaVersion: 1,
      state: 'ADMITTED',
      candidateId: candidate.candidateId,
      producer: input.contribution.analyzerIdentity,
      subjectDigest: input.contribution.subjectDigest,
      weaknessClassification: candidate.weaknessClassification,
      affectedControlId: candidate.affectedControlId,
      securityClaim: candidate.securityClaim,
      sourceAnchor: candidate.sourceAnchor,
      evidenceArtifactIds: candidate.evidenceArtifactIds,
    }),
  }, {
    artifactId: resolutionArtifactId,
    schemaId: 'dsh/security-validation-contract-resolution',
    mediaType: 'application/vnd.dsh.security.validation-contract-resolution+json',
    value: json({
      schemaVersion: 1,
      candidateId: candidate.candidateId,
      state: contractResolved ? 'RESOLVED' : 'UNRESOLVED',
      contractId: contractResolved ? NPM_AUDIT_VALIDATION_CONTRACT_ID : null,
      contractVersion: contractResolved ? 1 : null,
      policyDigest: input.policyDigest,
      alternativesConsidered: [NPM_AUDIT_VALIDATION_CONTRACT_ID],
    }),
  }, {
    artifactId: eligibilityArtifactId,
    schemaId: 'dsh/security-validation-evidence-eligibility-decision',
    mediaType: 'application/vnd.dsh.security.validation-evidence-eligibility-decision+json',
    value: json({
      schemaVersion: 1,
      decision: evidenceEligible ? 'ELIGIBLE' : 'INELIGIBLE',
      reason: evidenceEligible ? null : unresolvedReason,
      purpose: 'VALIDATION_EVIDENCE',
      candidateId: candidate.candidateId,
      securityClaim: candidate.securityClaim,
      contractId: contractResolved ? NPM_AUDIT_VALIDATION_CONTRACT_ID : null,
      subjectDigest: input.contribution.subjectDigest,
      evidenceArtifactIds: candidate.evidenceArtifactIds,
      producerEligibility: input.portfolioEntry.eligibility,
      negativeControls: [...NPM_AUDIT_NEGATIVE_CONTROLS],
    }),
  }]
  if (!evidenceEligible || evidenceEntry === undefined) {
    return {
      unresolved: true,
      evidence: [...commonEvidence, {
        artifactId: outcomeArtifactId,
        schemaId: 'dsh/security-validation-outcome',
        mediaType: 'application/vnd.dsh.security.validation-outcome+json',
        value: json({
          schemaVersion: 1,
          candidateId: candidate.candidateId,
          state: 'UNRESOLVED',
          contractId: contractResolved ? NPM_AUDIT_VALIDATION_CONTRACT_ID : null,
          evidenceEligibilityArtifactId: eligibilityArtifactId,
          proofGaps: [unresolvedReason ?? 'VALIDATION_EVIDENCE_INELIGIBLE'],
        }),
      }],
    }
  }

  const validationOutcome = {
    schemaVersion: 1,
    candidateId: candidate.candidateId,
    state: 'VALIDATED',
    contractId: NPM_AUDIT_VALIDATION_CONTRACT_ID,
    contractVersion: 1,
    evidenceEligibilityArtifactId: eligibilityArtifactId,
    evidenceArtifactIds: candidate.evidenceArtifactIds,
    proofGaps: [],
    negativeControls: [...NPM_AUDIT_NEGATIVE_CONTROLS],
  }
  const finding = json({
    schemaVersion: 1,
    findingId: `finding-${sha256Hex(canonicalJson({
      candidateId: candidate.candidateId,
      contractId: NPM_AUDIT_VALIDATION_CONTRACT_ID,
      subjectDigest: input.contribution.subjectDigest,
    }))}`,
    candidateId: candidate.candidateId,
    weaknessClassification: candidate.weaknessClassification,
    affectedControlId: candidate.affectedControlId,
    sourceAnchor: candidate.sourceAnchor,
    securityClaim: candidate.securityClaim,
    validation: validationOutcome,
    technicalSeverity: {
      value: evidenceEntry.severity,
      methodVersion: 'dsh/npm-audit/severity-mapping-v1',
      vector: {
        impact: 'KNOWN_VULNERABILITY',
        reachability: evidenceEntry.isDirect === true
          ? 'DIRECT'
          : evidenceEntry.isDirect === false ? 'TRANSITIVE' : 'UNKNOWN',
        affectedScope: 'DEPENDENCY',
      },
    },
    evidenceConfidence: {
      value: 'HIGH',
      methodVersion: 'dsh/npm-audit/deterministic-report-confidence-v1',
      rubric: {
        producerQualification: 'PASS',
        subjectBinding: 'PASS',
        reproducibility: 'PASS',
        negativeControls: 'PASS',
        proofGaps: 0,
      },
    },
    policySignificance: 'BLOCKING',
    policySignificanceTrace: {
      ruleId: 'npm-audit-known-vulnerability-blocks-v1',
      policyDigest: input.policyDigest,
      matched: true,
    },
  })
  return {
    finding,
    unresolved: false,
    evidence: [...commonEvidence, {
      artifactId: outcomeArtifactId,
      schemaId: 'dsh/security-validation-outcome',
      mediaType: 'application/vnd.dsh.security.validation-outcome+json',
      value: json(validationOutcome),
    }],
  }
}

function validateGitleaksCandidate(
  input: CandidateValidationInputV1,
  candidate: AnalyzerCandidateFindingV1,
): {
  readonly finding?: NonNullable<SecuritySubmissionJsonV1>
  readonly evidence: readonly EvidencePublicationInputV1[]
  readonly unresolved: boolean
} {
  const prefix = candidatePrefix(candidate.candidateId)
  const admissionArtifactId = `candidate-admission-${prefix}`
  const resolutionArtifactId = `validation-contract-${prefix}`
  const eligibilityArtifactId = `validation-eligibility-${prefix}`
  const outcomeArtifactId = `validation-outcome-${prefix}`
  const contractResolved = input.policyId === GITLEAKS_POLICY_ID
    && candidate.weaknessClassification.primary === GITLEAKS_WEAKNESS_ID
    && candidate.weaknessClassification.secondary.length === 1
    && candidate.weaknessClassification.secondary[0] === GITLEAKS_SECONDARY_WEAKNESS_ID
    && candidate.affectedControlId === GITLEAKS_CONTROL_ID
    && candidate.sourceAnchor.locator.kind === 'JSON_POINTER'
    && /^\/(?:0|[1-9][0-9]*)$/u.test(candidate.sourceAnchor.locator.value)
  const sourceSlice = input.subjectSlices.find(slice => (
    slice.path === candidate.sourceAnchor.path
    && canonicalJson(slice.digest) === canonicalJson(candidate.sourceAnchor.fileDigest)
  ))
  const referencedEvidence = candidate.evidenceArtifactIds.length === 1
    ? input.contribution.evidence.find(evidence => (
        evidence.artifactId === candidate.evidenceArtifactIds[0]
        && evidence.schemaId === GITLEAKS_EVIDENCE_SCHEMA_ID
        && evidence.mediaType === GITLEAKS_REPORT_MEDIA_TYPE
      ))
    : undefined
  const parsedEvidence = gitleaksReportEvidenceV1Schema.safeParse(referencedEvidence?.value)
  const matchingEntries = parsedEvidence.success
    ? parsedEvidence.data.entries.filter(entry => entry.candidateId === candidate.candidateId)
    : []
  const evidenceEntry = matchingEntries.length === 1 ? matchingEntries[0] : undefined
  const observed = sourceSlice === undefined
    ? undefined
    : resolveGitleaksReportEntry(sourceSlice, candidate.sourceAnchor.locator.value)
  const expectedCandidateId = sourceSlice === undefined || observed === undefined
    ? undefined
    : expectedGitleaksCandidateId({
        contribution: input.contribution,
        slice: sourceSlice,
        pointer: candidate.sourceAnchor.locator.value,
        observed,
      })
  const evidenceBound = parsedEvidence.success
    && sourceSlice !== undefined
    && evidenceEntry !== undefined
    && parsedEvidence.data.contractId === GITLEAKS_NORMALIZATION_CONTRACT_ID
    && canonicalJson(parsedEvidence.data.analyzerIdentity)
      === canonicalJson(input.contribution.analyzerIdentity)
    && canonicalJson(parsedEvidence.data.subjectDigest) === canonicalJson(input.contribution.subjectDigest)
    && parsedEvidence.data.reportPath === sourceSlice.path
    && canonicalJson(parsedEvidence.data.reportDigest) === canonicalJson(sourceSlice.digest)
    && canonicalJson(parsedEvidence.data.redaction.droppedFields)
      === canonicalJson(GITLEAKS_DROPPED_REPORT_FIELDS)
    && canonicalJson(evidenceEntry.sourceAnchor) === canonicalJson(candidate.sourceAnchor)
  const observedMatch = evidenceBound
    && observed !== undefined
    && evidenceEntry !== undefined
    && candidate.candidateId === expectedCandidateId
    && evidenceEntry.ruleId === observed.ruleId
    && evidenceEntry.affectedPath === observed.affectedPath
    && evidenceEntry.location.startLine === observed.startLine
    && evidenceEntry.location.endLine === observed.endLine
    && evidenceEntry.location.startColumn === observed.startColumn
    && evidenceEntry.location.endColumn === observed.endColumn
    && candidate.securityClaim === observed.securityClaim
  const evidenceEligible = input.portfolioEntry.eligibility.decision === 'ELIGIBLE'
    && contractResolved
    && sourceSlice !== undefined
    && evidenceBound
    && observedMatch
  const unresolvedReason = input.portfolioEntry.eligibility.reason
    ?? (!contractResolved
      ? 'VALIDATION_CONTRACT_UNAVAILABLE'
      : sourceSlice === undefined
        ? 'SOURCE_ANCHOR_UNBOUND'
        : !evidenceBound
          ? 'VALIDATION_EVIDENCE_INELIGIBLE'
          : !observedMatch
            ? 'VALIDATION_EVIDENCE_CONTRADICTS_SUBJECT'
            : null)
  // Invalid contributions are described only by fixed identifiers and reason
  // codes. Their attacker-controlled prose, paths and Evidence values never
  // cross into the published Evidence portfolio.
  const admissionValue = evidenceEligible ? {
    schemaVersion: 1,
    state: 'ADMITTED',
    candidateId: candidate.candidateId,
    producer: input.contribution.analyzerIdentity,
    subjectDigest: input.contribution.subjectDigest,
    weaknessClassification: candidate.weaknessClassification,
    affectedControlId: candidate.affectedControlId,
    securityClaim: candidate.securityClaim,
    sourceAnchor: candidate.sourceAnchor,
    evidenceArtifactIds: candidate.evidenceArtifactIds,
  } : {
    schemaVersion: 1,
    state: 'INELIGIBLE',
    candidateId: candidate.candidateId,
    producer: input.contribution.analyzerIdentity,
    subjectDigest: input.contribution.subjectDigest,
    reason: unresolvedReason ?? 'VALIDATION_EVIDENCE_INELIGIBLE',
  }
  const commonEvidence: EvidencePublicationInputV1[] = [{
    artifactId: admissionArtifactId,
    schemaId: 'dsh/security-candidate-admission',
    mediaType: 'application/vnd.dsh.security.candidate-admission+json',
    value: json(admissionValue),
  }, {
    artifactId: resolutionArtifactId,
    schemaId: 'dsh/security-validation-contract-resolution',
    mediaType: 'application/vnd.dsh.security.validation-contract-resolution+json',
    value: json({
      schemaVersion: 1,
      candidateId: candidate.candidateId,
      state: contractResolved ? 'RESOLVED' : 'UNRESOLVED',
      contractId: contractResolved ? GITLEAKS_VALIDATION_CONTRACT_ID : null,
      contractVersion: contractResolved ? 1 : null,
      policyDigest: input.policyDigest,
      alternativesConsidered: [GITLEAKS_VALIDATION_CONTRACT_ID],
    }),
  }, {
    artifactId: eligibilityArtifactId,
    schemaId: 'dsh/security-validation-evidence-eligibility-decision',
    mediaType: 'application/vnd.dsh.security.validation-evidence-eligibility-decision+json',
    value: json({
      schemaVersion: 1,
      decision: evidenceEligible ? 'ELIGIBLE' : 'INELIGIBLE',
      reason: evidenceEligible ? null : unresolvedReason,
      purpose: 'VALIDATION_EVIDENCE',
      candidateId: candidate.candidateId,
      contractId: contractResolved ? GITLEAKS_VALIDATION_CONTRACT_ID : null,
      subjectDigest: input.contribution.subjectDigest,
      evidenceArtifactIds: evidenceEligible ? candidate.evidenceArtifactIds : [],
      producerEligibility: input.portfolioEntry.eligibility,
      negativeControls: [...GITLEAKS_NEGATIVE_CONTROLS],
    }),
  }]
  if (!evidenceEligible || evidenceEntry === undefined) {
    return {
      unresolved: true,
      evidence: [...commonEvidence, {
        artifactId: outcomeArtifactId,
        schemaId: 'dsh/security-validation-outcome',
        mediaType: 'application/vnd.dsh.security.validation-outcome+json',
        value: json({
          schemaVersion: 1,
          candidateId: candidate.candidateId,
          state: 'UNRESOLVED',
          contractId: contractResolved ? GITLEAKS_VALIDATION_CONTRACT_ID : null,
          evidenceEligibilityArtifactId: eligibilityArtifactId,
          proofGaps: [unresolvedReason ?? 'VALIDATION_EVIDENCE_INELIGIBLE'],
        }),
      }],
    }
  }

  const validationOutcome = {
    schemaVersion: 1,
    candidateId: candidate.candidateId,
    state: 'VALIDATED',
    contractId: GITLEAKS_VALIDATION_CONTRACT_ID,
    contractVersion: 1,
    evidenceEligibilityArtifactId: eligibilityArtifactId,
    evidenceArtifactIds: candidate.evidenceArtifactIds,
    proofGaps: [],
    negativeControls: [...GITLEAKS_NEGATIVE_CONTROLS],
  }
  const finding = json({
    schemaVersion: 1,
    findingId: `finding-${sha256Hex(canonicalJson({
      candidateId: candidate.candidateId,
      contractId: GITLEAKS_VALIDATION_CONTRACT_ID,
      subjectDigest: input.contribution.subjectDigest,
    }))}`,
    candidateId: candidate.candidateId,
    weaknessClassification: candidate.weaknessClassification,
    affectedControlId: candidate.affectedControlId,
    sourceAnchor: candidate.sourceAnchor,
    securityClaim: candidate.securityClaim,
    validation: validationOutcome,
    technicalSeverity: {
      value: 'HIGH',
      methodVersion: 'dsh/gitleaks/reported-secret-presence-severity-v1',
      vector: {
        impact: 'CREDENTIAL_EXPOSURE',
        reachability: 'SOURCE_CONTROL',
        affectedScope: 'SECRET',
      },
    },
    evidenceConfidence: {
      value: 'HIGH',
      methodVersion: 'dsh/gitleaks/deterministic-report-confidence-v1',
      rubric: {
        producerQualification: 'PASS',
        subjectBinding: 'PASS',
        reproducibility: 'PASS',
        negativeControls: 'PASS',
        proofGaps: 0,
      },
    },
    policySignificance: 'BLOCKING',
    policySignificanceTrace: {
      ruleId: 'gitleaks-reported-secret-blocks-v1',
      policyDigest: input.policyDigest,
      matched: true,
    },
  })
  return {
    finding,
    unresolved: false,
    evidence: [...commonEvidence, {
      artifactId: outcomeArtifactId,
      schemaId: 'dsh/security-validation-outcome',
      mediaType: 'application/vnd.dsh.security.validation-outcome+json',
      value: json(validationOutcome),
    }],
  }
}

function validateCandidate(
  input: CandidateValidationInputV1,
  candidate: AnalyzerCandidateFindingV1,
): {
  readonly finding?: NonNullable<SecuritySubmissionJsonV1>
  readonly evidence: readonly EvidencePublicationInputV1[]
  readonly unresolved: boolean
} {
  if (input.policyId === NPM_AUDIT_POLICY_ID) {
    return validateNpmAuditCandidate(input, candidate)
  }
  if (input.policyId === GITLEAKS_POLICY_ID) {
    return validateGitleaksCandidate(input, candidate)
  }
  const prefix = candidatePrefix(candidate.candidateId)
  const admissionArtifactId = `candidate-admission-${prefix}`
  const resolutionArtifactId = `validation-contract-${prefix}`
  const eligibilityArtifactId = `validation-eligibility-${prefix}`
  const outcomeArtifactId = `validation-outcome-${prefix}`
  const contractResolved = input.policyId === 'security/reference-validation'
    && candidate.weaknessClassification.primary === WEAKNESS_ID
    && candidate.weaknessClassification.secondary.length === 0
    && candidate.affectedControlId === CONTROL_ID
    && candidate.securityClaim === SECURITY_CLAIM
    && candidate.sourceAnchor.path === 'package.json'
    && candidate.sourceAnchor.locator.kind === 'JSON_POINTER'
    && candidate.sourceAnchor.locator.value === JSON_POINTER
  const sourceSlice = input.subjectSlices.find(slice => (
    slice.path === candidate.sourceAnchor.path
    && canonicalJson(slice.digest) === canonicalJson(candidate.sourceAnchor.fileDigest)
  ))
  const referencedEvidence = candidate.evidenceArtifactIds.length === 1
    ? input.contribution.evidence.find(evidence => (
        evidence.artifactId === candidate.evidenceArtifactIds[0]
        && evidence.schemaId === EVIDENCE_SCHEMA_ID
      ))
    : undefined
  const parsedEvidence = referenceValidationEvidenceV1Schema.safeParse(referencedEvidence?.value)
  const observedReferenceControl = sourceSlice === undefined
    ? undefined
    : referenceControlState(sourceSlice)
  const evidenceBound = parsedEvidence.success
    && parsedEvidence.data.candidateId === candidate.candidateId
    && canonicalJson(parsedEvidence.data.subjectDigest) === canonicalJson(input.contribution.subjectDigest)
    && canonicalJson(parsedEvidence.data.sourceAnchor) === canonicalJson(candidate.sourceAnchor)
  const observedEvidenceValue = parsedEvidence.success ? parsedEvidence.data.observedValue : undefined
  const observedEvidenceImpact = parsedEvidence.success ? parsedEvidence.data.observedImpact : undefined
  const evidencePurpose = observedEvidenceValue === 'SATISFIED'
    ? 'COUNTER_EVIDENCE'
    : 'VALIDATION_EVIDENCE'
  const evidenceContradictsSubject = evidenceBound
    && observedEvidenceValue !== undefined
    && observedReferenceControl !== undefined
    && (
      observedEvidenceValue !== observedReferenceControl.value
      || observedEvidenceImpact !== observedReferenceControl.impact
    )
  const evidenceEligible = input.portfolioEntry.eligibility.decision === 'ELIGIBLE'
    && contractResolved
    && sourceSlice !== undefined
    && observedReferenceControl !== undefined
    && evidenceBound
    && observedEvidenceValue === observedReferenceControl.value
    && observedEvidenceImpact === observedReferenceControl.impact
  const unresolvedReason = input.portfolioEntry.eligibility.reason
    ?? (!contractResolved
      ? 'VALIDATION_CONTRACT_UNAVAILABLE'
      : sourceSlice === undefined
        ? 'SOURCE_ANCHOR_UNBOUND'
        : observedReferenceControl === undefined
          ? 'NEGATIVE_CONTROL_FAILED'
          : evidenceContradictsSubject
            ? 'VALIDATION_EVIDENCE_CONTRADICTS_SUBJECT'
            : !evidenceBound
              ? 'VALIDATION_EVIDENCE_INELIGIBLE'
              : null)
  const commonEvidence: EvidencePublicationInputV1[] = [{
    artifactId: admissionArtifactId,
    schemaId: 'dsh/security-candidate-admission',
    mediaType: 'application/vnd.dsh.security.candidate-admission+json',
    value: json({
      schemaVersion: 1,
      state: 'ADMITTED',
      candidateId: candidate.candidateId,
      producer: input.contribution.analyzerIdentity,
      subjectDigest: input.contribution.subjectDigest,
      weaknessClassification: candidate.weaknessClassification,
      affectedControlId: candidate.affectedControlId,
      securityClaim: candidate.securityClaim,
      sourceAnchor: candidate.sourceAnchor,
      evidenceArtifactIds: candidate.evidenceArtifactIds,
    }),
  }, {
    artifactId: resolutionArtifactId,
    schemaId: 'dsh/security-validation-contract-resolution',
    mediaType: 'application/vnd.dsh.security.validation-contract-resolution+json',
    value: json({
      schemaVersion: 1,
      candidateId: candidate.candidateId,
      state: contractResolved ? 'RESOLVED' : 'UNRESOLVED',
      contractId: contractResolved ? VALIDATION_CONTRACT_ID : null,
      contractVersion: contractResolved ? 1 : null,
      policyDigest: input.policyDigest,
      alternativesConsidered: [VALIDATION_CONTRACT_ID],
    }),
  }, {
    artifactId: eligibilityArtifactId,
    schemaId: 'dsh/security-validation-evidence-eligibility-decision',
    mediaType: 'application/vnd.dsh.security.validation-evidence-eligibility-decision+json',
    value: json({
      schemaVersion: 1,
      decision: evidenceEligible ? 'ELIGIBLE' : 'INELIGIBLE',
      reason: evidenceEligible ? null : unresolvedReason,
      purpose: evidencePurpose,
      candidateId: candidate.candidateId,
      securityClaim: candidate.securityClaim,
      contractId: contractResolved ? VALIDATION_CONTRACT_ID : null,
      subjectDigest: input.contribution.subjectDigest,
      evidenceArtifactIds: candidate.evidenceArtifactIds,
      producerEligibility: input.portfolioEntry.eligibility,
      negativeControls: [
        'verified-subject-digest',
        'exact-source-file-digest',
        'unique-json-security-keys',
        'exact-json-pointer',
        'exact-reference-control-marker',
        'observed-value-matches-subject',
      ],
    }),
  }]
  if (!evidenceEligible) {
    return {
      unresolved: true,
      evidence: [...commonEvidence, {
        artifactId: outcomeArtifactId,
        schemaId: 'dsh/security-validation-outcome',
        mediaType: 'application/vnd.dsh.security.validation-outcome+json',
        value: json({
          schemaVersion: 1,
          candidateId: candidate.candidateId,
          state: 'UNRESOLVED',
          contractId: contractResolved ? VALIDATION_CONTRACT_ID : null,
          evidenceEligibilityArtifactId: eligibilityArtifactId,
          proofGaps: [unresolvedReason ?? 'VALIDATION_EVIDENCE_INELIGIBLE'],
        }),
      }],
    }
  }

  if (observedEvidenceValue === 'SATISFIED') {
    return {
      unresolved: false,
      evidence: [...commonEvidence, {
        artifactId: outcomeArtifactId,
        schemaId: 'dsh/security-validation-outcome',
        mediaType: 'application/vnd.dsh.security.validation-outcome+json',
        value: json({
          schemaVersion: 1,
          candidateId: candidate.candidateId,
          state: 'REJECTED',
          contractId: VALIDATION_CONTRACT_ID,
          contractVersion: 1,
          evidenceEligibilityArtifactId: eligibilityArtifactId,
          rejectionCondition: 'EXACT_REFERENCE_CONTROL_SATISFIED',
          counterEvidenceArtifactIds: candidate.evidenceArtifactIds,
          proofGaps: [],
          negativeControls: [
            'verified-subject-digest',
            'exact-source-file-digest',
            'unique-json-security-keys',
            'exact-json-pointer',
            'exact-reference-control-marker',
            'observed-value-matches-subject',
          ],
        }),
      }],
    }
  }

  const validationOutcome = {
    schemaVersion: 1,
    candidateId: candidate.candidateId,
    state: 'VALIDATED',
    contractId: VALIDATION_CONTRACT_ID,
    contractVersion: 1,
    evidenceEligibilityArtifactId: eligibilityArtifactId,
    evidenceArtifactIds: candidate.evidenceArtifactIds,
    proofGaps: [],
    negativeControls: [
      'verified-subject-digest',
      'exact-source-file-digest',
      'unique-json-security-keys',
      'exact-json-pointer',
      'exact-reference-control-marker',
      'observed-value-matches-subject',
    ],
  }
  const finding = json({
    schemaVersion: 1,
    findingId: `finding-${sha256Hex(canonicalJson({
      candidateId: candidate.candidateId,
      contractId: VALIDATION_CONTRACT_ID,
      subjectDigest: input.contribution.subjectDigest,
    }))}`,
    candidateId: candidate.candidateId,
    weaknessClassification: candidate.weaknessClassification,
    affectedControlId: candidate.affectedControlId,
    sourceAnchor: candidate.sourceAnchor,
    securityClaim: candidate.securityClaim,
    validation: validationOutcome,
    technicalSeverity: {
      value: observedReferenceControl.impact,
      methodVersion: observedReferenceControl.impact === 'CRITICAL'
        ? 'dsh/conformance/reference-critical-severity-v1'
        : 'dsh/conformance/reference-control-severity-v1',
      vector: {
        impact: 'SECURITY_CONTROL_BYPASS',
        reachability: 'DIRECT',
        affectedScope: 'APPLICATION',
      },
    },
    evidenceConfidence: {
      value: 'HIGH',
      methodVersion: 'dsh/conformance/deterministic-evidence-confidence-v1',
      rubric: {
        producerQualification: 'PASS',
        subjectBinding: 'PASS',
        reproducibility: 'PASS',
        negativeControls: 'PASS',
        proofGaps: 0,
      },
    },
    policySignificance: 'BLOCKING',
    policySignificanceTrace: {
      ruleId: observedReferenceControl.impact === 'CRITICAL'
        ? 'baseline-critical-severity-blocks-v1'
        : 'baseline-high-severity-blocks-v1',
      policyDigest: input.policyDigest,
      matched: true,
    },
  })
  return {
    finding,
    unresolved: false,
    evidence: [...commonEvidence, {
      artifactId: outcomeArtifactId,
      schemaId: 'dsh/security-validation-outcome',
      mediaType: 'application/vnd.dsh.security.validation-outcome+json',
      value: json(validationOutcome),
    }],
  }
}

/** Pure deterministic Candidate Admission and weakness-specific Validation Module. */
export function validateExternalAnalyzerCandidates(
  inputs: readonly CandidateValidationInputV1[],
): CandidateValidationResultV1 {
  const findings: NonNullable<SecuritySubmissionJsonV1>[] = []
  const evidence: EvidencePublicationInputV1[] = []
  const unresolvedCandidateIds: string[] = []
  for (const input of inputs) {
    for (const candidate of input.contribution.candidateFindings) {
      const result = validateCandidate(input, candidate)
      evidence.push(...result.evidence)
      if (result.finding !== undefined) findings.push(result.finding)
      if (result.unresolved) unresolvedCandidateIds.push(candidate.candidateId)
    }
  }
  return { findings, evidence, unresolvedCandidateIds }
}
