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

/** External Analyzer Normalization Contract v1 — Gitleaks v8 JSON binding. */
export const GITLEAKS_NORMALIZATION_CONTRACT_ID = 'dsh/security/gitleaks-normalization/v1' as const
export const GITLEAKS_ANALYZER_ID = 'dsh/external-gitleaks' as const
export const GITLEAKS_ANALYZER_VERSION = '1.0.0' as const
export const GITLEAKS_POLICY_ID = 'security/secret-leak-audit' as const
export const GITLEAKS_REPORT_BASE_NAME = 'gitleaks-report.json' as const
export const GITLEAKS_WEAKNESS_ID = 'dsh/gitleaks/reported-secret-exposure' as const
export const GITLEAKS_SECONDARY_WEAKNESS_ID = 'cwe/798' as const
export const GITLEAKS_CONTROL_ID = 'dsh/gitleaks/no-committed-secrets' as const
export const GITLEAKS_EVIDENCE_SCHEMA_ID = 'dsh/security-gitleaks-report-evidence' as const
export const GITLEAKS_COVERAGE_OBLIGATION_ID = 'application-security-analysis' as const
export const GITLEAKS_REPORT_MEDIA_TYPE = 'application/vnd.dsh.security.gitleaks-report-evidence+json' as const
export const GITLEAKS_DROPPED_REPORT_FIELDS = [
  'Secret',
  'SecretSHA',
  'Match',
  'Line',
  'Author',
  'Email',
  'Message',
  'Date',
  'Description',
  'Tags',
  'Commit',
  'Fingerprint',
  'Entropy',
  'SymlinkFile',
] as const

const GITLEAKS_ANALYZER_METHOD = {
  schemaVersion: 1,
  contractId: GITLEAKS_NORMALIZATION_CONTRACT_ID,
  analyzerId: GITLEAKS_ANALYZER_ID,
  analyzerVersion: GITLEAKS_ANALYZER_VERSION,
  methodVersion: 'dsh-gitleaks-v8-json-normalization-v1',
  input: 'verified gitleaks-report.json slices frozen with the Subject',
  rule: 'every top-level report entry becomes one Candidate anchored by JSON Pointer',
  retainedFields: 'RuleID, File, StartLine, EndLine, StartColumn and EndColumn only',
  exclusions: 'Gitleaks execution, secret material, arbitrary scanner prose and live source reads stay outside the Pure boundary',
} as const

export const GITLEAKS_DESCRIPTOR: AnalyzerDescriptorV1 = deepFreeze({
  schemaVersion: 1,
  analyzerId: GITLEAKS_ANALYZER_ID,
  analyzerVersion: GITLEAKS_ANALYZER_VERSION,
  descriptorSchemaVersion: 1,
  buildDigest: structuredDigest('application/vnd.dsh.security.analyzer-method+json', GITLEAKS_ANALYZER_METHOD),
  executionClass: 'PURE',
  supportedAssessmentModes: ['REPOSITORY', 'CHANGE'],
  supportedPolicyIds: [GITLEAKS_POLICY_ID],
  coverageObligationIds: [GITLEAKS_COVERAGE_OBLIGATION_ID],
  evidenceSchemaIds: [GITLEAKS_EVIDENCE_SCHEMA_ID],
  egress: 'NONE',
})

const GITLEAKS_QUALIFICATION_CORE = {
  schemaVersion: 1 as const,
  qualificationId: 'dsh/qualification/external-gitleaks/v1' as const,
  analyzerIdentity: {
    analyzerId: GITLEAKS_DESCRIPTOR.analyzerId,
    analyzerVersion: GITLEAKS_DESCRIPTOR.analyzerVersion,
    descriptorSchemaVersion: GITLEAKS_DESCRIPTOR.descriptorSchemaVersion,
    buildDigest: GITLEAKS_DESCRIPTOR.buildDigest,
  },
  issuerId: 'dsh/security-assurance-development' as const,
  level: 'HOST_ATTESTED' as const,
  supportedEcosystemIds: ['gitleaks-v8-json-report'] as const,
  supportedAssessmentModes: ['REPOSITORY', 'CHANGE'] as const,
  supportedPolicyIds: [GITLEAKS_POLICY_ID] as const,
  coverageObligationIds: [GITLEAKS_COVERAGE_OBLIGATION_ID] as const,
  evidenceSchemaIds: [GITLEAKS_EVIDENCE_SCHEMA_ID] as const,
  executionClass: 'PURE' as const,
  executionBackendId: 'dsh/security-assurance/in-process-pure-v1' as const,
  providerIds: [SECURITY_ASSURANCE_PRODUCT_NAME] as const,
  egress: 'NONE' as const,
  platforms: ['win32', 'linux', 'darwin'] as const,
  issuedAt: '2026-01-01T00:00:00.000Z' as const,
  expiresAt: '2099-01-01T00:00:00.000Z' as const,
  evidenceDigests: [GITLEAKS_DESCRIPTOR.buildDigest] as const,
  limitations: [
    'Only the frozen built-in Gitleaks v8 JSON report is evaluated; report freshness and scan configuration are Host responsibilities.',
    'CHANGE mode evaluates the report frozen in the complete head tree for an exact committed base-to-head pair.',
    'Secret values, matches, source lines, secret hashes and identity-bearing commit metadata are deliberately discarded.',
    'This qualification does not claim detector effectiveness, history breadth, allowlist correctness or absence of secrets outside the report.',
  ] as const,
}

export const GITLEAKS_QUALIFICATION: AnalyzerQualificationRecordV1 = deepFreeze({
  ...GITLEAKS_QUALIFICATION_CORE,
  qualificationDigest: structuredDigest(
    'application/vnd.dsh.security.analyzer-qualification+json',
    GITLEAKS_QUALIFICATION_CORE,
  ),
})

const locationValue = z.number().int().nonnegative().max(2_147_483_647)
const gitleaksAffectedPathSchema = z.string().min(1).max(1024).transform((value, context) => {
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
const gitleaksDroppedReportFieldsSchema = z.tuple([
  z.literal('Secret'),
  z.literal('SecretSHA'),
  z.literal('Match'),
  z.literal('Line'),
  z.literal('Author'),
  z.literal('Email'),
  z.literal('Message'),
  z.literal('Date'),
  z.literal('Description'),
  z.literal('Tags'),
  z.literal('Commit'),
  z.literal('Fingerprint'),
  z.literal('Entropy'),
  z.literal('SymlinkFile'),
])
export const gitleaksReportFindingSchema = z.strictObject({
  RuleID: z.string().min(1).max(256),
  File: gitleaksAffectedPathSchema,
  StartLine: locationValue,
  EndLine: locationValue,
  StartColumn: locationValue,
  EndColumn: locationValue,
}).loose().superRefine((finding, context) => {
  if (finding.EndLine < finding.StartLine) {
    context.addIssue({ code: 'custom', message: 'Gitleaks end line precedes start line' })
  }
  if (finding.StartLine === finding.EndLine && finding.EndColumn < finding.StartColumn) {
    context.addIssue({ code: 'custom', message: 'Gitleaks end column precedes start column' })
  }
})

export const gitleaksReportSchema = z.array(gitleaksReportFindingSchema).max(768)
export type GitleaksReportFinding = z.infer<typeof gitleaksReportFindingSchema>

export const gitleaksFindingEvidenceEntryV1Schema = z.strictObject({
  candidateId: z.string().regex(/^candidate-[0-9a-f]{64}$/),
  ruleId: z.string().min(1).max(256),
  affectedPath: z.string().min(1).max(1024),
  location: z.strictObject({
    startLine: locationValue,
    endLine: locationValue,
    startColumn: locationValue,
    endColumn: locationValue,
  }),
  sourceAnchor: z.strictObject({
    path: z.string().min(1).max(1024),
    fileDigest: digestEnvelopeV1Schema,
    locator: z.strictObject({
      kind: z.literal('JSON_POINTER'),
      value: z.string().regex(/^\/[0-9]+$/),
    }),
  }),
})
export type GitleaksFindingEvidenceEntryV1 = z.infer<typeof gitleaksFindingEvidenceEntryV1Schema>

export const gitleaksReportEvidenceV1Schema = z.strictObject({
  schemaVersion: z.literal(1),
  contractId: z.literal(GITLEAKS_NORMALIZATION_CONTRACT_ID),
  analyzerIdentity: z.strictObject({
    analyzerId: z.literal(GITLEAKS_ANALYZER_ID),
    analyzerVersion: z.literal(GITLEAKS_ANALYZER_VERSION),
    descriptorSchemaVersion: z.literal(1),
    buildDigest: digestEnvelopeV1Schema,
  }),
  subjectDigest: digestEnvelopeV1Schema,
  reportPath: z.string().min(1).max(1024),
  reportDigest: digestEnvelopeV1Schema,
  reportFormat: z.literal('gitleaks-v8-json'),
  findingsCount: z.number().int().nonnegative().max(768),
  redaction: z.strictObject({
    retainedFields: z.tuple([
      z.literal('RuleID'),
      z.literal('File'),
      z.literal('StartLine'),
      z.literal('EndLine'),
      z.literal('StartColumn'),
      z.literal('EndColumn'),
    ]),
    droppedFields: gitleaksDroppedReportFieldsSchema,
  }),
  entries: z.array(gitleaksFindingEvidenceEntryV1Schema).max(768),
})
export type GitleaksReportEvidenceV1 = z.infer<typeof gitleaksReportEvidenceV1Schema>

function analyzerIdentity() {
  return {
    analyzerId: GITLEAKS_ANALYZER_ID,
    analyzerVersion: GITLEAKS_ANALYZER_VERSION,
    descriptorSchemaVersion: 1 as const,
    buildDigest: GITLEAKS_DESCRIPTOR.buildDigest,
  }
}

export function gitleaksSecurityClaim(entry: {
  readonly ruleId: string
  readonly affectedPath: string
  readonly startLine: number
}): string {
  const claim = `Gitleaks reported rule '${entry.ruleId}' at '${entry.affectedPath}:${entry.startLine}'. Sensitive match content was discarded during normalization.`
  return claim.length > 2048 ? claim.slice(0, 2048) : claim
}

type GitleaksDiagnostic =
  | 'GITLEAKS_REPORT_MISSING'
  | 'GITLEAKS_REPORT_LIMIT'
  | 'GITLEAKS_REPORT_INVALID_JSON'
  | 'GITLEAKS_REPORT_INVALID_SHAPE'
  | 'GITLEAKS_CANDIDATE_LIMIT'

const MAX_REPORT_SLICES = 127
const MAX_CANDIDATES = 768

/** Pure Gitleaks normalization with no filesystem, process, network, model, clock or Store authority. */
export function analyzeGitleaksReport(input: {
  readonly subjectDigest: DigestEnvelopeV1
  readonly slices: readonly {
    readonly path: string
    readonly digest: DigestEnvelopeV1
    readonly text: string
  }[]
}): AnalyzerContributionV1 {
  const diagnostics = new Set<GitleaksDiagnostic>()
  const reportSlices = [...input.slices].sort((left, right) => left.path.localeCompare(right.path))
  if (reportSlices.length === 0) diagnostics.add('GITLEAKS_REPORT_MISSING')
  const boundedSlices = reportSlices.slice(0, MAX_REPORT_SLICES)
  if (reportSlices.length > boundedSlices.length) diagnostics.add('GITLEAKS_REPORT_LIMIT')
  const candidates: AnalyzerContributionV1['candidateFindings'][number][] = []
  const evidence: {
    readonly artifactId: string
    readonly schemaId: string
    readonly mediaType: string
    readonly value: GitleaksReportEvidenceV1
  }[] = []
  let bytesRead = 0
  let incomplete = false

  for (const [sliceIndex, slice] of boundedSlices.entries()) {
    bytesRead += Buffer.byteLength(slice.text, 'utf8')
    const artifactId = sliceIndex === 0 ? 'gitleaks-report' : `gitleaks-report-${sliceIndex + 1}`
    let parsed: unknown
    try {
      parsed = JSON.parse(slice.text)
    } catch {
      diagnostics.add('GITLEAKS_REPORT_INVALID_JSON')
      incomplete = true
      continue
    }
    const report = gitleaksReportSchema.safeParse(parsed)
    if (!report.success) {
      diagnostics.add('GITLEAKS_REPORT_INVALID_SHAPE')
      incomplete = true
      continue
    }
    const entries: GitleaksFindingEvidenceEntryV1[] = []
    for (const [reportIndex, raw] of report.data.entries()) {
      if (candidates.length >= MAX_CANDIDATES) {
        diagnostics.add('GITLEAKS_CANDIDATE_LIMIT')
        incomplete = true
        break
      }
      const projected = {
        ruleId: raw.RuleID,
        affectedPath: raw.File,
        startLine: raw.StartLine,
        endLine: raw.EndLine,
        startColumn: raw.StartColumn,
        endColumn: raw.EndColumn,
      }
      const sourceAnchor = {
        path: slice.path,
        fileDigest: slice.digest,
        locator: { kind: 'JSON_POINTER' as const, value: `/${reportIndex}` },
      }
      const candidateId = `candidate-${sha256Hex(canonicalJson({
        analyzerIdentity: analyzerIdentity(),
        subjectDigest: input.subjectDigest,
        projected,
        sourceAnchor,
      }))}`
      candidates.push({
        schemaVersion: 1,
        candidateId,
        weaknessClassification: {
          schemaVersion: 1,
          primary: GITLEAKS_WEAKNESS_ID,
          secondary: [GITLEAKS_SECONDARY_WEAKNESS_ID],
        },
        affectedControlId: GITLEAKS_CONTROL_ID,
        securityClaim: gitleaksSecurityClaim(projected),
        sourceAnchor,
        evidenceArtifactIds: [artifactId],
      })
      entries.push({
        candidateId,
        ruleId: projected.ruleId,
        affectedPath: projected.affectedPath,
        location: {
          startLine: projected.startLine,
          endLine: projected.endLine,
          startColumn: projected.startColumn,
          endColumn: projected.endColumn,
        },
        sourceAnchor,
      })
    }
    evidence.push({
      artifactId,
      schemaId: GITLEAKS_EVIDENCE_SCHEMA_ID,
      mediaType: GITLEAKS_REPORT_MEDIA_TYPE,
      value: {
        schemaVersion: 1,
        contractId: GITLEAKS_NORMALIZATION_CONTRACT_ID,
        analyzerIdentity: analyzerIdentity(),
        subjectDigest: input.subjectDigest,
        reportPath: slice.path,
        reportDigest: slice.digest,
        reportFormat: 'gitleaks-v8-json',
        findingsCount: report.data.length,
        redaction: {
          retainedFields: ['RuleID', 'File', 'StartLine', 'EndLine', 'StartColumn', 'EndColumn'],
          droppedFields: [...GITLEAKS_DROPPED_REPORT_FIELDS],
        },
        entries,
      },
    })
  }

  const complete = reportSlices.length > 0 && !incomplete
  return deepFreeze(analyzerContributionV1Schema.parse({
    schemaVersion: 1,
    analyzerIdentity: analyzerIdentity(),
    subjectDigest: input.subjectDigest,
    completionDisposition: reportSlices.length === 0
      ? 'UNSUPPORTED'
      : complete ? 'COMPLETE' : 'INCOMPLETE',
    coverageClaims: complete && evidence.length > 0 ? [{
      obligationId: GITLEAKS_COVERAGE_OBLIGATION_ID,
      completion: 'COMPLETE',
      evidenceArtifactId: evidence[0]!.artifactId,
    }] : [],
    candidateFindings: candidates,
    evidence,
    diagnostics: [...diagnostics].sort(),
    resourceUse: { filesRead: boundedSlices.length, bytesRead },
  }))
}

export const createGitleaksAnalyzer: AnalyzerFactoryV1 = descriptor => ({
  descriptor,
  async analyze(analyzerInput) {
    return analyzeGitleaksReport({
      subjectDigest: analyzerInput.subject.digest,
      slices: analyzerInput.subject.textSlices.filter(slice => (
        slice.path.split('/').at(-1) === GITLEAKS_REPORT_BASE_NAME
      )),
    })
  },
  async dispose() {},
})
