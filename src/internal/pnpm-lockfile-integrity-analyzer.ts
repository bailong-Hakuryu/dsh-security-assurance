import { parseDocument, visit } from 'yaml'
import { z } from 'zod'

import type {
  AnalyzerCandidateFindingV1,
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
import type { VerifiedSubjectTextSliceV1 } from './subject-freeze.ts'

export const PNPM_LOCKFILE_ANALYSIS_CONTRACT_ID
  = 'dsh/security/pnpm-lockfile-integrity-analysis/v1' as const
export const PNPM_LOCKFILE_ANALYZER_ID = 'dsh/builtin-pnpm-lockfile-integrity' as const
export const PNPM_LOCKFILE_ANALYZER_VERSION = '1.0.0' as const
export const PNPM_LOCKFILE_POLICY_ID = 'security/pnpm-lockfile-integrity' as const
export const PNPM_LOCKFILE_WEAKNESS_ID = 'dsh/pnpm/unreproducible-resolution' as const
export const PNPM_LOCKFILE_CONTROL_ID = 'dsh/pnpm/lockfile-integrity' as const
export const PNPM_LOCKFILE_EVIDENCE_SCHEMA_ID
  = 'dsh/security-pnpm-lockfile-integrity-evidence' as const
export const PNPM_LOCKFILE_COVERAGE_OBLIGATION_ID = 'application-security-analysis' as const
export const PNPM_LOCKFILE_EVIDENCE_MEDIA_TYPE
  = 'application/vnd.dsh.security.pnpm-lockfile-integrity-evidence+json' as const

export const PNPM_LOCKFILE_RULE_IDS = [
  'PACKAGE_MANAGER_NOT_EXACTLY_PINNED',
  'PNPM_LOCKFILE_MISSING',
  'PNPM_LOCKFILE_IMPORTER_DRIFT',
  'PNPM_PACKAGE_INTEGRITY_MISSING',
] as const

export type PnpmLockfileRuleId = typeof PNPM_LOCKFILE_RULE_IDS[number]

const PNPM_LOCKFILE_METHOD = {
  schemaVersion: 1,
  contractId: PNPM_LOCKFILE_ANALYSIS_CONTRACT_ID,
  analyzerId: PNPM_LOCKFILE_ANALYZER_ID,
  analyzerVersion: PNPM_LOCKFILE_ANALYZER_VERSION,
  methodVersion: 'dsh-pnpm-lockfile-integrity-v1',
  input: 'verified root package.json and pnpm-lock.yaml slices frozen with the Subject',
  rules: [
    'packageManager is an exact pnpm semantic version',
    'a pnpm v9 lockfile exists for the root package',
    'the root importer dependency specifiers exactly match package.json',
    'every package resolution carries a valid SRI digest',
  ],
  exclusions: 'package installation, registry lookup, advisory lookup, workspace importer analysis and dependency execution',
} as const

export const PNPM_LOCKFILE_DESCRIPTOR: AnalyzerDescriptorV1 = deepFreeze({
  schemaVersion: 1,
  analyzerId: PNPM_LOCKFILE_ANALYZER_ID,
  analyzerVersion: PNPM_LOCKFILE_ANALYZER_VERSION,
  descriptorSchemaVersion: 1,
  buildDigest: structuredDigest(
    'application/vnd.dsh.security.analyzer-method+json',
    PNPM_LOCKFILE_METHOD,
  ),
  executionClass: 'PURE',
  supportedAssessmentModes: ['REPOSITORY', 'CHANGE'],
  supportedPolicyIds: [PNPM_LOCKFILE_POLICY_ID],
  coverageObligationIds: [PNPM_LOCKFILE_COVERAGE_OBLIGATION_ID],
  evidenceSchemaIds: [PNPM_LOCKFILE_EVIDENCE_SCHEMA_ID],
  egress: 'NONE',
})

const PNPM_LOCKFILE_QUALIFICATION_CORE = {
  schemaVersion: 1 as const,
  qualificationId: 'dsh/qualification/builtin-pnpm-lockfile-integrity/v1' as const,
  analyzerIdentity: {
    analyzerId: PNPM_LOCKFILE_DESCRIPTOR.analyzerId,
    analyzerVersion: PNPM_LOCKFILE_DESCRIPTOR.analyzerVersion,
    descriptorSchemaVersion: PNPM_LOCKFILE_DESCRIPTOR.descriptorSchemaVersion,
    buildDigest: PNPM_LOCKFILE_DESCRIPTOR.buildDigest,
  },
  issuerId: 'dsh/security-assurance-development' as const,
  level: 'HOST_ATTESTED' as const,
  supportedEcosystemIds: ['pnpm-lockfile-v9'] as const,
  supportedAssessmentModes: ['REPOSITORY', 'CHANGE'] as const,
  supportedPolicyIds: [PNPM_LOCKFILE_POLICY_ID] as const,
  coverageObligationIds: [PNPM_LOCKFILE_COVERAGE_OBLIGATION_ID] as const,
  evidenceSchemaIds: [PNPM_LOCKFILE_EVIDENCE_SCHEMA_ID] as const,
  executionClass: 'PURE' as const,
  executionBackendId: 'dsh/security-assurance/in-process-pure-v1' as const,
  providerIds: [SECURITY_ASSURANCE_PRODUCT_NAME] as const,
  egress: 'NONE' as const,
  platforms: ['win32', 'linux', 'darwin'] as const,
  issuedAt: '2026-01-01T00:00:00.000Z' as const,
  expiresAt: '2099-01-01T00:00:00.000Z' as const,
  evidenceDigests: [PNPM_LOCKFILE_DESCRIPTOR.buildDigest] as const,
  limitations: [
    'Only the root package.json and pnpm-lock.yaml importer are evaluated.',
    'Only pnpm lockfile version 9 is supported; other package managers and lockfile versions fail closed.',
    'The Analyzer proves frozen metadata consistency and SRI presence, not registry authenticity or vulnerability absence.',
    'CHANGE mode evaluates the complete frozen head tree and does not infer integrity from diff lines.',
  ] as const,
}

export const PNPM_LOCKFILE_QUALIFICATION: AnalyzerQualificationRecordV1 = deepFreeze({
  ...PNPM_LOCKFILE_QUALIFICATION_CORE,
  qualificationDigest: structuredDigest(
    'application/vnd.dsh.security.analyzer-qualification+json',
    PNPM_LOCKFILE_QUALIFICATION_CORE,
  ),
})

const sourceAnchorSchema = z.strictObject({
  path: z.enum(['package.json', 'pnpm-lock.yaml']),
  fileDigest: digestEnvelopeV1Schema,
  locator: z.strictObject({
    kind: z.literal('JSON_POINTER'),
    value: z.enum(['/packageManager', '/importers/.', '/packages']),
  }),
})

const evidenceEntrySchema = z.strictObject({
  candidateId: z.string().regex(/^candidate-[0-9a-f]{64}$/),
  ruleId: z.enum(PNPM_LOCKFILE_RULE_IDS),
  severity: z.enum(['HIGH', 'MEDIUM']),
  sourceAnchor: sourceAnchorSchema,
})

export const pnpmLockfileIntegrityEvidenceV1Schema = z.strictObject({
  schemaVersion: z.literal(1),
  contractId: z.literal(PNPM_LOCKFILE_ANALYSIS_CONTRACT_ID),
  analyzerIdentity: z.strictObject({
    analyzerId: z.literal(PNPM_LOCKFILE_ANALYZER_ID),
    analyzerVersion: z.literal(PNPM_LOCKFILE_ANALYZER_VERSION),
    descriptorSchemaVersion: z.literal(1),
    buildDigest: digestEnvelopeV1Schema,
  }),
  subjectDigest: digestEnvelopeV1Schema,
  rootManifest: z.nullable(z.strictObject({
    path: z.literal('package.json'),
    fileDigest: digestEnvelopeV1Schema,
    parseStatus: z.enum(['VALID', 'INVALID']),
    packageManagerState: z.enum(['EXACT_PNPM', 'MISSING', 'UNPINNED', 'UNSUPPORTED', 'INVALID']),
    dependencyCount: z.number().int().nonnegative().max(65_536),
  })),
  lockfile: z.nullable(z.strictObject({
    path: z.literal('pnpm-lock.yaml'),
    fileDigest: digestEnvelopeV1Schema,
    parseStatus: z.enum(['VALID', 'INVALID', 'UNSUPPORTED']),
    lockfileVersion: z.nullable(z.string().max(32)),
    importerMatchesManifest: z.nullable(z.boolean()),
    packageResolutionCount: z.number().int().nonnegative().max(1_000_000),
    missingIntegrityCount: z.number().int().nonnegative().max(1_000_000),
  })),
  entries: z.array(evidenceEntrySchema).max(PNPM_LOCKFILE_RULE_IDS.length),
})

export type PnpmLockfileIntegrityEvidenceV1 = z.infer<
  typeof pnpmLockfileIntegrityEvidenceV1Schema
>

type JsonRecord = Record<string, unknown>
type DependencySection = 'dependencies' | 'devDependencies' | 'optionalDependencies'

interface ParsedManifest {
  readonly packageManager: string | undefined
  readonly sections: Readonly<Record<DependencySection, Readonly<Record<string, string>>>>
  readonly dependencyCount: number
}

interface ParsedLockfile {
  readonly version: string | undefined
  readonly importerMatchesManifest: boolean
  readonly packageResolutionCount: number
  readonly missingIntegrityCount: number
}

interface DetectedViolation {
  readonly ruleId: PnpmLockfileRuleId
  readonly severity: 'HIGH' | 'MEDIUM'
  readonly sourceSlice: VerifiedSubjectTextSliceV1
  readonly locator: '/packageManager' | '/importers/.' | '/packages'
  readonly securityClaim: string
}

type PnpmLockfileDiagnostic =
  | 'ROOT_PACKAGE_MANIFEST_INVALID'
  | 'PNPM_LOCKFILE_INVALID'
  | 'PNPM_LOCKFILE_VERSION_UNSUPPORTED'
  | 'PNPM_PACKAGE_MANAGER_UNSUPPORTED'
  | 'PNPM_LOCKFILE_WITHOUT_ROOT_MANIFEST'

const DEPENDENCY_SECTIONS: readonly DependencySection[] = [
  'dependencies',
  'devDependencies',
  'optionalDependencies',
]
const EXACT_PNPM = /^pnpm@\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/u
const SRI = /^(?:sha256|sha384|sha512)-[A-Za-z0-9+/]+={0,2}$/u

function analyzerIdentity() {
  return {
    analyzerId: PNPM_LOCKFILE_ANALYZER_ID,
    analyzerVersion: PNPM_LOCKFILE_ANALYZER_VERSION,
    descriptorSchemaVersion: 1 as const,
    buildDigest: PNPM_LOCKFILE_DESCRIPTOR.buildDigest,
  }
}

function record(value: unknown): JsonRecord | undefined {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
    ? value as JsonRecord
    : undefined
}

function hasDuplicateJsonKey(text: string): boolean {
  type Frame = {
    readonly kind: 'OBJECT' | 'ARRAY'
    readonly keys: Set<string>
    pendingKey: string | undefined
  }
  const stack: Frame[] = []
  for (let index = 0; index < text.length;) {
    const character = text[index]
    if (character === '{' || character === '[') {
      const parent = stack.at(-1)
      if (parent?.kind === 'OBJECT') parent.pendingKey = undefined
      stack.push({
        kind: character === '{' ? 'OBJECT' : 'ARRAY',
        keys: new Set(),
        pendingKey: undefined,
      })
      index += 1
      continue
    }
    if (character === '}' || character === ']') {
      stack.pop()
      index += 1
      continue
    }
    if (character !== '"') {
      index += 1
      continue
    }
    const start = index
    index += 1
    let escaped = false
    while (index < text.length) {
      const current = text[index]!
      index += 1
      if (escaped) escaped = false
      else if (current === '\\') escaped = true
      else if (current === '"') break
    }
    const token = text.slice(start, index)
    let cursor = index
    while (/\s/u.test(text[cursor] ?? '')) cursor += 1
    if (text[cursor] !== ':') continue
    const frame = stack.at(-1)
    if (frame?.kind !== 'OBJECT') continue
    let key: unknown
    try {
      key = JSON.parse(token)
    } catch {
      continue
    }
    if (typeof key !== 'string') continue
    if (frame.keys.has(key)) return true
    frame.keys.add(key)
    frame.pendingKey = key
  }
  return false
}

function parseManifest(text: string): ParsedManifest | undefined {
  if (hasDuplicateJsonKey(text)) return undefined
  let value: unknown
  try {
    value = JSON.parse(text)
  } catch {
    return undefined
  }
  const manifest = record(value)
  if (manifest === undefined) return undefined
  if (manifest.packageManager !== undefined && typeof manifest.packageManager !== 'string') {
    return undefined
  }
  const sections = {} as Record<DependencySection, Readonly<Record<string, string>>>
  let dependencyCount = 0
  for (const sectionName of DEPENDENCY_SECTIONS) {
    const sectionValue = manifest[sectionName]
    if (sectionValue === undefined) {
      sections[sectionName] = {}
      continue
    }
    const section = record(sectionValue)
    if (section === undefined || Object.values(section).some(specifier => typeof specifier !== 'string')) {
      return undefined
    }
    sections[sectionName] = section as Record<string, string>
    dependencyCount += Object.keys(section).length
  }
  return { packageManager: manifest.packageManager, sections, dependencyCount }
}

function sectionMatches(
  manifestSection: Readonly<Record<string, string>>,
  lockSectionValue: unknown,
): boolean {
  const lockSection = lockSectionValue === undefined ? {} : record(lockSectionValue)
  if (lockSection === undefined) return false
  const manifestNames = Object.keys(manifestSection).sort()
  const lockNames = Object.keys(lockSection).sort()
  if (canonicalJson(manifestNames) !== canonicalJson(lockNames)) return false
  return manifestNames.every(name => {
    const locked = record(lockSection[name])
    return locked !== undefined && locked.specifier === manifestSection[name]
  })
}

function parseLockfile(text: string, manifest: ParsedManifest): ParsedLockfile | undefined {
  let value: unknown
  try {
    const document = parseDocument(text, {
      customTags: [],
      merge: false,
      prettyErrors: false,
      schema: 'core',
      strict: true,
      stringKeys: true,
      uniqueKeys: true,
      version: '1.2',
    })
    if (document.errors.length > 0 || document.warnings.length > 0 || document.contents === null) {
      return undefined
    }
    let hasAlias = false
    visit(document, {
      Alias() {
        hasAlias = true
        return visit.BREAK
      },
    })
    if (hasAlias) return undefined
    value = document.toJS({ maxAliasCount: 0 })
  } catch {
    return undefined
  }
  const lockfile = record(value)
  if (lockfile === undefined) return undefined
  const rawVersion = lockfile.lockfileVersion
  const version = typeof rawVersion === 'string'
    ? rawVersion
    : typeof rawVersion === 'number'
      ? String(rawVersion)
      : undefined
  const importers = record(lockfile.importers)
  const rootImporter = record(importers?.['.'])
  const packages = lockfile.packages === undefined ? {} : record(lockfile.packages)
  if (rootImporter === undefined || packages === undefined) return undefined
  const importerMatchesManifest = DEPENDENCY_SECTIONS.every(section => (
    sectionMatches(manifest.sections[section], rootImporter[section])
  ))
  let missingIntegrityCount = 0
  for (const packageValue of Object.values(packages)) {
    const packageRecord = record(packageValue)
    if (packageRecord === undefined) return undefined
    const resolution = record(packageRecord.resolution)
    if (resolution === undefined || typeof resolution.integrity !== 'string' || !SRI.test(resolution.integrity)) {
      missingIntegrityCount += 1
    }
  }
  return {
    version,
    importerMatchesManifest,
    packageResolutionCount: Object.keys(packages).length,
    missingIntegrityCount,
  }
}

function buildCandidate(
  subjectDigest: DigestEnvelopeV1,
  violation: DetectedViolation,
  evidenceArtifactId: string,
): AnalyzerCandidateFindingV1 {
  const sourceAnchor = {
    path: violation.sourceSlice.path,
    fileDigest: violation.sourceSlice.digest,
    locator: { kind: 'JSON_POINTER' as const, value: violation.locator },
  }
  return {
    schemaVersion: 1,
    candidateId: `candidate-${sha256Hex(canonicalJson({
      analyzerIdentity: analyzerIdentity(),
      subjectDigest,
      ruleId: violation.ruleId,
      sourceAnchor,
    }))}`,
    weaknessClassification: {
      schemaVersion: 1,
      primary: PNPM_LOCKFILE_WEAKNESS_ID,
      secondary: ['cwe/353'],
    },
    affectedControlId: PNPM_LOCKFILE_CONTROL_ID,
    securityClaim: violation.securityClaim,
    sourceAnchor,
    evidenceArtifactIds: [evidenceArtifactId],
  }
}

/** Analyze frozen root package metadata without filesystem, process or network authority. */
export function analyzePnpmLockfileIntegrity(input: {
  readonly subjectDigest: DigestEnvelopeV1
  readonly slices: readonly VerifiedSubjectTextSliceV1[]
}): AnalyzerContributionV1 {
  const slices = [...input.slices]
    .filter(slice => slice.path === 'package.json' || slice.path === 'pnpm-lock.yaml')
    .sort((left, right) => left.path.localeCompare(right.path))
  const manifestSlice = slices.find(slice => slice.path === 'package.json')
  const lockfileSlice = slices.find(slice => slice.path === 'pnpm-lock.yaml')
  const diagnostics = new Set<PnpmLockfileDiagnostic>()
  const violations: DetectedViolation[] = []
  const evidenceArtifactId = 'pnpm-lockfile-integrity-analysis'
  let incomplete = false
  const manifest = manifestSlice === undefined ? undefined : parseManifest(manifestSlice.text)
  const packageManagerUnsupported = manifest?.packageManager !== undefined
    && !manifest.packageManager.startsWith('pnpm@')

  if (manifestSlice !== undefined && manifest === undefined) {
    diagnostics.add('ROOT_PACKAGE_MANIFEST_INVALID')
    incomplete = true
  }
  if (manifestSlice === undefined && lockfileSlice !== undefined) {
    diagnostics.add('PNPM_LOCKFILE_WITHOUT_ROOT_MANIFEST')
    incomplete = true
  }
  if (manifest !== undefined && manifestSlice !== undefined) {
    if (manifest.packageManager === undefined || !EXACT_PNPM.test(manifest.packageManager)) {
      if (packageManagerUnsupported) {
        diagnostics.add('PNPM_PACKAGE_MANAGER_UNSUPPORTED')
        incomplete = true
      } else {
        violations.push({
          ruleId: 'PACKAGE_MANAGER_NOT_EXACTLY_PINNED',
          severity: 'MEDIUM',
          sourceSlice: manifestSlice,
          locator: '/packageManager',
          securityClaim: 'The root package does not pin pnpm to one exact semantic version.',
        })
      }
    }
    if (lockfileSlice === undefined && !packageManagerUnsupported) {
      violations.push({
        ruleId: 'PNPM_LOCKFILE_MISSING',
        severity: 'HIGH',
        sourceSlice: manifestSlice,
        locator: '/packageManager',
        securityClaim: 'The root package does not freeze dependency resolution in pnpm-lock.yaml.',
      })
    }
  }

  let parsedLockfile: ParsedLockfile | undefined
  if (lockfileSlice !== undefined && manifest !== undefined && !packageManagerUnsupported) {
    parsedLockfile = parseLockfile(lockfileSlice.text, manifest)
    if (parsedLockfile === undefined) {
      diagnostics.add('PNPM_LOCKFILE_INVALID')
      incomplete = true
    } else if (parsedLockfile.version !== '9.0' && parsedLockfile.version !== '9') {
      diagnostics.add('PNPM_LOCKFILE_VERSION_UNSUPPORTED')
      incomplete = true
    } else {
      if (!parsedLockfile.importerMatchesManifest) {
        violations.push({
          ruleId: 'PNPM_LOCKFILE_IMPORTER_DRIFT',
          severity: 'HIGH',
          sourceSlice: lockfileSlice,
          locator: '/importers/.',
          securityClaim: 'The root pnpm importer does not exactly match the frozen package manifest.',
        })
      }
      if (parsedLockfile.missingIntegrityCount > 0) {
        violations.push({
          ruleId: 'PNPM_PACKAGE_INTEGRITY_MISSING',
          severity: 'HIGH',
          sourceSlice: lockfileSlice,
          locator: '/packages',
          securityClaim: 'One or more pnpm package resolutions lack a valid Subresource Integrity digest.',
        })
      }
    }
  }

  const candidates = violations.map(violation => (
    buildCandidate(input.subjectDigest, violation, evidenceArtifactId)
  ))
  const entries = violations.map((violation, index) => ({
    candidateId: candidates[index]!.candidateId,
    ruleId: violation.ruleId,
    severity: violation.severity,
    sourceAnchor: candidates[index]!.sourceAnchor,
  }))
  const evidenceValue = pnpmLockfileIntegrityEvidenceV1Schema.parse({
    schemaVersion: 1,
    contractId: PNPM_LOCKFILE_ANALYSIS_CONTRACT_ID,
    analyzerIdentity: analyzerIdentity(),
    subjectDigest: input.subjectDigest,
    rootManifest: manifestSlice === undefined
      ? null
      : {
          path: 'package.json',
          fileDigest: manifestSlice.digest,
          parseStatus: manifest === undefined ? 'INVALID' : 'VALID',
          packageManagerState: manifest === undefined
            ? 'INVALID'
            : manifest.packageManager === undefined
              ? 'MISSING'
              : EXACT_PNPM.test(manifest.packageManager)
                ? 'EXACT_PNPM'
                : manifest.packageManager.startsWith('pnpm@')
                  ? 'UNPINNED'
                  : 'UNSUPPORTED',
          dependencyCount: manifest?.dependencyCount ?? 0,
        },
    lockfile: lockfileSlice === undefined
      ? null
      : {
          path: 'pnpm-lock.yaml',
          fileDigest: lockfileSlice.digest,
          parseStatus: packageManagerUnsupported
            ? 'UNSUPPORTED'
            : parsedLockfile === undefined
              ? 'INVALID'
            : parsedLockfile.version === '9.0' || parsedLockfile.version === '9'
              ? 'VALID'
              : 'UNSUPPORTED',
          lockfileVersion: parsedLockfile?.version ?? null,
          importerMatchesManifest: parsedLockfile?.importerMatchesManifest ?? null,
          packageResolutionCount: parsedLockfile?.packageResolutionCount ?? 0,
          missingIntegrityCount: parsedLockfile?.missingIntegrityCount ?? 0,
        },
    entries,
  })
  return deepFreeze(analyzerContributionV1Schema.parse({
    schemaVersion: 1,
    analyzerIdentity: analyzerIdentity(),
    subjectDigest: input.subjectDigest,
    completionDisposition: incomplete ? 'INCOMPLETE' : 'COMPLETE',
    coverageClaims: incomplete ? [] : [{
      obligationId: PNPM_LOCKFILE_COVERAGE_OBLIGATION_ID,
      completion: 'COMPLETE',
      evidenceArtifactId,
    }],
    candidateFindings: candidates,
    evidence: [{
      artifactId: evidenceArtifactId,
      schemaId: PNPM_LOCKFILE_EVIDENCE_SCHEMA_ID,
      mediaType: PNPM_LOCKFILE_EVIDENCE_MEDIA_TYPE,
      value: evidenceValue,
    }],
    diagnostics: [...diagnostics].sort(),
    resourceUse: {
      filesRead: slices.length,
      bytesRead: slices.reduce((total, slice) => total + Buffer.byteLength(slice.text, 'utf8'), 0),
    },
  }))
}

export const createPnpmLockfileIntegrityAnalyzer: AnalyzerFactoryV1 = descriptor => ({
  descriptor,
  async analyze(input) {
    return analyzePnpmLockfileIntegrity({
      subjectDigest: input.subject.digest,
      slices: input.subject.textSlices.filter(slice => (
        slice.path === 'package.json' || slice.path === 'pnpm-lock.yaml'
      )),
    })
  },
  async dispose() {},
})
