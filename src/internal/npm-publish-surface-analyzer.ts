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

export const NPM_PUBLISH_SURFACE_ANALYSIS_CONTRACT_ID
  = 'dsh/security/npm-publish-surface-analysis/v1' as const
export const NPM_PUBLISH_SURFACE_ANALYZER_ID = 'dsh/builtin-npm-publish-surface' as const
export const NPM_PUBLISH_SURFACE_ANALYZER_VERSION = '1.0.0' as const
export const NPM_PUBLISH_SURFACE_POLICY_ID = 'security/npm-publish-surface' as const
export const NPM_PUBLISH_SURFACE_WEAKNESS_ID = 'dsh/npm/publish-surface' as const
export const NPM_PUBLISH_SURFACE_CONTROL_ID = 'dsh/npm/publish-surface' as const
export const NPM_PUBLISH_SURFACE_EVIDENCE_SCHEMA_ID
  = 'dsh/security-npm-publish-surface-evidence' as const
export const NPM_PUBLISH_SURFACE_COVERAGE_OBLIGATION_ID = 'application-security-analysis' as const
export const NPM_PUBLISH_SURFACE_EVIDENCE_MEDIA_TYPE
  = 'application/vnd.dsh.security.npm-publish-surface-evidence+json' as const

export const NPM_PUBLISH_SURFACE_RULE_IDS = [
  'NPM_PACKAGE_PRIVATE',
  'NPM_PACKAGE_NAME_MISSING',
  'NPM_PACKAGE_VERSION_MISSING',
  'NPM_PUBLISH_ACCESS_NOT_PUBLIC',
  'NPM_PUBLISH_FILES_NOT_EXPLICIT',
  'NPM_PUBLISH_FILES_BROAD',
  'NPM_EXPORT_TARGET_NOT_INCLUDED',
  'NPM_MAIN_NOT_INCLUDED',
  'NPM_TYPES_NOT_INCLUDED',
  'NPM_BIN_TARGET_NOT_INCLUDED',
] as const
export type NpmPublishSurfaceRuleId = typeof NPM_PUBLISH_SURFACE_RULE_IDS[number]

const NPM_PUBLISH_SURFACE_METHOD = {
  schemaVersion: 1,
  contractId: NPM_PUBLISH_SURFACE_ANALYSIS_CONTRACT_ID,
  analyzerId: NPM_PUBLISH_SURFACE_ANALYZER_ID,
  analyzerVersion: NPM_PUBLISH_SURFACE_ANALYZER_VERSION,
  methodVersion: 'dsh-npm-publish-surface-v1',
  input: 'the exact frozen root package.json text slice',
  rule: 'publish identity, explicit public access, strict SemVer, explicit files allowlist, and declared entry-point containment',
  exclusions: 'npm pack execution, filesystem enumeration, registry lookup, package provenance, and dependency security',
} as const

export const NPM_PUBLISH_SURFACE_DESCRIPTOR: AnalyzerDescriptorV1 = deepFreeze({
  schemaVersion: 1,
  analyzerId: NPM_PUBLISH_SURFACE_ANALYZER_ID,
  analyzerVersion: NPM_PUBLISH_SURFACE_ANALYZER_VERSION,
  descriptorSchemaVersion: 1,
  buildDigest: structuredDigest(
    'application/vnd.dsh.security.analyzer-method+json',
    NPM_PUBLISH_SURFACE_METHOD,
  ),
  executionClass: 'PURE',
  supportedAssessmentModes: ['REPOSITORY', 'CHANGE'],
  supportedPolicyIds: [NPM_PUBLISH_SURFACE_POLICY_ID],
  coverageObligationIds: [NPM_PUBLISH_SURFACE_COVERAGE_OBLIGATION_ID],
  evidenceSchemaIds: [NPM_PUBLISH_SURFACE_EVIDENCE_SCHEMA_ID],
  egress: 'NONE',
})

const NPM_PUBLISH_SURFACE_QUALIFICATION_CORE = {
  schemaVersion: 1 as const,
  qualificationId: 'dsh/qualification/builtin-npm-publish-surface/v1' as const,
  analyzerIdentity: {
    analyzerId: NPM_PUBLISH_SURFACE_DESCRIPTOR.analyzerId,
    analyzerVersion: NPM_PUBLISH_SURFACE_DESCRIPTOR.analyzerVersion,
    descriptorSchemaVersion: NPM_PUBLISH_SURFACE_DESCRIPTOR.descriptorSchemaVersion,
    buildDigest: NPM_PUBLISH_SURFACE_DESCRIPTOR.buildDigest,
  },
  issuerId: 'dsh/security-assurance-development' as const,
  level: 'HOST_ATTESTED' as const,
  supportedEcosystemIds: ['npm-package-publish-surface'] as const,
  supportedAssessmentModes: ['REPOSITORY', 'CHANGE'] as const,
  supportedPolicyIds: [NPM_PUBLISH_SURFACE_POLICY_ID] as const,
  coverageObligationIds: [NPM_PUBLISH_SURFACE_COVERAGE_OBLIGATION_ID] as const,
  evidenceSchemaIds: [NPM_PUBLISH_SURFACE_EVIDENCE_SCHEMA_ID] as const,
  executionClass: 'PURE' as const,
  executionBackendId: 'dsh/security-assurance/in-process-pure-v1' as const,
  providerIds: [SECURITY_ASSURANCE_PRODUCT_NAME] as const,
  egress: 'NONE' as const,
  platforms: ['win32', 'linux', 'darwin'] as const,
  issuedAt: '2026-01-01T00:00:00.000Z' as const,
  expiresAt: '2099-01-01T00:00:00.000Z' as const,
  evidenceDigests: [NPM_PUBLISH_SURFACE_DESCRIPTOR.buildDigest] as const,
  limitations: [
    'Only the root package.json publish declaration is evaluated.',
    'The Analyzer proves manifest self-consistency, not the actual npm packlist or file existence.',
    'The Analyzer does not prove package provenance, dependency integrity, or registry policy.',
    'CHANGE mode evaluates the complete frozen head tree root manifest rather than diff lines.',
  ] as const,
}

export const NPM_PUBLISH_SURFACE_QUALIFICATION: AnalyzerQualificationRecordV1 = deepFreeze({
  ...NPM_PUBLISH_SURFACE_QUALIFICATION_CORE,
  qualificationDigest: structuredDigest(
    'application/vnd.dsh.security.analyzer-qualification+json',
    NPM_PUBLISH_SURFACE_QUALIFICATION_CORE,
  ),
})

const sourceAnchorSchema = z.strictObject({
  path: z.literal('package.json'),
  fileDigest: digestEnvelopeV1Schema,
  locator: z.strictObject({
    kind: z.literal('JSON_POINTER'),
    value: z.string().min(1).max(1024),
  }),
})

const evidenceEntrySchema = z.strictObject({
  candidateId: z.string().regex(/^candidate-[0-9a-f]{64}$/),
  ruleId: z.enum(NPM_PUBLISH_SURFACE_RULE_IDS),
  severity: z.enum(['HIGH', 'MEDIUM']),
  sourceAnchor: sourceAnchorSchema,
})

export const npmPublishSurfaceEvidenceV1Schema = z.strictObject({
  schemaVersion: z.literal(1),
  contractId: z.literal(NPM_PUBLISH_SURFACE_ANALYSIS_CONTRACT_ID),
  analyzerIdentity: z.strictObject({
    analyzerId: z.literal(NPM_PUBLISH_SURFACE_ANALYZER_ID),
    analyzerVersion: z.literal(NPM_PUBLISH_SURFACE_ANALYZER_VERSION),
    descriptorSchemaVersion: z.literal(1),
    buildDigest: digestEnvelopeV1Schema,
  }),
  subjectDigest: digestEnvelopeV1Schema,
  manifest: z.nullable(z.strictObject({
    path: z.literal('package.json'),
    fileDigest: digestEnvelopeV1Schema,
    parseStatus: z.enum(['VALID', 'INVALID']),
    privateState: z.enum(['PUBLIC', 'PRIVATE']),
    packageNameState: z.enum(['PRESENT', 'MISSING']),
    packageVersionState: z.enum(['PRESENT', 'MISSING']),
    publishAccess: z.enum(['PUBLIC', 'RESTRICTED', 'DEFAULT']),
    filesPatternCount: z.number().int().nonnegative().max(256),
    filesPatternState: z.enum(['EXPLICIT', 'MISSING']),
    exportTargetCount: z.number().int().nonnegative().max(256),
    referencedTargetCount: z.number().int().nonnegative().max(256),
  })),
  entries: z.array(evidenceEntrySchema).max(NPM_PUBLISH_SURFACE_RULE_IDS.length * 4),
})

export type NpmPublishSurfaceEvidenceV1 = z.infer<typeof npmPublishSurfaceEvidenceV1Schema>

type JsonRecord = Record<string, unknown>
type TargetKind = 'EXPORT' | 'MAIN' | 'TYPES' | 'BIN'
type Severity = 'HIGH' | 'MEDIUM'

interface EntryPoint {
  readonly kind: TargetKind
  readonly target: string
  readonly locator: string
}

interface ParsedManifest {
  readonly privateState: 'PUBLIC' | 'PRIVATE'
  readonly packageNameState: 'PRESENT' | 'MISSING'
  readonly packageVersionState: 'PRESENT' | 'MISSING'
  readonly publishAccess: 'PUBLIC' | 'RESTRICTED' | 'DEFAULT'
  readonly files: readonly string[]
  readonly entryPoints: readonly EntryPoint[]
}

interface DetectedViolation {
  readonly ruleId: NpmPublishSurfaceRuleId
  readonly severity: Severity
  readonly sourceSlice: VerifiedSubjectTextSliceV1
  readonly locator: string
  readonly securityClaim: string
}

type NpmPublishSurfaceDiagnostic =
  | 'NPM_PACKAGE_MANIFEST_INVALID_JSON'
  | 'NPM_PUBLISH_SURFACE_INVALID_SHAPE'

function analyzerIdentity() {
  return {
    analyzerId: NPM_PUBLISH_SURFACE_ANALYZER_ID,
    analyzerVersion: NPM_PUBLISH_SURFACE_ANALYZER_VERSION,
    descriptorSchemaVersion: 1 as const,
    buildDigest: NPM_PUBLISH_SURFACE_DESCRIPTOR.buildDigest,
  }
}

function record(value: unknown): JsonRecord | undefined {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
    ? value as JsonRecord
    : undefined
}

const SEMVER_IDENTIFIER = '(?:0|[1-9]\\d*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)'
const STRICT_SEMVER = new RegExp(
  `^(?:0|[1-9]\\d*)\\.(?:0|[1-9]\\d*)\\.(?:0|[1-9]\\d*)`
  + `(?:-(?:${SEMVER_IDENTIFIER})(?:\\.(?:${SEMVER_IDENTIFIER}))*)?`
  + `(?:\\+[0-9A-Za-z-]+(?:\\.[0-9A-Za-z-]+)*)?$`,
  'u',
)

function hasDuplicateJsonKey(text: string): boolean {
  type Frame = { readonly kind: 'OBJECT' | 'ARRAY'; readonly keys: Set<string> }
  const stack: Frame[] = []
  for (let index = 0; index < text.length;) {
    const character = text[index]
    if (character === '{' || character === '[') {
      stack.push({ kind: character === '{' ? 'OBJECT' : 'ARRAY', keys: new Set() })
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
      const current = text[index++]!
      if (escaped) escaped = false
      else if (current === '\\') escaped = true
      else if (current === '"') break
    }
    const token = text.slice(start, index)
    let cursor = index
    while (/\s/u.test(text[cursor] ?? '')) cursor += 1
    const frame = stack.at(-1)
    if (text[cursor] !== ':' || frame?.kind !== 'OBJECT') continue
    try {
      const key = JSON.parse(token)
      if (typeof key === 'string') {
        if (frame.keys.has(key)) return true
        frame.keys.add(key)
      }
    } catch {
      continue
    }
  }
  return false
}

function pointerSegment(value: string): string {
  return value.replaceAll('~', '~0').replaceAll('/', '~1')
}

function validTarget(value: string): boolean {
  if (!value.startsWith('./') || value.includes('\\') || value.includes('\0')) return false
  const path = value.slice(2)
  return path.length > 0 && path.split('/').every(segment => segment.length > 0 && segment !== '.' && segment !== '..')
}

function targetPath(value: string): string | undefined {
  const normalized = value.startsWith('./') ? value : `./${value}`
  return validTarget(normalized) ? normalized.slice(2) : undefined
}

function collectExportTargets(value: unknown, locator: string, output: EntryPoint[]): boolean {
  if (typeof value === 'string') {
    if (!validTarget(value)) return false
    output.push({ kind: 'EXPORT', target: value.slice(2), locator })
    return true
  }
  if (value === null) return true
  if (Array.isArray(value)) {
    return value.every((child, index) => collectExportTargets(child, `${locator}/${index}`, output))
  }
  const object = record(value)
  return object !== undefined && Object.entries(object).every(([key, child]) => (
    collectExportTargets(child, `${locator}/${pointerSegment(key)}`, output)
  ))
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
  const name = manifest.name
  const version = manifest.version
  const privateState = manifest.private === true ? 'PRIVATE' : 'PUBLIC'
  if (manifest.private !== undefined && typeof manifest.private !== 'boolean') return undefined

  const publishConfig = manifest.publishConfig === undefined ? undefined : record(manifest.publishConfig)
  if (manifest.publishConfig !== undefined && publishConfig === undefined) return undefined
  const access = publishConfig?.access
  if (access !== undefined && access !== 'public' && access !== 'restricted') return undefined

  const filesValue = manifest.files
  if (filesValue !== undefined && (!Array.isArray(filesValue) || filesValue.some(item => typeof item !== 'string'))) {
    return undefined
  }
  const files = filesValue === undefined ? [] : filesValue as string[]
  const entryPoints: EntryPoint[] = []
  const main = manifest.main
  const types = manifest.types
  if (main !== undefined) {
    if (typeof main !== 'string') return undefined
    const target = targetPath(main)
    if (target === undefined) return undefined
    entryPoints.push({ kind: 'MAIN', target, locator: '/main' })
  }
  if (types !== undefined) {
    if (typeof types !== 'string') return undefined
    const target = targetPath(types)
    if (target === undefined) return undefined
    entryPoints.push({ kind: 'TYPES', target, locator: '/types' })
  }
  if (manifest.exports !== undefined && !collectExportTargets(manifest.exports, '/exports', entryPoints)) return undefined
  const bin = manifest.bin
  if (bin !== undefined) {
    if (typeof bin === 'string') {
      const target = targetPath(bin)
      if (target === undefined) return undefined
      entryPoints.push({ kind: 'BIN', target, locator: '/bin' })
    } else {
      const binObject = record(bin)
      if (binObject === undefined) return undefined
      for (const [nameKey, target] of Object.entries(binObject)) {
        if (typeof target !== 'string') return undefined
        const targetPathValue = targetPath(target)
        if (targetPathValue === undefined) return undefined
        entryPoints.push({
          kind: 'BIN',
          target: targetPathValue,
          locator: `/bin/${pointerSegment(nameKey)}`,
        })
      }
    }
  }
  return {
    privateState,
    packageNameState: typeof name === 'string' && name.length > 0 ? 'PRESENT' : 'MISSING',
    packageVersionState: typeof version === 'string' && STRICT_SEMVER.test(version)
      ? 'PRESENT'
      : 'MISSING',
    publishAccess: access === 'public' ? 'PUBLIC' : access === 'restricted' ? 'RESTRICTED' : 'DEFAULT',
    files,
    entryPoints,
  }
}

function patternMatches(pattern: string, target: string): boolean {
  const normalized = pattern.replaceAll('\\', '/').replace(/^\.\//u, '').replace(/\/$/u, '')
  if (normalized.length === 0 || normalized === '.' || normalized === '*' || normalized === '**') return false
  if (normalized === target || target.startsWith(`${normalized}/`)) return true
  const segments = normalized.split('/')
  let expression = ''
  segments.forEach((segment, index) => {
    if (index > 0 && segments[index - 1] !== '**') expression += '/'
    if (segment === '**') {
      expression += '(?:[^/]+/)*'
      return
    }
    expression += segment
      .replace(/[.+^${}()|[\]\\]/gu, '\\$&')
      .replaceAll('*', '[^/]*')
      .replaceAll('?', '[^/]')
  })
  return new RegExp(`^${expression}$`, 'u').test(target)
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
      primary: NPM_PUBLISH_SURFACE_WEAKNESS_ID,
      secondary: ['cwe/16'],
    },
    affectedControlId: NPM_PUBLISH_SURFACE_CONTROL_ID,
    securityClaim: violation.securityClaim,
    sourceAnchor,
    evidenceArtifactIds: [evidenceArtifactId],
  }
}

/** Analyze the root npm publish declaration without filesystem, process, or network authority. */
export function analyzeNpmPublishSurface(input: {
  readonly subjectDigest: DigestEnvelopeV1
  readonly slices: readonly VerifiedSubjectTextSliceV1[]
}): AnalyzerContributionV1 {
  const manifestSlice = input.slices.find(slice => slice.path === 'package.json')
  const diagnostics = new Set<NpmPublishSurfaceDiagnostic>()
  const violations: DetectedViolation[] = []
  const evidenceArtifactId = 'npm-publish-surface-analysis'
  const manifest = manifestSlice === undefined ? undefined : parseManifest(manifestSlice.text)
  let incomplete = false

  if (manifestSlice !== undefined && manifest === undefined) {
    diagnostics.add(hasDuplicateJsonKey(manifestSlice.text)
      ? 'NPM_PACKAGE_MANIFEST_INVALID_JSON'
      : 'NPM_PUBLISH_SURFACE_INVALID_SHAPE')
    incomplete = true
  }
  if (manifest !== undefined && manifestSlice !== undefined) {
    const add = (
      ruleId: NpmPublishSurfaceRuleId,
      severity: Severity,
      locator: string,
      securityClaim: string,
    ) => violations.push({ ruleId, severity, sourceSlice: manifestSlice, locator, securityClaim })
    if (manifest.privateState === 'PRIVATE') {
      add('NPM_PACKAGE_PRIVATE', 'HIGH', '/private', 'The package manifest is private and cannot provide the declared public npm release surface.')
    }
    if (manifest.packageNameState === 'MISSING') {
      add('NPM_PACKAGE_NAME_MISSING', 'HIGH', '/name', 'The package manifest does not declare a publishable npm package name.')
    }
    if (manifest.packageVersionState === 'MISSING') {
      add('NPM_PACKAGE_VERSION_MISSING', 'HIGH', '/version', 'The package manifest does not declare a valid publishable npm version.')
    }
    if (manifest.publishAccess !== 'PUBLIC') {
      add('NPM_PUBLISH_ACCESS_NOT_PUBLIC', 'MEDIUM', '/publishConfig/access', 'The package manifest does not explicitly declare public npm access.')
    }
    const broadFiles = manifest.files.some(pattern => pattern === '*' || pattern === '**' || pattern === '.' || pattern === './' || pattern.startsWith('/'))
    if (manifest.files.length === 0) {
      add('NPM_PUBLISH_FILES_NOT_EXPLICIT', 'HIGH', '/files', 'The package manifest does not declare an explicit npm publish files allowlist.')
    } else if (broadFiles) {
      add('NPM_PUBLISH_FILES_BROAD', 'HIGH', '/files', 'The npm publish files allowlist contains a broad or non-portable pattern.')
    }
    for (const entryPoint of broadFiles ? [] : manifest.entryPoints) {
      if (manifest.files.length > 0 && manifest.files.some(pattern => patternMatches(pattern, entryPoint.target))) continue
      const ruleId = entryPoint.kind === 'EXPORT'
        ? 'NPM_EXPORT_TARGET_NOT_INCLUDED'
        : entryPoint.kind === 'MAIN'
          ? 'NPM_MAIN_NOT_INCLUDED'
          : entryPoint.kind === 'TYPES'
            ? 'NPM_TYPES_NOT_INCLUDED'
            : 'NPM_BIN_TARGET_NOT_INCLUDED'
      add(ruleId, 'HIGH', entryPoint.locator, `The npm ${entryPoint.kind.toLowerCase()} target is not contained by the declared files allowlist.`)
    }
  }

  const candidates = violations.map(violation => buildCandidate(input.subjectDigest, violation, evidenceArtifactId))
  const entries = violations.map((violation, index) => ({
    candidateId: candidates[index]!.candidateId,
    ruleId: violation.ruleId,
    severity: violation.severity,
    sourceAnchor: candidates[index]!.sourceAnchor,
  }))
  const evidenceValue = npmPublishSurfaceEvidenceV1Schema.parse({
    schemaVersion: 1,
    contractId: NPM_PUBLISH_SURFACE_ANALYSIS_CONTRACT_ID,
    analyzerIdentity: analyzerIdentity(),
    subjectDigest: input.subjectDigest,
    manifest: manifestSlice === undefined
      ? null
      : {
          path: 'package.json',
          fileDigest: manifestSlice.digest,
          parseStatus: manifest === undefined ? 'INVALID' : 'VALID',
          privateState: manifest?.privateState ?? 'PUBLIC',
          packageNameState: manifest?.packageNameState ?? 'MISSING',
          packageVersionState: manifest?.packageVersionState ?? 'MISSING',
          publishAccess: manifest?.publishAccess ?? 'DEFAULT',
          filesPatternCount: manifest?.files.length ?? 0,
          filesPatternState: manifest === undefined || manifest.files.length === 0 ? 'MISSING' : 'EXPLICIT',
          exportTargetCount: manifest?.entryPoints.filter(entry => entry.kind === 'EXPORT').length ?? 0,
          referencedTargetCount: manifest?.entryPoints.length ?? 0,
        },
    entries,
  })
  return deepFreeze(analyzerContributionV1Schema.parse({
    schemaVersion: 1,
    analyzerIdentity: analyzerIdentity(),
    subjectDigest: input.subjectDigest,
    completionDisposition: incomplete ? 'INCOMPLETE' : 'COMPLETE',
    coverageClaims: incomplete ? [] : [{
      obligationId: NPM_PUBLISH_SURFACE_COVERAGE_OBLIGATION_ID,
      completion: 'COMPLETE',
      evidenceArtifactId,
    }],
    candidateFindings: candidates,
    evidence: [{
      artifactId: evidenceArtifactId,
      schemaId: NPM_PUBLISH_SURFACE_EVIDENCE_SCHEMA_ID,
      mediaType: NPM_PUBLISH_SURFACE_EVIDENCE_MEDIA_TYPE,
      value: evidenceValue,
    }],
    diagnostics: [...diagnostics].sort(),
    resourceUse: {
      filesRead: manifestSlice === undefined ? 0 : 1,
      bytesRead: manifestSlice === undefined ? 0 : Buffer.byteLength(manifestSlice.text, 'utf8'),
    },
  }))
}

export const createNpmPublishSurfaceAnalyzer: AnalyzerFactoryV1 = descriptor => ({
  descriptor,
  async analyze(input) {
    return analyzeNpmPublishSurface({
      subjectDigest: input.subject.digest,
      slices: input.subject.textSlices.filter(slice => slice.path === 'package.json'),
    })
  },
  async dispose() {},
})
