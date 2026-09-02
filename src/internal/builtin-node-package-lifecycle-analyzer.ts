import { z } from 'zod'
import {
  digestEnvelopeV1Schema,
  securitySubmissionJsonV1Schema,
} from '../contracts.ts'
import type {
  DigestEnvelopeV1,
  SecuritySubmissionJsonV1,
} from '../contracts.ts'
import { canonicalJson, sha256Hex, structuredDigest } from './canonical.ts'
import { deepFreeze } from './freeze.ts'
import type { VerifiedSubjectTextSliceV1 } from './subject-freeze.ts'

const INSTALL_LIFECYCLE_NAMES = ['preinstall', 'install', 'postinstall'] as const
const ANALYZER_METHOD = {
  schemaVersion: 1,
  analyzerId: 'dsh/builtin-node-package-lifecycle',
  analyzerVersion: '1.1.0',
  methodVersion: 'dsh-node-package-lifecycle-policy-v1',
  input: 'all verified package.json text slices inside one immutable Assessment Target',
  rule: 'preinstall, install, and postinstall script keys with non-empty string values are candidates',
  exclusions: 'script bodies are never retained as Evidence',
}

export const BUILTIN_NODE_PACKAGE_LIFECYCLE_DESCRIPTOR = deepFreeze({
  schemaVersion: 1 as const,
  analyzerId: 'dsh/builtin-node-package-lifecycle' as const,
  analyzerVersion: '1.1.0' as const,
  descriptorSchemaVersion: 1 as const,
  buildDigest: structuredDigest('application/vnd.dsh.security.analyzer-method+json', ANALYZER_METHOD),
  executionClass: 'PURE' as const,
  supportedAssessmentModes: ['REPOSITORY', 'CHANGE', 'TARGETED'] as const,
  supportedPolicyIds: ['security/node-package-lifecycle'] as const,
  coverageObligationIds: ['node-package-install-lifecycle-policy'] as const,
  evidenceSchemaIds: ['dsh/security-node-package-manifest-evidence'] as const,
  egress: 'NONE' as const,
})

const QUALIFICATION_CORE = {
  schemaVersion: 1,
  qualificationId: 'dsh/qualification/builtin-node-package-lifecycle/v2',
  analyzerIdentity: {
    analyzerId: BUILTIN_NODE_PACKAGE_LIFECYCLE_DESCRIPTOR.analyzerId,
    analyzerVersion: BUILTIN_NODE_PACKAGE_LIFECYCLE_DESCRIPTOR.analyzerVersion,
    buildDigest: BUILTIN_NODE_PACKAGE_LIFECYCLE_DESCRIPTOR.buildDigest,
  },
  issuer: 'dsh-security-assurance-development',
  level: 'DEVELOPMENT_BUILTIN',
  supportedEcosystemIds: ['node-package-manifest'] as const,
  supportedAssessmentModes: ['REPOSITORY', 'CHANGE', 'TARGETED'],
  supportedPolicyIds: ['security/node-package-lifecycle'],
  coverageObligationIds: ['node-package-install-lifecycle-policy'],
  platforms: ['win32', 'linux', 'darwin'] as const,
  limitations: [
    'Only package.json install lifecycle key presence is evaluated.',
    'CHANGE mode evaluates every package.json in the complete frozen head tree, not only changed files.',
    'TARGETED mode evaluates only package.json files at or below the exact frozen Target paths.',
    'This qualification does not claim general Node or application security coverage.',
  ],
}

export const BUILTIN_NODE_PACKAGE_LIFECYCLE_QUALIFICATION = deepFreeze({
  ...QUALIFICATION_CORE,
  qualificationDigest: structuredDigest(
    'application/vnd.dsh.security.analyzer-qualification+json',
    QUALIFICATION_CORE,
  ),
})

const analyzerIdentitySchema = z.strictObject({
  analyzerId: z.literal(BUILTIN_NODE_PACKAGE_LIFECYCLE_DESCRIPTOR.analyzerId),
  analyzerVersion: z.literal(BUILTIN_NODE_PACKAGE_LIFECYCLE_DESCRIPTOR.analyzerVersion),
  buildDigest: digestEnvelopeV1Schema,
})

const sourceAnchorSchema = z.strictObject({
  path: z.string().min(1).max(1024),
  jsonPointer: z.enum(['/scripts/preinstall', '/scripts/install', '/scripts/postinstall']),
  fileDigest: digestEnvelopeV1Schema,
})

const candidateSchema = z.strictObject({
  candidateId: z.string().regex(/^candidate-[0-9a-f]{64}$/),
  kind: z.literal('NODE_PACKAGE_INSTALL_LIFECYCLE_POLICY_VIOLATION'),
  weaknessId: z.literal('DSH-NODE-POLICY-001'),
  sourceAnchor: sourceAnchorSchema,
  securityClaim: z.literal('A Node package install lifecycle script is present where the frozen Policy forbids it.'),
  evidenceDigest: digestEnvelopeV1Schema,
})

const manifestEvidenceSchema = z.strictObject({
  schemaVersion: z.literal(1),
  analyzerIdentity: analyzerIdentitySchema,
  subjectDigest: digestEnvelopeV1Schema,
  manifests: z.array(z.strictObject({
    path: z.string().min(1).max(1024),
    digest: digestEnvelopeV1Schema,
    parseStatus: z.enum(['VALID', 'INVALID']),
    installLifecycleScripts: z.array(z.enum(INSTALL_LIFECYCLE_NAMES)).max(3),
  })).max(256),
})

export const nodePackageLifecycleAnalyzerContributionV1Schema = z.strictObject({
  schemaVersion: z.literal(1),
  analyzerIdentity: analyzerIdentitySchema,
  subjectDigest: digestEnvelopeV1Schema,
  completionDisposition: z.enum(['COMPLETE', 'UNSUPPORTED', 'INCOMPLETE']),
  coverageClaims: z.array(z.strictObject({
    obligationId: z.literal('node-package-install-lifecycle-policy'),
    completion: z.literal('COMPLETE'),
    evidenceDigest: digestEnvelopeV1Schema,
  })).max(1),
  candidateFindings: z.array(candidateSchema).max(768),
  manifestEvidence: z.strictObject({
    schemaId: z.literal('dsh/security-node-package-manifest-evidence'),
    digest: digestEnvelopeV1Schema,
    value: manifestEvidenceSchema,
  }),
  diagnostics: z.array(z.enum([
    'NO_NODE_PACKAGE_MANIFEST',
    'PACKAGE_MANIFEST_INVALID_JSON',
    'PACKAGE_MANIFEST_INVALID_SCRIPTS',
    'PACKAGE_MANIFEST_DUPLICATE_SECURITY_KEY',
  ])).max(256),
  resourceUse: z.strictObject({
    filesRead: z.number().int().nonnegative().max(256),
    bytesRead: z.number().int().nonnegative().max(4 * 1024 * 1024),
  }),
})

export type NodePackageLifecycleAnalyzerContributionV1 = z.infer<
  typeof nodePackageLifecycleAnalyzerContributionV1Schema
>

function analyzerIdentity(): {
  readonly analyzerId: typeof BUILTIN_NODE_PACKAGE_LIFECYCLE_DESCRIPTOR.analyzerId
  readonly analyzerVersion: typeof BUILTIN_NODE_PACKAGE_LIFECYCLE_DESCRIPTOR.analyzerVersion
  readonly buildDigest: DigestEnvelopeV1
} {
  return {
    analyzerId: BUILTIN_NODE_PACKAGE_LIFECYCLE_DESCRIPTOR.analyzerId,
    analyzerVersion: BUILTIN_NODE_PACKAGE_LIFECYCLE_DESCRIPTOR.analyzerVersion,
    buildDigest: BUILTIN_NODE_PACKAGE_LIFECYCLE_DESCRIPTOR.buildDigest,
  }
}

function jsonObject(text: string): Record<string, unknown> | undefined {
  try {
    const parsed: unknown = JSON.parse(text)
    return typeof parsed === 'object' && parsed !== null && !Array.isArray(parsed)
      ? parsed as Record<string, unknown>
      : undefined
  } catch {
    return undefined
  }
}

function hasDuplicateSecurityKey(text: string): boolean {
  const counts = new Map<string, number>()
  // Scan JSON property tokens rather than matching quoted substrings.  This
  // deliberately skips string values, so text such as `"scripts":` inside a
  // description cannot manufacture a duplicate-key diagnostic.
  for (let index = 0; index < text.length;) {
    if (text[index] !== '"') {
      index += 1
      continue
    }
    const start = index
    index += 1
    let escaped = false
    while (index < text.length) {
      const character = text[index]!
      index += 1
      if (escaped) {
        escaped = false
      } else if (character === '\\') {
        escaped = true
      } else if (character === '"') {
        break
      }
    }
    const token = text.slice(start, index)
    let cursor = index
    while (/\s/u.test(text[cursor] ?? '')) cursor += 1
    if (text[cursor] !== ':') continue
    let key: unknown
    try {
      key = JSON.parse(token)
    } catch {
      continue
    }
    if (typeof key !== 'string' || (
      key !== 'scripts' && !INSTALL_LIFECYCLE_NAMES.includes(
        key as (typeof INSTALL_LIFECYCLE_NAMES)[number],
      )
    )) continue
    const count = (counts.get(key) ?? 0) + 1
    if (count > 1) return true
    counts.set(key, count)
  }
  return false
}

/** Pure Analyzer: no filesystem, process, network, model, clock, or Store authority. */
export function analyzeNodePackageInstallLifecycle(input: {
  readonly subjectDigest: DigestEnvelopeV1
  readonly slices: readonly VerifiedSubjectTextSliceV1[]
}): NodePackageLifecycleAnalyzerContributionV1 {
  const manifests: {
    path: string
    digest: DigestEnvelopeV1
    parseStatus: 'VALID' | 'INVALID'
    installLifecycleScripts: (typeof INSTALL_LIFECYCLE_NAMES)[number][]
  }[] = []
  const candidateInputs: {
    readonly path: string
    readonly digest: DigestEnvelopeV1
    readonly name: (typeof INSTALL_LIFECYCLE_NAMES)[number]
  }[] = []
  const diagnostics: (
    | 'NO_NODE_PACKAGE_MANIFEST'
    | 'PACKAGE_MANIFEST_INVALID_JSON'
    | 'PACKAGE_MANIFEST_INVALID_SCRIPTS'
    | 'PACKAGE_MANIFEST_DUPLICATE_SECURITY_KEY'
  )[] = []

  for (const slice of input.slices) {
    const value = jsonObject(slice.text)
    if (value === undefined) {
      diagnostics.push('PACKAGE_MANIFEST_INVALID_JSON')
      manifests.push({
        path: slice.path,
        digest: slice.digest,
        parseStatus: 'INVALID',
        installLifecycleScripts: [],
      })
      continue
    }
    const scripts = value.scripts
    if (scripts !== undefined && (typeof scripts !== 'object' || scripts === null || Array.isArray(scripts))) {
      diagnostics.push('PACKAGE_MANIFEST_INVALID_SCRIPTS')
      manifests.push({
        path: slice.path,
        digest: slice.digest,
        parseStatus: 'INVALID',
        installLifecycleScripts: [],
      })
      continue
    }
    const scriptRecord = scripts as Record<string, unknown> | undefined
    const duplicateSecurityKey = hasDuplicateSecurityKey(slice.text)
    if (duplicateSecurityKey) diagnostics.push('PACKAGE_MANIFEST_DUPLICATE_SECURITY_KEY')
    const malformedLifecycle = INSTALL_LIFECYCLE_NAMES.some(name => (
      scriptRecord !== undefined
      && Object.hasOwn(scriptRecord, name)
      && typeof scriptRecord[name] !== 'string'
    ))
    if (malformedLifecycle) diagnostics.push('PACKAGE_MANIFEST_INVALID_SCRIPTS')
    const present = INSTALL_LIFECYCLE_NAMES.filter(name => (
      scriptRecord !== undefined
      && Object.hasOwn(scriptRecord, name)
      && typeof scriptRecord[name] === 'string'
      && scriptRecord[name].trim().length > 0
    ))
    manifests.push({
      path: slice.path,
      digest: slice.digest,
      parseStatus: malformedLifecycle || duplicateSecurityKey ? 'INVALID' : 'VALID',
      installLifecycleScripts: present,
    })
    for (const name of present) candidateInputs.push({ path: slice.path, digest: slice.digest, name })
  }
  if (input.slices.length === 0) diagnostics.push('NO_NODE_PACKAGE_MANIFEST')

  const manifestEvidenceValue = manifestEvidenceSchema.parse({
    schemaVersion: 1,
    analyzerIdentity: analyzerIdentity(),
    subjectDigest: input.subjectDigest,
    manifests,
  })
  const evidenceDigest = structuredDigest(
    'application/vnd.dsh.security.node-package-manifest-evidence+json',
    manifestEvidenceValue,
  )
  const complete = input.slices.length > 0 && diagnostics.length === 0
  const contribution = nodePackageLifecycleAnalyzerContributionV1Schema.parse({
    schemaVersion: 1,
    analyzerIdentity: analyzerIdentity(),
    subjectDigest: input.subjectDigest,
    completionDisposition: input.slices.length === 0
      ? 'UNSUPPORTED'
      : complete ? 'COMPLETE' : 'INCOMPLETE',
    coverageClaims: complete ? [{
      obligationId: 'node-package-install-lifecycle-policy',
      completion: 'COMPLETE',
      evidenceDigest,
    }] : [],
    candidateFindings: candidateInputs.map(candidate => ({
      candidateId: `candidate-${sha256Hex(canonicalJson({
        analyzerIdentity: analyzerIdentity(),
        subjectDigest: input.subjectDigest,
        path: candidate.path,
        jsonPointer: `/scripts/${candidate.name}`,
        evidenceDigest,
      }))}`,
      kind: 'NODE_PACKAGE_INSTALL_LIFECYCLE_POLICY_VIOLATION',
      weaknessId: 'DSH-NODE-POLICY-001',
      sourceAnchor: {
        path: candidate.path,
        jsonPointer: `/scripts/${candidate.name}`,
        fileDigest: candidate.digest,
      },
      securityClaim: 'A Node package install lifecycle script is present where the frozen Policy forbids it.',
      evidenceDigest,
    })),
    manifestEvidence: {
      schemaId: 'dsh/security-node-package-manifest-evidence',
      digest: evidenceDigest,
      value: manifestEvidenceValue,
    },
    diagnostics,
    resourceUse: {
      filesRead: input.slices.length,
      bytesRead: input.slices.reduce((sum, slice) => sum + Buffer.byteLength(slice.text, 'utf8'), 0),
    },
  })
  return deepFreeze(contribution)
}

export function contributionAsJson(
  contribution: NodePackageLifecycleAnalyzerContributionV1,
): NonNullable<SecuritySubmissionJsonV1> {
  const value = securitySubmissionJsonV1Schema.parse(contribution)
  if (value === null) throw new TypeError('Analyzer Contribution must be a JSON object')
  return value
}
