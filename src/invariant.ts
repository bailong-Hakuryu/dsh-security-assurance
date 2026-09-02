import { createRequire } from 'node:module'
import type { Context } from '@deepseek-ai/cordis'
import type { InvariantInstaller } from '@deepseek-ai/dsh-invariants'
import {
  SUPPORTED_HARNESS_VERSIONS,
} from './contracts.ts'
import { evaluateHarnessVersionAdmission } from './internal/harness-version-admission.ts'
import {
  createHarnessVerificationOwner,
  HARNESS_VERIFICATION_AUTHORITY,
  RECEIVE_HARNESS_VERIFICATION,
  type HarnessVerificationCheck,
  type HarnessVerificationContribution,
  type HarnessVerificationReceiver,
} from './internal/harness-verification.ts'
import type {} from './index.ts'

const PACKAGE_NAME = 'dsh-security-assurance'
const PACKAGE_FACE = 'host'
const PACKAGE_KEY = `${PACKAGE_NAME}#${PACKAGE_FACE}`
const SERVICE_KEY = 'securityAssurance'
const SERVICE_EXPORT_NAME = 'SecurityAssuranceService'
const ROOT_ENTRY_ID = 'dsh-security-assurance'
const ROOT_ENTRY_NAME = 'dsh-security-assurance'
const INVARIANT_ENTRY_ID = 'dsh-security-assurance-invariant'
const INVARIANT_ENTRY_NAME = 'dsh-security-assurance/invariant'

const REQUIRED_PUBLIC_METHODS = Object.freeze([
  'whenReady',
  'registerAnalyzer',
  'getHealth',
  'getCatalog',
  'registerRepository',
  'updateRepository',
  'disableRepository',
  'getRepository',
  'listRepositories',
  'startAssessment',
  'resumeAssessment',
  'cancelAssessment',
  'listAssessments',
  'getAssessment',
  'listFindings',
  'getFinding',
  'getEvidenceView',
  'recordRiskDecision',
  'waitForAssessmentRevision',
  'getBundleManifest',
  'getAssuranceSubmission',
  'requestExport',
  'getExport',
] as const)

const REQUIRED_BUNDLE_DEPENDENCIES = Object.freeze([
  '@deepseek-ai/cordis',
  '@deepseek-ai/cordis-plugin-loader',
  '@deepseek-ai/dsh-invariants',
  '@deepseek-ai/dsh-typert-registry',
  'zod',
] as const)

interface LoaderEntryLike {
  readonly options?: {
    readonly id?: unknown
    readonly name?: unknown
    readonly disabled?: unknown
  }
}

interface LoaderLike {
  entries(): Iterable<LoaderEntryLike>
}

interface TypertMemberLike {
  readonly kind?: unknown
  readonly name?: unknown
}

interface TypertServiceLike {
  readonly key?: unknown
  readonly exportName?: unknown
  readonly members?: readonly TypertMemberLike[]
}

interface TypertPackageLike {
  readonly package?: unknown
  readonly face?: unknown
  readonly key?: unknown
  readonly model?: {
    readonly services?: readonly TypertServiceLike[]
  }
}

interface TypertLike {
  getPackage(packageName: string, face?: string): TypertPackageLike | undefined
}

interface PackageManifest {
  readonly version?: unknown
}

interface HostRepositoryProviderLike {
  whenReady(): Promise<void>
}

const require = createRequire(import.meta.url)

function pass(id: string, message: string): HarnessVerificationCheck {
  return Object.freeze({ id, status: 'PASS', required: true, message })
}

function fail(id: string, message: string): HarnessVerificationCheck {
  return Object.freeze({ id, status: 'FAIL', required: true, message })
}

function notEvaluated(id: string, message: string): HarnessVerificationCheck {
  return Object.freeze({ id, status: 'NOT_EVALUATED', required: true, message })
}

/** Bound and redact diagnostics before they enter the public Health envelope. */
function sanitizeErrorMessage(error: unknown): string {
  const raw = error instanceof Error ? error.message : String(error)
  const sanitized = raw
    .replace(/\b((?:api[_-]?key|access[_-]?token|secret|password|credential)s?)\s*[:=]\s*[^\s,;]+/gi, '$1=[redacted]')
    .replace(/\bsk-[A-Za-z0-9_-]{8,}\b/g, '[token]')
    .replace(/\bBearer\s+[A-Za-z0-9._~-]+/gi, 'Bearer [redacted]')
    .replace(/\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g, '[token]')
    .replace(/\bAKIA[0-9A-Z]{16}\b/g, '[key]')
    .replace(/\b[0-9a-f]{32,}\b/gi, '[key]')
    .replace(/\b(?:https?|file):\/\/[^\s]+/gi, '[url]')
    .replace(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g, '[ip]')
    .replace(/(?:[A-Z]:[\\/]|\\\\)[^\s]*/gi, '[path]')
    .replace(/(?:^|\s)\/[^\s:]*/g, ' [path]')
    .slice(0, 200)
  return sanitized.length > 0 ? sanitized : 'unknown error'
}

function serviceFromContext(ctx: Context, name: string): unknown {
  try {
    return ctx.reflect.get(name)
  } catch {
    return undefined
  }
}

function packageVersion(packageName: string): string {
  const manifest = require(`${packageName}/package.json`) as PackageManifest
  if (typeof manifest.version !== 'string') {
    throw new TypeError(`${packageName} package version is unavailable`)
  }
  return manifest.version
}

function verifyHarnessVersion(): HarnessVerificationCheck {
  const id = 'composition.harness-version'
  try {
    const harnessPackages = [
      '@deepseek-ai/dsh-invariants',
      '@deepseek-ai/dsh-typert-registry',
    ] as const
    const resolved = harnessPackages.map(packageName => ({
      packageName,
      actual: packageVersion(packageName),
    }))
    const describe = (entries: readonly { packageName: string, actual: string }[]) =>
      entries.map(({ packageName, actual }) => `${packageName}@${actual}`).join(', ')
    const admission = evaluateHarnessVersionAdmission(resolved, SUPPORTED_HARNESS_VERSIONS)
    if (admission.status === 'UNSUPPORTED') {
      return fail(id, `Unsupported Harness runtime version: ${describe(admission.packages)}; supported: ${SUPPORTED_HARNESS_VERSIONS.join(', ')}.`)
    }
    if (admission.status === 'VERSION_SKEW') {
      return fail(id, `Harness runtime package version skew: ${describe(admission.packages)}.`)
    }
    return pass(id, `Harness runtime packages coherently match supported version ${admission.version}: ${describe(resolved)}.`)
  } catch (error) {
    return notEvaluated(id, `Harness version verification unavailable: ${sanitizeErrorMessage(error)}.`)
  }
}

function verifyRequiredServiceDefinitions(ctx: Context): HarnessVerificationCheck {
  const id = 'composition.required-service-definitions'
  const securityAssurance = serviceFromContext(ctx, SERVICE_KEY) as Record<PropertyKey, unknown> | undefined
  const invariants = serviceFromContext(ctx, 'invariants') as { register?: unknown } | undefined
  const loader = serviceFromContext(ctx, 'loader') as { entries?: unknown } | undefined
  const typert = serviceFromContext(ctx, 'typert') as { getPackage?: unknown } | undefined
  const missing: string[] = []
  if (securityAssurance === undefined
    || typeof securityAssurance.getHealth !== 'function'
    || typeof securityAssurance[RECEIVE_HARNESS_VERIFICATION] !== 'function') missing.push(SERVICE_KEY)
  if (invariants === undefined || typeof invariants.register !== 'function') missing.push('invariants')
  if (loader === undefined || typeof loader.entries !== 'function') missing.push('loader')
  if (typert === undefined || typeof typert.getPackage !== 'function') missing.push('typert')
  return missing.length === 0
    ? pass(id, 'Required Harness Service Definitions are available.')
    : fail(id, `Missing or incompatible Service Definitions: ${missing.join(', ')}.`)
}

function verifyBundleDependencies(): HarnessVerificationCheck {
  const id = 'composition.bundle-dependencies'
  try {
    const resolved = REQUIRED_BUNDLE_DEPENDENCIES.map(packageName =>
      `${packageName}@${packageVersion(packageName)}`)
    return pass(id, `Required runtime bundle dependencies are present: ${resolved.join(', ')}.`)
  } catch (error) {
    return notEvaluated(id, `Bundle dependency verification unavailable: ${sanitizeErrorMessage(error)}.`)
  }
}

function getTypertPackage(ctx: Context): TypertPackageLike | undefined {
  const typert = serviceFromContext(ctx, 'typert') as TypertLike | undefined
  return typert?.getPackage(PACKAGE_NAME, PACKAGE_FACE)
}

function mainServiceModel(record: TypertPackageLike | undefined): TypertServiceLike | undefined {
  return record?.model?.services?.find(service => service.key === SERVICE_KEY)
}

function verifyGeneratedContract(ctx: Context): HarnessVerificationCheck {
  const id = 'composition.generated-contract'
  try {
    const record = getTypertPackage(ctx)
    if (record === undefined) {
      return notEvaluated(id, `Generated ${PACKAGE_KEY} contract is not registered.`)
    }
    const model = mainServiceModel(record)
    if (model === undefined || !Array.isArray(model.members)) {
      return fail(id, `Generated contract does not define ${SERVICE_KEY}.`)
    }
    const declaredMethods = new Set(model.members
      .filter(member => member.kind === 'method' && typeof member.name === 'string')
      .map(member => member.name as string))
    const service = serviceFromContext(ctx, SERVICE_KEY) as Record<string, unknown> | undefined
    const missingGenerated = REQUIRED_PUBLIC_METHODS.filter(method => !declaredMethods.has(method))
    const missingLive = REQUIRED_PUBLIC_METHODS.filter(method => typeof service?.[method] !== 'function')
    if (missingGenerated.length > 0 || missingLive.length > 0) {
      const details = [
        missingGenerated.length === 0 ? undefined : `generated: ${missingGenerated.join(', ')}`,
        missingLive.length === 0 ? undefined : `live: ${missingLive.join(', ')}`,
      ].filter(detail => detail !== undefined)
      return fail(id, `Public contract methods are missing (${details.join('; ')}).`)
    }
    return pass(id, 'Generated host contract matches the live Security Assurance Service.')
  } catch (error) {
    return notEvaluated(id, `Generated contract verification unavailable: ${sanitizeErrorMessage(error)}.`)
  }
}

function verifyCapabilityIdentity(ctx: Context): HarnessVerificationCheck {
  const id = 'composition.capability-identity'
  try {
    const record = getTypertPackage(ctx)
    if (record === undefined) {
      return notEvaluated(id, `Generated ${PACKAGE_KEY} capability identity is not registered.`)
    }
    const model = mainServiceModel(record)
    const matches = record.package === PACKAGE_NAME
      && record.face === PACKAGE_FACE
      && record.key === PACKAGE_KEY
      && model?.key === SERVICE_KEY
      && model.exportName === SERVICE_EXPORT_NAME
    return matches
      ? pass(id, `Capability identity ${PACKAGE_KEY}/${SERVICE_KEY} is exact.`)
      : fail(id, 'Generated capability identity does not match the package contract.')
  } catch (error) {
    return notEvaluated(id, `Capability identity verification unavailable: ${sanitizeErrorMessage(error)}.`)
  }
}

function verifyDeclaredRuntimeComposition(ctx: Context): HarnessVerificationCheck {
  const id = 'composition.declared-runtime'
  try {
    const loader = serviceFromContext(ctx, 'loader') as LoaderLike | undefined
    if (loader === undefined || typeof loader.entries !== 'function') {
      return notEvaluated(id, 'Loader entries are unavailable for declared composition verification.')
    }
    const entries = [...loader.entries()].map(entry => entry.options)
    const hasEnabledEntry = (entryId: string, entryName: string): boolean => entries.some(options =>
      options?.id === entryId && options.name === entryName && options.disabled !== true)
    const missing = [
      hasEnabledEntry(ROOT_ENTRY_ID, ROOT_ENTRY_NAME) ? undefined : ROOT_ENTRY_ID,
      hasEnabledEntry(INVARIANT_ENTRY_ID, INVARIANT_ENTRY_NAME) ? undefined : INVARIANT_ENTRY_ID,
    ].filter(entryId => entryId !== undefined)
    return missing.length === 0
      ? pass(id, 'Security Assurance and its invariant companion are enabled in Loader composition.')
      : fail(id, `Required enabled Loader entries are missing: ${missing.join(', ')}.`)
  } catch (error) {
    return notEvaluated(id, `Declared composition verification unavailable: ${sanitizeErrorMessage(error)}.`)
  }
}

function performVerification(ctx: Context): HarnessVerificationContribution {
  const checks = Object.freeze([
    verifyHarnessVersion(),
    verifyRequiredServiceDefinitions(ctx),
    verifyBundleDependencies(),
    verifyGeneratedContract(ctx),
    verifyCapabilityIdentity(ctx),
    verifyDeclaredRuntimeComposition(ctx),
  ])
  return Object.freeze({
    result: checks.every(check => !check.required || check.status === 'PASS') ? 'PASS' : 'FAIL',
    checks,
  })
}

function verificationReceiver(ctx: Context): HarnessVerificationReceiver | undefined {
  const service = serviceFromContext(ctx, SERVICE_KEY) as Record<PropertyKey, unknown> | undefined
  const receiver = service?.[RECEIVE_HARNESS_VERIFICATION]
  return typeof receiver === 'function'
    ? receiver.bind(service) as HarnessVerificationReceiver
    : undefined
}

export const name = 'security-assurance-invariant'
export const inject = ['invariants']

function installVerification(ctx: Context, hostBootstrapFailure?: unknown): void {
  const owner = createHarnessVerificationOwner()
  const receiver = verificationReceiver(ctx)
  if (receiver === undefined) return
  const verification = performVerification(ctx)
  const checks = hostBootstrapFailure === undefined
    ? verification.checks
    : Object.freeze([
        ...verification.checks,
        {
          id: 'composition.host-repository-bootstrap',
          status: 'FAIL' as const,
          required: true,
          message: `Host Repository bootstrap unavailable: ${sanitizeErrorMessage(hostBootstrapFailure)}.`,
        },
      ])
  receiver(HARNESS_VERIFICATION_AUTHORITY, owner, {
    result: hostBootstrapFailure === undefined ? verification.result : 'FAIL',
    checks,
  })
  ctx.effect(() => () => {
    receiver(HARNESS_VERIFICATION_AUTHORITY, owner, undefined)
  })
}

const install: InvariantInstaller = Object.assign((ctx: Context) => {
  installVerification(ctx)
}, { inject: [SERVICE_KEY] })

/** Register the dormant package-owned check after direct-use Host bootstrap settles. */
export async function apply(ctx: Context): Promise<() => void> {
  const hostRepositories = serviceFromContext(ctx, 'securityAssuranceHostRepositories') as
    Partial<HostRepositoryProviderLike> | undefined
  let hostBootstrapFailure: unknown
  if (typeof hostRepositories?.whenReady === 'function') {
    try {
      await hostRepositories.whenReady()
    } catch (error) {
      hostBootstrapFailure = error
    }
  }
  const installer = hostBootstrapFailure === undefined
    ? install
    : Object.assign((installerCtx: Context) => {
        installVerification(installerCtx, hostBootstrapFailure)
      }, { inject: [SERVICE_KEY] }) satisfies InvariantInstaller
  return Promise.resolve(ctx.invariants.register(PACKAGE_NAME, installer))
}
