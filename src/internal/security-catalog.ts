import type { AnalyzerPortfolioEntryV1 } from '../analyzer.ts'
import type {
  AssessmentMode,
  RepositorySnapshotV1,
  SecurityCatalogAssessmentModeV1,
  SecurityCatalogProfileV1,
  SecurityCatalogSnapshotV1,
  StartAssessmentSelectionV1,
  StartPreflightProviderV1,
  StartPreflightV1,
} from '../contracts.ts'
import {
  CRITICAL_BREAK_GLASS_CONTROL_ID,
  RISK_DECISION_WINDOW_CONTROL_ID,
  SECURITY_ASSURANCE_PRODUCT_NAME,
} from '../contracts.ts'
import {
  BUILTIN_NODE_PACKAGE_LIFECYCLE_DESCRIPTOR,
  BUILTIN_NODE_PACKAGE_LIFECYCLE_QUALIFICATION,
} from './builtin-node-package-lifecycle-analyzer.ts'
import { structuredDigest } from './canonical.ts'
import { deepFreeze } from './freeze.ts'

const START_PREFLIGHT_MEDIA_TYPE = 'application/vnd.dsh.security.start-preflight+json'
const MODE_DEFINITIONS = [
  {
    assessmentMode: 'REPOSITORY',
    label: { en: 'Repository', zhCN: '完整仓库' },
    targetKind: 'repository',
    subjectKinds: ['git_revision', 'workspace_snapshot'],
  },
  {
    assessmentMode: 'CHANGE',
    label: { en: 'Exact change', zhCN: '精确变更' },
    targetKind: 'change',
    subjectKinds: ['change'],
  },
  {
    assessmentMode: 'TARGETED',
    label: { en: 'Explicit targets', zhCN: '明确目标' },
    targetKind: 'targeted',
    subjectKinds: ['git_revision', 'workspace_snapshot'],
  },
] as const

export interface SecurityCatalogCompositionInputV1 {
  readonly repository: RepositorySnapshotV1 | null
  readonly proposedStart?: StartAssessmentSelectionV1 | undefined
  readonly portfolioForMode: (mode: AssessmentMode) => readonly AnalyzerPortfolioEntryV1[]
}
function builtinSupports(repository: RepositorySnapshotV1, mode: AssessmentMode): boolean {
  return repository.bindings.policyId === 'security/node-package-lifecycle'
    && BUILTIN_NODE_PACKAGE_LIFECYCLE_DESCRIPTOR.supportedAssessmentModes.includes(
      mode,
    )
    && BUILTIN_NODE_PACKAGE_LIFECYCLE_QUALIFICATION.platforms.includes(repository.bindings.platform)
}

function providerSummary(
  repository: RepositorySnapshotV1,
  mode: AssessmentMode,
  portfolio: readonly AnalyzerPortfolioEntryV1[],
): readonly StartPreflightProviderV1[] {
  const providers: StartPreflightProviderV1[] = []
  if (builtinSupports(repository, mode)) {
    providers.push({
      providerId: SECURITY_ASSURANCE_PRODUCT_NAME,
      analyzerId: BUILTIN_NODE_PACKAGE_LIFECYCLE_DESCRIPTOR.analyzerId,
      analyzerVersion: BUILTIN_NODE_PACKAGE_LIFECYCLE_DESCRIPTOR.analyzerVersion,
      executionClass: 'PURE',
      eligibility: 'ELIGIBLE',
      reason: null,
      supportedEcosystemIds: BUILTIN_NODE_PACKAGE_LIFECYCLE_QUALIFICATION.supportedEcosystemIds,
      supportedPlatforms: BUILTIN_NODE_PACKAGE_LIFECYCLE_QUALIFICATION.platforms,
      coverageObligationIds: BUILTIN_NODE_PACKAGE_LIFECYCLE_DESCRIPTOR.coverageObligationIds,
    })
  }
  for (const entry of portfolio) {
    const qualifiedScope = entry.eligibility.decision === 'ELIGIBLE'
      ? entry.qualification
      : null
    providers.push({
      providerId: SECURITY_ASSURANCE_PRODUCT_NAME,
      analyzerId: entry.descriptor.analyzerId,
      analyzerVersion: entry.descriptor.analyzerVersion,
      executionClass: entry.descriptor.executionClass,
      eligibility: entry.eligibility.decision,
      reason: entry.eligibility.reason,
      supportedEcosystemIds: qualifiedScope?.supportedEcosystemIds ?? [],
      supportedPlatforms: qualifiedScope?.platforms ?? [],
      coverageObligationIds: entry.descriptor.coverageObligationIds,
    })
  }
  return providers
}

function modeCapability(
  repository: RepositorySnapshotV1,
  definition: typeof MODE_DEFINITIONS[number],
  portfolio: readonly AnalyzerPortfolioEntryV1[],
): SecurityCatalogAssessmentModeV1 {
  const supported = builtinSupports(repository, definition.assessmentMode)
    || portfolio.some(entry => entry.eligibility.decision === 'ELIGIBLE')
  const qualificationLimitations = portfolio.flatMap(entry => entry.qualification?.limitations ?? [])
  const limitations = supported
    ? [...new Set([
        ...builtinSupports(repository, definition.assessmentMode)
          ? BUILTIN_NODE_PACKAGE_LIFECYCLE_QUALIFICATION.limitations
          : [],
        ...qualificationLimitations,
      ])]
    : ['No qualified Analyzer composition currently supports this Repository, Policy, platform, and Mode.']
  return {
    ...definition,
    subjectKinds: definition.subjectKinds,
    support: supported ? 'SUPPORTED' : 'UNSUPPORTED',
    limitations,
  }
}

function profile(repository: RepositorySnapshotV1): SecurityCatalogProfileV1 {
  const profileId = repository.bindings.assessmentProfileId
  const label = profileId === 'security/standard'
    ? { en: 'Standard', zhCN: '标准' }
    : profileId === 'security/deep'
      ? { en: 'Deep', zhCN: '深度' }
      : { en: profileId, zhCN: profileId }
  return {
    assessmentProfileId: profileId,
    label,
    maximumBudget: { status: 'NOT_REPORTED' },
    limitations: ['The v0.1 Service does not yet report a numeric maximum execution budget.'],
  }
}

function preflight(
  repository: RepositorySnapshotV1,
  selection: StartAssessmentSelectionV1,
  portfolio: readonly AnalyzerPortfolioEntryV1[],
): StartPreflightV1 {
  const providers = providerSummary(repository, selection.assessmentMode, portfolio)
  const eligibleProviders = providers.filter(provider => provider.eligibility === 'ELIGIBLE')
  const unsupportedConditions: string[] = []
  if (repository.state !== 'ENABLED') unsupportedConditions.push('REPOSITORY_DISABLED')
  if (selection.assessmentProfileId !== repository.bindings.assessmentProfileId) {
    unsupportedConditions.push('ASSESSMENT_PROFILE_NOT_BOUND')
  }
  if (eligibleProviders.length === 0) unsupportedConditions.push('NO_ELIGIBLE_ANALYZER_COMPOSITION')
  const claimLimitations = [...new Set([
    ...builtinSupports(repository, selection.assessmentMode)
      ? BUILTIN_NODE_PACKAGE_LIFECYCLE_QUALIFICATION.limitations
      : [],
    ...portfolio.flatMap(entry => entry.qualification?.limitations ?? []),
  ])]
  const coverageLimitations = eligibleProviders.length === 0
    ? ['Mandatory Coverage cannot be satisfied by the currently qualified composition.']
    : claimLimitations
  const core = {
    schemaVersion: 1 as const,
    repository: {
      repositoryId: repository.repositoryId,
      repositoryRevision: repository.repositoryRevision,
      displayName: repository.displayName,
    },
    selection,
    effectivePolicyId: repository.bindings.policyId,
    effectiveProfileId: repository.bindings.assessmentProfileId,
    providerComposition: providers,
    dataEgress: {
      policyId: repository.bindings.dataEgressPolicyId,
      destinationIds: [] as readonly string[],
      categories: ['NONE'] as const,
    },
    evidenceProtection: { policyId: repository.bindings.evidenceProtectionId },
    maximumBudget: { status: 'NOT_REPORTED' as const },
    unsupportedConditions,
    claimLimitations,
    coverageLimitations,
    admissible: unsupportedConditions.length === 0,
  }
  return {
    ...core,
    proposalDigest: structuredDigest(START_PREFLIGHT_MEDIA_TYPE, core),
  }
}

/** Build the bounded authority-filtered Catalog and optional digest-bound proposal. */
export function buildSecurityCatalog(
  input: SecurityCatalogCompositionInputV1,
): SecurityCatalogSnapshotV1 {
  const repository = input.repository
  const portfolios = new Map<AssessmentMode, readonly AnalyzerPortfolioEntryV1[]>(
    repository === null
      ? []
      : MODE_DEFINITIONS.map(definition => [
          definition.assessmentMode,
          input.portfolioForMode(definition.assessmentMode),
        ]),
  )
  const modes = repository === null
    ? MODE_DEFINITIONS.map(definition => ({
        ...definition,
        subjectKinds: definition.subjectKinds,
        support: 'UNSUPPORTED' as const,
        limitations: ['Select an authorized Repository to resolve effective support.'],
      }))
    : MODE_DEFINITIONS.map(definition => modeCapability(
        repository,
        definition,
        portfolios.get(definition.assessmentMode) ?? [],
      ))
  const qualifiedProviders = repository === null
    ? []
    : MODE_DEFINITIONS.flatMap(definition => providerSummary(
        repository,
        definition.assessmentMode,
        portfolios.get(definition.assessmentMode) ?? [],
      )).filter(provider => provider.eligibility === 'ELIGIBLE')
  const proposedStart = input.proposedStart
  return deepFreeze({
    schemaVersion: 1,
    repository,
    assessmentModes: modes,
    assessmentProfiles: repository === null ? [] : [profile(repository)],
    strongerControls: [{
      controlId: RISK_DECISION_WINDOW_CONTROL_ID,
      label: { en: 'Risk decision window', zhCN: '风险决策窗口' },
      requiresControlIds: [],
    }, {
      controlId: CRITICAL_BREAK_GLASS_CONTROL_ID,
      label: { en: 'Critical dual authority', zhCN: 'Critical 双重授权' },
      requiresControlIds: [RISK_DECISION_WINDOW_CONTROL_ID],
    }],
    supportedEcosystemIds: [...new Set(
      qualifiedProviders.flatMap(provider => provider.supportedEcosystemIds),
    )],
    supportedPlatforms: [...new Set(
      qualifiedProviders.flatMap(provider => provider.supportedPlatforms),
    )],
    supportMatrixReferences: ['dsh-security-assurance/support-matrix/v0.1-development'],
    startPreflight: repository !== null && proposedStart !== undefined
      ? preflight(
          repository,
          proposedStart,
          portfolios.get(proposedStart.assessmentMode) ?? [],
        )
      : null,
  })
}
