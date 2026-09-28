import type { Context } from '@deepseek-ai/cordis'
import type { SecurityAssuranceHostRepositoryProvider } from '../host-repository-provider.ts'

/**
 * Path-free Host bindings grouped by Repository (ADR 0326, ADR 0328). A
 * missing, failed, or disposing Host Repository Provider yields no marks,
 * never a guessed one.
 */
export async function hostBindingIdsByRepository(ctx: Context): Promise<ReadonlyMap<string, readonly string[]>> {
  const grouped = new Map<string, string[]>()
  try {
    const provider = ctx.get('securityAssuranceHostRepositories') as SecurityAssuranceHostRepositoryProvider | undefined
    for (const binding of await provider?.bindings() ?? []) {
      const ids = grouped.get(binding.repositoryId) ?? []
      ids.push(binding.bindingId)
      grouped.set(binding.repositoryId, ids)
    }
  } catch {
    return new Map()
  }
  for (const ids of grouped.values()) ids.sort()
  return grouped
}
