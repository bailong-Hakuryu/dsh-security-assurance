import type { Context } from '@deepseek-ai/cordis'
import LocalSubprocessRuntime from '@deepseek-ai/dsh-subprocess-local'
import SecurityAssuranceService from '../../src/index.ts'
import type { Config } from '../../src/index.ts'

/**
 * Test-only composition that owns both the Host subprocess provider and the
 * Security Assurance Service so disposing the returned Fiber tears them down
 * together in reverse activation order.
 */
export async function SecurityAssuranceTestComposition(
  ctx: Context,
  config: Config = {},
): Promise<void> {
  await ctx.plugin(LocalSubprocessRuntime)
  await ctx.plugin(SecurityAssuranceService, config)
}
