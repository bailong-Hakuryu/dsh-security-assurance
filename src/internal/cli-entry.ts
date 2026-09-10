import { realpathSync } from 'node:fs'
import { fileURLToPath } from 'node:url'

export function isDirectCliInvocation(
  moduleUrl: string,
  invokedPath: string | undefined = process.argv[1],
): boolean {
  if (invokedPath === undefined) return false
  try {
    return realpathSync(invokedPath) === realpathSync(fileURLToPath(moduleUrl))
  } catch {
    return false
  }
}
