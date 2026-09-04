import type { RmOptions } from 'node:fs'

export type RemoveDirectory = (path: string, options: RmOptions) => Promise<void>

export interface RemoveTemporaryRootOptions {
  readonly remove?: RemoveDirectory
  readonly wait?: (milliseconds: number) => Promise<void>
  readonly maxRetries?: number
  readonly retryDelayMs?: number
}

export function removeTemporaryRoot(
  path: string,
  options?: RemoveTemporaryRootOptions,
): Promise<void>
