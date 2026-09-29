export function parseNpmLatest(output: string): string

export interface ResolveBrowserHarnessVersionOptions {
  readonly requested: string | undefined
  readonly supported: readonly string[]
  readonly readLatest: () => Promise<string>
}

export function resolveBrowserHarnessVersion(options: ResolveBrowserHarnessVersionOptions): Promise<string>
