export interface ResolvedHarnessPackageVersion {
  readonly packageName: string
  readonly actual: string
}

export type HarnessVersionAdmission =
  | {
      readonly status: 'SUPPORTED'
      readonly version: string
    }
  | {
      readonly status: 'UNSUPPORTED'
      readonly packages: readonly ResolvedHarnessPackageVersion[]
    }
  | {
      readonly status: 'VERSION_SKEW'
      readonly packages: readonly ResolvedHarnessPackageVersion[]
    }

/** Admit one coherent Harness release, never a mixture of supported releases. */
export function evaluateHarnessVersionAdmission(
  resolved: readonly ResolvedHarnessPackageVersion[],
  supportedVersions: readonly string[],
): HarnessVersionAdmission {
  const unsupported = resolved.filter(({ actual }) => !supportedVersions.includes(actual))
  if (unsupported.length > 0) {
    return Object.freeze({ status: 'UNSUPPORTED', packages: Object.freeze(unsupported) })
  }
  const versions = new Set(resolved.map(({ actual }) => actual))
  const first = resolved[0]
  if (first === undefined || versions.size !== 1) {
    return Object.freeze({ status: 'VERSION_SKEW', packages: Object.freeze([...resolved]) })
  }
  return Object.freeze({ status: 'SUPPORTED', version: first.actual })
}
