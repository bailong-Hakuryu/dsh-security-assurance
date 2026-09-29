/**
 * Choose the npm Harness the release browser proof installs (ADR 0324).
 *
 * `DSH_BROWSER_HARNESS_VERSION` wins. Otherwise the proof follows the npm
 * `latest` dist-tag of `@deepseek-ai/dsh`, the Harness a direct-use operator
 * installs. Either way the version must be in the verified set, so a new npm
 * `latest` fails closed until it is admitted instead of silently testing an
 * older Harness.
 */

const SEMVER = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z]+(?:\.[0-9A-Za-z]+)*)?$/u

/** Read exactly one version from `npm view @deepseek-ai/dsh dist-tags.latest` output. */
export function parseNpmLatest(output) {
  const version = output.trim()
  if (!SEMVER.test(version)) {
    throw new Error(`npm reported no usable latest Harness version: ${JSON.stringify(output.slice(0, 80))}`)
  }
  return version
}

/** Resolve the requested or npm `latest` Harness version and require it to be verified. */
export async function resolveBrowserHarnessVersion({ requested, supported, readLatest }) {
  if (requested !== undefined && requested !== '') {
    if (!supported.includes(requested)) {
      throw new Error(`DSH_BROWSER_HARNESS_VERSION ${requested} is outside the verified Harness set`)
    }
    return requested
  }
  const latest = parseNpmLatest(await readLatest())
  if (!supported.includes(latest)) {
    throw new Error(
      `npm latest Harness ${latest} is outside the verified Harness set; `
        + 'admit it first or set DSH_BROWSER_HARNESS_VERSION to a verified version',
    )
  }
  return latest
}
