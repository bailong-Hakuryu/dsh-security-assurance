import { createHash } from 'node:crypto'

export interface ControlPlaneWorkspaceFingerprintInputV1 {
  readonly branch: string
  readonly head: string
  readonly status: string
}

export interface ControlPlaneProducedChangeFingerprintInputV1 {
  readonly baseCommit: string
  readonly trackedDiff: string
  readonly untrackedFiles: readonly {
    readonly path: string
    readonly digest: string
  }[]
}

/** Local protocol verifier; conformance tests pin it to the optional Control Plane peer. */
export function computeControlPlaneWorkspaceFingerprintV1(
  input: ControlPlaneWorkspaceFingerprintInputV1,
): string {
  if (input.branch.length === 0 || input.branch !== input.branch.trim() || input.branch.includes('\0')) {
    throw new TypeError('Control Plane workspace branch must be one canonical non-empty name')
  }
  if (!/^[0-9a-f]{40,64}$/u.test(input.head)) {
    throw new TypeError('Control Plane workspace HEAD must be one exact Git object id')
  }
  return `sha256:${createHash('sha256')
    .update(`${input.branch}\0${input.head}\0${input.status}`)
    .digest('hex')}`
}

/** Local byte-exact verifier for the Control Plane V1 Produced Change Fingerprint. */
export function computeControlPlaneProducedChangeFingerprintV1(
  input: ControlPlaneProducedChangeFingerprintInputV1,
): string {
  if (!/^[0-9a-f]{40,64}$/u.test(input.baseCommit)) {
    throw new TypeError('Control Plane produced change base must be one exact Git object id')
  }
  const seen = new Set<string>()
  const untrackedFiles = input.untrackedFiles.map(file => {
    if (file.path.length === 0 || file.path.includes('\0') || seen.has(file.path)) {
      throw new TypeError('Control Plane produced change paths must be unique non-empty Git paths')
    }
    if (!/^sha256:[0-9a-f]{64}$/u.test(file.digest)) {
      throw new TypeError('Control Plane produced change file digest must be a SHA-256 envelope')
    }
    seen.add(file.path)
    return { path: file.path, digest: file.digest }
  })
  const trackedDiffDigest = `sha256:${createHash('sha256')
    .update(input.trackedDiff)
    .digest('hex')}`
  const canonical = JSON.stringify({
    schemaVersion: 1,
    baseCommit: input.baseCommit,
    trackedDiffDigest,
    untrackedFiles,
  })
  return `sha256:${createHash('sha256').update(canonical).digest('hex')}`
}
