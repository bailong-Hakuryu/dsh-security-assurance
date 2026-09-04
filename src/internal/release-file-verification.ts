import { execFile } from 'node:child_process'
import { createHash } from 'node:crypto'
import { createReadStream } from 'node:fs'
import { stat } from 'node:fs/promises'
import { promisify } from 'node:util'

import type { DigestEnvelopeV1 } from '../digest-envelope.ts'

const executeFile = promisify(execFile)

export class ReleaseFileBoundaryError extends Error {
  readonly code: string

  constructor(code: string, message: string) {
    super(message)
    this.name = 'ReleaseFileBoundaryError'
    this.code = code
  }
}

export function releaseFileFailure(code: string, message: string): never {
  throw new ReleaseFileBoundaryError(code, message)
}

async function git(repository: string, args: readonly string[]): Promise<string> {
  try {
    const result = await executeFile('git', [
      '-c',
      `safe.directory=${repository}`,
      '-C',
      repository,
      ...args,
    ], {
      encoding: 'utf8',
      maxBuffer: 1024 * 1024,
      windowsHide: true,
    })
    return result.stdout
  } catch {
    return releaseFileFailure(
      'SOURCE_UNAVAILABLE',
      'The bound source repository cannot be verified.',
    )
  }
}

export async function inspectCleanSourceRevision(repository: string): Promise<string> {
  let repositoryStat
  try {
    repositoryStat = await stat(repository)
  } catch {
    return releaseFileFailure(
      'SOURCE_UNAVAILABLE',
      'The bound source repository cannot be verified.',
    )
  }
  if (!repositoryStat.isDirectory()) {
    return releaseFileFailure(
      'SOURCE_UNAVAILABLE',
      'The bound source repository cannot be verified.',
    )
  }
  const head = (await git(repository, ['rev-parse', '--verify', 'HEAD'])).trim()
  const trackedStatus = await git(repository, ['status', '--porcelain=v1', '--untracked-files=no'])
  if (trackedStatus.trim().length !== 0) {
    return releaseFileFailure(
      'SOURCE_NOT_CLEAN',
      'Tracked source changes are not represented by the revision.',
    )
  }
  return head
}

export async function digestRawFile(
  path: string,
  mediaType: string,
): Promise<DigestEnvelopeV1> {
  const hash = createHash('sha256')
  let byteLength = 0
  try {
    for await (const chunk of createReadStream(path)) {
      const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)
      byteLength += bytes.byteLength
      hash.update(bytes)
    }
  } catch {
    return releaseFileFailure(
      'EVIDENCE_FILE_UNAVAILABLE',
      'A bound release evidence file is unavailable.',
    )
  }
  return {
    schemaVersion: 1,
    algorithm: 'sha256',
    mediaType,
    byteLength,
    canonicalization: 'raw-bytes',
    value: hash.digest('hex'),
  }
}

export function sameDigest(left: DigestEnvelopeV1, right: DigestEnvelopeV1): boolean {
  return left.schemaVersion === right.schemaVersion
    && left.algorithm === right.algorithm
    && left.mediaType === right.mediaType
    && left.byteLength === right.byteLength
    && left.canonicalization === right.canonicalization
    && left.value === right.value
}
