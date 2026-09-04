import { lstat, link, mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises'
import { basename, dirname, resolve } from 'node:path'

import {
  ReleaseFileBoundaryError,
  digestRawFile,
  releaseFileFailure,
  sameDigest,
} from './internal/release-file-verification.ts'
import {
  RELEASE_PROOF_RECORD_ENGINE_ID,
  releaseProofRecordV1Schema,
  type ReleaseProofRecordV1,
} from './release-proof.ts'

export type WriteReleaseProofRecordInput = Omit<
  ReleaseProofRecordV1,
  'schemaVersion' | 'engineId' | 'candidateArtifactDigest' | 'reportedStatus'
> & {
  readonly outputPath: string
  readonly candidateArtifactPath: string
  readonly retainedCandidateArtifactPath?: string
  readonly candidateArtifactMediaType: string
}

function reportedStatus(
  assertions: WriteReleaseProofRecordInput['assertions'],
): ReleaseProofRecordV1['reportedStatus'] {
  return assertions.some(assertion => assertion.status === 'FAILED')
    ? 'FAILED'
    : assertions.some(assertion => assertion.status === 'INCONCLUSIVE')
      ? 'INCONCLUSIVE'
      : 'PASSED'
}

async function assertOutputAbsent(outputPath: string): Promise<void> {
  try {
    await lstat(outputPath)
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return
    return releaseFileFailure('OUTPUT_UNAVAILABLE', 'Release proof output cannot be prepared.')
  }
  return releaseFileFailure('OUTPUT_ALREADY_EXISTS', 'Release proof output already exists.')
}

async function writeExclusiveJson(outputPath: string, value: unknown): Promise<void> {
  const parent = dirname(outputPath)
  await mkdir(parent, { recursive: true })
  const staging = await mkdtemp(resolve(parent, `.${basename(outputPath)}-`))
  const stagedFile = resolve(staging, basename(outputPath))
  try {
    await writeFile(stagedFile, `${JSON.stringify(value, null, 2)}\n`, {
      encoding: 'utf8',
      flag: 'wx',
      mode: 0o600,
    })
    await link(stagedFile, outputPath)
  } catch (error) {
    if (error instanceof ReleaseFileBoundaryError) throw error
    return releaseFileFailure('OUTPUT_WRITE_FAILED', 'Release proof output could not be committed.')
  } finally {
    await rm(staging, { recursive: true, force: true }).catch(() => undefined)
  }
}

export async function writeReleaseProofRecord(
  input: WriteReleaseProofRecordInput,
): Promise<ReleaseProofRecordV1> {
  const outputPath = resolve(input.outputPath)
  await assertOutputAbsent(outputPath)
  const candidateArtifactDigest = await digestRawFile(
    resolve(input.candidateArtifactPath),
    input.candidateArtifactMediaType,
  )
  if (input.retainedCandidateArtifactPath !== undefined) {
    const retainedCandidateArtifactDigest = await digestRawFile(
      resolve(input.retainedCandidateArtifactPath),
      input.candidateArtifactMediaType,
    )
    if (!sameDigest(candidateArtifactDigest, retainedCandidateArtifactDigest)) {
      return releaseFileFailure(
        'CANDIDATE_SNAPSHOT_MISMATCH',
        'The retained candidate no longer matches the tested release snapshot.',
      )
    }
  }
  const record = releaseProofRecordV1Schema.parse({
    schemaVersion: 1,
    engineId: RELEASE_PROOF_RECORD_ENGINE_ID,
    proofRecordId: input.proofRecordId,
    proofKind: input.proofKind,
    producer: input.producer,
    producerVersion: input.producerVersion,
    reportedStatus: reportedStatus(input.assertions),
    candidateArtifactDigest,
    completedAtEpochMs: input.completedAtEpochMs,
    environment: input.environment,
    assertions: input.assertions,
  })
  await writeExclusiveJson(outputPath, record)
  return record
}
