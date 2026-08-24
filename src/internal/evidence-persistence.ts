import { randomUUID } from 'node:crypto'
import {
  chmod,
  lstat,
  mkdir,
  readFile,
  rename,
  rm,
  writeFile,
} from 'node:fs/promises'
import { join } from 'node:path'
import { z } from 'zod'
import {
  assessmentIdSchema,
  digestEnvelopeV1Schema,
  securitySubmissionJsonV1Schema,
} from '../contracts.ts'
import type {
  AssessmentId,
  DigestEnvelopeV1,
  SecuritySubmissionJsonV1,
} from '../contracts.ts'
import { canonicalJson, structuredDigest } from './canonical.ts'

export interface EvidencePublicationInputV1 {
  readonly artifactId: string
  readonly schemaId: string
  readonly mediaType: string
  readonly value: SecuritySubmissionJsonV1
}

export interface EvidencePublicationReceiptV1 {
  readonly schemaVersion: 1
  readonly artifactId: string
  readonly schemaId: string
  readonly digest: DigestEnvelopeV1
}

const evidenceEnvelopeV1Schema = z.strictObject({
  schemaVersion: z.literal(1),
  assessmentId: assessmentIdSchema,
  subjectDigest: digestEnvelopeV1Schema,
  artifactId: z.string().regex(/^[a-z0-9][a-z0-9-]{0,127}$/u),
  schemaId: z.string().regex(/^[a-z0-9][a-z0-9._-]*(?:\/[a-z0-9][a-z0-9._-]*){1,7}$/),
  digest: digestEnvelopeV1Schema,
  value: securitySubmissionJsonV1Schema,
})

function evidenceEnvelope(input: {
  readonly assessmentId: AssessmentId
  readonly subjectDigest: DigestEnvelopeV1
  readonly record: EvidencePublicationInputV1
}): {
  readonly schemaVersion: 1
  readonly assessmentId: AssessmentId
  readonly subjectDigest: DigestEnvelopeV1
  readonly artifactId: string
  readonly schemaId: string
  readonly digest: DigestEnvelopeV1
  readonly value: SecuritySubmissionJsonV1
} {
  return {
    schemaVersion: 1,
    assessmentId: input.assessmentId,
    subjectDigest: input.subjectDigest,
    artifactId: input.record.artifactId,
    schemaId: input.record.schemaId,
    digest: structuredDigest(input.record.mediaType, input.record.value),
    value: input.record.value,
  }
}

async function verifyRegularCanonicalFile(path: string, expected: string): Promise<void> {
  const status = await lstat(path)
  if (!status.isFile() || status.isSymbolicLink()) throw new Error('Evidence object is not a regular file')
  if (await readFile(path, 'utf8') !== expected) throw new Error('Evidence object failed canonical verification')
}

/**
 * Stage, atomically publish, and verify bounded immutable Evidence objects.
 * Callers receive identities and digests, never writable paths or Store handles.
 */
export async function publishEvidenceSet(
  securityRoot: string,
  assessmentId: AssessmentId,
  subjectDigest: DigestEnvelopeV1,
  records: readonly EvidencePublicationInputV1[],
): Promise<readonly EvidencePublicationReceiptV1[]> {
  if (records.length > 128) throw new Error('Evidence publication count exceeds the v1 limit')
  const evidenceRoot = join(securityRoot, 'evidence')
  const stagingRoot = join(securityRoot, 'staging')
  await Promise.all([
    mkdir(evidenceRoot, { recursive: true, mode: 0o700 }),
    mkdir(stagingRoot, { recursive: true, mode: 0o700 }),
  ])
  const receipts: EvidencePublicationReceiptV1[] = []
  for (const record of records) {
    if (!/^[a-z0-9][a-z0-9-]{0,127}$/u.test(record.artifactId)) {
      throw new Error('Evidence artifact identity is invalid')
    }
    const envelope = evidenceEnvelope({ assessmentId, subjectDigest, record })
    const bytes = canonicalJson(envelope)
    if (Buffer.byteLength(bytes, 'utf8') > 4 * 1024 * 1024) {
      throw new Error('Evidence object exceeds the v1 byte limit')
    }
    const assessmentEvidenceRoot = join(evidenceRoot, assessmentId)
    await mkdir(assessmentEvidenceRoot, { recursive: true, mode: 0o700 })
    const artifactRoot = join(assessmentEvidenceRoot, record.artifactId)
    await mkdir(artifactRoot, { recursive: true, mode: 0o700 })
    const destination = join(artifactRoot, envelope.digest.value)
    const destinationFile = join(destination, 'evidence.json')
    const staging = join(stagingRoot, `evidence-${randomUUID()}`)
    await mkdir(staging, { mode: 0o700 })
    const stagingFile = join(staging, 'evidence.json')
    try {
      await writeFile(stagingFile, bytes, { encoding: 'utf8', flag: 'wx', mode: 0o600 })
      await chmod(stagingFile, 0o600)
      try {
        await rename(staging, destination)
      } catch (error) {
        const code = (error as NodeJS.ErrnoException).code
        if (code !== 'EEXIST' && code !== 'ENOTEMPTY') throw error
        await verifyRegularCanonicalFile(destinationFile, bytes)
        await rm(staging, { recursive: true, force: true })
      }
      await verifyRegularCanonicalFile(destinationFile, bytes)
    } catch (error) {
      await rm(staging, { recursive: true, force: true })
      throw error
    }
    receipts.push({
      schemaVersion: 1,
      artifactId: record.artifactId,
      schemaId: record.schemaId,
      digest: envelope.digest,
    })
  }
  return receipts
}

/** Read only exact published identities after re-verifying canonical bytes and every binding. */
export async function readPublishedEvidenceSet(
  securityRoot: string,
  assessmentId: AssessmentId,
  subjectDigest: DigestEnvelopeV1,
  receipts: readonly EvidencePublicationReceiptV1[],
): Promise<readonly EvidencePublicationInputV1[]> {
  const records: EvidencePublicationInputV1[] = []
  for (const receipt of receipts) {
    const path = join(
      securityRoot,
      'evidence',
      assessmentId,
      receipt.artifactId,
      receipt.digest.value,
      'evidence.json',
    )
    const status = await lstat(path)
    if (!status.isFile() || status.isSymbolicLink()) {
      throw new Error('Evidence object is not a regular file')
    }
    const bytes = await readFile(path, 'utf8')
    const envelope = evidenceEnvelopeV1Schema.parse(JSON.parse(bytes))
    if (
      bytes !== canonicalJson(envelope)
      || envelope.assessmentId !== assessmentId
      || envelope.artifactId !== receipt.artifactId
      || envelope.schemaId !== receipt.schemaId
      || canonicalJson(envelope.subjectDigest) !== canonicalJson(subjectDigest)
      || canonicalJson(envelope.digest) !== canonicalJson(receipt.digest)
      || canonicalJson(structuredDigest(receipt.digest.mediaType, envelope.value))
        !== canonicalJson(receipt.digest)
    ) throw new Error('Evidence object failed identity or digest verification')
    records.push({
      artifactId: envelope.artifactId,
      schemaId: envelope.schemaId,
      mediaType: envelope.digest.mediaType,
      value: envelope.value,
    })
  }
  return records
}
