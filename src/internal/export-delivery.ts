import { randomUUID } from 'node:crypto'
import {
  chmod,
  mkdir,
  open,
  readFile,
  rename,
  rm,
  writeFile,
} from 'node:fs/promises'
import { join } from 'node:path'
import { z } from 'zod'
import {
  EXPORT_DOWNLOAD_CAPABILITY_LIFETIME_SECONDS,
  exportDestinationViewV1Schema,
  exportDownloadV1Schema,
  exportIdSchema,
  exportProfileViewV1Schema,
  exportRequestReceiptV1Schema,
  exportStatusV1Schema,
  INTERNAL_JSON_EXPORT_PROFILE_ID,
  LOCAL_AUDIT_DELIVERY_DESTINATION_ID,
  MAX_EXPORT_DOWNLOAD_BYTES,
} from '../contracts.ts'
import type {
  ExportDestinationViewV1,
  ExportDownloadV1,
  ExportId,
  ExportPreviewV1,
  ExportProfileViewV1,
  ExportStatusV1,
  GetExportDownloadRequest,
  RequestExportRequest,
  SecurityAssuranceSubmissionV1,
} from '../contracts.ts'
import { binaryDigest, canonicalJson, sha256Hex } from './canonical.ts'

export const EXPORT_ARTIFACT_LIFETIME_SECONDS = 24 * 60 * 60

const PROFILE: ExportProfileViewV1 = exportProfileViewV1Schema.parse({
  exportProfileId: INTERNAL_JSON_EXPORT_PROFILE_ID,
  audience: 'INTERNAL',
  artifactFormat: 'JSON',
  mediaType: 'application/vnd.dsh.security.export+json',
  includedCategories: [
    'SUBJECT',
    'POLICY',
    'COVERAGE',
    'FINDINGS',
    'RISK_DECISIONS',
    'EVIDENCE',
    'PROVENANCE',
    'SEAL',
  ],
  redactions: [
    'ORIGINAL_CREDENTIAL_VALUES',
    'HOST_CREDENTIALS',
    'PRIVATE_STORE_PATHS',
  ],
})

const DESTINATION: ExportDestinationViewV1 = exportDestinationViewV1Schema.parse({
  deliveryDestinationId: LOCAL_AUDIT_DELIVERY_DESTINATION_ID,
  kind: 'HOST_REGISTERED_LOCAL_AUDIT',
  summary: 'Host-registered local audit delivery',
})

const internalExportRecordV1Schema = z.strictObject({
  schemaVersion: z.literal(1),
  owner: z.strictObject({
    principalId: z.string().min(1).max(128),
    authorityKind: z.enum(['harness-session', 'host-operator', 'control-plane']),
  }),
  requestDigest: z.string().regex(/^[0-9a-f]{64}$/),
  receipt: exportRequestReceiptV1Schema,
  view: exportStatusV1Schema,
})

interface InternalExportRecordV1 extends z.infer<typeof internalExportRecordV1Schema> {}

export interface ExportDeliveryAuthorityV1 {
  readonly principalId: string
  readonly authorityKind: 'harness-session' | 'host-operator' | 'control-plane'
}

export interface BeginExportResultV1 {
  readonly record: InternalExportRecordV1
  readonly replayed: boolean
}

export class ExportDeliveryError extends Error {
  constructor(
    readonly code:
      | 'IDEMPOTENCY_CONFLICT'
      | 'NOT_FOUND'
      | 'CONFLICT'
      | 'CAPABILITY_CONSUMED'
      | 'CAPABILITY_EXPIRED'
      | 'UNAVAILABLE',
    message: string,
  ) {
    super(message)
    this.name = 'ExportDeliveryError'
  }
}

/** Non-serializable process-local authority for exactly one bounded artifact read. */
export class OneUseExportDownloadCapability {
  readonly #owner: ExportDeliveryAuthorityV1
  readonly #view: ExportStatusV1
  readonly #artifactFile: string
  readonly #issuedAt: string
  readonly #expiresAt: string
  #consumed = false

  constructor(
    owner: ExportDeliveryAuthorityV1,
    view: ExportStatusV1,
    artifactFile: string,
    issuedAt: string,
    expiresAt: string,
  ) {
    this.#owner = owner
    this.#view = view
    this.#artifactFile = artifactFile
    this.#issuedAt = issuedAt
    this.#expiresAt = expiresAt
  }

  claim(authority: ExportDeliveryAuthorityV1, now: string): {
    readonly view: ExportStatusV1
    readonly artifactFile: string
    readonly issuedAt: string
    readonly expiresAt: string
    readonly consumedAt: string
  } {
    if (
      this.#owner.principalId !== authority.principalId
      || this.#owner.authorityKind !== authority.authorityKind
    ) {
      throw new ExportDeliveryError('NOT_FOUND', 'Export download capability is not visible to this authority')
    }
    if (Date.parse(now) >= Date.parse(this.#expiresAt)) {
      throw new ExportDeliveryError('CAPABILITY_EXPIRED', 'Export download capability expired')
    }
    if (this.#consumed) {
      throw new ExportDeliveryError('CAPABILITY_CONSUMED', 'Export download capability was already consumed')
    }
    this.#consumed = true
    return {
      view: this.#view,
      artifactFile: this.#artifactFile,
      issuedAt: this.#issuedAt,
      expiresAt: this.#expiresAt,
      consumedAt: now,
    }
  }
}

export function exportProfileView(): ExportProfileViewV1 {
  return PROFILE
}

export function exportDestinationView(destinationId: string): ExportDestinationViewV1 | undefined {
  return destinationId === LOCAL_AUDIT_DELIVERY_DESTINATION_ID ? DESTINATION : undefined
}

export function buildExportPreview(input: {
  readonly assessmentId: ExportPreviewV1['assessmentId']
  readonly assessmentRevision: number
  readonly sealId: string
  readonly deliveryDestinationId: string
}): ExportPreviewV1 | undefined {
  const destination = exportDestinationView(input.deliveryDestinationId)
  if (destination === undefined) return undefined
  return {
    schemaVersion: 1,
    kind: 'PREVIEW',
    assessmentId: input.assessmentId,
    assessmentRevision: input.assessmentRevision,
    sealId: input.sealId,
    profile: PROFILE,
    destination,
    expiresAfterSeconds: EXPORT_ARTIFACT_LIFETIME_SECONDS,
    warnings: [
      'The artifact is delivered by the Service; no private Store path or credential is disclosed.',
      'Browser download requires fresh Host authority and a separate short-lived one-use capability.',
    ],
  }
}

function recordDirectory(root: string, exportId: ExportId): string {
  return join(root, 'exports', exportId)
}

function recordPath(root: string, exportId: ExportId): string {
  return join(recordDirectory(root, exportId), 'record.json')
}

function artifactPath(root: string, exportId: ExportId): string {
  return join(root, 'destinations', 'local-audit', `${exportId}.json`)
}

async function readBoundedArtifact(path: string, expectedByteLength: number): Promise<Buffer> {
  const handle = await open(path, 'r')
  try {
    const metadata = await handle.stat()
    if (
      metadata.size !== expectedByteLength
      || metadata.size <= 0
      || metadata.size > MAX_EXPORT_DOWNLOAD_BYTES
    ) {
      throw new ExportDeliveryError('UNAVAILABLE', 'The delivered Export artifact has an invalid bounded size')
    }
    const bounded = Buffer.alloc(metadata.size + 1)
    let offset = 0
    while (offset < bounded.byteLength) {
      const { bytesRead } = await handle.read(bounded, offset, bounded.byteLength - offset, offset)
      if (bytesRead === 0) break
      offset += bytesRead
    }
    if (offset !== metadata.size) {
      throw new ExportDeliveryError('UNAVAILABLE', 'The delivered Export artifact changed during its bounded read')
    }
    return bounded.subarray(0, metadata.size)
  } finally {
    await handle.close()
  }
}

function exportIdFor(authority: ExportDeliveryAuthorityV1, request: RequestExportRequest): ExportId {
  return exportIdSchema.parse(`export-${sha256Hex(canonicalJson({
    authorityKind: authority.authorityKind,
    principalId: authority.principalId,
    assessmentId: request.assessmentId,
    idempotencyKey: request.idempotencyKey,
  }))}`)
}

function requestDigest(request: RequestExportRequest): string {
  return sha256Hex(canonicalJson(request))
}

function ownerMatches(record: InternalExportRecordV1, authority: ExportDeliveryAuthorityV1): boolean {
  return record.owner.principalId === authority.principalId
    && record.owner.authorityKind === authority.authorityKind
}

async function readRecord(root: string, exportId: ExportId): Promise<InternalExportRecordV1 | undefined> {
  try {
    return internalExportRecordV1Schema.parse(JSON.parse(await readFile(recordPath(root, exportId), 'utf8')))
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return undefined
    if (error instanceof SyntaxError || error instanceof z.ZodError) {
      throw new ExportDeliveryError('UNAVAILABLE', 'Export delivery record failed validation')
    }
    throw error
  }
}

async function replaceRecord(root: string, record: InternalExportRecordV1): Promise<void> {
  const directory = recordDirectory(root, record.receipt.exportId)
  const temporary = join(directory, `.record-${randomUUID()}.tmp`)
  await writeFile(temporary, canonicalJson(record), { encoding: 'utf8', flag: 'wx', mode: 0o600 })
  await chmod(temporary, 0o600)
  try {
    await rename(temporary, recordPath(root, record.receipt.exportId))
  } finally {
    await rm(temporary, { force: true })
  }
}

/** Durable, path-hiding Delivery module for the first registered local-audit destination. */
export class ExportDeliveryModule {
  private readonly root: string

  constructor(
    securityRoot: string,
    private readonly now: () => string = () => new Date().toISOString(),
    private readonly nextCorrelationId: () => string = () => `sec-${randomUUID()}`,
  ) {
    this.root = join(securityRoot, 'delivery')
  }

  async begin(
    authority: ExportDeliveryAuthorityV1,
    request: RequestExportRequest,
    preview: ExportPreviewV1,
  ): Promise<BeginExportResultV1> {
    const exportId = exportIdFor(authority, request)
    const digest = requestDigest(request)
    const existing = await readRecord(this.root, exportId)
    if (existing !== undefined) return this.replay(existing, authority, digest)

    const acceptedAt = this.now()
    const receipt = exportRequestReceiptV1Schema.parse({
      schemaVersion: 1,
      operation: 'request_export',
      exportId,
      assessmentId: request.assessmentId,
      assessmentRevision: request.expectedAssessmentRevision,
      idempotencyKey: request.idempotencyKey,
      acceptedState: 'PENDING',
      acceptedAt,
      correlationId: this.nextCorrelationId(),
    })
    const view = exportStatusV1Schema.parse({
      schemaVersion: 1,
      kind: 'STATUS',
      exportId,
      assessmentId: request.assessmentId,
      assessmentRevision: request.expectedAssessmentRevision,
      status: 'PENDING',
      profile: preview.profile,
      destination: preview.destination,
      artifact: null,
      expiresAt: null,
      accessAction: { kind: 'NONE', reason: 'DELIVERY_PENDING' },
      failure: null,
      createdAt: acceptedAt,
      updatedAt: acceptedAt,
    })
    const record = internalExportRecordV1Schema.parse({
      schemaVersion: 1,
      owner: authority,
      requestDigest: digest,
      receipt,
      view,
    })
    const directory = recordDirectory(this.root, exportId)
    await mkdir(directory, { recursive: true, mode: 0o700 })
    await chmod(directory, 0o700)
    try {
      await writeFile(recordPath(this.root, exportId), canonicalJson(record), {
        encoding: 'utf8',
        flag: 'wx',
        mode: 0o600,
      })
      await chmod(recordPath(this.root, exportId), 0o600)
      return { record, replayed: false }
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error
      const raced = await readRecord(this.root, exportId)
      if (raced === undefined) throw new ExportDeliveryError('UNAVAILABLE', 'Export delivery race lost its durable record')
      return this.replay(raced, authority, digest)
    }
  }

  async deliver(
    begin: BeginExportResultV1,
    submission: SecurityAssuranceSubmissionV1,
  ): Promise<ExportStatusV1> {
    if (begin.record.view.status === 'DELIVERED') return begin.record.view
    const exportedAt = begin.record.receipt.acceptedAt
    const value = {
      schemaVersion: 1,
      exportProfileId: begin.record.view.profile.exportProfileId,
      exportedAt,
      source: {
        assessmentId: begin.record.view.assessmentId,
        assessmentRevision: begin.record.view.assessmentRevision,
        seal: submission.payload.sourceSeal,
        submissionDigest: submission.digest,
      },
      submission,
    }
    const bytes = Buffer.from(canonicalJson(value), 'utf8')
    const destinationDirectory = join(this.root, 'destinations', 'local-audit')
    await mkdir(destinationDirectory, { recursive: true, mode: 0o700 })
    await chmod(destinationDirectory, 0o700)
    const destination = artifactPath(this.root, begin.record.receipt.exportId)
    try {
      await writeFile(destination, bytes, { flag: 'wx', mode: 0o600 })
      await chmod(destination, 0o600)
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'EEXIST') {
        return this.fail(begin.record)
      }
      const existing = await readFile(destination)
      if (!existing.equals(bytes)) return this.fail(begin.record)
    }
    const updatedAt = this.now()
    const expiresAt = new Date(
      Date.parse(begin.record.receipt.acceptedAt) + EXPORT_ARTIFACT_LIFETIME_SECONDS * 1000,
    ).toISOString()
    const view = exportStatusV1Schema.parse({
      ...begin.record.view,
      status: 'DELIVERED',
      artifact: {
        artifactId: `${begin.record.receipt.exportId}/artifact`,
        digest: binaryDigest('application/vnd.dsh.security.export+json', bytes),
      },
      expiresAt,
      accessAction: { kind: 'HOST_MANAGED', action: 'DELIVERED_TO_REGISTERED_DESTINATION' },
      failure: null,
      updatedAt,
    })
    await replaceRecord(this.root, internalExportRecordV1Schema.parse({ ...begin.record, view }))
    return view
  }

  async get(exportId: ExportId, authority: ExportDeliveryAuthorityV1): Promise<ExportStatusV1 | undefined> {
    const record = await readRecord(this.root, exportId)
    if (record === undefined || !ownerMatches(record, authority)) return undefined
    if (
      record.view.status === 'DELIVERED'
      && record.view.expiresAt !== null
      && Date.parse(record.view.expiresAt) <= Date.parse(this.now())
    ) {
      return exportStatusV1Schema.parse({
        ...record.view,
        status: 'EXPIRED',
        artifact: null,
        accessAction: { kind: 'NONE', reason: 'ARTIFACT_EXPIRED' },
        updatedAt: this.now(),
      })
    }
    return record.view
  }

  projectAuthorizedAccess(view: ExportStatusV1, mayDownload: boolean): ExportStatusV1 {
    if (
      !mayDownload
      || view.status !== 'DELIVERED'
      || view.artifact === null
      || view.artifact.digest.byteLength > MAX_EXPORT_DOWNLOAD_BYTES
    ) return view
    return exportStatusV1Schema.parse({
      ...view,
      accessAction: {
        kind: 'ONE_USE_DOWNLOAD',
        action: 'REQUEST_ONE_USE_DOWNLOAD',
        capabilityExpiresAfterSeconds: EXPORT_DOWNLOAD_CAPABILITY_LIFETIME_SECONDS,
        maxByteLength: MAX_EXPORT_DOWNLOAD_BYTES,
      },
    })
  }

  async authorizeDownload(
    authority: ExportDeliveryAuthorityV1,
    request: GetExportDownloadRequest,
  ): Promise<OneUseExportDownloadCapability> {
    const view = await this.get(request.exportId, authority)
    if (view === undefined) throw new ExportDeliveryError('NOT_FOUND', 'The Export does not exist')
    if (view.status !== 'DELIVERED' || view.artifact === null || view.expiresAt === null) {
      throw new ExportDeliveryError('CONFLICT', 'The Export artifact is not available for download')
    }
    if (
      view.artifact.artifactId !== request.artifactId
      || canonicalJson(view.artifact.digest) !== canonicalJson(request.expectedDigest)
    ) {
      throw new ExportDeliveryError('CONFLICT', 'The download request does not match the delivered artifact')
    }
    if (view.artifact.digest.byteLength > MAX_EXPORT_DOWNLOAD_BYTES) {
      throw new ExportDeliveryError('CONFLICT', 'The Export artifact exceeds the bounded browser download limit')
    }
    const issuedAt = this.now()
    const expiresAt = new Date(Math.min(
      Date.parse(view.expiresAt),
      Date.parse(issuedAt) + EXPORT_DOWNLOAD_CAPABILITY_LIFETIME_SECONDS * 1000,
    )).toISOString()
    if (Date.parse(expiresAt) <= Date.parse(issuedAt)) {
      throw new ExportDeliveryError('CAPABILITY_EXPIRED', 'The Export download capability cannot outlive its artifact')
    }
    return new OneUseExportDownloadCapability(
      authority,
      view,
      artifactPath(this.root, request.exportId),
      issuedAt,
      expiresAt,
    )
  }

  async consumeDownload(
    authority: ExportDeliveryAuthorityV1,
    capability: OneUseExportDownloadCapability,
  ): Promise<ExportDownloadV1> {
    const claim = capability.claim(authority, this.now())
    let bytes: Buffer
    try {
      const expectedByteLength = claim.view.artifact?.digest.byteLength
      if (expectedByteLength === undefined) {
        throw new ExportDeliveryError('UNAVAILABLE', 'The delivered Export record lost its artifact')
      }
      bytes = await readBoundedArtifact(claim.artifactFile, expectedByteLength)
    } catch (error) {
      if (error instanceof ExportDeliveryError) throw error
      throw new ExportDeliveryError('UNAVAILABLE', 'The delivered Export artifact is unavailable')
    }
    const artifact = claim.view.artifact
    if (artifact === null) throw new ExportDeliveryError('UNAVAILABLE', 'The delivered Export record lost its artifact')
    const actualDigest = binaryDigest('application/vnd.dsh.security.export+json', bytes)
    if (canonicalJson(actualDigest) !== canonicalJson(artifact.digest)) {
      throw new ExportDeliveryError('UNAVAILABLE', 'The delivered Export artifact failed digest verification')
    }
    if (bytes.byteLength > MAX_EXPORT_DOWNLOAD_BYTES) {
      throw new ExportDeliveryError('CONFLICT', 'The Export artifact exceeds the bounded browser download limit')
    }
    return exportDownloadV1Schema.parse({
      schemaVersion: 1,
      kind: 'DOWNLOAD',
      exportId: claim.view.exportId,
      assessmentId: claim.view.assessmentId,
      assessmentRevision: claim.view.assessmentRevision,
      artifactId: artifact.artifactId,
      fileName: `dsh-security-${claim.view.assessmentId}-${claim.view.exportId.slice(7, 19)}.json`,
      mediaType: 'application/vnd.dsh.security.export+json',
      byteLength: bytes.byteLength,
      digest: actualDigest,
      capability: {
        kind: 'CONSUMED_ONE_USE',
        issuedAt: claim.issuedAt,
        expiresAt: claim.expiresAt,
        consumedAt: claim.consumedAt,
      },
      content: { encoding: 'base64', value: bytes.toString('base64') },
    })
  }

  private replay(
    record: InternalExportRecordV1,
    authority: ExportDeliveryAuthorityV1,
    digest: string,
  ): BeginExportResultV1 {
    if (!ownerMatches(record, authority) || record.requestDigest !== digest) {
      throw new ExportDeliveryError('IDEMPOTENCY_CONFLICT', 'Export idempotency key conflicts with a different request')
    }
    return { record, replayed: true }
  }

  private async fail(record: InternalExportRecordV1): Promise<ExportStatusV1> {
    const updatedAt = this.now()
    const view = exportStatusV1Schema.parse({
      ...record.view,
      status: 'FAILED',
      artifact: null,
      expiresAt: null,
      accessAction: { kind: 'NONE', reason: 'DELIVERY_FAILED' },
      failure: { code: 'ARTIFACT_DELIVERY_FAILED' },
      updatedAt,
    })
    await replaceRecord(this.root, internalExportRecordV1Schema.parse({ ...record, view }))
    return view
  }
}
