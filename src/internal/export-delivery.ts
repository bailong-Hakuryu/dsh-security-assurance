import { randomUUID } from 'node:crypto'
import {
  chmod,
  mkdir,
  readFile,
  rename,
  rm,
  writeFile,
} from 'node:fs/promises'
import { join } from 'node:path'
import { z } from 'zod'
import {
  exportDestinationViewV1Schema,
  exportIdSchema,
  exportProfileViewV1Schema,
  exportRequestReceiptV1Schema,
  exportStatusV1Schema,
  INTERNAL_JSON_EXPORT_PROFILE_ID,
  LOCAL_AUDIT_DELIVERY_DESTINATION_ID,
} from '../contracts.ts'
import type {
  ExportDestinationViewV1,
  ExportId,
  ExportPreviewV1,
  ExportProfileViewV1,
  ExportStatusV1,
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
    readonly code: 'IDEMPOTENCY_CONFLICT' | 'NOT_FOUND' | 'UNAVAILABLE',
    message: string,
  ) {
    super(message)
    this.name = 'ExportDeliveryError'
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
      'Browser download requires a separate short-lived Host capability and is not included in this delivery action.',
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
