import { randomUUID } from 'node:crypto'
import { chmod, mkdir } from 'node:fs/promises'
import { dirname } from 'node:path'
import { DatabaseSync } from 'node:sqlite'
import {
  repositoryCommandReceiptV1Schema,
  repositorySnapshotV1Schema,
  assessmentReceiptV1Schema,
  assessmentResumeReceiptV1Schema,
  assessmentCancellationReceiptV1Schema,
  riskDecisionReceiptV1Schema,
  riskDecisionRecordV1Schema,
} from '../contracts.ts'
import type {
  AssessmentId,
  AssessmentReceiptV1,
  AssessmentResumeReceiptV1,
  AssessmentOperatorReasonV1,
  AssessmentCancellationReceiptV1,
  AssessmentSubjectSourceV1,
  BundleManifestV1,
  DigestEnvelopeV1,
  RepositoryBindingsV1,
  RepositoryCommandReceiptV1,
  RepositoryId,
  RepositoryListSnapshotV1,
  RepositorySnapshotV1,
  RecordRiskDecisionRequest,
  RiskDecisionAuthorizationModeV1,
  RiskDecisionReceiptV1,
  SecurityAssuranceSubmissionV1,
} from '../contracts.ts'
import { canonicalJson, sha256Hex } from './canonical.ts'
import {
  internalAssessmentRecordV1Schema,
} from './assessment-record.ts'
import type { InternalAssessmentRecordV1 } from './assessment-record.ts'
import type {
  DeterministicAssessmentOutcomeV1,
  PreparedAssessmentContractV1,
} from './deterministic-kernel.ts'
import type { EvidencePublicationReceiptV1 } from './evidence-persistence.ts'

const APPLICATION_ID = 0x4453_4853
const SCHEMA_VERSION = 1

export type SecurityPersistenceErrorCode =
  | 'foreign_database'
  | 'unsupported_schema'
  | 'corrupt_database'
  | 'idempotency_conflict'
  | 'repository_conflict'
  | 'repository_not_found'
  | 'assessment_not_found'
  | 'revision_conflict'

export class SecurityPersistenceError extends Error {
  constructor(
    readonly code: SecurityPersistenceErrorCode,
    message: string,
  ) {
    super(message)
    this.name = 'SecurityPersistenceError'
  }
}

export interface RegisterRepositoryPersistenceInput {
  readonly principalId: string
  readonly authorityKind: string
  readonly idempotencyKey: string
  readonly canonicalRequest: unknown
  readonly canonicalRoot: string
  readonly displayName: string
  readonly bindings: RepositoryBindingsV1
}

export interface UpdateRepositoryPersistenceInput {
  readonly principalId: string
  readonly authorityKind: string
  readonly idempotencyKey: string
  readonly canonicalRequest: unknown
  readonly repositoryId: RepositoryId
  readonly expectedRepositoryRevision: number
  readonly displayName?: string
  readonly bindings?: RepositoryBindingsV1
}

export interface DisableRepositoryPersistenceInput {
  readonly principalId: string
  readonly authorityKind: string
  readonly idempotencyKey: string
  readonly canonicalRequest: unknown
  readonly repositoryId: RepositoryId
  readonly expectedRepositoryRevision: number
}

export interface RegisteredRepositoryResolution {
  readonly canonicalRoot: string
  readonly snapshot: RepositorySnapshotV1
}

export interface AssessmentStartPersistenceInput {
  readonly principalId: string
  readonly authorityKind: string
  readonly idempotencyKey: string
  readonly repositoryId: RepositoryId
  readonly expectedRepositoryRevision: number
  readonly canonicalRequest: unknown
  readonly subject: AssessmentSubjectSourceV1
  readonly subjectDigest: DigestEnvelopeV1
  readonly subjectStats: {
    readonly files: number
    readonly bytes: number
    readonly symbolicLinks: number
    readonly submodules: number
  }
  readonly preparedContract: PreparedAssessmentContractV1
}

export interface AssessmentResumePersistenceInput {
  readonly principalId: string
  readonly authorityKind: string
  readonly idempotencyKey: string
  readonly assessmentId: AssessmentId
  readonly expectedAssessmentRevision: number
  readonly reason: AssessmentOperatorReasonV1
  readonly canonicalRequest: unknown
}

export interface AssessmentCancellationPersistenceInput {
  readonly principalId: string
  readonly authorityKind: string
  readonly idempotencyKey: string
  readonly assessmentId: AssessmentId
  readonly expectedAssessmentRevision: number
  readonly reason: AssessmentOperatorReasonV1
  readonly canonicalRequest: unknown
}

export interface SealAssessmentPersistenceInput {
  readonly assessmentId: AssessmentId
  readonly expectedAssessmentRevision: number
  readonly coverage: InternalAssessmentRecordV1['coverage']
  readonly findings: InternalAssessmentRecordV1['findings']
  readonly evaluationTrace: NonNullable<InternalAssessmentRecordV1['evaluationTrace']>
  readonly verdict: NonNullable<InternalAssessmentRecordV1['verdict']>
  readonly seal: NonNullable<InternalAssessmentRecordV1['seal']>
  readonly bundleManifest: BundleManifestV1
  readonly submission: SecurityAssuranceSubmissionV1
  readonly publicationDigest: DigestEnvelopeV1
}

export interface OpenRiskDecisionWindowPersistenceInput {
  readonly assessmentId: AssessmentId
  readonly expectedAssessmentRevision: number
  readonly evaluationInstant: string
  readonly findingRecordIds: readonly string[]
  readonly outcome: DeterministicAssessmentOutcomeV1
  readonly evidenceReceipts: readonly EvidencePublicationReceiptV1[]
}

export interface RecordRiskDecisionPersistenceInput {
  readonly principalId: string
  readonly authorityKind: 'host-operator' | 'control-plane'
  readonly request: RecordRiskDecisionRequest
  readonly canonicalRequest: unknown
  readonly authorizationMode?: RiskDecisionAuthorizationModeV1
}

export interface SecurityPersistenceOptions {
  readonly databasePath: string
  readonly now?: () => string
  readonly nextRepositoryId?: () => RepositoryId
  readonly nextCorrelationId?: () => string
  readonly nextAssessmentId?: () => AssessmentId
  readonly nextRiskDecisionId?: () => string
}

interface IdempotencyRow {
  readonly request_digest: string
  readonly receipt_json: string
}

interface RepositoryRow {
  readonly snapshot_json: string
}

interface AssessmentRow {
  readonly snapshot_json: string
}

export interface AssessmentListKey {
  readonly createdAt: string
  readonly assessmentId: AssessmentId
}

interface AssessmentListIdentityRow {
  readonly assessment_id: AssessmentId
  readonly created_at: string
}

type AssessmentListRow = AssessmentRow & AssessmentListIdentityRow

function digest(value: unknown): string {
  return `sha256:${sha256Hex(canonicalJson(value))}`
}

function integerPragma(db: DatabaseSync, name: string): number {
  const row = db.prepare(`PRAGMA ${name}`).get() as Record<string, unknown> | undefined
  const value = row?.[name]
  if (typeof value !== 'number' || !Number.isSafeInteger(value)) {
    throw new SecurityPersistenceError('corrupt_database', `SQLite ${name} is invalid`)
  }
  return value
}

function verifyIntegrity(db: DatabaseSync): void {
  const row = db.prepare('PRAGMA quick_check').get() as Record<string, unknown> | undefined
  if (row?.quick_check !== 'ok') {
    throw new SecurityPersistenceError('corrupt_database', 'SQLite quick_check failed')
  }
  const foreignKeyFailure = db.prepare('PRAGMA foreign_key_check').get()
  if (foreignKeyFailure !== undefined) {
    throw new SecurityPersistenceError('corrupt_database', 'SQLite foreign_key_check failed')
  }
}

function verifySchema(db: DatabaseSync): void {
  const expected = new Map<string, readonly string[]>([
    ['repositories', [
      'repository_id', 'canonical_root', 'current_revision', 'snapshot_json', 'created_at', 'updated_at',
    ]],
    ['repository_revisions', [
      'repository_id', 'repository_revision', 'snapshot_json', 'committed_at',
    ]],
    ['idempotency_records', [
      'principal_id', 'authority_kind', 'operation', 'target_key', 'idempotency_key',
      'request_digest', 'receipt_json', 'committed_at',
    ]],
    ['assessments', [
      'assessment_id', 'repository_id', 'repository_revision', 'current_revision', 'state',
      'subject_digest', 'snapshot_json', 'created_at', 'updated_at',
    ]],
    ['assessment_revisions', [
      'assessment_id', 'assessment_revision', 'event_kind', 'snapshot_json', 'committed_at',
    ]],
  ])
  const tables = db.prepare(`
    SELECT name FROM sqlite_master
    WHERE type = 'table' AND name NOT LIKE 'sqlite_%'
    ORDER BY name
  `).all() as unknown as readonly { readonly name: string }[]
  if (canonicalJson(tables.map(row => row.name)) !== canonicalJson([...expected.keys()].sort())) {
    throw new SecurityPersistenceError('corrupt_database', 'SQLite table catalog does not match schema')
  }
  for (const [table, columns] of expected) {
    const observed = db.prepare(`PRAGMA table_info('${table}')`).all() as unknown as readonly {
      readonly name: string
    }[]
    if (canonicalJson(observed.map(row => row.name)) !== canonicalJson(columns)) {
      throw new SecurityPersistenceError('corrupt_database', `SQLite table ${table} has invalid columns`)
    }
  }
}

function installSchema(db: DatabaseSync): void {
  db.exec(`
    CREATE TABLE repositories (
      repository_id       TEXT PRIMARY KEY,
      canonical_root      TEXT NOT NULL UNIQUE,
      current_revision    INTEGER NOT NULL,
      snapshot_json       TEXT NOT NULL,
      created_at          TEXT NOT NULL,
      updated_at          TEXT NOT NULL
    ) STRICT;

    CREATE TABLE repository_revisions (
      repository_id       TEXT NOT NULL REFERENCES repositories(repository_id),
      repository_revision INTEGER NOT NULL,
      snapshot_json       TEXT NOT NULL,
      committed_at        TEXT NOT NULL,
      PRIMARY KEY (repository_id, repository_revision)
    ) STRICT;

    CREATE TABLE idempotency_records (
      principal_id        TEXT NOT NULL,
      authority_kind      TEXT NOT NULL,
      operation           TEXT NOT NULL,
      target_key          TEXT NOT NULL,
      idempotency_key     TEXT NOT NULL,
      request_digest      TEXT NOT NULL,
      receipt_json        TEXT NOT NULL,
      committed_at        TEXT NOT NULL,
      PRIMARY KEY (principal_id, authority_kind, operation, target_key, idempotency_key)
    ) STRICT;

    CREATE TABLE assessments (
      assessment_id       TEXT PRIMARY KEY,
      repository_id       TEXT NOT NULL REFERENCES repositories(repository_id),
      repository_revision INTEGER NOT NULL,
      current_revision    INTEGER NOT NULL,
      state               TEXT NOT NULL,
      subject_digest      TEXT NOT NULL,
      snapshot_json       TEXT NOT NULL,
      created_at          TEXT NOT NULL,
      updated_at          TEXT NOT NULL
    ) STRICT;

    CREATE TABLE assessment_revisions (
      assessment_id       TEXT NOT NULL REFERENCES assessments(assessment_id),
      assessment_revision INTEGER NOT NULL,
      event_kind          TEXT NOT NULL,
      snapshot_json       TEXT NOT NULL,
      committed_at        TEXT NOT NULL,
      PRIMARY KEY (assessment_id, assessment_revision)
    ) STRICT;
  `)
  db.exec(`PRAGMA application_id = ${APPLICATION_ID}`)
  db.exec(`PRAGMA user_version = ${SCHEMA_VERSION}`)
}

function openDatabase(path: string): DatabaseSync {
  const db = new DatabaseSync(path)
  try {
    db.exec('PRAGMA foreign_keys = ON')
    const applicationId = integerPragma(db, 'application_id')
    const userVersion = integerPragma(db, 'user_version')
    if (applicationId === 0 && userVersion === 0) {
      const objects = db.prepare(`
        SELECT count(*) AS count
        FROM sqlite_master
        WHERE name NOT LIKE 'sqlite_%'
      `).get() as { readonly count?: unknown } | undefined
      if (objects?.count !== 0) {
        throw new SecurityPersistenceError('foreign_database', 'Unidentified SQLite database is not empty')
      }
      db.exec('BEGIN EXCLUSIVE')
      try {
        installSchema(db)
        db.exec('COMMIT')
      } catch (error) {
        db.exec('ROLLBACK')
        throw error
      }
    } else if (applicationId !== APPLICATION_ID) {
      throw new SecurityPersistenceError('foreign_database', 'SQLite database belongs to another application')
    } else if (userVersion !== SCHEMA_VERSION) {
      throw new SecurityPersistenceError('unsupported_schema', 'SQLite schema version is unsupported')
    }
    verifySchema(db)
    verifyIntegrity(db)
    db.exec('PRAGMA journal_mode = WAL')
    return db
  } catch (error) {
    db.close()
    throw error
  }
}

/** Package-private deep Module owning durable Repository Registry state and idempotency. */
export class SecurityPersistence {
  private closed = false

  constructor(
    private readonly db: DatabaseSync,
    private readonly now: () => string,
    private readonly nextRepositoryId: () => RepositoryId,
    private readonly nextCorrelationId: () => string,
    private readonly nextAssessmentId: () => AssessmentId,
    private readonly nextRiskDecisionId: () => string,
  ) {}

  registerRepository(input: RegisterRepositoryPersistenceInput): RepositoryCommandReceiptV1 {
    this.requireOpen()
    const targetKey = digest({ canonicalRoot: input.canonicalRoot })
    const requestDigest = digest(input.canonicalRequest)
    this.db.exec('BEGIN IMMEDIATE')
    try {
      const replay = this.db.prepare(`
        SELECT request_digest, receipt_json
        FROM idempotency_records
        WHERE principal_id = ? AND authority_kind = ? AND operation = ?
          AND target_key = ? AND idempotency_key = ?
      `).get(
        input.principalId,
        input.authorityKind,
        'register_repository',
        targetKey,
        input.idempotencyKey,
      ) as IdempotencyRow | undefined
      if (replay !== undefined) {
        if (replay.request_digest !== requestDigest) {
          throw new SecurityPersistenceError(
            'idempotency_conflict',
            'Repository registration idempotency key conflicts with a different request',
          )
        }
        const receipt = repositoryCommandReceiptV1Schema.parse(JSON.parse(replay.receipt_json))
        this.db.exec('COMMIT')
        return receipt
      }

      const duplicate = this.db.prepare(`
        SELECT repository_id FROM repositories WHERE canonical_root = ?
      `).get(input.canonicalRoot)
      if (duplicate !== undefined) {
        throw new SecurityPersistenceError('repository_conflict', 'Canonical Repository is already registered')
      }

      const acceptedAt = this.now()
      const repositoryId = this.nextRepositoryId()
      const snapshot = repositorySnapshotV1Schema.parse({
        schemaVersion: 1,
        repositoryId,
        repositoryRevision: 1,
        state: 'ENABLED',
        displayName: input.displayName,
        rootIdentityDigest: targetKey,
        bindings: input.bindings,
        createdAt: acceptedAt,
        updatedAt: acceptedAt,
      })
      const receipt = repositoryCommandReceiptV1Schema.parse({
        schemaVersion: 1,
        operation: 'register_repository',
        repositoryId,
        repositoryRevision: 1,
        idempotencyKey: input.idempotencyKey,
        acceptedState: 'ENABLED',
        acceptedAt,
        correlationId: this.nextCorrelationId(),
      })
      const snapshotJson = canonicalJson(snapshot)
      this.db.prepare(`
        INSERT INTO repositories (
          repository_id, canonical_root, current_revision, snapshot_json, created_at, updated_at
        ) VALUES (?, ?, 1, ?, ?, ?)
      `).run(repositoryId, input.canonicalRoot, snapshotJson, acceptedAt, acceptedAt)
      this.db.prepare(`
        INSERT INTO repository_revisions (
          repository_id, repository_revision, snapshot_json, committed_at
        ) VALUES (?, 1, ?, ?)
      `).run(repositoryId, snapshotJson, acceptedAt)
      this.db.prepare(`
        INSERT INTO idempotency_records (
          principal_id, authority_kind, operation, target_key, idempotency_key,
          request_digest, receipt_json, committed_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        input.principalId,
        input.authorityKind,
        'register_repository',
        targetKey,
        input.idempotencyKey,
        requestDigest,
        canonicalJson(receipt),
        acceptedAt,
      )
      this.db.exec('COMMIT')
      return receipt
    } catch (error) {
      this.db.exec('ROLLBACK')
      throw error
    }
  }

  updateRepository(input: UpdateRepositoryPersistenceInput): RepositoryCommandReceiptV1 {
    this.requireOpen()
    const requestDigest = digest(input.canonicalRequest)
    this.db.exec('BEGIN IMMEDIATE')
    try {
      const replay = this.findReplay(
        input.principalId,
        input.authorityKind,
        'update_repository',
        input.repositoryId,
        input.idempotencyKey,
        requestDigest,
      )
      if (replay !== undefined) {
        this.db.exec('COMMIT')
        return replay
      }
      const current = this.getRepository(input.repositoryId)
      if (current === undefined) {
        throw new SecurityPersistenceError('repository_not_found', 'Repository does not exist')
      }
      if (current.repositoryRevision !== input.expectedRepositoryRevision) {
        throw new SecurityPersistenceError('revision_conflict', 'Repository Revision does not match')
      }
      if (current.state !== 'ENABLED') {
        throw new SecurityPersistenceError('repository_conflict', 'Disabled Repository cannot be updated')
      }
      const acceptedAt = this.now()
      const nextRevision = current.repositoryRevision + 1
      const snapshot = repositorySnapshotV1Schema.parse({
        ...current,
        repositoryRevision: nextRevision,
        displayName: input.displayName ?? current.displayName,
        bindings: input.bindings ?? current.bindings,
        updatedAt: acceptedAt,
      })
      const receipt = repositoryCommandReceiptV1Schema.parse({
        schemaVersion: 1,
        operation: 'update_repository',
        repositoryId: input.repositoryId,
        repositoryRevision: nextRevision,
        idempotencyKey: input.idempotencyKey,
        acceptedState: snapshot.state,
        acceptedAt,
        correlationId: this.nextCorrelationId(),
      })
      this.commitRepositoryRevision(snapshot, acceptedAt)
      this.recordIdempotency(
        input.principalId,
        input.authorityKind,
        'update_repository',
        input.repositoryId,
        input.idempotencyKey,
        requestDigest,
        receipt,
        acceptedAt,
      )
      this.db.exec('COMMIT')
      return receipt
    } catch (error) {
      this.db.exec('ROLLBACK')
      throw error
    }
  }

  disableRepository(input: DisableRepositoryPersistenceInput): RepositoryCommandReceiptV1 {
    this.requireOpen()
    const requestDigest = digest(input.canonicalRequest)
    this.db.exec('BEGIN IMMEDIATE')
    try {
      const replay = this.findReplay(
        input.principalId,
        input.authorityKind,
        'disable_repository',
        input.repositoryId,
        input.idempotencyKey,
        requestDigest,
      )
      if (replay !== undefined) {
        this.db.exec('COMMIT')
        return replay
      }
      const current = this.getRepository(input.repositoryId)
      if (current === undefined) {
        throw new SecurityPersistenceError('repository_not_found', 'Repository does not exist')
      }
      if (current.repositoryRevision !== input.expectedRepositoryRevision) {
        throw new SecurityPersistenceError('revision_conflict', 'Repository Revision does not match')
      }
      if (current.state !== 'ENABLED') {
        throw new SecurityPersistenceError('repository_conflict', 'Repository is already disabled')
      }
      const acceptedAt = this.now()
      const nextRevision = current.repositoryRevision + 1
      const snapshot = repositorySnapshotV1Schema.parse({
        ...current,
        repositoryRevision: nextRevision,
        state: 'DISABLED',
        updatedAt: acceptedAt,
      })
      const receipt = repositoryCommandReceiptV1Schema.parse({
        schemaVersion: 1,
        operation: 'disable_repository',
        repositoryId: input.repositoryId,
        repositoryRevision: nextRevision,
        idempotencyKey: input.idempotencyKey,
        acceptedState: snapshot.state,
        acceptedAt,
        correlationId: this.nextCorrelationId(),
      })
      this.commitRepositoryRevision(snapshot, acceptedAt)
      this.recordIdempotency(
        input.principalId,
        input.authorityKind,
        'disable_repository',
        input.repositoryId,
        input.idempotencyKey,
        requestDigest,
        receipt,
        acceptedAt,
      )
      this.db.exec('COMMIT')
      return receipt
    } catch (error) {
      this.db.exec('ROLLBACK')
      throw error
    }
  }

  getRepository(repositoryId: RepositoryId): RepositorySnapshotV1 | undefined {
    this.requireOpen()
    const row = this.db.prepare(`
      SELECT snapshot_json FROM repositories WHERE repository_id = ?
    `).get(repositoryId) as RepositoryRow | undefined
    return row === undefined
      ? undefined
      : repositorySnapshotV1Schema.parse(JSON.parse(row.snapshot_json))
  }

  resolveRepository(repositoryId: RepositoryId): RegisteredRepositoryResolution | undefined {
    this.requireOpen()
    const row = this.db.prepare(`
      SELECT canonical_root, snapshot_json FROM repositories WHERE repository_id = ?
    `).get(repositoryId) as { readonly canonical_root: string; readonly snapshot_json: string } | undefined
    return row === undefined
      ? undefined
      : {
          canonicalRoot: row.canonical_root,
          snapshot: repositorySnapshotV1Schema.parse(JSON.parse(row.snapshot_json)),
        }
  }

  findAssessmentStartReplay(input: Pick<
    AssessmentStartPersistenceInput,
    'principalId' | 'authorityKind' | 'idempotencyKey' | 'repositoryId' | 'canonicalRequest'
  >): AssessmentReceiptV1 | undefined {
    this.requireOpen()
    const replay = this.db.prepare(`
      SELECT request_digest, receipt_json
      FROM idempotency_records
      WHERE principal_id = ? AND authority_kind = ? AND operation = ?
        AND target_key = ? AND idempotency_key = ?
    `).get(
      input.principalId,
      input.authorityKind,
      'start_assessment',
      input.repositoryId,
      input.idempotencyKey,
    ) as IdempotencyRow | undefined
    if (replay === undefined) return undefined
    if (replay.request_digest !== digest(input.canonicalRequest)) {
      throw new SecurityPersistenceError(
        'idempotency_conflict',
        'Assessment start idempotency key conflicts with a different request',
      )
    }
    return assessmentReceiptV1Schema.parse(JSON.parse(replay.receipt_json))
  }

  /** Package-internal lookup by the stable owning identity, without replaying a mutable request. */
  findAssessmentStartIdentity(input: Pick<
    AssessmentStartPersistenceInput,
    'principalId' | 'authorityKind' | 'idempotencyKey' | 'repositoryId'
  >): AssessmentReceiptV1 | undefined {
    this.requireOpen()
    const replay = this.db.prepare(`
      SELECT receipt_json
      FROM idempotency_records
      WHERE principal_id = ? AND authority_kind = ? AND operation = ?
        AND target_key = ? AND idempotency_key = ?
    `).get(
      input.principalId,
      input.authorityKind,
      'start_assessment',
      input.repositoryId,
      input.idempotencyKey,
    ) as Pick<IdempotencyRow, 'receipt_json'> | undefined
    return replay === undefined
      ? undefined
      : assessmentReceiptV1Schema.parse(JSON.parse(replay.receipt_json))
  }

  createAssessment(input: AssessmentStartPersistenceInput): AssessmentReceiptV1 {
    this.requireOpen()
    const requestDigest = digest(input.canonicalRequest)
    this.db.exec('BEGIN IMMEDIATE')
    try {
      const replay = this.findAssessmentStartReplay(input)
      if (replay !== undefined) {
        this.db.exec('COMMIT')
        return replay
      }
      const repository = this.resolveRepository(input.repositoryId)
      if (repository === undefined) {
        throw new SecurityPersistenceError('repository_not_found', 'Repository does not exist')
      }
      if (
        repository.snapshot.repositoryRevision !== input.expectedRepositoryRevision
        || repository.snapshot.state !== 'ENABLED'
      ) {
        throw new SecurityPersistenceError('revision_conflict', 'Repository changed during Subject Freeze')
      }
      const acceptedAt = this.now()
      const assessmentId = this.nextAssessmentId()
      const receipt = assessmentReceiptV1Schema.parse({
        schemaVersion: 1,
        operation: 'start_assessment',
        assessmentId,
        assessmentRevision: 1,
        state: 'CREATED',
        repositoryId: input.repositoryId,
        repositoryRevision: input.expectedRepositoryRevision,
        subject: {
          kind: input.subject.kind,
          digest: input.subjectDigest,
        },
        idempotencyKey: input.idempotencyKey,
        acceptedAt,
        correlationId: this.nextCorrelationId(),
      })
      const snapshot = internalAssessmentRecordV1Schema.parse({
        schemaVersion: 1,
        assessmentId,
        assessmentRevision: 1,
        state: 'CREATED',
        repository: {
          repositoryId: repository.snapshot.repositoryId,
          repositoryRevision: repository.snapshot.repositoryRevision,
          rootIdentityDigest: repository.snapshot.rootIdentityDigest,
          bindings: repository.snapshot.bindings,
        },
        subject: {
          source: input.subject,
          digest: input.subjectDigest,
          stats: input.subjectStats,
        },
        contract: input.preparedContract,
        coverage: input.preparedContract.coverage,
        findings: [],
        evaluationTrace: null,
        verdict: null,
        seal: null,
        bundleManifest: null,
        submission: null,
        publicationDigest: null,
        failureCode: null,
        riskDecisionWindow: null,
        riskDecisions: [],
        operatorActions: [],
        pendingCancellation: null,
        createdAt: acceptedAt,
        updatedAt: acceptedAt,
      })
      const snapshotJson = canonicalJson(snapshot)
      this.db.prepare(`
        INSERT INTO assessments (
          assessment_id, repository_id, repository_revision, current_revision,
          state, subject_digest, snapshot_json, created_at, updated_at
        ) VALUES (?, ?, ?, 1, 'CREATED', ?, ?, ?, ?)
      `).run(
        assessmentId,
        input.repositoryId,
        input.expectedRepositoryRevision,
        input.subjectDigest.value,
        snapshotJson,
        acceptedAt,
        acceptedAt,
      )
      this.db.prepare(`
        INSERT INTO assessment_revisions (
          assessment_id, assessment_revision, event_kind, snapshot_json, committed_at
        ) VALUES (?, 1, 'assessment_created', ?, ?)
      `).run(assessmentId, snapshotJson, acceptedAt)
      this.recordIdempotency(
        input.principalId,
        input.authorityKind,
        'start_assessment',
        input.repositoryId,
        input.idempotencyKey,
        requestDigest,
        receipt,
        acceptedAt,
      )
      this.db.exec('COMMIT')
      return receipt
    } catch (error) {
      this.db.exec('ROLLBACK')
      throw error
    }
  }

  getAssessmentRecord(assessmentId: AssessmentId): InternalAssessmentRecordV1 | undefined {
    this.requireOpen()
    const row = this.db.prepare(`
      SELECT snapshot_json FROM assessments WHERE assessment_id = ?
    `).get(assessmentId) as AssessmentRow | undefined
    return row === undefined
      ? undefined
      : internalAssessmentRecordV1Schema.parse(JSON.parse(row.snapshot_json))
  }

  getAssessmentListWatermark(): AssessmentListKey | null {
    this.requireOpen()
    const row = this.db.prepare(`
      SELECT assessment_id, created_at
      FROM assessments
      ORDER BY created_at DESC, assessment_id DESC
      LIMIT 1
    `).get() as AssessmentListIdentityRow | undefined
    return row === undefined
      ? null
      : { createdAt: row.created_at, assessmentId: row.assessment_id }
  }

  listAssessmentRecordsPage(input: {
    readonly upperInclusive: AssessmentListKey
    readonly afterExclusive: AssessmentListKey | null
    readonly limit: number
  }): readonly InternalAssessmentRecordV1[] {
    this.requireOpen()
    if (!Number.isSafeInteger(input.limit) || input.limit < 1 || input.limit > 101) {
      throw new SecurityPersistenceError('corrupt_database', 'Assessment page limit is invalid')
    }
    const rows = input.afterExclusive === null
      ? this.db.prepare(`
          SELECT assessment_id, created_at, snapshot_json
          FROM assessments
          WHERE created_at < ? OR (created_at = ? AND assessment_id <= ?)
          ORDER BY created_at DESC, assessment_id DESC
          LIMIT ?
        `).all(
          input.upperInclusive.createdAt,
          input.upperInclusive.createdAt,
          input.upperInclusive.assessmentId,
          input.limit,
        )
      : this.db.prepare(`
          SELECT assessment_id, created_at, snapshot_json
          FROM assessments
          WHERE (created_at < ? OR (created_at = ? AND assessment_id <= ?))
            AND (created_at < ? OR (created_at = ? AND assessment_id < ?))
          ORDER BY created_at DESC, assessment_id DESC
          LIMIT ?
        `).all(
          input.upperInclusive.createdAt,
          input.upperInclusive.createdAt,
          input.upperInclusive.assessmentId,
          input.afterExclusive.createdAt,
          input.afterExclusive.createdAt,
          input.afterExclusive.assessmentId,
          input.limit,
        )
    return (rows as unknown as readonly AssessmentListRow[]).map(row =>
      internalAssessmentRecordV1Schema.parse(JSON.parse(row.snapshot_json)))
  }

  listCreatedAssessmentIds(): readonly AssessmentId[] {
    this.requireOpen()
    const rows = this.db.prepare(`
      SELECT assessment_id FROM assessments WHERE state = 'CREATED' ORDER BY rowid
    `).all() as unknown as readonly { readonly assessment_id: AssessmentId }[]
    return rows.map(row => row.assessment_id)
  }

  /** Persist the durable execution boundary before any evaluation work begins. */
  beginAssessment(assessmentId: AssessmentId): InternalAssessmentRecordV1 | undefined {
    this.requireOpen()
    this.db.exec('BEGIN IMMEDIATE')
    try {
      const current = this.getAssessmentRecord(assessmentId)
      if (current === undefined) {
        throw new SecurityPersistenceError('assessment_not_found', 'Assessment does not exist')
      }
      if (current.state !== 'CREATED') {
        this.db.exec('COMMIT')
        return undefined
      }
      const committedAt = this.now()
      const running = internalAssessmentRecordV1Schema.parse({
        ...current,
        assessmentRevision: current.assessmentRevision + 1,
        state: 'RUNNING',
        updatedAt: committedAt,
      })
      this.commitAssessmentRevision(running, 'assessment_begun', committedAt)
      this.db.exec('COMMIT')
      return running
    } catch (error) {
      this.db.exec('ROLLBACK')
      throw error
    }
  }

  /** Admit one operator-authorized replacement execution without changing Subject or Policy. */
  resumeAssessment(input: AssessmentResumePersistenceInput): AssessmentResumeReceiptV1 {
    this.requireOpen()
    const requestDigest = digest(input.canonicalRequest)
    this.db.exec('BEGIN IMMEDIATE')
    try {
      const replayRow = this.db.prepare(`
        SELECT request_digest, receipt_json
        FROM idempotency_records
        WHERE principal_id = ? AND authority_kind = ? AND operation = ?
          AND target_key = ? AND idempotency_key = ?
      `).get(
        input.principalId,
        input.authorityKind,
        'resume_assessment',
        input.assessmentId,
        input.idempotencyKey,
      ) as IdempotencyRow | undefined
      if (replayRow !== undefined) {
        if (replayRow.request_digest !== requestDigest) {
          throw new SecurityPersistenceError(
            'idempotency_conflict',
            'Assessment resume idempotency key conflicts with a different request',
          )
        }
        const replay = assessmentResumeReceiptV1Schema.parse(JSON.parse(replayRow.receipt_json))
        this.db.exec('COMMIT')
        return replay
      }

      const current = this.getAssessmentRecord(input.assessmentId)
      if (current === undefined) {
        throw new SecurityPersistenceError('assessment_not_found', 'Assessment does not exist')
      }
      if (
        current.state !== 'BLOCKED'
        || current.assessmentRevision !== input.expectedAssessmentRevision
        || current.riskDecisionWindow !== null
      ) {
        throw new SecurityPersistenceError('revision_conflict', 'Assessment is not resumable at this revision')
      }
      const acceptedAt = this.now()
      const resumed = internalAssessmentRecordV1Schema.parse({
        ...current,
        assessmentRevision: current.assessmentRevision + 1,
        state: 'CREATED',
        coverage: current.contract.coverage,
        findings: [],
        evaluationTrace: null,
        verdict: null,
        seal: null,
        bundleManifest: null,
        submission: null,
        publicationDigest: null,
        failureCode: null,
        pendingCancellation: null,
        operatorActions: [
          ...current.operatorActions,
          {
            operation: 'resume_assessment',
            principalId: input.principalId,
            authorityKind: input.authorityKind,
            reason: input.reason,
            recordedAt: acceptedAt,
          },
        ],
        updatedAt: acceptedAt,
      })
      const receipt = assessmentResumeReceiptV1Schema.parse({
        schemaVersion: 1,
        operation: 'resume_assessment',
        assessmentId: resumed.assessmentId,
        assessmentRevision: resumed.assessmentRevision,
        state: 'CREATED',
        idempotencyKey: input.idempotencyKey,
        acceptedAt,
        correlationId: this.nextCorrelationId(),
      })
      this.commitAssessmentRevision(resumed, 'assessment_resume_admitted', acceptedAt)
      this.recordIdempotency(
        input.principalId,
        input.authorityKind,
        'resume_assessment',
        input.assessmentId,
        input.idempotencyKey,
        requestDigest,
        receipt,
        acceptedAt,
      )
      this.db.exec('COMMIT')
      return receipt
    } catch (error) {
      this.db.exec('ROLLBACK')
      throw error
    }
  }

  /** Persist cancellation intent before any process-local execution is interrupted. */
  requestAssessmentCancellation(
    input: AssessmentCancellationPersistenceInput,
  ): AssessmentCancellationReceiptV1 {
    this.requireOpen()
    const requestDigest = digest(input.canonicalRequest)
    this.db.exec('BEGIN IMMEDIATE')
    try {
      const replayRow = this.db.prepare(`
        SELECT request_digest, receipt_json
        FROM idempotency_records
        WHERE principal_id = ? AND authority_kind = ? AND operation = ?
          AND target_key = ? AND idempotency_key = ?
      `).get(
        input.principalId,
        input.authorityKind,
        'cancel_assessment',
        input.assessmentId,
        input.idempotencyKey,
      ) as IdempotencyRow | undefined
      if (replayRow !== undefined) {
        if (replayRow.request_digest !== requestDigest) {
          throw new SecurityPersistenceError(
            'idempotency_conflict',
            'Assessment cancellation idempotency key conflicts with a different request',
          )
        }
        const replay = assessmentCancellationReceiptV1Schema.parse(JSON.parse(replayRow.receipt_json))
        this.db.exec('COMMIT')
        return replay
      }

      const current = this.getAssessmentRecord(input.assessmentId)
      if (current === undefined) {
        throw new SecurityPersistenceError('assessment_not_found', 'Assessment does not exist')
      }
      if (
        (current.state !== 'CREATED' && current.state !== 'RUNNING' && current.state !== 'BLOCKED')
        || current.assessmentRevision !== input.expectedAssessmentRevision
        || current.pendingCancellation !== null
      ) {
        throw new SecurityPersistenceError('revision_conflict', 'Assessment is not cancelable at this revision')
      }
      const acceptedAt = this.now()
      const requestRevision = current.assessmentRevision + 1
      const requested = internalAssessmentRecordV1Schema.parse({
        ...current,
        assessmentRevision: requestRevision,
        operatorActions: [
          ...current.operatorActions,
          {
            operation: 'cancel_assessment',
            principalId: input.principalId,
            authorityKind: input.authorityKind,
            reason: input.reason,
            recordedAt: acceptedAt,
          },
        ],
        pendingCancellation: { requestRevision, requestedAt: acceptedAt },
        updatedAt: acceptedAt,
      })
      const receipt = assessmentCancellationReceiptV1Schema.parse({
        schemaVersion: 1,
        operation: 'cancel_assessment',
        assessmentId: requested.assessmentId,
        assessmentRevision: requestRevision,
        acceptedState: current.state,
        idempotencyKey: input.idempotencyKey,
        acceptedAt,
        correlationId: this.nextCorrelationId(),
      })
      this.commitAssessmentRevision(requested, 'assessment_cancellation_requested', acceptedAt)
      this.recordIdempotency(
        input.principalId,
        input.authorityKind,
        'cancel_assessment',
        input.assessmentId,
        input.idempotencyKey,
        requestDigest,
        receipt,
        acceptedAt,
      )
      this.db.exec('COMMIT')
      return receipt
    } catch (error) {
      this.db.exec('ROLLBACK')
      throw error
    }
  }

  /** Commit CANCELED only after the owning Service has proved process-local quiescence. */
  completeAssessmentCancellation(
    assessmentId: AssessmentId,
    requestRevision: number,
  ): InternalAssessmentRecordV1 {
    this.requireOpen()
    this.db.exec('BEGIN IMMEDIATE')
    try {
      const current = this.getAssessmentRecord(assessmentId)
      if (current === undefined) {
        throw new SecurityPersistenceError('assessment_not_found', 'Assessment does not exist')
      }
      if (
        current.state === 'CANCELED'
        && current.pendingCancellation?.requestRevision === requestRevision
      ) {
        this.db.exec('COMMIT')
        return current
      }
      if (
        current.assessmentRevision !== requestRevision
        || current.pendingCancellation?.requestRevision !== requestRevision
        || current.state === 'SEALED'
        || current.state === 'CANCELED'
      ) {
        throw new SecurityPersistenceError('revision_conflict', 'Assessment cancellation cannot complete')
      }
      const committedAt = this.now()
      const canceled = internalAssessmentRecordV1Schema.parse({
        ...current,
        assessmentRevision: current.assessmentRevision + 1,
        state: 'CANCELED',
        coverage: current.contract.coverage,
        findings: [],
        evaluationTrace: null,
        verdict: null,
        seal: null,
        bundleManifest: null,
        submission: null,
        publicationDigest: null,
        failureCode: null,
        updatedAt: committedAt,
      })
      this.commitAssessmentRevision(canceled, 'assessment_canceled', committedAt)
      this.db.exec('COMMIT')
      return canceled
    } catch (error) {
      this.db.exec('ROLLBACK')
      throw error
    }
  }

  /** Atomically commit Verdict, Seal, Bundle and Submission as one terminal revision. */
  sealAssessment(input: SealAssessmentPersistenceInput): InternalAssessmentRecordV1 {
    this.requireOpen()
    this.db.exec('BEGIN IMMEDIATE')
    try {
      const current = this.getAssessmentRecord(input.assessmentId)
      if (current === undefined) {
        throw new SecurityPersistenceError('assessment_not_found', 'Assessment does not exist')
      }
      if (
        (
          current.state !== 'RUNNING'
          && !(current.state === 'BLOCKED' && current.riskDecisionWindow?.state === 'RESOLVED')
        )
        || current.assessmentRevision !== input.expectedAssessmentRevision
      ) {
        throw new SecurityPersistenceError('revision_conflict', 'Assessment is not sealable at this revision')
      }
      const committedAt = this.now()
      const sealed = internalAssessmentRecordV1Schema.parse({
        ...current,
        assessmentRevision: current.assessmentRevision + 1,
        state: 'SEALED',
        coverage: input.coverage,
        findings: input.findings,
        evaluationTrace: input.evaluationTrace,
        verdict: input.verdict,
        seal: input.seal,
        bundleManifest: input.bundleManifest,
        submission: input.submission,
        publicationDigest: input.publicationDigest,
        failureCode: null,
        updatedAt: committedAt,
      })
      this.commitAssessmentRevision(sealed, 'assessment_sealed', committedAt)
      this.db.exec('COMMIT')
      return sealed
    } catch (error) {
      this.db.exec('ROLLBACK')
      throw error
    }
  }

  /** Persist established Findings and an explicit pre-Seal Risk Decision Window. */
  openRiskDecisionWindow(
    input: OpenRiskDecisionWindowPersistenceInput,
  ): InternalAssessmentRecordV1 {
    this.requireOpen()
    this.db.exec('BEGIN IMMEDIATE')
    try {
      const current = this.getAssessmentRecord(input.assessmentId)
      if (current === undefined) {
        throw new SecurityPersistenceError('assessment_not_found', 'Assessment does not exist')
      }
      if (
        current.state !== 'RUNNING'
        || current.assessmentRevision !== input.expectedAssessmentRevision
        || current.riskDecisionWindow !== null
      ) {
        throw new SecurityPersistenceError('revision_conflict', 'Assessment cannot open a Risk Decision Window')
      }
      const committedAt = this.now()
      const blocked = internalAssessmentRecordV1Schema.parse({
        ...current,
        assessmentRevision: current.assessmentRevision + 1,
        state: 'BLOCKED',
        coverage: input.outcome.coverage,
        findings: input.outcome.findings,
        evaluationTrace: input.outcome.evaluationTrace,
        verdict: null,
        failureCode: 'RISK_DECISION_WINDOW',
        riskDecisionWindow: {
          schemaVersion: 1,
          state: 'OPEN',
          controlId: 'security/risk-decision-window-v1',
          openedAt: committedAt,
          evaluationInstant: input.evaluationInstant,
          proposedVerdict: input.outcome.verdict,
          findingRecordIds: input.findingRecordIds,
          providerComposition: input.outcome.providerComposition,
          evidenceReceipts: input.evidenceReceipts,
          resolvedAt: null,
        },
        updatedAt: committedAt,
      })
      this.commitAssessmentRevision(blocked, 'risk_decision_window_opened', committedAt)
      this.db.exec('COMMIT')
      return blocked
    } catch (error) {
      this.db.exec('ROLLBACK')
      throw error
    }
  }

  /** Resolve an exact authority-scoped idempotent Risk Decision replay without mutation. */
  replayRiskDecision(
    input: RecordRiskDecisionPersistenceInput,
  ): RiskDecisionReceiptV1 | undefined {
    this.requireOpen()
    const requestDigest = digest(input.canonicalRequest)
    const replayRow = this.db.prepare(`
      SELECT request_digest, receipt_json
      FROM idempotency_records
      WHERE principal_id = ? AND authority_kind = ? AND operation = ?
        AND target_key = ? AND idempotency_key = ?
    `).get(
      input.principalId,
      input.authorityKind,
      'record_risk_decision',
      input.request.assessmentId,
      input.request.idempotencyKey,
    ) as IdempotencyRow | undefined
    if (replayRow === undefined) return undefined
    if (replayRow.request_digest !== requestDigest) {
      throw new SecurityPersistenceError(
        'idempotency_conflict',
        'Risk Decision idempotency key conflicts with a different request',
      )
    }
    return riskDecisionReceiptV1Schema.parse(JSON.parse(replayRow.receipt_json))
  }

  /** Append one authority-derived immutable decision at exact Assessment revision. */
  recordRiskDecision(input: RecordRiskDecisionPersistenceInput): RiskDecisionReceiptV1 {
    this.requireOpen()
    const requestDigest = digest(input.canonicalRequest)
    const { request } = input
    this.db.exec('BEGIN IMMEDIATE')
    try {
      const replayRow = this.db.prepare(`
        SELECT request_digest, receipt_json
        FROM idempotency_records
        WHERE principal_id = ? AND authority_kind = ? AND operation = ?
          AND target_key = ? AND idempotency_key = ?
      `).get(
        input.principalId,
        input.authorityKind,
        'record_risk_decision',
        request.assessmentId,
        request.idempotencyKey,
      ) as IdempotencyRow | undefined
      if (replayRow !== undefined) {
        if (replayRow.request_digest !== requestDigest) {
          throw new SecurityPersistenceError(
            'idempotency_conflict',
            'Risk Decision idempotency key conflicts with a different request',
          )
        }
        const replay = riskDecisionReceiptV1Schema.parse(JSON.parse(replayRow.receipt_json))
        this.db.exec('COMMIT')
        return replay
      }
      const current = this.getAssessmentRecord(request.assessmentId)
      const window = current?.riskDecisionWindow
      const existing = current?.riskDecisions.find(
        decision => decision.finding.recordId === request.finding.recordId,
      )
      const completingCriticalDualAuthority = existing !== undefined
        && existing.authorizationMode === 'CRITICAL_DUAL_AUTHORITY'
        && existing.resolution === 'PENDING_DUAL_AUTHORITY'
        && input.authorizationMode === 'CRITICAL_DUAL_AUTHORITY'
      if (
        current === undefined
        || current.state !== 'BLOCKED'
        || current.assessmentRevision !== request.expectedAssessmentRevision
        || current.failureCode !== 'RISK_DECISION_WINDOW'
        || window === undefined
        || window === null
        || window.state !== 'OPEN'
        || !window.findingRecordIds.includes(request.finding.recordId)
        || request.finding.recordRevision !== 1
        || (existing !== undefined && !completingCriticalDualAuthority)
        || input.authorizationMode === undefined
        || (
          input.authorizationMode === 'CRITICAL_DUAL_AUTHORITY'
          && (
            input.authorityKind !== 'host-operator'
            || !current.contract.requestedStrongerControlIds.includes('security/critical-break-glass-v1')
          )
        )
      ) {
        throw new SecurityPersistenceError('revision_conflict', 'Risk Decision Window does not admit this decision')
      }
      const recordedAt = this.now()
      const decisionMaker = {
        kind: input.authorityKind,
        principalId: input.principalId,
      }
      const decision = completingCriticalDualAuthority
        ? (() => {
            if (
              existing.decision !== 'ACCEPT'
              || request.decision !== 'ACCEPT'
              || existing.decisionMaker.principalId === input.principalId
              || existing.rationale !== request.rationale
              || canonicalJson(existing.compensatingControls) !== canonicalJson(request.compensatingControls)
              || existing.expiresAt !== request.expiresAt
              || existing.expiresAt === null
              || Date.parse(existing.expiresAt) <= Date.parse(recordedAt)
              || canonicalJson(existing.finding) !== canonicalJson(request.finding)
            ) {
              throw new SecurityPersistenceError(
                'revision_conflict',
                'Critical Dual Authority attestation does not independently match',
              )
            }
            return riskDecisionRecordV1Schema.parse({
              ...existing,
              resolution: 'ACCEPTED',
              attestations: [
                ...(existing.attestations ?? []),
                {
                  sequence: 2,
                  decisionMaker,
                  authorizationEvidence: {
                    permission: 'risk:break-glass',
                    invocationClass: 'independently-authenticated',
                  },
                  attestedAt: recordedAt,
                },
              ],
            })
          })()
        : riskDecisionRecordV1Schema.parse({
            schemaVersion: 1,
            decisionId: this.nextRiskDecisionId(),
            assessmentId: request.assessmentId,
            finding: request.finding,
            decision: request.decision,
            resolution: request.decision === 'DENY'
              ? 'DENIED'
              : input.authorizationMode === 'CRITICAL_DUAL_AUTHORITY'
                ? 'PENDING_DUAL_AUTHORITY'
                : 'ACCEPTED',
            authorizationMode: input.authorizationMode,
            rationale: request.rationale,
            compensatingControls: request.compensatingControls,
            expiresAt: request.expiresAt,
            decisionMaker,
            scope: {
              subjectDigest: current.subject.digest,
              policyDigest: current.contract.policy.digest,
            },
            attestations: input.authorizationMode === 'CRITICAL_DUAL_AUTHORITY'
              ? [{
                  sequence: 1,
                  decisionMaker,
                  authorizationEvidence: {
                    permission: 'risk:break-glass',
                    invocationClass: 'independently-authenticated',
                  },
                  attestedAt: recordedAt,
                }]
              : [],
            recordedAt,
          })
      const decisions = completingCriticalDualAuthority
        ? current.riskDecisions.map(candidate => (
            candidate.decisionId === decision.decisionId ? decision : candidate
          ))
        : [...current.riskDecisions, decision]
      const resolved = window.findingRecordIds.every(recordId => (
        decisions.some(candidate => (
          candidate.finding.recordId === recordId
          && candidate.resolution !== 'PENDING_DUAL_AUTHORITY'
        ))
      ))
      const updated = internalAssessmentRecordV1Schema.parse({
        ...current,
        assessmentRevision: current.assessmentRevision + 1,
        riskDecisions: decisions,
        riskDecisionWindow: {
          ...window,
          state: resolved ? 'RESOLVED' : 'OPEN',
          resolvedAt: resolved ? recordedAt : null,
        },
        updatedAt: recordedAt,
      })
      const receipt = riskDecisionReceiptV1Schema.parse({
        schemaVersion: 1,
        operation: 'record_risk_decision',
        assessmentId: request.assessmentId,
        assessmentRevision: updated.assessmentRevision,
        acceptedState: 'BLOCKED',
        decisionId: decision.decisionId,
        finding: decision.finding,
        decision: decision.decision,
        resolution: decision.resolution,
        idempotencyKey: request.idempotencyKey,
        recordedAt,
        correlationId: this.nextCorrelationId(),
      })
      this.commitAssessmentRevision(updated, 'risk_decision_recorded', recordedAt)
      this.recordIdempotency(
        input.principalId,
        input.authorityKind,
        'record_risk_decision',
        request.assessmentId,
        request.idempotencyKey,
        requestDigest,
        receipt,
        recordedAt,
      )
      this.db.exec('COMMIT')
      return receipt
    } catch (error) {
      this.db.exec('ROLLBACK')
      throw error
    }
  }

  blockAssessment(
    assessmentId: AssessmentId,
    expectedAssessmentRevision: number,
    failureCode: string,
  ): InternalAssessmentRecordV1 | undefined {
    this.requireOpen()
    this.db.exec('BEGIN IMMEDIATE')
    try {
      const current = this.getAssessmentRecord(assessmentId)
      if (
        current === undefined
        || current.state !== 'RUNNING'
        || current.assessmentRevision !== expectedAssessmentRevision
      ) {
        this.db.exec('COMMIT')
        return undefined
      }
      const committedAt = this.now()
      const blocked = internalAssessmentRecordV1Schema.parse({
        ...current,
        assessmentRevision: current.assessmentRevision + 1,
        state: 'BLOCKED',
        failureCode,
        updatedAt: committedAt,
      })
      this.commitAssessmentRevision(blocked, 'assessment_blocked', committedAt)
      this.db.exec('COMMIT')
      return blocked
    } catch (error) {
      this.db.exec('ROLLBACK')
      throw error
    }
  }

  /** A process restart never silently replays evaluation that had durably begun. */
  recoverInterruptedAssessments(): readonly AssessmentId[] {
    this.requireOpen()
    const cancellationRows = this.db.prepare(`
      SELECT snapshot_json FROM assessments
      WHERE state NOT IN ('SEALED', 'CANCELED') ORDER BY rowid
    `).all() as unknown as readonly AssessmentRow[]
    for (const row of cancellationRows) {
      const record = internalAssessmentRecordV1Schema.parse(JSON.parse(row.snapshot_json))
      if (record.pendingCancellation !== null) {
        this.completeAssessmentCancellation(record.assessmentId, record.pendingCancellation.requestRevision)
      }
    }
    const rows = this.db.prepare(`
      SELECT assessment_id, current_revision
      FROM assessments WHERE state = 'RUNNING' ORDER BY rowid
    `).all() as unknown as readonly {
      readonly assessment_id: AssessmentId
      readonly current_revision: number
    }[]
    for (const row of rows) {
      this.blockAssessment(row.assessment_id, row.current_revision, 'HOST_RESTART_DURING_EVALUATION')
    }
    return rows.map(row => row.assessment_id)
  }

  listRepositories(limit: number, state?: RepositorySnapshotV1['state']): RepositoryListSnapshotV1 {
    this.requireOpen()
    const rows = state === undefined
      ? this.db.prepare(`
          SELECT snapshot_json FROM repositories ORDER BY rowid LIMIT ?
        `).all(limit + 1) as unknown as readonly RepositoryRow[]
      : this.db.prepare(`
          SELECT snapshot_json FROM repositories
          WHERE json_extract(snapshot_json, '$.state') = ?
          ORDER BY rowid LIMIT ?
        `).all(state, limit + 1) as unknown as readonly RepositoryRow[]
    return {
      schemaVersion: 1,
      repositories: rows.slice(0, limit).map(row => (
        repositorySnapshotV1Schema.parse(JSON.parse(row.snapshot_json))
      )),
      truncated: rows.length > limit,
    }
  }

  close(): void {
    if (this.closed) return
    this.closed = true
    this.db.close()
  }

  private requireOpen(): void {
    if (this.closed) throw new SecurityPersistenceError('corrupt_database', 'Security Persistence is closed')
  }

  private findReplay(
    principalId: string,
    authorityKind: string,
    operation: string,
    targetKey: string,
    idempotencyKey: string,
    requestDigest: string,
  ): RepositoryCommandReceiptV1 | undefined {
    const replay = this.db.prepare(`
      SELECT request_digest, receipt_json
      FROM idempotency_records
      WHERE principal_id = ? AND authority_kind = ? AND operation = ?
        AND target_key = ? AND idempotency_key = ?
    `).get(principalId, authorityKind, operation, targetKey, idempotencyKey) as IdempotencyRow | undefined
    if (replay === undefined) return undefined
    if (replay.request_digest !== requestDigest) {
      throw new SecurityPersistenceError(
        'idempotency_conflict',
        'Idempotency key conflicts with a different request',
      )
    }
    return repositoryCommandReceiptV1Schema.parse(JSON.parse(replay.receipt_json))
  }

  private commitRepositoryRevision(snapshot: RepositorySnapshotV1, committedAt: string): void {
    const snapshotJson = canonicalJson(snapshot)
    this.db.prepare(`
      UPDATE repositories
      SET current_revision = ?, snapshot_json = ?, updated_at = ?
      WHERE repository_id = ?
    `).run(snapshot.repositoryRevision, snapshotJson, committedAt, snapshot.repositoryId)
    this.db.prepare(`
      INSERT INTO repository_revisions (
        repository_id, repository_revision, snapshot_json, committed_at
      ) VALUES (?, ?, ?, ?)
    `).run(snapshot.repositoryId, snapshot.repositoryRevision, snapshotJson, committedAt)
  }

  private commitAssessmentRevision(
    snapshot: InternalAssessmentRecordV1,
    eventKind: string,
    committedAt: string,
  ): void {
    const snapshotJson = canonicalJson(snapshot)
    const changed = this.db.prepare(`
      UPDATE assessments
      SET current_revision = ?, state = ?, snapshot_json = ?, updated_at = ?
      WHERE assessment_id = ?
    `).run(
      snapshot.assessmentRevision,
      snapshot.state,
      snapshotJson,
      committedAt,
      snapshot.assessmentId,
    )
    if (changed.changes !== 1) {
      throw new SecurityPersistenceError('assessment_not_found', 'Assessment does not exist')
    }
    this.db.prepare(`
      INSERT INTO assessment_revisions (
        assessment_id, assessment_revision, event_kind, snapshot_json, committed_at
      ) VALUES (?, ?, ?, ?, ?)
    `).run(snapshot.assessmentId, snapshot.assessmentRevision, eventKind, snapshotJson, committedAt)
  }

  private recordIdempotency(
    principalId: string,
    authorityKind: string,
    operation: string,
    targetKey: string,
    idempotencyKey: string,
    requestDigest: string,
    receipt: unknown,
    committedAt: string,
  ): void {
    this.db.prepare(`
      INSERT INTO idempotency_records (
        principal_id, authority_kind, operation, target_key, idempotency_key,
        request_digest, receipt_json, committed_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      principalId,
      authorityKind,
      operation,
      targetKey,
      idempotencyKey,
      requestDigest,
      canonicalJson(receipt),
      committedAt,
    )
  }
}

export async function openSecurityPersistence(
  options: SecurityPersistenceOptions,
): Promise<SecurityPersistence> {
  await mkdir(dirname(options.databasePath), { recursive: true, mode: 0o700 })
  const database = openDatabase(options.databasePath)
  try {
    await chmod(options.databasePath, 0o600)
  } catch (error) {
    database.close()
    throw error
  }
  return new SecurityPersistence(
    database,
    options.now ?? (() => new Date().toISOString()),
    options.nextRepositoryId ?? (() => `repo-${randomUUID()}` as RepositoryId),
    options.nextCorrelationId ?? (() => `sec-${randomUUID()}`),
    options.nextAssessmentId ?? (() => `asm-${randomUUID()}` as AssessmentId),
    options.nextRiskDecisionId ?? (() => `risk-decision-${randomUUID()}`),
  )
}
