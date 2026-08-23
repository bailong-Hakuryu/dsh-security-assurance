import { randomUUID } from 'node:crypto'
import { chmod, mkdir } from 'node:fs/promises'
import { dirname } from 'node:path'
import { DatabaseSync } from 'node:sqlite'
import {
  repositoryCommandReceiptV1Schema,
  repositorySnapshotV1Schema,
  assessmentReceiptV1Schema,
} from '../contracts.ts'
import type {
  AssessmentId,
  AssessmentReceiptV1,
  AssessmentSubjectSourceV1,
  AssessmentTargetSelectorV1,
  DigestEnvelopeV1,
  RepositoryBindingsV1,
  RepositoryCommandReceiptV1,
  RepositoryId,
  RepositoryListSnapshotV1,
  RepositorySnapshotV1,
} from '../contracts.ts'
import { canonicalJson, sha256Hex } from './canonical.ts'

const APPLICATION_ID = 0x4453_4853
const SCHEMA_VERSION = 1

export type SecurityPersistenceErrorCode =
  | 'foreign_database'
  | 'unsupported_schema'
  | 'corrupt_database'
  | 'idempotency_conflict'
  | 'repository_conflict'
  | 'repository_not_found'
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
  readonly canonicalRoot: string
  readonly displayName: string
  readonly bindings: RepositoryBindingsV1
}

export interface UpdateRepositoryPersistenceInput {
  readonly principalId: string
  readonly authorityKind: string
  readonly idempotencyKey: string
  readonly repositoryId: RepositoryId
  readonly expectedRepositoryRevision: number
  readonly displayName?: string
  readonly bindings?: RepositoryBindingsV1
}

export interface DisableRepositoryPersistenceInput {
  readonly principalId: string
  readonly authorityKind: string
  readonly idempotencyKey: string
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
  readonly assessmentMode: 'REPOSITORY' | 'CHANGE' | 'TARGETED'
  readonly assessmentProfileId: string
  readonly target: AssessmentTargetSelectorV1
  readonly requestedStrongerControlIds: readonly string[]
}

export interface SecurityPersistenceOptions {
  readonly databasePath: string
  readonly now?: () => string
  readonly nextRepositoryId?: () => RepositoryId
  readonly nextCorrelationId?: () => string
  readonly nextAssessmentId?: () => AssessmentId
}

interface IdempotencyRow {
  readonly request_digest: string
  readonly receipt_json: string
}

interface RepositoryRow {
  readonly snapshot_json: string
}

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
  ) {}

  registerRepository(input: RegisterRepositoryPersistenceInput): RepositoryCommandReceiptV1 {
    this.requireOpen()
    const targetKey = digest({ canonicalRoot: input.canonicalRoot })
    const requestDigest = digest({
      canonicalRoot: input.canonicalRoot,
      displayName: input.displayName,
      bindings: input.bindings,
    })
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
    const requestDigest = digest({
      expectedRepositoryRevision: input.expectedRepositoryRevision,
      ...input.displayName === undefined ? {} : { displayName: input.displayName },
      ...input.bindings === undefined ? {} : { bindings: input.bindings },
    })
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
    const requestDigest = digest({ expectedRepositoryRevision: input.expectedRepositoryRevision })
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
      const snapshot = {
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
        contract: {
          assessmentMode: input.assessmentMode,
          assessmentProfileId: input.assessmentProfileId,
          target: input.target,
          requestedStrongerControlIds: input.requestedStrongerControlIds,
        },
        createdAt: acceptedAt,
        updatedAt: acceptedAt,
      }
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
  )
}
