import { randomUUID } from 'node:crypto'
import { chmod, mkdir, rename, unlink } from 'node:fs/promises'
import { basename, dirname, join } from 'node:path'
import { backup, DatabaseSync } from 'node:sqlite'
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
import type { RoleContextGrantV1 } from '../role-context-grant.ts'
import type {
  ModelInvocationRecordBindingsV1,
  ModelInvocationRecordV1,
} from './model-invocation-settlement.ts'
import { parseModelInvocationRecordV1 } from './model-invocation-settlement.ts'
import type {
  ModelInvocationEvidenceLinkV1,
  ModelInvocationEvidencePublicationReceiptV1,
} from './model-invocation-evidence.ts'
import {
  createModelInvocationEvidenceLinkV1,
  parseModelInvocationEvidenceLinkV1,
} from './model-invocation-evidence.ts'
import type {
  CompleteRoleAttemptValuesV1,
  RoleAttemptRecordV1,
  RoleAttemptStartBindingsV1,
} from './role-attempt.ts'
import {
  completeRoleAttemptV1,
  createRunningRoleAttemptV1,
  parseRoleAttemptRecordV1,
  projectRoleAttemptCardV1,
} from './role-attempt.ts'

const APPLICATION_ID = 0x4453_4853
const SCHEMA_VERSION = 3

export type SecurityPersistenceErrorCode =
  | 'foreign_database'
  | 'unsupported_schema'
  | 'corrupt_database'
  | 'idempotency_conflict'
  | 'repository_conflict'
  | 'repository_not_found'
  | 'assessment_not_found'
  | 'model_invocation_conflict'
  | 'role_attempt_conflict'
  | 'role_attempt_not_found'
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

export interface LinkModelInvocationEvidencePersistenceInput {
  readonly contextGrant: RoleContextGrantV1
  readonly expectedAssessmentRevision: number
  readonly receipt: ModelInvocationEvidencePublicationReceiptV1
  readonly record: ModelInvocationRecordV1
  readonly expected: ModelInvocationRecordBindingsV1
}

export interface StartRoleAttemptPersistenceInput extends RoleAttemptStartBindingsV1 {
  readonly contextGrant: RoleContextGrantV1
  readonly expectedAssessmentRevision: number
}

export interface CompleteRoleAttemptPersistenceInput extends CompleteRoleAttemptValuesV1 {
  readonly assessmentId: AssessmentId
  readonly attemptId: string
  readonly generation: number
  readonly fenceDigest: DigestEnvelopeV1
  readonly expectedAssessmentRevision: number
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

interface ModelInvocationEvidenceLinkRow {
  readonly assessment_id: AssessmentId
  readonly invocation_id: string
  readonly assessment_revision: number
  readonly attempt_id: string
  readonly attempt_generation: number
  readonly attempt_fence_digest: string
  readonly context_grant_digest: string
  readonly artifact_id: string
  readonly evidence_schema_id: string
  readonly evidence_digest: string
  readonly record_digest: string
  readonly publication_receipt_digest: string
  readonly link_json: string
  readonly committed_at: string
}

interface SchemaMigrationRow {
  readonly target_version: number
  readonly source_version: number
  readonly backup_name: string
  readonly source_state_digest: string
  readonly result_digest: string
  readonly committed_at: string
}

interface RoleAttemptRow {
  readonly assessment_id: AssessmentId
  readonly attempt_id: string
  readonly generation: number
  readonly assessment_revision: number
  readonly state: RoleAttemptRecordV1['lifecycleState']
  readonly fence_digest: string
  readonly context_grant_digest: string
  readonly record_digest: string
  readonly record_json: string
  readonly created_at: string
  readonly updated_at: string
}

function sameRoleAttemptStart(
  current: RoleAttemptRecordV1,
  expected: RoleAttemptRecordV1,
): boolean {
  return canonicalJson({
    assessmentId: current.assessmentId,
    attemptId: current.attemptId,
    parentAttemptId: current.parentAttemptId,
    generation: current.generation,
    fenceDigest: current.fenceDigest,
    contextGrantDigest: current.contextGrantDigest,
    roleDefinition: current.roleDefinition,
    provider: current.provider,
    prompt: current.prompt,
    requestLimit: current.budget.requestLimit,
    tokenLimit: current.budget.tokenLimit,
    startedAt: current.startedAt,
  }) === canonicalJson({
    assessmentId: expected.assessmentId,
    attemptId: expected.attemptId,
    parentAttemptId: expected.parentAttemptId,
    generation: expected.generation,
    fenceDigest: expected.fenceDigest,
    contextGrantDigest: expected.contextGrantDigest,
    roleDefinition: expected.roleDefinition,
    provider: expected.provider,
    prompt: expected.prompt,
    requestLimit: expected.budget.requestLimit,
    tokenLimit: expected.budget.tokenLimit,
    startedAt: expected.startedAt,
  })
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

function verifySchema(db: DatabaseSync, schemaVersion = SCHEMA_VERSION): void {
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
  if (schemaVersion >= 2) {
    expected.set('schema_migrations', [
      'target_version', 'source_version', 'backup_name', 'source_state_digest',
      'result_digest', 'committed_at',
    ])
    expected.set('model_invocation_evidence_links', [
      'assessment_id', 'invocation_id', 'assessment_revision', 'attempt_id',
      'attempt_generation', 'attempt_fence_digest', 'context_grant_digest',
      'artifact_id', 'evidence_schema_id', 'evidence_digest', 'record_digest',
      'publication_receipt_digest', 'link_json', 'committed_at',
    ])
  }
  if (schemaVersion >= 3) {
    expected.set('role_attempts', [
      'assessment_id', 'attempt_id', 'generation', 'assessment_revision', 'state',
      'fence_digest', 'context_grant_digest', 'record_digest', 'record_json',
      'created_at', 'updated_at',
    ])
  }
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
      readonly notnull: number
      readonly pk: number
    }[]
    if (canonicalJson(observed.map(row => row.name)) !== canonicalJson(columns)) {
      throw new SecurityPersistenceError('corrupt_database', `SQLite table ${table} has invalid columns`)
    }
    if (observed.some(row => row.notnull !== 1)) {
      throw new SecurityPersistenceError('corrupt_database', `SQLite table ${table} has nullable columns`)
    }
  }

  const tableList = db.prepare(`
    SELECT name, strict FROM pragma_table_list
    WHERE name NOT LIKE 'sqlite_%'
  `).all() as unknown as readonly { readonly name: string; readonly strict: number }[]
  if (tableList.some(row => row.strict !== 1)) {
    throw new SecurityPersistenceError('corrupt_database', 'SQLite tables are not STRICT')
  }
  const primaryKeys = new Map<string, readonly string[]>([
    ['repositories', ['repository_id']],
    ['repository_revisions', ['repository_id', 'repository_revision']],
    ['idempotency_records', ['principal_id', 'authority_kind', 'operation', 'target_key', 'idempotency_key']],
    ['assessments', ['assessment_id']],
    ['assessment_revisions', ['assessment_id', 'assessment_revision']],
  ])
  if (schemaVersion >= 2) {
    primaryKeys.set('schema_migrations', ['target_version'])
    primaryKeys.set('model_invocation_evidence_links', ['assessment_id', 'invocation_id'])
  }
  if (schemaVersion >= 3) {
    primaryKeys.set('role_attempts', ['assessment_id', 'attempt_id', 'generation'])
  }
  for (const [table, columns] of primaryKeys) {
    const observed = db.prepare(`PRAGMA table_info('${table}')`).all() as unknown as readonly {
      readonly name: string
      readonly pk: number
    }[]
    const actual = [...observed]
      .filter(row => row.pk > 0)
      .sort((left, right) => left.pk - right.pk)
      .map(row => row.name)
    if (canonicalJson(actual) !== canonicalJson(columns)) {
      throw new SecurityPersistenceError('corrupt_database', `SQLite table ${table} has invalid primary key`)
    }
  }
  const repositoryIndexes = db.prepare("PRAGMA index_list('repositories')").all() as unknown as readonly {
    readonly name: string
    readonly unique: number
  }[]
  const hasCanonicalRootUnique = repositoryIndexes
    .filter(index => index.unique === 1)
    .some(index => {
      const columns = db.prepare(`PRAGMA index_info('${index.name}')`).all() as unknown as readonly { readonly name: string }[]
      return columns.length === 1 && columns[0]?.name === 'canonical_root'
    })
  if (!hasCanonicalRootUnique) {
    throw new SecurityPersistenceError('corrupt_database', 'Repository canonical_root uniqueness constraint is missing')
  }
  const foreignKeys = new Map<string, readonly [string, string, string][]>([
    ['repository_revisions', [['repository_id', 'repositories', 'repository_id']]],
    ['assessments', [['repository_id', 'repositories', 'repository_id']]],
    ['assessment_revisions', [['assessment_id', 'assessments', 'assessment_id']]],
  ])
  if (schemaVersion >= 2) {
    foreignKeys.set('model_invocation_evidence_links', [
      ['assessment_id', 'assessment_revisions', 'assessment_id'],
      ['assessment_revision', 'assessment_revisions', 'assessment_revision'],
    ])
  }
  if (schemaVersion >= 3) {
    foreignKeys.set('role_attempts', [
      ['assessment_id', 'assessment_revisions', 'assessment_id'],
      ['assessment_revision', 'assessment_revisions', 'assessment_revision'],
    ])
    foreignKeys.set('model_invocation_evidence_links', [
      ['assessment_id', 'assessment_revisions', 'assessment_id'],
      ['assessment_revision', 'assessment_revisions', 'assessment_revision'],
      ['assessment_id', 'role_attempts', 'assessment_id'],
      ['attempt_id', 'role_attempts', 'attempt_id'],
      ['attempt_generation', 'role_attempts', 'generation'],
    ])
  }
  for (const [table, expectedForeignKeys] of foreignKeys) {
    const observed = db.prepare(`PRAGMA foreign_key_list('${table}')`).all() as unknown as readonly {
      readonly from: string
      readonly table: string
      readonly to: string
    }[]
    const actual = observed
      .map(row => [row.from, row.table, row.to] as const)
      .sort((left, right) => canonicalJson(left).localeCompare(canonicalJson(right)))
    const expectedSorted = [...expectedForeignKeys]
      .sort((left, right) => canonicalJson(left).localeCompare(canonicalJson(right)))
    if (canonicalJson(actual) !== canonicalJson(expectedSorted)) {
      throw new SecurityPersistenceError('corrupt_database', `SQLite table ${table} has invalid foreign keys`)
    }
  }
}

function installSchemaV2Objects(db: DatabaseSync): void {
  db.exec(`
    CREATE TABLE schema_migrations (
      target_version INTEGER NOT NULL PRIMARY KEY,
      source_version INTEGER NOT NULL,
      backup_name    TEXT NOT NULL,
      source_state_digest TEXT NOT NULL,
      result_digest  TEXT NOT NULL,
      committed_at   TEXT NOT NULL
    ) STRICT;

    CREATE TABLE model_invocation_evidence_links (
      assessment_id              TEXT NOT NULL,
      invocation_id              TEXT NOT NULL,
      assessment_revision        INTEGER NOT NULL,
      attempt_id                 TEXT NOT NULL,
      attempt_generation         INTEGER NOT NULL CHECK (attempt_generation > 0),
      attempt_fence_digest       TEXT NOT NULL,
      context_grant_digest       TEXT NOT NULL,
      artifact_id                TEXT NOT NULL,
      evidence_schema_id         TEXT NOT NULL,
      evidence_digest            TEXT NOT NULL,
      record_digest              TEXT NOT NULL,
      publication_receipt_digest TEXT NOT NULL,
      link_json                  TEXT NOT NULL,
      committed_at               TEXT NOT NULL,
      PRIMARY KEY (assessment_id, invocation_id),
      FOREIGN KEY (assessment_id, assessment_revision)
        REFERENCES assessment_revisions(assessment_id, assessment_revision)
    ) STRICT;
  `)
}

function installSchemaV3Objects(db: DatabaseSync): void {
  db.exec(`
    CREATE TABLE role_attempts (
      assessment_id       TEXT NOT NULL,
      attempt_id          TEXT NOT NULL,
      generation          INTEGER NOT NULL CHECK (generation > 0),
      assessment_revision INTEGER NOT NULL,
      state               TEXT NOT NULL,
      fence_digest        TEXT NOT NULL,
      context_grant_digest TEXT NOT NULL,
      record_digest       TEXT NOT NULL,
      record_json         TEXT NOT NULL,
      created_at          TEXT NOT NULL,
      updated_at          TEXT NOT NULL,
      PRIMARY KEY (assessment_id, attempt_id, generation),
      UNIQUE (assessment_id, attempt_id),
      FOREIGN KEY (assessment_id, assessment_revision)
        REFERENCES assessment_revisions(assessment_id, assessment_revision)
    ) STRICT;

    ALTER TABLE model_invocation_evidence_links
      RENAME TO model_invocation_evidence_links_v2;

    CREATE TABLE model_invocation_evidence_links (
      assessment_id              TEXT NOT NULL,
      invocation_id              TEXT NOT NULL,
      assessment_revision        INTEGER NOT NULL,
      attempt_id                 TEXT NOT NULL,
      attempt_generation         INTEGER NOT NULL CHECK (attempt_generation > 0),
      attempt_fence_digest       TEXT NOT NULL,
      context_grant_digest       TEXT NOT NULL,
      artifact_id                TEXT NOT NULL,
      evidence_schema_id         TEXT NOT NULL,
      evidence_digest            TEXT NOT NULL,
      record_digest              TEXT NOT NULL,
      publication_receipt_digest TEXT NOT NULL,
      link_json                  TEXT NOT NULL,
      committed_at               TEXT NOT NULL,
      PRIMARY KEY (assessment_id, invocation_id),
      FOREIGN KEY (assessment_id, assessment_revision)
        REFERENCES assessment_revisions(assessment_id, assessment_revision),
      FOREIGN KEY (assessment_id, attempt_id, attempt_generation)
        REFERENCES role_attempts(assessment_id, attempt_id, generation)
    ) STRICT;

    INSERT INTO model_invocation_evidence_links
      SELECT * FROM model_invocation_evidence_links_v2;

    DROP TABLE model_invocation_evidence_links_v2;
  `)
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
  installSchemaV2Objects(db)
  installSchemaV3Objects(db)
  db.exec(`PRAGMA application_id = ${APPLICATION_ID}`)
  db.exec(`PRAGMA user_version = ${SCHEMA_VERSION}`)
}

function schemaStateDigest(db: DatabaseSync, schemaVersion: number): string {
  const queries: [string, string][] = [
    ['repositories', 'SELECT * FROM repositories ORDER BY repository_id'],
    ['repository_revisions', `
      SELECT * FROM repository_revisions ORDER BY repository_id, repository_revision
    `],
    ['idempotency_records', `
      SELECT * FROM idempotency_records
      ORDER BY principal_id, authority_kind, operation, target_key, idempotency_key
    `],
    ['assessments', 'SELECT * FROM assessments ORDER BY assessment_id'],
    ['assessment_revisions', `
      SELECT * FROM assessment_revisions ORDER BY assessment_id, assessment_revision
    `],
  ]
  if (schemaVersion >= 2) {
    queries.push(
      ['schema_migrations', 'SELECT * FROM schema_migrations ORDER BY target_version'],
      ['model_invocation_evidence_links', `
        SELECT * FROM model_invocation_evidence_links ORDER BY assessment_id, invocation_id
      `],
    )
  }
  if (schemaVersion >= 3) {
    queries.push(['role_attempts', `
      SELECT * FROM role_attempts ORDER BY assessment_id, attempt_id, generation
    `])
  }
  let stateDigest = digest({ schemaVersion })
  for (const [table, query] of queries) {
    for (const row of db.prepare(query).iterate() as Iterable<Record<string, unknown>>) {
      stateDigest = digest({ previousDigest: stateDigest, table, row })
    }
  }
  return stateDigest
}

function verifyMigrationBackup(
  backupPath: string,
  databasePath: string,
  expectedVersion: number,
): string {
  const backupDatabase = new DatabaseSync(backupPath, { readOnly: true })
  try {
    if (integerPragma(backupDatabase, 'application_id') !== APPLICATION_ID
      || integerPragma(backupDatabase, 'user_version') !== expectedVersion) {
      throw new SecurityPersistenceError(
        'corrupt_database',
        'SQLite migration backup identity is invalid',
      )
    }
    verifySchema(backupDatabase, expectedVersion)
    verifyIntegrity(backupDatabase)
    if (expectedVersion >= 2) {
      verifyMigrationHistory(backupDatabase, databasePath, expectedVersion)
    }
    return schemaStateDigest(backupDatabase, expectedVersion)
  } finally {
    backupDatabase.close()
  }
}

function verifyMigrationHistory(
  db: DatabaseSync,
  path: string,
  schemaVersion = SCHEMA_VERSION,
): void {
  const rows = db.prepare(`
    SELECT * FROM schema_migrations ORDER BY target_version
  `).all() as unknown as readonly SchemaMigrationRow[]
  if (rows.length > 0 && rows.at(-1)?.target_version !== schemaVersion) {
    throw new SecurityPersistenceError('corrupt_database', 'SQLite migration history is incomplete')
  }
  for (const [index, row] of rows.entries()) {
    const previous = rows[index - 1]
    const backupPrefix = `${basename(path)}.pre-migration-v${row.source_version}-`
    const backupId = row.backup_name.startsWith(backupPrefix)
      && row.backup_name.endsWith('.sqlite')
      ? row.backup_name.slice(backupPrefix.length, -'.sqlite'.length)
      : ''
    const expectedResultDigest = digest({
      sourceVersion: row.source_version,
      targetVersion: row.target_version,
      backupName: row.backup_name,
      sourceStateDigest: row.source_state_digest,
      committedAt: row.committed_at,
    })
    if (
      row.source_version < 1
      || row.target_version !== row.source_version + 1
      || row.target_version > schemaVersion
      || (previous !== undefined && previous.target_version !== row.source_version)
      || !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u
        .test(backupId)
      || !/^sha256:[0-9a-f]{64}$/u.test(row.source_state_digest)
      || row.result_digest !== expectedResultDigest
      || Number.isNaN(Date.parse(row.committed_at))
    ) {
      throw new SecurityPersistenceError('corrupt_database', 'SQLite migration history is invalid')
    }
  }
}

async function migrateSchemaStep(
  db: DatabaseSync,
  path: string,
  now: () => string,
  sourceVersion: 1 | 2,
  targetVersion: 2 | 3,
  installTargetObjects: (db: DatabaseSync) => void,
): Promise<void> {
  verifySchema(db, sourceVersion)
  verifyIntegrity(db)
  if (sourceVersion >= 2) verifyMigrationHistory(db, path, sourceVersion)
  if (sourceVersion === 2) {
    const links = db.prepare(`
      SELECT count(*) AS count FROM model_invocation_evidence_links
    `).get() as { readonly count?: unknown } | undefined
    if (links?.count !== 0) {
      throw new SecurityPersistenceError(
        'unsupported_schema',
        'Schema v2 contains Model Invocation links without durable Role Attempts',
      )
    }
  }

  const migrationId = randomUUID()
  const backupName = `${basename(path)}.pre-migration-v${sourceVersion}-${migrationId}.sqlite`
  const backupPath = join(dirname(path), backupName)
  const pendingBackupPath = `${backupPath}.pending`
  let transactionOpen = false
  let backupPublished = false
  try {
    await backup(db, pendingBackupPath)
    const backupStateDigest = verifyMigrationBackup(pendingBackupPath, path, sourceVersion)
    await chmod(pendingBackupPath, 0o600)

    db.exec('BEGIN EXCLUSIVE')
    transactionOpen = true
    verifySchema(db, sourceVersion)
    verifyIntegrity(db)
    if (sourceVersion >= 2) verifyMigrationHistory(db, path, sourceVersion)
    if (schemaStateDigest(db, sourceVersion) !== backupStateDigest) {
      throw new SecurityPersistenceError(
        'corrupt_database',
        'SQLite database changed while its migration backup was created',
      )
    }
    await rename(pendingBackupPath, backupPath)
    backupPublished = true

    installTargetObjects(db)
    const committedAt = now()
    const resultDigest = digest({
      sourceVersion,
      targetVersion,
      backupName,
      sourceStateDigest: backupStateDigest,
      committedAt,
    })
    db.prepare(`
      INSERT INTO schema_migrations (
        target_version, source_version, backup_name, source_state_digest,
        result_digest, committed_at
      ) VALUES (?, ?, ?, ?, ?, ?)
    `).run(targetVersion, sourceVersion, backupName, backupStateDigest, resultDigest, committedAt)
    db.exec(`PRAGMA user_version = ${targetVersion}`)
    verifySchema(db, targetVersion)
    verifyIntegrity(db)
    verifyMigrationHistory(db, path, targetVersion)
    db.exec('COMMIT')
    transactionOpen = false
  } catch (error) {
    if (transactionOpen) {
      db.exec('ROLLBACK')
    }
    if (!backupPublished) {
      await unlink(pendingBackupPath).catch(() => undefined)
    }
    throw error
  }
}

async function openDatabase(path: string, now: () => string): Promise<DatabaseSync> {
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
    } else if (userVersion < 1 || userVersion > SCHEMA_VERSION) {
      throw new SecurityPersistenceError('unsupported_schema', 'SQLite schema version is unsupported')
    }
    let admittedVersion = integerPragma(db, 'user_version')
    if (admittedVersion === 1) {
      await migrateSchemaStep(db, path, now, 1, 2, installSchemaV2Objects)
      admittedVersion = 2
    }
    if (admittedVersion === 2) {
      await migrateSchemaStep(db, path, now, 2, 3, installSchemaV3Objects)
      admittedVersion = 3
    }
    if (admittedVersion !== SCHEMA_VERSION) {
      throw new SecurityPersistenceError('unsupported_schema', 'SQLite schema version is unsupported')
    }
    verifySchema(db)
    verifyIntegrity(db)
    verifyMigrationHistory(db, path)
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
        blockingAttempt: null,
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

  /** Persist one exact RUNNING Role Attempt before its isolated session starts. */
  startRoleAttempt(input: StartRoleAttemptPersistenceInput): RoleAttemptRecordV1 {
    this.requireOpen()
    this.db.exec('BEGIN IMMEDIATE')
    try {
      const replay = this.getRoleAttempt(
        input.contextGrant.assessmentId,
        input.contextGrant.roleAttemptId,
        input.generation,
      )
      if (replay !== undefined) {
        const expectedReplay = createRunningRoleAttemptV1({
          ...input,
          assessmentRevision: replay.assessmentRevision,
          startedAt: replay.startedAt,
        })
        if (!sameRoleAttemptStart(replay, expectedReplay)) {
          throw new SecurityPersistenceError(
            'role_attempt_conflict',
            'Role Attempt identity is already bound to different execution inputs',
          )
        }
        this.db.exec('COMMIT')
        return replay
      }
      const boundGeneration = this.db.prepare(`
        SELECT generation FROM role_attempts
        WHERE assessment_id = ? AND attempt_id = ?
      `).get(
        input.contextGrant.assessmentId,
        input.contextGrant.roleAttemptId,
      ) as { readonly generation: number } | undefined
      if (boundGeneration !== undefined) {
        throw new SecurityPersistenceError(
          'role_attempt_conflict',
          'Role Attempt identity is already bound to a different generation',
        )
      }

      const current = this.getAssessmentRecord(input.contextGrant.assessmentId)
      if (current === undefined) {
        throw new SecurityPersistenceError('assessment_not_found', 'Assessment does not exist')
      }
      if (
        current.state !== 'RUNNING'
        || current.assessmentRevision !== input.expectedAssessmentRevision
        || current.pendingCancellation !== null
      ) {
        throw new SecurityPersistenceError(
          'revision_conflict',
          'Assessment cannot start a Role Attempt at this revision',
        )
      }
      if (
        canonicalJson(current.subject.digest)
          !== canonicalJson(input.contextGrant.subject.digest)
        || current.contract.assessmentMode !== input.contextGrant.purpose.assessmentMode
        || current.contract.assessmentProfileId
          !== input.contextGrant.purpose.assessmentProfileId
        || canonicalJson(current.contract.targetDigest)
          !== canonicalJson(input.contextGrant.purpose.targetDigest)
        || current.roleCards.length >= 128
      ) {
        throw new SecurityPersistenceError(
          'role_attempt_conflict',
          'Role Attempt does not bind the durable Assessment contract or capacity',
        )
      }
      const committedAt = this.now()
      const attempt = createRunningRoleAttemptV1({
        ...input,
        assessmentRevision: current.assessmentRevision + 1,
        startedAt: committedAt,
      })
      const roleCard = projectRoleAttemptCardV1(attempt)
      const started = internalAssessmentRecordV1Schema.parse({
        ...current,
        assessmentRevision: attempt.assessmentRevision,
        roleCards: [...current.roleCards, roleCard],
        updatedAt: committedAt,
      })
      this.commitAssessmentRevision(started, 'role_attempt_started', committedAt)
      this.db.prepare(`
        INSERT INTO role_attempts (
          assessment_id, attempt_id, generation, assessment_revision, state,
          fence_digest, context_grant_digest, record_digest, record_json,
          created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        attempt.assessmentId,
        attempt.attemptId,
        attempt.generation,
        attempt.assessmentRevision,
        attempt.lifecycleState,
        attempt.fenceDigest.value,
        attempt.contextGrantDigest.value,
        attempt.recordDigest.value,
        canonicalJson(attempt),
        committedAt,
        committedAt,
      )
      this.db.exec('COMMIT')
      return attempt
    } catch (error) {
      this.db.exec('ROLLBACK')
      throw error
    }
  }

  getRoleAttempt(
    assessmentId: AssessmentId,
    attemptId: string,
    generation: number,
  ): RoleAttemptRecordV1 | undefined {
    this.requireOpen()
    const row = this.db.prepare(`
      SELECT * FROM role_attempts
      WHERE assessment_id = ? AND attempt_id = ? AND generation = ?
    `).get(assessmentId, attemptId, generation) as RoleAttemptRow | undefined
    return row === undefined ? undefined : this.parseRoleAttemptRow(row)
  }

  /** Admit one terminal Role result only from the current durable generation and fence. */
  completeRoleAttempt(input: CompleteRoleAttemptPersistenceInput): RoleAttemptRecordV1 {
    this.requireOpen()
    this.db.exec('BEGIN IMMEDIATE')
    try {
      const currentAttempt = this.getRoleAttempt(
        input.assessmentId,
        input.attemptId,
        input.generation,
      )
      if (currentAttempt === undefined) {
        throw new SecurityPersistenceError('role_attempt_not_found', 'Role Attempt does not exist')
      }
      const exactCompletion = (
        currentAttempt.assessmentRevision === input.expectedAssessmentRevision + 1
        && canonicalJson(currentAttempt.fenceDigest) === canonicalJson(input.fenceDigest)
        && currentAttempt.completionDisposition === input.completionDisposition
        && currentAttempt.budget.requestsUsed === input.usage.requestsUsed
        && currentAttempt.budget.tokensUsed === input.usage.tokensUsed
        && currentAttempt.evidenceCount === input.evidenceCount
        && currentAttempt.candidateCount === input.candidateCount
        && canonicalJson(currentAttempt.milestones) === canonicalJson(input.milestones)
      )
      if (currentAttempt.lifecycleState === 'COMPLETED') {
        if (!exactCompletion) {
          throw new SecurityPersistenceError(
            'role_attempt_conflict',
            'Role Attempt is already completed with a different result',
          )
        }
        this.db.exec('COMMIT')
        return currentAttempt
      }
      if (canonicalJson(currentAttempt.fenceDigest) !== canonicalJson(input.fenceDigest)) {
        throw new SecurityPersistenceError(
          'role_attempt_conflict',
          'Role Attempt completion carries a stale or different fence',
        )
      }
      const currentAssessment = this.getAssessmentRecord(input.assessmentId)
      if (
        currentAssessment === undefined
        || currentAssessment.state !== 'RUNNING'
        || currentAssessment.assessmentRevision !== input.expectedAssessmentRevision
        || currentAssessment.pendingCancellation !== null
      ) {
        throw new SecurityPersistenceError(
          'revision_conflict',
          'Role Attempt cannot complete at this Assessment revision',
        )
      }
      const cardIndex = currentAssessment.roleCards.findIndex(
        card => card.attempt.attemptId === input.attemptId,
      )
      if (cardIndex < 0) {
        throw new SecurityPersistenceError(
          'corrupt_database',
          'Role Attempt current projection is missing',
        )
      }
      const committedAt = this.now()
      const completed = completeRoleAttemptV1({
        current: currentAttempt,
        assessmentRevision: currentAssessment.assessmentRevision + 1,
        completedAt: committedAt,
        completionDisposition: input.completionDisposition,
        usage: input.usage,
        evidenceCount: input.evidenceCount,
        candidateCount: input.candidateCount,
        milestones: input.milestones,
      })
      const roleCards = [...currentAssessment.roleCards]
      roleCards[cardIndex] = projectRoleAttemptCardV1(completed)
      const assessment = internalAssessmentRecordV1Schema.parse({
        ...currentAssessment,
        assessmentRevision: completed.assessmentRevision,
        roleCards,
        updatedAt: committedAt,
      })
      this.commitAssessmentRevision(assessment, 'role_attempt_completed', committedAt)
      const changed = this.db.prepare(`
        UPDATE role_attempts
        SET assessment_revision = ?, state = ?, record_digest = ?, record_json = ?, updated_at = ?
        WHERE assessment_id = ? AND attempt_id = ? AND generation = ?
          AND state = 'RUNNING' AND fence_digest = ?
      `).run(
        completed.assessmentRevision,
        completed.lifecycleState,
        completed.recordDigest.value,
        canonicalJson(completed),
        committedAt,
        completed.assessmentId,
        completed.attemptId,
        completed.generation,
        completed.fenceDigest.value,
      )
      if (changed.changes !== 1) {
        throw new SecurityPersistenceError(
          'role_attempt_conflict',
          'Role Attempt generation changed during completion',
        )
      }
      this.db.exec('COMMIT')
      return completed
    } catch (error) {
      this.db.exec('ROLLBACK')
      throw error
    }
  }

  /**
   * Atomically append one already-published Model Invocation Evidence link to
   * the Assessment journal and current projection.
   */
  linkModelInvocationEvidence(
    input: LinkModelInvocationEvidencePersistenceInput,
  ): ModelInvocationEvidenceLinkV1 {
    this.requireOpen()
    this.db.exec('BEGIN IMMEDIATE')
    try {
      const invocation = parseModelInvocationRecordV1(input.record, input.expected)
      if (canonicalJson(invocation.recordDigest) !== canonicalJson(input.receipt.recordDigest)) {
        throw new SecurityPersistenceError(
          'model_invocation_conflict',
          'Model Invocation Evidence receipt does not bind the supplied record',
        )
      }
      const replay = this.getModelInvocationEvidenceLink(
        input.receipt.assessmentId,
        input.receipt.invocationId,
      )
      if (replay !== undefined) {
        const expectedReplay = createModelInvocationEvidenceLinkV1({
          assessmentRevision: replay.assessmentRevision,
          linkedAt: replay.linkedAt,
          contextGrant: input.contextGrant,
          receipt: input.receipt,
          expected: input.expected,
        })
        if (canonicalJson(expectedReplay) !== canonicalJson(replay)) {
          throw new SecurityPersistenceError(
            'model_invocation_conflict',
            'Model Invocation identity is already linked to different Evidence',
          )
        }
        this.db.exec('COMMIT')
        return replay
      }

      const current = this.getAssessmentRecord(input.receipt.assessmentId)
      if (current === undefined) {
        throw new SecurityPersistenceError('assessment_not_found', 'Assessment does not exist')
      }
      if (
        current.state !== 'RUNNING'
        || current.assessmentRevision !== input.expectedAssessmentRevision
        || current.pendingCancellation !== null
      ) {
        throw new SecurityPersistenceError(
          'revision_conflict',
          'Assessment cannot link Model Invocation Evidence at this revision',
        )
      }
      if (current.modelInvocationEvidenceLinks.length >= 256) {
        throw new SecurityPersistenceError(
          'model_invocation_conflict',
          'Assessment Model Invocation Evidence link limit is exhausted',
        )
      }
      const roleAttempt = this.getRoleAttempt(
        input.receipt.assessmentId,
        input.expected.attemptId,
        input.expected.attemptGeneration,
      )
      if (roleAttempt === undefined) {
        throw new SecurityPersistenceError(
          'role_attempt_not_found',
          'Model Invocation Evidence requires its exact durable Role Attempt',
        )
      }
      if (
        roleAttempt.lifecycleState !== 'RUNNING'
        || canonicalJson(roleAttempt.fenceDigest)
          !== canonicalJson(input.expected.attemptFenceDigest)
        || canonicalJson(roleAttempt.contextGrantDigest)
          !== canonicalJson(input.expected.contextGrantDigest)
        || canonicalJson({
          roleId: roleAttempt.roleDefinition.roleId,
          roleVersion: roleAttempt.roleDefinition.roleVersion,
          definitionDigest: roleAttempt.roleDefinition.definitionDigest,
        }) !== canonicalJson(invocation.roleDefinition)
        || canonicalJson(roleAttempt.provider) !== canonicalJson({
          providerId: invocation.provider.providerId,
          modelId: invocation.provider.modelId,
          movingProvider: invocation.provider.movingProvider,
        })
        || canonicalJson(roleAttempt.prompt) !== canonicalJson(invocation.prompt)
      ) {
        throw new SecurityPersistenceError(
          'role_attempt_conflict',
          'Model Invocation Evidence does not bind the current durable Role Attempt lineage',
        )
      }
      const committedAt = this.now()
      const link = createModelInvocationEvidenceLinkV1({
        assessmentRevision: current.assessmentRevision + 1,
        linkedAt: committedAt,
        contextGrant: input.contextGrant,
        receipt: input.receipt,
        expected: input.expected,
      })
      if (
        current.assessmentId !== link.publicationReceipt.assessmentId
        || canonicalJson(current.subject.digest)
          !== canonicalJson(link.publicationReceipt.subjectDigest)
      ) {
        throw new SecurityPersistenceError(
          'model_invocation_conflict',
          'Model Invocation Evidence does not bind the durable Assessment Subject',
        )
      }
      const linked = internalAssessmentRecordV1Schema.parse({
        ...current,
        assessmentRevision: link.assessmentRevision,
        modelInvocationEvidenceLinks: [...current.modelInvocationEvidenceLinks, link],
        updatedAt: committedAt,
      })
      this.commitAssessmentRevision(
        linked,
        'model_invocation_evidence_linked',
        committedAt,
      )
      const receipt = link.publicationReceipt
      this.db.prepare(`
        INSERT INTO model_invocation_evidence_links (
          assessment_id, invocation_id, assessment_revision, attempt_id,
          attempt_generation, attempt_fence_digest, context_grant_digest,
          artifact_id, evidence_schema_id, evidence_digest, record_digest,
          publication_receipt_digest, link_json, committed_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        receipt.assessmentId,
        receipt.invocationId,
        link.assessmentRevision,
        receipt.parentAttempt.attemptId,
        receipt.parentAttempt.generation,
        receipt.parentAttempt.fenceDigest.value,
        link.contextGrantDigest.value,
        receipt.artifactId,
        receipt.schemaId,
        receipt.evidenceDigest.value,
        receipt.recordDigest.value,
        receipt.publicationReceiptDigest.value,
        canonicalJson(link),
        committedAt,
      )
      this.db.exec('COMMIT')
      return link
    } catch (error) {
      this.db.exec('ROLLBACK')
      throw error
    }
  }

  getModelInvocationEvidenceLink(
    assessmentId: AssessmentId,
    invocationId: string,
  ): ModelInvocationEvidenceLinkV1 | undefined {
    this.requireOpen()
    const row = this.db.prepare(`
      SELECT * FROM model_invocation_evidence_links
      WHERE assessment_id = ? AND invocation_id = ?
    `).get(assessmentId, invocationId) as ModelInvocationEvidenceLinkRow | undefined
    return row === undefined ? undefined : this.parseModelInvocationEvidenceLinkRow(row)
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
      if (current.state !== 'CREATED' || current.pendingCancellation !== null) {
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
        || current.pendingCancellation !== null
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
        blockingAttempt: null,
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
        current.assessmentRevision < requestRevision
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
        blockingAttempt: null,
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
        || current.pendingCancellation !== null
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
        blockingAttempt: null,
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
        || current.pendingCancellation !== null
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
        blockingAttempt: null,
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
        || current.pendingCancellation !== null
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
              || existing.decisionMaker.principalId.toLocaleLowerCase('en-US')
                === input.principalId.toLocaleLowerCase('en-US')
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
        || current.pendingCancellation !== null
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
        blockingAttempt: {
          attemptId: `${assessmentId}:assessment-execution:${expectedAssessmentRevision}`,
          attemptKind: 'ASSESSMENT_EXECUTION',
          lifecycleState: failureCode === 'HOST_RESTART_DURING_EVALUATION'
            ? 'INTERRUPTED'
            : 'FAILED',
        },
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

  private parseRoleAttemptRow(row: RoleAttemptRow): RoleAttemptRecordV1 {
    const attempt = parseRoleAttemptRecordV1(JSON.parse(row.record_json))
    if (
      row.record_json !== canonicalJson(attempt)
      || row.assessment_id !== attempt.assessmentId
      || row.attempt_id !== attempt.attemptId
      || row.generation !== attempt.generation
      || row.assessment_revision !== attempt.assessmentRevision
      || row.state !== attempt.lifecycleState
      || row.fence_digest !== attempt.fenceDigest.value
      || row.context_grant_digest !== attempt.contextGrantDigest.value
      || row.record_digest !== attempt.recordDigest.value
      || row.created_at !== attempt.startedAt
      || row.updated_at !== (attempt.completedAt ?? attempt.startedAt)
    ) {
      throw new SecurityPersistenceError(
        'corrupt_database',
        'Role Attempt row does not match its canonical record',
      )
    }
    return attempt
  }

  private parseModelInvocationEvidenceLinkRow(
    row: ModelInvocationEvidenceLinkRow,
  ): ModelInvocationEvidenceLinkV1 {
    const link = parseModelInvocationEvidenceLinkV1(JSON.parse(row.link_json))
    const receipt = link.publicationReceipt
    if (
      row.link_json !== canonicalJson(link)
      || row.assessment_id !== receipt.assessmentId
      || row.invocation_id !== receipt.invocationId
      || row.assessment_revision !== link.assessmentRevision
      || row.attempt_id !== receipt.parentAttempt.attemptId
      || row.attempt_generation !== receipt.parentAttempt.generation
      || row.attempt_fence_digest !== receipt.parentAttempt.fenceDigest.value
      || row.context_grant_digest !== link.contextGrantDigest.value
      || row.artifact_id !== receipt.artifactId
      || row.evidence_schema_id !== receipt.schemaId
      || row.evidence_digest !== receipt.evidenceDigest.value
      || row.record_digest !== receipt.recordDigest.value
      || row.publication_receipt_digest !== receipt.publicationReceiptDigest.value
      || row.committed_at !== link.linkedAt
    ) {
      throw new SecurityPersistenceError(
        'corrupt_database',
        'Model Invocation Evidence link row does not match its canonical projection',
      )
    }
    return link
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
  const now = options.now ?? (() => new Date().toISOString())
  const database = await openDatabase(options.databasePath, now)
  try {
    await chmod(options.databasePath, 0o600)
  } catch (error) {
    database.close()
    throw error
  }
  return new SecurityPersistence(
    database,
    now,
    options.nextRepositoryId ?? (() => `repo-${randomUUID()}` as RepositoryId),
    options.nextCorrelationId ?? (() => `sec-${randomUUID()}`),
    options.nextAssessmentId ?? (() => `asm-${randomUUID()}` as AssessmentId),
    options.nextRiskDecisionId ?? (() => `risk-decision-${randomUUID()}`),
  )
}
