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
import {
  assessmentSealV1Schema,
  bundleManifestV1Schema,
  digestEnvelopeV1Schema,
  securityAssuranceSubmissionV1Schema,
  securitySubmissionArtifactV1Schema,
  securitySubmissionJsonV1Schema,
  SECURITY_ASSURANCE_PRODUCT_NAME,
  SECURITY_ASSURANCE_PRODUCT_VERSION,
} from '../contracts.ts'
import type {
  AssessmentSealV1,
  BundleManifestV1,
  DigestEnvelopeV1,
  SecurityAssuranceSubmissionV1,
  SecuritySubmissionArtifactV1,
  SecuritySubmissionJsonV1,
} from '../contracts.ts'
import { canonicalJson, structuredDigest } from './canonical.ts'
import type { InternalAssessmentRecordV1 } from './assessment-record.ts'
import type { DeterministicAssessmentOutcomeV1 } from './deterministic-kernel.ts'

const MANIFEST_FILE = 'bundle-manifest.json'
const SUBMISSION_FILE = 'assurance-submission.json'

export interface SealIdentityV1 {
  readonly sealId: string
  readonly sealedAt: string
}

export interface SealedArtifactsV1 {
  readonly seal: AssessmentSealV1
  readonly bundleManifest: BundleManifestV1
  readonly submission: SecurityAssuranceSubmissionV1
  readonly publicationDigest: DigestEnvelopeV1
}

function json(value: unknown): SecuritySubmissionJsonV1 {
  return securitySubmissionJsonV1Schema.parse(value)
}

function artifact(
  artifactId: string,
  schemaId: string,
  mediaType: string,
  value: unknown,
): SecuritySubmissionArtifactV1 {
  const normalized = json(value)
  return securitySubmissionArtifactV1Schema.parse({
    artifactId,
    schemaId,
    schemaVersion: 1,
    digest: structuredDigest(mediaType, normalized),
    value: normalized,
  })
}

function record(
  recordId: string,
  schemaId: string,
  mediaType: string,
  value: unknown,
): BundleManifestV1['records'][number] {
  return {
    recordId,
    schemaId,
    schemaVersion: 1,
    classification: 'CONTROL_PLANE',
    digest: structuredDigest(mediaType, value),
  }
}

/** Purely assemble all terminal artifacts from one seal-admissible durable revision. */
export function assembleSealedArtifacts(
  assessment: InternalAssessmentRecordV1,
  outcome: DeterministicAssessmentOutcomeV1,
  identity: SealIdentityV1,
): SealedArtifactsV1 {
  if (
    assessment.state !== 'RUNNING'
    && !(
      assessment.state === 'BLOCKED'
      && assessment.riskDecisionWindow?.state === 'RESOLVED'
    )
  ) {
    throw new TypeError('only a RUNNING or resolved Risk Decision Assessment can be sealed')
  }
  const terminalRevision = assessment.assessmentRevision + 1
  const subject = json({
    schemaVersion: 1,
    source: assessment.subject.source,
    digest: assessment.subject.digest,
    stats: assessment.subject.stats,
  })
  const coverage = json(outcome.coverage)
  const findings = json({ schemaVersion: 1, findings: outcome.findings })
  const riskDecisions = json({ schemaVersion: 1, decisions: assessment.riskDecisions })
  const evaluationTrace = json(outcome.evaluationTrace)
  const verdict = json({
    schemaVersion: 1,
    verdict: outcome.verdict,
    coverageDigest: outcome.coverage.digest,
    evaluationTraceDigest: structuredDigest(
      'application/vnd.dsh.security.evaluation-trace+json',
      evaluationTrace,
    ),
  })
  const provenance = json({
    schemaVersion: 1,
    product: {
      name: SECURITY_ASSURANCE_PRODUCT_NAME,
      version: SECURITY_ASSURANCE_PRODUCT_VERSION,
    },
    evaluatorVersion: 'dsh-security-policy-evaluator-v1',
    repositoryIdentityDigest: assessment.repository.rootIdentityDigest,
    evaluatedAt: identity.sealedAt,
  })
  const sealPayload = json({
    schemaVersion: 1,
    sealId: identity.sealId,
    assessmentId: assessment.assessmentId,
    assessmentRevision: terminalRevision,
    repositoryId: assessment.repository.repositoryId,
    repositoryRevision: assessment.repository.repositoryRevision,
    subjectDigest: assessment.subject.digest,
    policyDigest: assessment.contract.policy.digest,
    coverageDigest: outcome.coverage.digest,
    findingsDigest: structuredDigest('application/vnd.dsh.security.findings+json', findings),
    riskDecisionsDigest: structuredDigest(
      'application/vnd.dsh.security.risk-decisions+json',
      riskDecisions,
    ),
    verdict: outcome.verdict,
    sealedAt: identity.sealedAt,
  })
  const seal = assessmentSealV1Schema.parse({
    schemaVersion: 1,
    sealId: identity.sealId,
    assessmentRevision: terminalRevision,
    verdict: outcome.verdict,
    digest: structuredDigest('application/vnd.dsh.security.assessment-seal+json', sealPayload),
    sealedAt: identity.sealedAt,
  })
  const records = [
    record('subject', 'dsh/security-subject', 'application/vnd.dsh.security.subject+json', subject),
    record('policy', 'dsh/security-policy', 'application/vnd.dsh.security.policy+json', assessment.contract.policy.value),
    record('coverage', 'dsh/security-coverage', 'application/vnd.dsh.security.coverage+json', coverage),
    record('findings', 'dsh/security-findings', 'application/vnd.dsh.security.findings+json', findings),
    record(
      'risk-decisions',
      'dsh/security-risk-decisions',
      'application/vnd.dsh.security.risk-decisions+json',
      riskDecisions,
    ),
    record('verdict', 'dsh/security-verdict', 'application/vnd.dsh.security.verdict+json', verdict),
    record('provenance', 'dsh/security-provenance', 'application/vnd.dsh.security.provenance+json', provenance),
    ...outcome.evidence.map(value => record(
      value.artifactId,
      value.schemaId,
      value.mediaType,
      value.value,
    )),
  ]
  const manifestCore = {
    schemaVersion: 1,
    assessmentId: assessment.assessmentId,
    assessmentRevision: terminalRevision,
    verdict: outcome.verdict,
    seal,
    records,
    omissions: [{
      schemaId: 'dsh/security-threat-model',
      reason: 'NO_ELIGIBLE_ANALYZER',
    }],
  }
  const bundleManifest = bundleManifestV1Schema.parse({
    ...manifestCore,
    digest: structuredDigest('application/vnd.dsh.security.bundle-manifest+json', manifestCore),
  })

  const providerComposition = artifact(
    'provider-composition',
    'dsh/security-provider-composition',
    'application/vnd.dsh.security.provider-composition+json',
    outcome.providerComposition,
  )
  const providerPolicy = artifact(
    'provider-policy',
    'dsh/security-policy',
    'application/vnd.dsh.security.policy+json',
    assessment.contract.policy.value,
  )
  const coverageArtifact = artifact(
    'coverage',
    'dsh/security-coverage',
    'application/vnd.dsh.security.coverage+json',
    coverage,
  )
  const findingsArtifact = artifact(
    'findings',
    'dsh/security-findings',
    'application/vnd.dsh.security.findings+json',
    findings,
  )
  const riskDecisionsArtifact = artifact(
    'risk-decisions',
    'dsh/security-risk-decisions',
    'application/vnd.dsh.security.risk-decisions+json',
    riskDecisions,
  )
  const sourceSeal = artifact(
    'source-seal',
    'dsh/security-source-seal',
    'application/vnd.dsh.security.source-seal+json',
    { seal, binding: sealPayload },
  )
  const provenanceArtifact = artifact(
    'provenance',
    'dsh/security-provenance',
    'application/vnd.dsh.security.provenance+json',
    provenance,
  )
  const evidence = [
    artifact(
      'subject-inventory',
      'dsh/security-subject-inventory',
      'application/vnd.dsh.security.subject-inventory+json',
      subject,
    ),
    artifact(
      'evaluation-trace',
      'dsh/security-evaluation-trace',
      'application/vnd.dsh.security.evaluation-trace+json',
      evaluationTrace,
    ),
    ...outcome.evidence.map(value => artifact(
      value.artifactId,
      value.schemaId,
      value.mediaType,
      value.value,
    )),
  ]
  const payload = {
    assessment: {
      assessmentId: assessment.assessmentId,
      assessmentRevision: terminalRevision,
      state: 'SEALED' as const,
      verdict: outcome.verdict,
    },
    binding: {
      repositoryId: assessment.repository.repositoryId,
      repositoryRevision: assessment.repository.repositoryRevision,
      subjectDigest: assessment.subject.digest,
      policyId: assessment.contract.policy.policyId,
      policyDigest: assessment.contract.policy.digest,
    },
    providerComposition,
    providerPolicy,
    coverage: coverageArtifact,
    findings: findingsArtifact,
    riskDecisions: riskDecisionsArtifact,
    sourceSeal,
    provenance: provenanceArtifact,
    evidence,
  }
  const submission = securityAssuranceSubmissionV1Schema.parse({
    schemaVersion: 1,
    payload,
    digest: structuredDigest('application/vnd.dsh.security.assurance-submission+json', payload),
  })
  const publicationDigest = structuredDigest(
    'application/vnd.dsh.security.sealed-publication+json',
    { manifestDigest: bundleManifest.digest, submissionDigest: submission.digest },
  )
  return { seal, bundleManifest, submission, publicationDigest }
}

function publicationDirectory(
  securityRoot: string,
  assessmentId: string,
  publicationDigest: DigestEnvelopeV1,
): string {
  return join(securityRoot, 'bundles', assessmentId, publicationDigest.value)
}

function requireDigest(expected: DigestEnvelopeV1, value: unknown): void {
  const observed = structuredDigest(expected.mediaType, value)
  if (canonicalJson(observed) !== canonicalJson(expected)) {
    throw new Error('sealed artifact digest verification failed')
  }
}

function verifySealedArtifactSemantics(artifacts: SealedArtifactsV1): void {
  const manifest = bundleManifestV1Schema.parse(artifacts.bundleManifest)
  const submission = securityAssuranceSubmissionV1Schema.parse(artifacts.submission)
  const { digest: manifestDigest, ...manifestCore } = manifest
  requireDigest(manifestDigest, manifestCore)
  requireDigest(submission.digest, submission.payload)
  const riskDecisions = submission.payload.riskDecisions
  for (const embedded of [
    submission.payload.providerComposition,
    submission.payload.providerPolicy,
    submission.payload.coverage,
    submission.payload.findings,
    ...(riskDecisions === undefined ? [] : [riskDecisions]),
    submission.payload.sourceSeal,
    submission.payload.provenance,
    ...submission.payload.evidence,
  ]) {
    requireDigest(embedded.digest, embedded.value)
  }
  const sourceSeal = submission.payload.sourceSeal.value
  if (sourceSeal === null || Array.isArray(sourceSeal) || typeof sourceSeal !== 'object') {
    throw new Error('source seal is not self-contained')
  }
  const embeddedSeal = assessmentSealV1Schema.parse(sourceSeal.seal)
  const binding = securitySubmissionJsonV1Schema.parse(sourceSeal.binding)
  if (binding === null || Array.isArray(binding) || typeof binding !== 'object') {
    throw new Error('source seal binding is invalid')
  }
  const boundRiskDecisionsDigest = binding.riskDecisionsDigest
  if ((riskDecisions === undefined) !== (boundRiskDecisionsDigest === undefined)) {
    throw new Error('source seal Risk Decision binding is incomplete')
  }
  if (riskDecisions !== undefined) {
    const expectedRiskDecisionsDigest = digestEnvelopeV1Schema.parse(boundRiskDecisionsDigest)
    requireDigest(expectedRiskDecisionsDigest, riskDecisions.value)
    if (canonicalJson(expectedRiskDecisionsDigest) !== canonicalJson(riskDecisions.digest)) {
      throw new Error('source seal Risk Decision digest does not match the Submission artifact')
    }
  }
  if (canonicalJson(embeddedSeal) !== canonicalJson(artifacts.seal)) {
    throw new Error('source seal does not match the Assessment Seal')
  }
  requireDigest(artifacts.seal.digest, binding)
  if (canonicalJson(manifest.seal) !== canonicalJson(artifacts.seal)) {
    throw new Error('Bundle Manifest does not bind the Assessment Seal')
  }
  requireDigest(artifacts.publicationDigest, {
    manifestDigest: manifest.digest,
    submissionDigest: submission.digest,
  })
}

async function verifyRegularFile(path: string, expected: string): Promise<void> {
  const status = await lstat(path)
  if (!status.isFile() || status.isSymbolicLink()) throw new Error('sealed artifact is not a regular file')
  if (await readFile(path, 'utf8') !== expected) throw new Error('sealed artifact failed canonical verification')
}

/** Verify that private published bytes still exactly match their durable values. */
export async function verifyPublishedSealedArtifacts(
  securityRoot: string,
  assessmentId: string,
  artifacts: SealedArtifactsV1,
): Promise<void> {
  verifySealedArtifactSemantics(artifacts)
  const destination = publicationDirectory(securityRoot, assessmentId, artifacts.publicationDigest)
  const status = await lstat(destination)
  if (!status.isDirectory() || status.isSymbolicLink()) throw new Error('sealed publication is not a directory')
  await Promise.all([
    verifyRegularFile(join(destination, MANIFEST_FILE), canonicalJson(artifacts.bundleManifest)),
    verifyRegularFile(join(destination, SUBMISSION_FILE), canonicalJson(artifacts.submission)),
  ])
}

/** Publish both official files together under one content-addressed private directory. */
export async function publishSealedArtifacts(
  securityRoot: string,
  assessmentId: string,
  artifacts: SealedArtifactsV1,
): Promise<void> {
  verifySealedArtifactSemantics(artifacts)
  const assessmentDirectory = join(securityRoot, 'bundles', assessmentId)
  await mkdir(assessmentDirectory, { recursive: true, mode: 0o700 })
  await chmod(assessmentDirectory, 0o700)
  const destination = publicationDirectory(securityRoot, assessmentId, artifacts.publicationDigest)
  const staging = join(assessmentDirectory, `.staging-${randomUUID()}`)
  await mkdir(staging, { mode: 0o700 })
  try {
    const manifestPath = join(staging, MANIFEST_FILE)
    const submissionPath = join(staging, SUBMISSION_FILE)
    await Promise.all([
      writeFile(manifestPath, canonicalJson(artifacts.bundleManifest), { encoding: 'utf8', flag: 'wx', mode: 0o600 }),
      writeFile(submissionPath, canonicalJson(artifacts.submission), { encoding: 'utf8', flag: 'wx', mode: 0o600 }),
    ])
    await Promise.all([chmod(manifestPath, 0o600), chmod(submissionPath, 0o600)])
    try {
      await rename(staging, destination)
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error
      await verifyPublishedSealedArtifacts(securityRoot, assessmentId, artifacts)
      await rm(staging, { recursive: true, force: true })
    }
    await verifyPublishedSealedArtifacts(securityRoot, assessmentId, artifacts)
  } catch (error) {
    await rm(staging, { recursive: true, force: true })
    throw error
  }
}
