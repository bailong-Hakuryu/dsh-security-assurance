import { createHmac } from 'node:crypto'
import { z } from 'zod'
import type { DigestEnvelopeV1 } from '../contracts.ts'
import { digestEnvelopeV1Schema } from '../contracts.ts'
import { binaryDigest, canonicalJson, structuredDigest } from './canonical.ts'
import { deepFreeze } from './freeze.ts'
import type { ProtectedSourceSliceMaterialV1 } from './subject-freeze.ts'

export const SOURCE_SLICE_SECRET_INSPECTION_MEDIA_TYPE =
  'application/vnd.dsh.security.source-slice-secret-inspection+json'

const SECRET_DETECTOR_POLICY_ID = 'security/high-confidence-secret-patterns-v1'
const fingerprintKeyIdSchema = z.string().regex(/^[a-z0-9][a-z0-9._/-]{0,127}$/iu)
const subjectRelativePathSchema = z.string().min(1).max(1024).refine(path => (
  !path.startsWith('/')
  && !path.startsWith('\\')
  && !/^[a-z]:/iu.test(path)
  && !path.includes('\\')
  && path.split('/').every(segment => segment.length > 0 && segment !== '.' && segment !== '..')
), 'Protected Source Slice material requires a canonical Subject-relative path')

export type ProtectedSourceSliceSecretKindV1 =
  | 'ASSIGNMENT_SECRET'
  | 'BEARER_TOKEN'
  | 'PRIVATE_KEY'

export interface ProtectedSourceSliceSecretFindingV1 {
  readonly kind: ProtectedSourceSliceSecretKindV1
  readonly startOffset: number
  readonly endOffset: number
  readonly line: number
  readonly column: number
  readonly fingerprint: string
}

export interface ProtectedSourceSliceSecretInspectionCoreV1 {
  readonly schemaVersion: 1
  readonly requestDigest: DigestEnvelopeV1
  readonly subjectDigest: DigestEnvelopeV1
  readonly sourceDigest: DigestEnvelopeV1
  readonly path: string
  readonly detectorPolicyId: typeof SECRET_DETECTOR_POLICY_ID
  readonly fingerprintKeyId: string
  readonly decision: 'REDACTION_REQUIRED' | 'ADDITIONAL_REVIEW_REQUIRED'
  readonly findings: readonly ProtectedSourceSliceSecretFindingV1[]
}

export interface ProtectedSourceSliceSecretInspectionV1
  extends ProtectedSourceSliceSecretInspectionCoreV1 {
  readonly inspectionDigest: DigestEnvelopeV1
}

export interface InspectProtectedSourceSliceSecretsOptionsV1 {
  readonly material: ProtectedSourceSliceMaterialV1
  readonly fingerprintKey: Uint8Array
  readonly fingerprintKeyId: string
}

interface SecretCandidate {
  readonly kind: ProtectedSourceSliceSecretKindV1
  readonly startOffset: number
  readonly endOffset: number
  readonly secret: string
}

function sameDigest(left: DigestEnvelopeV1, right: DigestEnvelopeV1): boolean {
  return canonicalJson(left) === canonicalJson(right)
}

function parseProtectedMaterial(candidate: ProtectedSourceSliceMaterialV1): ProtectedSourceSliceMaterialV1 {
  const requestDigest = digestEnvelopeV1Schema.parse(candidate.requestDigest)
  const subjectDigest = digestEnvelopeV1Schema.parse(candidate.subjectDigest)
  const digest = digestEnvelopeV1Schema.parse(candidate.digest)
  const path = subjectRelativePathSchema.parse(candidate.path)
  const text = z.string().max(1024 * 1024).parse(candidate.text)
  if (
    requestDigest.mediaType !== 'application/vnd.dsh.security.source-slice-request+json'
    || subjectDigest.mediaType !== 'application/vnd.dsh.security.subject-manifest+json'
    || digest.mediaType !== 'application/octet-stream'
    || digest.canonicalization !== 'raw-bytes'
  ) {
    throw new TypeError('Protected Source Slice material has unsupported digest bindings')
  }
  const observedDigest = binaryDigest('application/octet-stream', Buffer.from(text, 'utf8'))
  if (!sameDigest(digest, observedDigest)) {
    throw new TypeError('Protected Source Slice material digest does not bind its text')
  }
  return deepFreeze({ requestDigest, subjectDigest, path, digest, text })
}

function assignmentCandidates(text: string): SecretCandidate[] {
  const pattern = /\b(?:api[_-]?key|access[_-]?token|auth[_-]?token|secret|password|credential)\b[ \t]*[:=][ \t]*(?:"([^"\r\n]{4,})"|'([^'\r\n]{4,})'|([^\s,;#]{4,}))/giu
  const candidates: SecretCandidate[] = []
  for (const match of text.matchAll(pattern)) {
    const secret = match[1] ?? match[2] ?? match[3]
    if (secret === undefined || match.index === undefined) continue
    const secretOffset = match[0].lastIndexOf(secret)
    const startOffset = match.index + secretOffset
    candidates.push({
      kind: 'ASSIGNMENT_SECRET',
      startOffset,
      endOffset: startOffset + secret.length,
      secret,
    })
  }
  return candidates
}

function bearerCandidates(text: string): SecretCandidate[] {
  const pattern = /\bBearer[ \t]+([A-Za-z0-9._~+/=-]{8,})/gu
  const candidates: SecretCandidate[] = []
  for (const match of text.matchAll(pattern)) {
    const secret = match[1]
    if (secret === undefined || match.index === undefined) continue
    const startOffset = match.index + match[0].lastIndexOf(secret)
    candidates.push({
      kind: 'BEARER_TOKEN',
      startOffset,
      endOffset: startOffset + secret.length,
      secret,
    })
  }
  return candidates
}

function privateKeyCandidates(text: string): SecretCandidate[] {
  const pattern = /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----/gu
  return [...text.matchAll(pattern)].flatMap(match => {
    if (match.index === undefined) return []
    return [{
      kind: 'PRIVATE_KEY' as const,
      startOffset: match.index,
      endOffset: match.index + match[0].length,
      secret: match[0],
    }]
  })
}

function secretCandidates(text: string): SecretCandidate[] {
  const candidates = [
    ...assignmentCandidates(text),
    ...bearerCandidates(text),
    ...privateKeyCandidates(text),
  ].sort((left, right) => (
    left.startOffset - right.startOffset
    || right.endOffset - left.endOffset
    || left.kind.localeCompare(right.kind)
  ))
  const nonOverlapping: SecretCandidate[] = []
  for (const candidate of candidates) {
    if (nonOverlapping.some(existing => (
      candidate.startOffset < existing.endOffset && candidate.endOffset > existing.startOffset
    ))) continue
    nonOverlapping.push(candidate)
  }
  return nonOverlapping
}

function location(text: string, offset: number): { readonly line: number; readonly column: number } {
  const prefix = text.slice(0, offset)
  const lines = prefix.split('\n')
  return { line: lines.length, column: (lines.at(-1)?.length ?? 0) + 1 }
}

/**
 * Detect only bounded high-confidence patterns in protected local text. Empty
 * findings never prove absence; raw matches and the fingerprint key are not retained.
 */
export function inspectProtectedSourceSliceSecrets(
  options: InspectProtectedSourceSliceSecretsOptionsV1,
): ProtectedSourceSliceSecretInspectionV1 {
  const material = parseProtectedMaterial(options.material)
  const fingerprintKeyId = fingerprintKeyIdSchema.parse(options.fingerprintKeyId)
  if (!(options.fingerprintKey instanceof Uint8Array) || options.fingerprintKey.byteLength < 32) {
    throw new TypeError('Secret fingerprint keys must contain at least 32 bytes')
  }
  const fingerprintKey = Buffer.from(options.fingerprintKey)
  try {
    const findings = secretCandidates(material.text).map(candidate => ({
      kind: candidate.kind,
      startOffset: candidate.startOffset,
      endOffset: candidate.endOffset,
      ...location(material.text, candidate.startOffset),
      fingerprint: `hmac-sha256:${createHmac('sha256', fingerprintKey)
        .update(candidate.secret, 'utf8')
        .digest('hex')}`,
    }))
    const core: ProtectedSourceSliceSecretInspectionCoreV1 = {
      schemaVersion: 1,
      requestDigest: material.requestDigest,
      subjectDigest: material.subjectDigest,
      sourceDigest: material.digest,
      path: material.path,
      detectorPolicyId: SECRET_DETECTOR_POLICY_ID,
      fingerprintKeyId,
      decision: findings.length > 0 ? 'REDACTION_REQUIRED' : 'ADDITIONAL_REVIEW_REQUIRED',
      findings,
    }
    return deepFreeze({
      ...core,
      inspectionDigest: structuredDigest(SOURCE_SLICE_SECRET_INSPECTION_MEDIA_TYPE, core),
    })
  } finally {
    fingerprintKey.fill(0)
  }
}
