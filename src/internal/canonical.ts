import { createHash } from 'node:crypto'
import type { DigestEnvelopeV1 } from '../contracts.ts'

/** Deterministic JSON encoding for bounded JSON-safe domain records. */
export function canonicalJson(value: unknown): string {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return JSON.stringify(value)
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new TypeError('canonical JSON rejects non-finite numbers')
    return JSON.stringify(value)
  }
  if (Array.isArray(value)) return `[${value.map(item => canonicalJson(item)).join(',')}]`
  if (typeof value !== 'object') throw new TypeError('canonical JSON accepts only JSON-safe values')
  const record = value as Record<string, unknown>
  return `{${Object.keys(record).sort().map(key => (
    `${JSON.stringify(key)}:${canonicalJson(record[key])}`
  )).join(',')}}`
}

export function sha256Hex(bytes: Uint8Array | string): string {
  return createHash('sha256').update(bytes).digest('hex')
}

export function structuredDigest(mediaType: string, value: unknown): DigestEnvelopeV1 {
  const encoded = canonicalJson(value)
  return {
    schemaVersion: 1,
    algorithm: 'sha256',
    mediaType,
    byteLength: Buffer.byteLength(encoded, 'utf8'),
    canonicalization: 'dsh-canonical-json-v1',
    value: sha256Hex(encoded),
  }
}

export function binaryDigest(mediaType: string, bytes: Uint8Array): DigestEnvelopeV1 {
  return {
    schemaVersion: 1,
    algorithm: 'sha256',
    mediaType,
    byteLength: bytes.byteLength,
    canonicalization: 'raw-bytes',
    value: sha256Hex(bytes),
  }
}
