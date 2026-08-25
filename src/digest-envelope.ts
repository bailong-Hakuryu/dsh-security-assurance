import { z } from 'zod'

export interface DigestEnvelopeV1 {
  readonly schemaVersion: 1
  readonly algorithm: 'sha256'
  readonly mediaType: string
  readonly byteLength: number
  readonly canonicalization: 'raw-bytes' | 'dsh-canonical-json-v1'
  readonly value: string
}

export const digestEnvelopeV1Schema: z.ZodType<DigestEnvelopeV1> = z.strictObject({
  schemaVersion: z.literal(1),
  algorithm: z.literal('sha256'),
  mediaType: z.string().regex(/^application\/[a-z0-9.+-]+$|^text\/[a-z0-9.+-]+$/).max(128),
  byteLength: z.number().int().nonnegative(),
  canonicalization: z.enum(['raw-bytes', 'dsh-canonical-json-v1']),
  value: z.string().regex(/^[0-9a-f]{64}$/),
})
