import { describe, expect, it } from 'vitest'
import {
  bundleManifestV1Schema,
  getAssuranceSubmissionRequestSchema,
  getBundleManifestRequestSchema,
  recordRiskDecisionRequestSchema,
  securityAssuranceContractMajorVersionSchema,
  securityAssuranceSubmissionV1Schema,
} from '../src/index.ts'

const assessmentId = 'asm-00000000-0000-0000-0000-000000000274'

interface RuntimeSchema {
  readonly shape?: Record<string, unknown>
  safeParse(value: unknown): { readonly success: boolean }
  isOptional?(): boolean
}

function runtimeSchema(schema: unknown): RuntimeSchema {
  return schema as RuntimeSchema
}

function field(schema: unknown, name: string): RuntimeSchema {
  const value = runtimeSchema(schema).shape?.[name]
  if (value === undefined) throw new TypeError(`Missing schema field ${name}`)
  return runtimeSchema(value)
}

describe('ADR 0274 Contract major compatibility', () => {
  it('admits the supported public major and rejects an unknown major', () => {
    for (const schema of [getBundleManifestRequestSchema, getAssuranceSubmissionRequestSchema]) {
      expect(schema.safeParse({ schemaVersion: 1, assessmentId }).success).toBe(true)
      expect(schema.safeParse({ schemaVersion: 2, assessmentId }).success).toBe(false)
    }
    expect(securityAssuranceContractMajorVersionSchema.safeParse(1).success).toBe(true)
    expect(securityAssuranceContractMajorVersionSchema.safeParse(2).success).toBe(false)
    expect(field(recordRiskDecisionRequestSchema, 'contractVersion').safeParse(1).success).toBe(true)
  })

  it('keeps explicit v1 readers for sealed Manifests and Submissions', () => {
    expect(field(bundleManifestV1Schema, 'schemaVersion').safeParse(1).success).toBe(true)
    expect(field(bundleManifestV1Schema, 'schemaVersion').safeParse(2).success).toBe(false)
    expect(field(securityAssuranceSubmissionV1Schema, 'schemaVersion').safeParse(1).success).toBe(true)
    expect(field(securityAssuranceSubmissionV1Schema, 'schemaVersion').safeParse(2).success).toBe(false)
    const payload = field(securityAssuranceSubmissionV1Schema, 'payload')
    expect(field(payload, 'riskDecisions').isOptional?.()).toBe(true)
  })
})
