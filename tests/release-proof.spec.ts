import { describe, expect, it } from 'vitest'

import { SECURITY_ASSURANCE_PRODUCT_VERSION } from '../src/contracts.js'
import { releaseProofRecordV1Schema } from '../src/release-proof.js'

const candidateArtifactDigest = {
  schemaVersion: 1 as const,
  algorithm: 'sha256' as const,
  mediaType: 'application/gzip',
  byteLength: 29,
  canonicalization: 'raw-bytes' as const,
  value: 'a'.repeat(64),
}

const validRecord = {
  schemaVersion: 1,
  engineId: 'security/release-proof-record/v1',
  proofRecordId: `proof/packed-profile/linux/${SECURITY_ASSURANCE_PRODUCT_VERSION}`,
  proofKind: 'LINUX_PLATFORM',
  producer: 'PACKED_HARNESS_PROFILE_SMOKE',
  producerVersion: SECURITY_ASSURANCE_PRODUCT_VERSION,
  reportedStatus: 'PASSED',
  candidateArtifactDigest,
  completedAtEpochMs: 1_788_516_000_000,
  environment: {
    platform: 'LINUX',
    architecture: 'x64',
    nodeVersion: '24.19.0',
    harnessVersion: '0.1.2-alpha.1',
  },
  assertions: [
    { assertionId: 'PACKED_SECURITY_ASSURANCE_INSTALLED', status: 'PASSED' },
    { assertionId: 'HARNESS_WEB_RESPONDED', status: 'PASSED' },
  ],
}

describe('Release Proof Record v1', () => {
  it('accepts one exact-artifact platform proof with derived status', () => {
    expect(releaseProofRecordV1Schema.parse(validRecord)).toEqual(validRecord)
  })

  it('rejects a platform claim produced on a different platform', () => {
    expect(releaseProofRecordV1Schema.safeParse({
      ...validRecord,
      proofKind: 'WINDOWS_PLATFORM',
    }).success).toBe(false)
  })

  it('rejects a PASS summary when any recorded assertion is inconclusive', () => {
    expect(releaseProofRecordV1Schema.safeParse({
      ...validRecord,
      assertions: [
        validRecord.assertions[0],
        { assertionId: 'HARNESS_WEB_RESPONDED', status: 'INCONCLUSIVE' },
      ],
    }).success).toBe(false)
  })

  it('accepts an inconclusive browser record when the candidate ships no Workbench client', () => {
    const record = {
      ...validRecord,
      proofRecordId: `proof/packed-browser/windows/${SECURITY_ASSURANCE_PRODUCT_VERSION}`,
      proofKind: 'WORKBENCH',
      producer: 'PACKED_BROWSER_E2E',
      reportedStatus: 'INCONCLUSIVE',
      environment: { ...validRecord.environment, platform: 'WINDOWS' },
      assertions: [
        { assertionId: 'PACKED_HOST_READY', status: 'PASSED' },
        { assertionId: 'CURRENT_WEB_SHELL_LOADED', status: 'PASSED' },
        { assertionId: 'WORKBENCH_CLIENT_SHIPPED', status: 'INCONCLUSIVE' },
      ],
    }
    expect(releaseProofRecordV1Schema.parse(record)).toEqual(record)
  })

  it('rejects a passed Workbench record without an explicit shipped-client assertion', () => {
    expect(releaseProofRecordV1Schema.safeParse({
      ...validRecord,
      proofRecordId: `proof/packed-browser/windows/${SECURITY_ASSURANCE_PRODUCT_VERSION}`,
      proofKind: 'WORKBENCH',
      producer: 'PACKED_BROWSER_E2E',
      environment: { ...validRecord.environment, platform: 'WINDOWS' },
      assertions: [
        { assertionId: 'PACKED_HOST_READY', status: 'PASSED' },
        { assertionId: 'CURRENT_WEB_SHELL_LOADED', status: 'PASSED' },
      ],
    }).success).toBe(false)
  })
})
