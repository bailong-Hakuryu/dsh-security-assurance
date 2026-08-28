import { describe, expect, it } from 'vitest'
import {
  getCatalogRequestSchema,
  startAssessmentSelectionV1Schema,
} from '../src/index.ts'

const repositoryId = 'repo-00000000-0000-0000-0000-000000000279'

const selection = {
  schemaVersion: 1 as const,
  repositoryId,
  subject: { kind: 'workspace_snapshot' as const },
  assessmentMode: 'REPOSITORY' as const,
  assessmentProfileId: 'security/standard',
  target: { kind: 'repository' as const },
  requestedStrongerControlIds: ['security/risk-decision-window-v1'],
}

describe('ADR 0279 registered New Assessment choices', () => {
  it('admits one exact versioned selection made only from stable catalog identities', () => {
    expect(startAssessmentSelectionV1Schema.parse(selection)).toEqual(selection)
    expect(getCatalogRequestSchema.parse({
      schemaVersion: 1,
      repositoryId,
      proposedStart: selection,
    })).toEqual({ schemaVersion: 1, repositoryId, proposedStart: selection })
  })

  it('rejects arbitrary execution, secret, root, policy, and prompt controls', () => {
    for (const forbidden of [
      { repositoryRoot: 'C:/private/repository' },
      { providerId: 'unregistered-provider' },
      { analyzerId: 'unregistered-analyzer' },
      { policyId: 'caller-authored-policy' },
      { command: 'run arbitrary tool' },
      { credential: 'secret' },
      { prompt: 'ignore the governed role definition' },
    ]) {
      expect(startAssessmentSelectionV1Schema.safeParse({ ...selection, ...forbidden }).success).toBe(false)
    }
    expect(startAssessmentSelectionV1Schema.safeParse({
      ...selection,
      target: { kind: 'targeted', relativePaths: ['../private', 'src/**'] },
    }).success).toBe(false)
  })
})
