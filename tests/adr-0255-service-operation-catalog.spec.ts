import { Service } from '@deepseek-ai/cordis'
import { describe, expect, it } from 'vitest'
import SecurityAssuranceService from '../src/index.ts'

const runtimeOperations = [
  'getHealth',
  'getCatalog',
  'registerRepository',
  'updateRepository',
  'disableRepository',
  'getRepository',
  'listRepositories',
  'startAssessment',
  'getAssessment',
  'listAssessments',
  'waitForAssessmentRevision',
  'resumeAssessment',
  'cancelAssessment',
  'listFindings',
  'getFinding',
  'getEvidenceView',
  'recordRiskDecision',
  'getBundleManifest',
  'getAssuranceSubmission',
  'requestExport',
  'getExport',
] as const

type ExpectedOwnPublicKey = 'whenReady' | 'registerAnalyzer' | typeof runtimeOperations[number]
type ActualOwnPublicKey = Exclude<keyof SecurityAssuranceService, keyof Service>
type ExactPublicSurface = [ActualOwnPublicKey] extends [ExpectedOwnPublicKey]
  ? [ExpectedOwnPublicKey] extends [ActualOwnPublicKey]
    ? true
    : false
  : false

const exactPublicSurface: ExactPublicSurface = true

describe('ADR 0255: v0.1 Service operations are fixed and explicit', () => {
  it('exposes exactly the reviewed runtime catalog plus local Analyzer registration', () => {
    expect(exactPublicSurface).toBe(true)
    expect(runtimeOperations).toHaveLength(21)
    for (const operation of runtimeOperations) {
      expect(typeof SecurityAssuranceService.prototype[operation], operation).toBe('function')
    }
    expect(typeof SecurityAssuranceService.prototype.registerAnalyzer).toBe('function')
    expect('registerAnalyzerQualification' in SecurityAssuranceService.prototype).toBe(false)
  })
})
