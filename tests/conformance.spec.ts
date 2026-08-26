import { readFile } from 'node:fs/promises'
import { describe, expect, it } from 'vitest'
import {
  assertConformanceReportV1,
  createAnalyzerConformanceFixtureV1,
  createAssuranceProviderConformanceFixtureV1,
  createReferenceAnalyzerFactoryV1,
  runAssuranceProviderContractSuiteV1,
  runAnalyzerContractSuiteV1,
} from '../src/conformance.ts'

describe('public conformance module', () => {
  it('proves the deterministic Reference Analyzer through the public v1 contract', async () => {
    const fixture = createAnalyzerConformanceFixtureV1()
    const report = await runAnalyzerContractSuiteV1({
      descriptor: fixture.descriptor,
      factory: createReferenceAnalyzerFactoryV1(),
    }, fixture)

    expect(report).toEqual({
      schemaVersion: 1,
      suiteId: 'dsh-security-assurance/analyzer-contract/v1',
      subjectId: 'fixture/conformance-analyzer@1.0.0',
      passed: true,
      checks: [
        { schemaVersion: 1, checkId: 'descriptor.valid', status: 'PASS' },
        { schemaVersion: 1, checkId: 'instance.descriptor-bound', status: 'PASS' },
        { schemaVersion: 1, checkId: 'analysis.result-valid', status: 'PASS' },
        { schemaVersion: 1, checkId: 'analysis.identity-bound', status: 'PASS' },
        { schemaVersion: 1, checkId: 'analysis.subject-bound', status: 'PASS' },
        { schemaVersion: 1, checkId: 'analysis.coverage-bound', status: 'PASS' },
        { schemaVersion: 1, checkId: 'lifecycle.disposed', status: 'PASS' },
      ],
    })
    expect(Object.isFrozen(report)).toBe(true)
    expect(Object.isFrozen(report.checks)).toBe(true)
    expect(() => assertConformanceReportV1(report)).not.toThrow()
  })

  it('rejects malformed Reference Analyzer output and still disposes its Attempt instance', async () => {
    const fixture = createAnalyzerConformanceFixtureV1()
    const report = await runAnalyzerContractSuiteV1({
      descriptor: fixture.descriptor,
      factory: createReferenceAnalyzerFactoryV1('MALFORMED_OUTPUT'),
    }, fixture)

    expect(report.passed).toBe(false)
    expect(report.checks).toEqual([
      { schemaVersion: 1, checkId: 'descriptor.valid', status: 'PASS' },
      { schemaVersion: 1, checkId: 'instance.descriptor-bound', status: 'PASS' },
      { schemaVersion: 1, checkId: 'analysis.result-valid', status: 'FAIL' },
      { schemaVersion: 1, checkId: 'analysis.identity-bound', status: 'FAIL' },
      { schemaVersion: 1, checkId: 'analysis.subject-bound', status: 'FAIL' },
      { schemaVersion: 1, checkId: 'analysis.coverage-bound', status: 'FAIL' },
      { schemaVersion: 1, checkId: 'lifecycle.disposed', status: 'PASS' },
    ])
    expect(() => assertConformanceReportV1(report)).toThrow(
      'Conformance failed: analysis.result-valid, analysis.identity-bound, analysis.subject-bound, analysis.coverage-bound',
    )
  })

  it('aborts a delayed Reference Analyzer and proves bounded Attempt cleanup', async () => {
    const fixture = createAnalyzerConformanceFixtureV1({ invocation: 'CANCEL' })
    const report = await runAnalyzerContractSuiteV1({
      descriptor: fixture.descriptor,
      factory: createReferenceAnalyzerFactoryV1('DELAY_UNTIL_ABORT'),
    }, fixture)

    expect(report).toEqual({
      schemaVersion: 1,
      suiteId: 'dsh-security-assurance/analyzer-contract/v1',
      subjectId: 'fixture/conformance-analyzer@1.0.0',
      passed: true,
      checks: [
        { schemaVersion: 1, checkId: 'descriptor.valid', status: 'PASS' },
        { schemaVersion: 1, checkId: 'instance.descriptor-bound', status: 'PASS' },
        { schemaVersion: 1, checkId: 'analysis.cancellation-observed', status: 'PASS' },
        { schemaVersion: 1, checkId: 'lifecycle.disposed', status: 'PASS' },
      ],
    })
  })

  it('redacts deterministic Analyzer failures into stable canonical checks', async () => {
    const fixture = createAnalyzerConformanceFixtureV1()
    const report = await runAnalyzerContractSuiteV1({
      descriptor: fixture.descriptor,
      factory: createReferenceAnalyzerFactoryV1('FAILURE'),
    }, fixture)

    expect(report.passed).toBe(false)
    expect(report.checks.filter(check => check.status === 'FAIL').map(check => check.checkId)).toEqual([
      'analysis.result-valid',
      'analysis.identity-bound',
      'analysis.subject-bound',
      'analysis.coverage-bound',
    ])
    expect(JSON.stringify(report)).not.toContain('Reference Analyzer deterministic failure')
    expect(() => assertConformanceReportV1(report)).toThrow(
      'Conformance failed: analysis.result-valid, analysis.identity-bound, analysis.subject-bound, analysis.coverage-bound',
    )
  })

  it('normalizes one supplied public Service composition into a canonical Provider report', async () => {
    const fixture = createAssuranceProviderConformanceFixtureV1()
    const report = await runAssuranceProviderContractSuiteV1(fixture, async subject => ({
      schemaVersion: 1,
      descriptor: subject.descriptor,
      invocationState: 'settled',
      outcomeKind: 'sealed_submission',
      claimedOutcome: 'satisfied',
    }))

    expect(report).toEqual({
      schemaVersion: 1,
      suiteId: 'dsh-security-assurance/assurance-provider-contract/v1',
      subjectId: 'fixture/conformance-provider@1.0.0',
      passed: true,
      checks: [
        { schemaVersion: 1, checkId: 'descriptor.valid', status: 'PASS' },
        { schemaVersion: 1, checkId: 'composition.descriptor-bound', status: 'PASS' },
        { schemaVersion: 1, checkId: 'composition.invocation-settled', status: 'PASS' },
        { schemaVersion: 1, checkId: 'composition.outcome-accepted', status: 'PASS' },
      ],
    })
    expect(() => assertConformanceReportV1(report)).not.toThrow()
  })

  it('redacts public composition adapter failures into stable Provider checks', async () => {
    const fixture = createAssuranceProviderConformanceFixtureV1()
    const report = await runAssuranceProviderContractSuiteV1(fixture, async () => {
      throw new Error('credential=must-not-cross-the-conformance-seam')
    })

    expect(report.passed).toBe(false)
    expect(report.checks).toEqual([
      { schemaVersion: 1, checkId: 'descriptor.valid', status: 'PASS' },
      { schemaVersion: 1, checkId: 'composition.descriptor-bound', status: 'FAIL' },
      { schemaVersion: 1, checkId: 'composition.invocation-settled', status: 'FAIL' },
      { schemaVersion: 1, checkId: 'composition.outcome-accepted', status: 'FAIL' },
    ])
    expect(JSON.stringify(report)).not.toContain('must-not-cross-the-conformance-seam')
    expect(() => assertConformanceReportV1(report)).toThrow(
      'Conformance failed: composition.descriptor-bound, composition.invocation-settled, composition.outcome-accepted',
    )
  })

  it('is published as a side-effect-free package entry', async () => {
    const manifest = JSON.parse(await readFile(new URL('../package.json', import.meta.url), 'utf8'))

    expect(manifest.exports['./conformance']).toEqual({
      types: './lib/types/conformance.d.ts',
      default: './lib/conformance.js',
    })
    expect(manifest.files).toEqual(expect.arrayContaining([
      'lib/conformance.js',
      'lib/types/conformance.d.ts',
      'lib/types/conformance.d.ts.map',
    ]))
  })
})
