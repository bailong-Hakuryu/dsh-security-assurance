import { SecurityAssuranceTestComposition } from './support/security-assurance-test-composition.ts'
import { removeTemporaryRoots } from './support/remove-temporary-root.ts'
import { execFile } from 'node:child_process'
import { mkdir, mkdtemp, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { promisify } from 'node:util'
import { Context } from '@deepseek-ai/cordis'
import { afterEach, describe, expect, it } from 'vitest'
import type {
  AssessmentId,
  SecurityAssuranceService,
  SecurityInvocation,
} from '../src/index.ts'
import { GITLEAKS_POLICY_ID, NPM_AUDIT_POLICY_ID } from '../src/index.ts'
import { referenceHostInvocation } from './support/reference-host.ts'

const run = promisify(execFile)
const temporaryRoots: string[] = []

afterEach(async () => {
  await removeTemporaryRoots(temporaryRoots)
})

async function commit(repository: string, message: string): Promise<string> {
  await run('git', ['add', '.'], { cwd: repository })
  await run('git', ['commit', '-m', message], { cwd: repository })
  return (await run('git', ['rev-parse', 'HEAD'], { cwd: repository })).stdout.trim()
}

async function changeRepositoryFixture(
  baseFiles: Readonly<Record<string, string>>,
  headFiles: Readonly<Record<string, string>>,
): Promise<{ readonly root: string; readonly baseCommit: string; readonly headCommit: string }> {
  const root = await mkdtemp(join(tmpdir(), 'dsh-security-change-'))
  temporaryRoots.push(root)
  await run('git', ['init', '-b', 'main'], { cwd: root })
  await run('git', ['config', 'user.email', 'fixture@example.invalid'], { cwd: root })
  await run('git', ['config', 'user.name', 'Fixture'], { cwd: root })
  for (const [path, contents] of Object.entries(baseFiles)) {
    const destination = join(root, ...path.split('/'))
    await mkdir(dirname(destination), { recursive: true })
    await writeFile(destination, contents, 'utf8')
  }
  const baseCommit = await commit(root, 'change base')
  for (const [path, contents] of Object.entries(headFiles)) {
    const destination = join(root, ...path.split('/'))
    await mkdir(dirname(destination), { recursive: true })
    await writeFile(destination, contents, 'utf8')
  }
  const headCommit = await commit(root, 'change head')
  return { root, baseCommit, headCommit }
}

async function waitUntilSealed(
  service: SecurityAssuranceService,
  invocation: SecurityInvocation,
  assessmentId: AssessmentId,
): Promise<void> {
  let revision = 1
  for (let attempt = 0; attempt < 5; attempt += 1) {
    const changed = await service.waitForAssessmentRevision(invocation, {
      schemaVersion: 1,
      assessmentId,
      afterRevision: revision,
      timeoutMs: 5_000,
    })
    if (!changed.ok) throw new Error(`wait failed: ${changed.error.code}`)
    const assessment = await service.getAssessment(invocation, { schemaVersion: 1, assessmentId })
    if (!assessment.ok) throw new Error(`query failed: ${assessment.error.code}`)
    if (assessment.value.state === 'SEALED') return
    revision = assessment.value.assessmentRevision
  }
  throw new Error('Assessment did not reach SEALED')
}

async function runChangeAssessment(input: {
  readonly id: string
  readonly policyId: string
  readonly repository: string
  readonly baseCommit: string
  readonly headCommit: string
}): Promise<{
  readonly assessment: Awaited<ReturnType<SecurityAssuranceService['getAssessment']>>
  readonly findings: Awaited<ReturnType<SecurityAssuranceService['listFindings']>>
}> {
  const dshHome = await mkdtemp(join(tmpdir(), 'dsh-security-change-home-'))
  temporaryRoots.push(dshHome)
  const ctx = new Context()
  const fiber = await ctx.plugin(SecurityAssuranceTestComposition, { dshHome })
  const platform = process.platform
  if (platform !== 'win32' && platform !== 'linux' && platform !== 'darwin') {
    throw new Error(`unsupported test platform: ${platform}`)
  }
  try {
    const invocation = referenceHostInvocation(ctx.securityAssurance)
    const registered = await ctx.securityAssurance.registerRepository(invocation, {
      schemaVersion: 1,
      contractVersion: 1,
      idempotencyKey: `change-register-${input.id}`,
      root: input.repository,
      displayName: 'Exact committed change fixture',
      bindings: {
        policyId: input.policyId,
        assessmentProfileId: 'security/standard',
        evidenceProtectionId: 'evidence/local-protected',
        dataEgressPolicyId: 'egress/deny-by-default',
        platform,
        deliveryDestinationIds: [],
      },
    })
    if (!registered.ok) throw new Error(`registration failed: ${registered.error.code}`)
    const started = await ctx.securityAssurance.startAssessment(invocation, {
      schemaVersion: 1,
      contractVersion: 1,
      idempotencyKey: `change-assessment-${input.id}`,
      repositoryId: registered.value.repositoryId,
      subject: {
        kind: 'change',
        baseCommit: input.baseCommit,
        headCommit: input.headCommit,
      },
      assessmentMode: 'CHANGE',
      assessmentProfileId: 'security/standard',
      target: {
        kind: 'change',
        baseCommit: input.baseCommit,
        headCommit: input.headCommit,
        impactCone: 'POLICY_DEFAULT',
      },
      requestedStrongerControlIds: [],
    })
    if (!started.ok) throw new Error(`start failed: ${started.error.code}`)
    await waitUntilSealed(ctx.securityAssurance, invocation, started.value.assessmentId)
    return {
      assessment: await ctx.securityAssurance.getAssessment(invocation, {
        schemaVersion: 1,
        assessmentId: started.value.assessmentId,
      }),
      findings: await ctx.securityAssurance.listFindings(invocation, {
        schemaVersion: 1,
        assessmentId: started.value.assessmentId,
        limit: 64,
      }),
    }
  } finally {
    await fiber.dispose()
  }
}

describe('exact-commit CHANGE Assessment', () => {
  it('evaluates the complete resulting tree for the Node lifecycle policy', async () => {
    const fixture = await changeRepositoryFixture({
      'package.json': '{"name":"change-fixture","version":"1.0.0"}\n',
      'packages/unchanged/package.json': '{"name":"unchanged","scripts":{"postinstall":"node setup.js"}}\n',
    }, {
      'src/change.ts': 'export const changed = true\n',
    })
    const result = await runChangeAssessment({
      id: 'node-full-tree',
      policyId: 'security/node-package-lifecycle',
      repository: fixture.root,
      baseCommit: fixture.baseCommit,
      headCommit: fixture.headCommit,
    })
    expect(result.assessment).toMatchObject({
      ok: true,
      value: {
        state: 'SEALED',
        subject: { kind: 'change' },
        contract: {
          assessmentMode: 'CHANGE',
          target: {
            kind: 'change',
            baseCommit: fixture.baseCommit,
            headCommit: fixture.headCommit,
            impactCone: 'POLICY_DEFAULT',
          },
        },
        verdict: 'FAILED',
        coverage: { status: 'COMPLETE' },
      },
    })
    expect(result.findings).toMatchObject({
      ok: true,
      value: {
        findings: [{
          validationState: 'VALIDATED',
          policySignificance: 'BLOCKING',
        }],
      },
    })
  }, 30_000)

  it('seals a clean exact change as SATISFIED with complete Coverage', async () => {
    const fixture = await changeRepositoryFixture({
      'package.json': '{"name":"clean-change-fixture","version":"1.0.0"}\n',
    }, {
      'src/change.ts': 'export const changed = true\n',
    })
    const result = await runChangeAssessment({
      id: 'node-clean',
      policyId: 'security/node-package-lifecycle',
      repository: fixture.root,
      baseCommit: fixture.baseCommit,
      headCommit: fixture.headCommit,
    })
    expect(result.assessment).toMatchObject({
      ok: true,
      value: {
        state: 'SEALED',
        contract: { assessmentMode: 'CHANGE' },
        verdict: 'SATISFIED',
        coverage: {
          status: 'COMPLETE',
          mandatoryObligations: 1,
          satisfiedObligations: 1,
          gapObligations: 0,
        },
      },
    })
    expect(result.findings).toMatchObject({ ok: true, value: { findings: [] } })
  }, 30_000)

  it('normalizes and independently validates the npm audit report frozen in the head tree', async () => {
    const vulnerableReport = `${JSON.stringify({
      auditReportVersion: 2,
      vulnerabilities: {
        lodash: {
          name: 'lodash',
          severity: 'high',
          isDirect: true,
          via: [{
            title: 'Prototype Pollution in lodash',
            url: 'https://github.com/advisories/GHSA-35jh-r3h4-6jhm',
            severity: 'high',
          }],
          range: '<4.17.21',
          fixAvailable: true,
        },
      },
    }, null, 2)}\n`
    const fixture = await changeRepositoryFixture({
      'package.json': '{"name":"audit-change-fixture","version":"1.0.0"}\n',
      'npm-audit.json': '{"auditReportVersion":2,"vulnerabilities":{}}\n',
    }, {
      'npm-audit.json': vulnerableReport,
    })
    const result = await runChangeAssessment({
      id: 'npm-audit',
      policyId: NPM_AUDIT_POLICY_ID,
      repository: fixture.root,
      baseCommit: fixture.baseCommit,
      headCommit: fixture.headCommit,
    })
    expect(result.assessment).toMatchObject({
      ok: true,
      value: {
        state: 'SEALED',
        subject: { kind: 'change' },
        contract: { assessmentMode: 'CHANGE' },
        verdict: 'FAILED',
        coverage: { status: 'COMPLETE' },
      },
    })
    expect(result.findings).toMatchObject({
      ok: true,
      value: {
        findings: [{
          validationState: 'VALIDATED',
          validationContractId: 'dsh/security/npm-audit-validation/v1',
          technicalSeverity: 'HIGH',
          policySignificance: 'BLOCKING',
        }],
      },
    })
  }, 30_000)

  it('normalizes and independently validates the redacted Gitleaks projection in the head tree', async () => {
    const report = `${JSON.stringify([{
      Description: 'Fixture secret',
      StartLine: 3,
      EndLine: 3,
      StartColumn: 10,
      EndColumn: 50,
      Match: 'token = FIXTURE_CHANGE_SECRET_NOT_A_REAL_CREDENTIAL',
      Secret: 'FIXTURE_CHANGE_SECRET_NOT_A_REAL_CREDENTIAL',
      File: 'config/change.env',
      Author: 'Fixture Author',
      Email: 'fixture@example.invalid',
      Message: 'sensitive fixture metadata',
      RuleID: 'generic-api-key',
    }], null, 2)}\n`
    const fixture = await changeRepositoryFixture({
      'package.json': '{"name":"gitleaks-change-fixture","version":"1.0.0"}\n',
      'gitleaks-report.json': '[]\n',
    }, {
      'gitleaks-report.json': report,
    })
    const result = await runChangeAssessment({
      id: 'gitleaks',
      policyId: GITLEAKS_POLICY_ID,
      repository: fixture.root,
      baseCommit: fixture.baseCommit,
      headCommit: fixture.headCommit,
    })
    expect(result.assessment).toMatchObject({
      ok: true,
      value: {
        state: 'SEALED',
        subject: { kind: 'change' },
        contract: { assessmentMode: 'CHANGE' },
        verdict: 'FAILED',
        coverage: { status: 'COMPLETE' },
      },
    })
    expect(result.findings).toMatchObject({
      ok: true,
      value: {
        findings: [{
          validationState: 'VALIDATED',
          validationContractId: 'dsh/security/gitleaks-validation/v1',
          technicalSeverity: 'HIGH',
          policySignificance: 'BLOCKING',
        }],
      },
    })
    expect(JSON.stringify(result)).not.toContain('FIXTURE_CHANGE_SECRET_NOT_A_REAL_CREDENTIAL')
  }, 30_000)
})
