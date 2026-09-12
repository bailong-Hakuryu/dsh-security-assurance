import LocalSubprocessRuntime from '@deepseek-ai/dsh-subprocess-local'
import { Context } from '@deepseek-ai/cordis'
import { execFile } from 'node:child_process'
import { chmod, mkdtemp, mkdir, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { promisify } from 'node:util'
import { afterEach, describe, expect, it } from 'vitest'
import {
  createRoleContextGrantV1,
  createSourceSliceRequestV1,
  type AssessmentMode,
  type DigestEnvelopeV1,
} from '../src/index.ts'
import {
  freezeSubject,
  readVerifiedRequestedSourceSlice,
} from '../src/internal/subject-freeze.ts'
import { removeTemporaryRoots } from './support/remove-temporary-root.ts'

const run = promisify(execFile)
const temporaryRoots: string[] = []

afterEach(async () => {
  await removeTemporaryRoots(temporaryRoots)
})

const structuredDigest = (value: string, mediaType: string) => ({
  schemaVersion: 1 as const,
  algorithm: 'sha256' as const,
  mediaType,
  byteLength: 1,
  canonicalization: 'dsh-canonical-json-v1' as const,
  value: value.repeat(64),
})

async function frozenTargetFixture() {
  const repositoryRoot = await mkdtemp(join(tmpdir(), 'dsh-requested-source-repository-'))
  const securityRoot = await mkdtemp(join(tmpdir(), 'dsh-requested-source-security-'))
  temporaryRoots.push(repositoryRoot, securityRoot)
  await run('git', ['init', '-b', 'main'], { cwd: repositoryRoot })
  await run('git', ['config', 'user.email', 'fixture@example.invalid'], { cwd: repositoryRoot })
  await run('git', ['config', 'user.name', 'Fixture'], { cwd: repositoryRoot })
  await mkdir(join(repositoryRoot, 'src'))
  await writeFile(join(repositoryRoot, 'src', 'allowed.ts'), 'export const answer = 42\n', 'utf8')
  await writeFile(join(repositoryRoot, 'src', 'outside.ts'), 'export const outside = true\n', 'utf8')
  await run('git', ['add', '.'], { cwd: repositoryRoot })
  await run('git', ['commit', '-m', 'requested source fixture'], { cwd: repositoryRoot })
  const commit = (await run('git', ['rev-parse', 'HEAD'], { cwd: repositoryRoot })).stdout.trim()
  const context = new Context()
  const subprocessFiber = await context.plugin(LocalSubprocessRuntime)
  const frozen = await freezeSubject({
    subprocess: context.subprocess,
    repositoryRoot,
    securityRoot,
    source: { kind: 'git_revision', commit },
    target: { kind: 'targeted', relativePaths: ['src/allowed.ts'] },
  })
  return { frozen, securityRoot, subprocessFiber }
}

function exactRequest(
  frozen: Awaited<ReturnType<typeof freezeSubject>>,
  options: {
    readonly path?: string
    readonly expectedSourceDigest?: DigestEnvelopeV1
    readonly contextBytes?: number
    readonly destinationId?: string
    readonly targetDigest?: DigestEnvelopeV1
    readonly assessmentMode?: AssessmentMode
  } = {},
) {
  const subjectDigest = frozen.manifestDigest
  const assessmentId = 'asm-00000000-0000-0000-0000-000000000168'
  const roleAttemptId = 'role-attempt-00000000-0000-0000-0000-000000000168'
  const contextGrant = createRoleContextGrantV1({
    schemaVersion: 1,
    assessmentId,
    roleAttemptId,
    roleDefinition: {
      roleId: 'discovery-analyst',
      roleVersion: '1.0.0',
      definitionDigest: structuredDigest('a', 'application/vnd.dsh.security.role-definition+json'),
    },
    purpose: {
      purposeId: 'security/deep-discovery',
      assessmentMode: options.assessmentMode ?? 'TARGETED',
      assessmentProfileId: 'security/deep',
      targetDigest: options.targetDigest ?? frozen.targetDigest,
      coverageObligationIds: ['security/source-review'],
      constraintIds: ['security/read-only'],
      peerContributionVisibility: 'NONE',
    },
    subject: {
      digest: subjectDigest,
      inventory: [{
        artifactId: 'inventory-requested-source-0168',
        schemaId: 'dsh/security-subject-inventory',
        digest: structuredDigest('c', 'application/vnd.dsh.security.subject-inventory+json'),
        disclosureCategoryId: 'security/subject-inventory',
      }],
      sourceSlices: [],
    },
    evidenceProjections: [],
    disclosure: {
      dataEgressPolicyId: 'egress/deny-by-default',
      destinationId: 'provider/reference',
      categoryIds: ['security/source-slice', 'security/subject-inventory'],
    },
    budget: {
      contextBytes: { limit: 65_536, granted: 12_288 },
      tokens: { limit: 8_192, granted: 4_096 },
    },
  })
  const request = createSourceSliceRequestV1({
    schemaVersion: 1,
    requestId: 'slice-request-00000000-0000-0000-0000-000000000168',
    assessmentId,
    roleAttemptId,
    contextGrantDigest: contextGrant.grantDigest,
    subjectDigest,
    purpose: {
      purposeId: 'security/deep-discovery',
      coverageObligationId: 'security/source-review',
      needId: 'security/trace-data-flow',
    },
    target: {
      path: options.path ?? 'src/allowed.ts',
      expectedSourceDigest: options.expectedSourceDigest ?? {
        schemaVersion: 1,
        algorithm: 'sha256',
        mediaType: 'application/octet-stream',
        byteLength: 25,
        canonicalization: 'raw-bytes',
        value: '5d2eb782fe3a645dbf5bdf2d765a254438962649c9c892811408cb50e04a5be4',
      },
    },
    disclosure: {
      dataEgressPolicyId: 'egress/deny-by-default',
      destinationId: options.destinationId ?? 'provider/reference',
      categoryId: 'security/source-slice',
    },
    budget: { contextBytes: options.contextBytes ?? 25, tokens: 32 },
  })
  return { contextGrant, request }
}

describe('ADR 0168 requested Source Slice protected materialization', () => {
  it('reads only the exact digest-bound text from the frozen Subject target', async () => {
    const fixture = await frozenTargetFixture()
    try {
      const { contextGrant, request } = exactRequest(fixture.frozen)

      const slice = await readVerifiedRequestedSourceSlice({
        securityRoot: fixture.securityRoot,
        contextGrant,
        request,
      })

      expect(slice).toEqual({
        requestDigest: request.requestDigest,
        subjectDigest: fixture.frozen.manifestDigest,
        path: 'src/allowed.ts',
        digest: request.target.expectedSourceDigest,
        text: 'export const answer = 42\n',
      })
      expect(Object.isFrozen(slice)).toBe(true)
      expect(Object.isFrozen(slice.digest)).toBe(true)
      expect(JSON.stringify(slice)).not.toMatch(/workspaceRoot|credential|capability|GRANTED/iu)
    } finally {
      await fixture.subprocessFiber.dispose()
    }
  })

  it('rejects an existing Subject file outside the frozen Target selector', async () => {
    const fixture = await frozenTargetFixture()
    try {
      const { contextGrant, request } = exactRequest(fixture.frozen, {
        path: 'src/outside.ts',
        expectedSourceDigest: {
          schemaVersion: 1,
          algorithm: 'sha256',
          mediaType: 'application/octet-stream',
          byteLength: 28,
          canonicalization: 'raw-bytes',
          value: '186187ddd92fa9cd80508f26fb7d803ad59cbd5cfd89c8eb935fb75506db3211',
        },
        contextBytes: 28,
      })

      await expect(readVerifiedRequestedSourceSlice({
        securityRoot: fixture.securityRoot,
        contextGrant,
        request,
      })).rejects.toMatchObject({
        code: 'invalid_subject',
        message: expect.stringMatching(/not contained/iu),
      })
    } finally {
      await fixture.subprocessFiber.dispose()
    }
  })

  it('rejects a requested digest that differs from the frozen Manifest entry', async () => {
    const fixture = await frozenTargetFixture()
    try {
      const { contextGrant, request } = exactRequest(fixture.frozen, {
        expectedSourceDigest: {
          schemaVersion: 1,
          algorithm: 'sha256',
          mediaType: 'application/octet-stream',
          byteLength: 25,
          canonicalization: 'raw-bytes',
          value: '0'.repeat(64),
        },
      })

      await expect(readVerifiedRequestedSourceSlice({
        securityRoot: fixture.securityRoot,
        contextGrant,
        request,
      })).rejects.toMatchObject({
        code: 'integrity_failure',
        message: expect.stringMatching(/does not match/iu),
      })
    } finally {
      await fixture.subprocessFiber.dispose()
    }
  })

  it('meters the actual bytes against the request budget', async () => {
    const fixture = await frozenTargetFixture()
    try {
      const { contextGrant, request } = exactRequest(fixture.frozen, {
        contextBytes: 24,
      })

      await expect(readVerifiedRequestedSourceSlice({
        securityRoot: fixture.securityRoot,
        contextGrant,
        request,
      })).rejects.toMatchObject({
        code: 'resource_limit',
        message: expect.stringMatching(/byte budget/iu),
      })
    } finally {
      await fixture.subprocessFiber.dispose()
    }
  })

  it('rejects frozen content drift before returning protected material', async () => {
    const fixture = await frozenTargetFixture()
    try {
      const { contextGrant, request } = exactRequest(fixture.frozen)
      const frozenFile = join(
        fixture.securityRoot,
        'subjects',
        fixture.frozen.manifestDigest.value,
        'content',
        'src',
        'allowed.ts',
      )
      await chmod(frozenFile, 0o644)
      await writeFile(frozenFile, 'export const answer = 43\n', 'utf8')

      await expect(readVerifiedRequestedSourceSlice({
        securityRoot: fixture.securityRoot,
        contextGrant,
        request,
      })).rejects.toMatchObject({
        code: 'integrity_failure',
        message: expect.stringMatching(/digest verification/iu),
      })
    } finally {
      await fixture.subprocessFiber.dispose()
    }
  })

  it('fails a rejected static preflight before touching Subject storage', async () => {
    const fixture = await frozenTargetFixture()
    try {
      const { contextGrant, request } = exactRequest(fixture.frozen, {
        destinationId: 'provider/unapproved',
      })

      await expect(readVerifiedRequestedSourceSlice({
        securityRoot: join(fixture.securityRoot, 'missing'),
        contextGrant,
        request,
      })).rejects.toThrow(/static preflight/iu)
    } finally {
      await fixture.subprocessFiber.dispose()
    }
  })

  it('rejects a Context Grant whose Target digest does not match the frozen Subject', async () => {
    const fixture = await frozenTargetFixture()
    try {
      const { contextGrant, request } = exactRequest(fixture.frozen, {
        targetDigest: structuredDigest(
          'b',
          'application/vnd.dsh.security.target-selector+json',
        ),
      })

      await expect(readVerifiedRequestedSourceSlice({
        securityRoot: fixture.securityRoot,
        contextGrant,
        request,
      })).rejects.toMatchObject({
        code: 'integrity_failure',
        message: expect.stringMatching(/Target digest/iu),
      })
    } finally {
      await fixture.subprocessFiber.dispose()
    }
  })

  it('rejects a Context Grant whose Assessment mode contradicts the frozen Target', async () => {
    const fixture = await frozenTargetFixture()
    try {
      const { contextGrant, request } = exactRequest(fixture.frozen, {
        assessmentMode: 'REPOSITORY',
      })

      await expect(readVerifiedRequestedSourceSlice({
        securityRoot: fixture.securityRoot,
        contextGrant,
        request,
      })).rejects.toMatchObject({
        code: 'invalid_subject',
        message: expect.stringMatching(/Assessment mode/iu),
      })
    } finally {
      await fixture.subprocessFiber.dispose()
    }
  })

  it('keeps protected materialization outside the package root interface', async () => {
    const packageRoot = await import('../src/index.ts')

    expect(packageRoot).not.toHaveProperty('readVerifiedRequestedSourceSlice')
  })
})
