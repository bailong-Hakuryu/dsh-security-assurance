import { spawnSync } from 'node:child_process'
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { afterEach, describe, expect, it } from 'vitest'

import {
  SUPPORTED_HARNESS_VERSIONS,
  TARGET_HARNESS_VERSION,
  isSupportedHarnessVersion,
} from '../src/contracts.js'
import { evaluateHarnessVersionAdmission } from '../src/internal/harness-version-admission.js'
import { removeTemporaryRoots } from './support/remove-temporary-root.js'

interface MatrixLane {
  readonly harness: string
  readonly ref: string
  readonly commit: string
  readonly track: 'target' | 'supported' | 'recent' | 'manual'
  readonly os: string
  readonly node: string
}

interface MatrixDocument {
  readonly include: readonly MatrixLane[]
}

const scriptPath = fileURLToPath(new URL('../scripts/harness-compat-matrix.mjs', import.meta.url))
const temporaryRoots: string[] = []

const PUBLISHED_VERSIONS = [
  '0.1.0-rc.7',
  '0.1.0-rc.8',
  '0.1.1-rc.1',
  '0.1.1-rc.2',
  '0.1.2-alpha.1',
  '0.1.2-alpha.2',
  '0.1.2-alpha.3',
  '0.1.2-alpha.4',
  '0.1.2-alpha.5',
] as const

function tagLine(version: string, index: number, peeled = false): string {
  const commit = index.toString(16).padStart(40, '0')
  return `${commit}\trefs/tags/dsh-v${version}${peeled ? '^{}' : ''}`
}

function tagCommit(version: string): string {
  const index = PUBLISHED_VERSIONS.indexOf(version as (typeof PUBLISHED_VERSIONS)[number])
  if (index < 0) throw new Error(`fixture version is not published: ${version}`)
  return (index + 1).toString(16).padStart(40, '0')
}

function writeTags(lines: readonly string[]): string {
  const directory = mkdtempSync(join(tmpdir(), 'dsh-harness-compat-'))
  temporaryRoots.push(directory)
  const file = join(directory, 'tags.txt')
  writeFileSync(file, `${lines.join('\n')}\n`)
  return file
}

function publishedTagsFixture(extra: readonly string[] = [], exclude?: string): string {
  return writeTags([
    ...PUBLISHED_VERSIONS
      .filter(version => version !== exclude)
      .map((version, index) => tagLine(version, index + 1)),
    ...extra.map((version, index) => tagLine(version, 100 + index)),
  ])
}

function runMatrix(args: readonly string[]): { status: number, stdout: string, stderr: string } {
  const result = spawnSync(process.execPath, [scriptPath, ...args], { encoding: 'utf8' })
  return {
    status: result.status ?? -1,
    stdout: result.stdout,
    stderr: result.stderr,
  }
}

function parseMatrix(stdout: string): MatrixDocument {
  return JSON.parse(stdout) as MatrixDocument
}

afterEach(async () => {
  await removeTemporaryRoots(temporaryRoots)
})

describe('declared Harness compatibility window', () => {
  it('is a closed supported set led by the primary qualification target', () => {
    expect(SUPPORTED_HARNESS_VERSIONS).toEqual([
      '0.1.2-alpha.1',
      '0.1.2-alpha.2',
      '0.1.2-alpha.3',
      '0.1.2-alpha.4',
      '0.1.2-alpha.5',
    ])
    expect(SUPPORTED_HARNESS_VERSIONS[0]).toBe(TARGET_HARNESS_VERSION)
    expect(isSupportedHarnessVersion('0.1.2-alpha.1')).toBe(true)
    expect(isSupportedHarnessVersion('0.1.2-alpha.5')).toBe(true)
    expect(isSupportedHarnessVersion('0.1.2-alpha.6')).toBe(false)
    expect(isSupportedHarnessVersion('0.1.1-rc.2')).toBe(false)
  })

  it('admits only a coherent runtime release and rejects supported-version skew', () => {
    expect(evaluateHarnessVersionAdmission([
      { packageName: '@deepseek-ai/dsh-invariants', actual: '0.1.2-alpha.5' },
      { packageName: '@deepseek-ai/dsh-typert-registry', actual: '0.1.2-alpha.5' },
    ], SUPPORTED_HARNESS_VERSIONS)).toEqual({ status: 'SUPPORTED', version: '0.1.2-alpha.5' })

    expect(evaluateHarnessVersionAdmission([
      { packageName: '@deepseek-ai/dsh-invariants', actual: '0.1.2-alpha.2' },
      { packageName: '@deepseek-ai/dsh-typert-registry', actual: '0.1.2-alpha.4' },
    ], SUPPORTED_HARNESS_VERSIONS)).toMatchObject({ status: 'VERSION_SKEW' })

    expect(evaluateHarnessVersionAdmission([
      { packageName: '@deepseek-ai/dsh-invariants', actual: '0.1.2-alpha.6' },
      { packageName: '@deepseek-ai/dsh-typert-registry', actual: '0.1.2-alpha.6' },
    ], SUPPORTED_HARNESS_VERSIONS)).toMatchObject({ status: 'UNSUPPORTED' })
  })

  it('matches the peer dependency ranges and the dual-plugin E2E script composition', () => {
    const packageJson = JSON.parse(readFileSync(
      new URL('../package.json', import.meta.url),
      'utf8',
    )) as {
      peerDependencies?: Record<string, string>
      scripts?: Record<string, string>
    }
    const expectedRange = SUPPORTED_HARNESS_VERSIONS.join(' || ')
    for (const name of [
      '@deepseek-ai/dsh-agent',
      '@deepseek-ai/dsh-commands',
      '@deepseek-ai/dsh-api-gateway',
      '@deepseek-ai/dsh-home-paths',
      '@deepseek-ai/dsh-invariants',
      '@deepseek-ai/dsh-llm',
      '@deepseek-ai/dsh-subprocess',
      '@deepseek-ai/dsh-tools',
      '@deepseek-ai/dsh-typert-protocol',
      '@deepseek-ai/dsh-typert-registry',
    ]) {
      expect(packageJson.peerDependencies?.[name]).toBe(expectedRange)
    }
    const dualPluginE2e = packageJson.scripts?.['test:dual-plugin-e2e'] ?? ''
    for (const spec of [
      'tests/control-plane-provider.spec.ts',
      'tests/change-assessment.spec.ts',
      'tests/subject-freeze.spec.ts',
      'tests/invariant.spec.ts',
    ]) {
      expect(dualPluginE2e).toContain(spec)
    }
  })
})

describe('harness-compat-matrix discovery', () => {
  it('builds the discovered matrix with the primary target on three operating systems', () => {
    const result = runMatrix(['--tags-file', publishedTagsFixture()])

    expect(result.status).toBe(0)
    const matrix = parseMatrix(result.stdout)
    expect(matrix.include).toHaveLength(14)

    const target = matrix.include.filter(lane => lane.track === 'target')
    expect(target.map(lane => lane.harness)).toEqual(Array(6).fill(TARGET_HARNESS_VERSION))
    expect(new Set(target.map(lane => lane.os))).toEqual(
      new Set(['ubuntu-latest', 'macos-latest', 'windows-latest']),
    )
    expect(new Set(target.map(lane => lane.node))).toEqual(new Set(['22', '24']))
    expect(target.every(lane => lane.ref === `dsh-v${TARGET_HARNESS_VERSION}`)).toBe(true)
    expect(target.every(lane => lane.commit === tagCommit(TARGET_HARNESS_VERSION))).toBe(true)

    for (const version of ['0.1.2-alpha.2', '0.1.2-alpha.3', '0.1.2-alpha.4', '0.1.2-alpha.5']) {
      const lanes = matrix.include.filter(lane => lane.harness === version)
      expect(lanes.map(lane => lane.track)).toEqual(['supported', 'supported'])
      expect(lanes.map(lane => lane.os)).toEqual(['ubuntu-latest', 'ubuntu-latest'])
      expect(lanes.map(lane => lane.node)).toEqual(['22', '24'])
      expect(lanes.every(lane => lane.ref === `dsh-v${version}`)).toBe(true)
      expect(lanes.every(lane => lane.commit === tagCommit(version))).toBe(true)
    }
  })

  it('deduplicates annotated tags in favour of their peeled release commit', () => {
    const tagsFile = writeTags([
      ...PUBLISHED_VERSIONS.map((version, index) => tagLine(version, index + 1)),
      tagLine('0.1.2-alpha.4', 99, true),
    ])

    const result = runMatrix(['--tags-file', tagsFile])

    expect(result.status).toBe(0)
    const matrix = parseMatrix(result.stdout)
    expect(matrix.include).toHaveLength(14)
    const alpha4 = matrix.include.filter(lane => lane.harness === '0.1.2-alpha.4')
    expect(alpha4).toHaveLength(2)
    expect(alpha4.every(lane => lane.commit === '63'.padStart(40, '0'))).toBe(true)
  })

  it('admits a newly published Harness tag into verification automatically', () => {
    const result = runMatrix(['--tags-file', publishedTagsFixture(['0.1.2-alpha.6'])])

    expect(result.status).toBe(0)
    const matrix = parseMatrix(result.stdout)
    expect(matrix.include).toHaveLength(16)
    const recent = matrix.include.filter(lane => lane.track === 'recent')
    expect(recent).toHaveLength(2)
    expect(recent.every(lane => lane.harness === '0.1.2-alpha.6')).toBe(true)
    expect(new Set(recent.map(lane => lane.node))).toEqual(new Set(['22', '24']))
  })

  it('ranks a final release above prereleases when selecting recent versions', () => {
    const result = runMatrix(['--tags-file', publishedTagsFixture(['0.1.2'])])

    expect(result.status).toBe(0)
    const matrix = parseMatrix(result.stdout)
    const recent = matrix.include.filter(lane => lane.track === 'recent')
    expect(recent).toHaveLength(2)
    expect(recent.every(lane => lane.harness === '0.1.2')).toBe(true)
    // 0.1.2-alpha.2 stays covered through the declared supported set even
    // though it fell out of the three most recent tags.
    expect(matrix.include.filter(lane => lane.harness === '0.1.2-alpha.2')).toHaveLength(2)
  })

  it('runs a manual debugging ref across the full primary lane set', () => {
    const result = runMatrix([
      '--tags-file',
      publishedTagsFixture(),
      '--ref',
      'dsh-v0.1.2-alpha.4',
    ])

    expect(result.status).toBe(0)
    const lanes = parseMatrix(result.stdout).include
    expect(lanes).toHaveLength(6)
    expect(new Set(lanes.map(lane => lane.track))).toEqual(new Set(['manual']))
    expect(lanes.every(lane => lane.harness === '0.1.2-alpha.4')).toBe(true)
    expect(new Set(lanes.map(lane => lane.os))).toEqual(
      new Set(['ubuntu-latest', 'macos-latest', 'windows-latest']),
    )
    expect(new Set(lanes.map(lane => lane.node))).toEqual(new Set(['22', '24']))
  })

  it('fails closed when fewer than three verifiable tags exist', () => {
    const tagsFile = writeTags([
      tagLine('0.1.2-alpha.1', 1),
      tagLine('0.1.2-alpha.2', 2),
    ])

    const result = runMatrix(['--tags-file', tagsFile])

    expect(result.status).toBe(1)
    expect(result.stderr).toContain('verifiable Harness tags')
  })

  it('fails closed when the primary target is not a published tag', () => {
    const result = runMatrix(['--tags-file', publishedTagsFixture([], TARGET_HARNESS_VERSION)])

    expect(result.status).toBe(1)
    expect(result.stderr).toContain('primary target')
  })

  it('fails closed when a declared supported version is not published upstream', () => {
    const result = runMatrix(['--tags-file', publishedTagsFixture([], '0.1.2-alpha.3')])

    expect(result.status).toBe(1)
    expect(result.stderr).toContain('0.1.2-alpha.3')
    expect(result.stderr).toContain('not a published tag')
  })

  it('fails closed on an unknown manual ref', () => {
    const result = runMatrix(['--tags-file', publishedTagsFixture(), '--ref', 'dsh-v9.9.9'])

    expect(result.status).toBe(1)
    expect(result.stderr).toContain('dsh-v9.9.9')
  })

  it('fails closed when the contracts source cannot be parsed', () => {
    const directory = mkdtempSync(join(tmpdir(), 'dsh-harness-compat-'))
    temporaryRoots.push(directory)
    const contracts = join(directory, 'contracts.ts')
    writeFileSync(contracts, 'export const UNRELATED = true\n')

    const result = runMatrix([
      '--tags-file',
      publishedTagsFixture(),
      '--contracts',
      contracts,
    ])

    expect(result.status).toBe(1)
    expect(result.stderr).toContain('could not parse')
  })

  it('fails closed when no verifiable tags are discovered at all', () => {
    const result = runMatrix(['--tags-file', writeTags([])])

    expect(result.status).toBe(1)
    expect(result.stderr).toContain('no verifiable')
  })
})

describe('Harness Compatibility workflow contract', () => {
  const workflow = readFileSync(
    new URL('../.github/workflows/harness-compat.yml', import.meta.url),
    'utf8',
  )

  it('discovers versions on a schedule and supports a manual debugging ref', () => {
    expect(workflow).toContain('schedule:')
    expect(workflow).toContain('cron:')
    expect(workflow).toContain('workflow_dispatch')
    expect(workflow).toContain('harness_ref')
  })

  it('feeds the discovered matrix into the compatibility job verbatim', () => {
    expect(workflow).toContain('scripts/harness-compat-matrix.mjs')
    expect(workflow).toContain('matrix: ${{ fromJSON(needs.discover.outputs.matrix) }}')
    expect(workflow).toContain('runs-on: ${{ matrix.os }}')
    expect(workflow).toContain('node-version: ${{ matrix.node }}')
    expect(workflow).toContain('ref: ${{ matrix.commit }}')
  })

  it('runs compatibility for product changes, not only matrix-infrastructure changes', () => {
    expect(workflow).toContain("- 'src/**'")
    expect(workflow).toContain("- 'package.json'")
    expect(workflow).toContain("- 'pnpm-lock.yaml'")
    expect(workflow).toContain("- 'tests/**'")
  })

  it('executes the dual-plugin joint E2E and the packed fresh-profile probe', () => {
    expect(workflow).toContain('pnpm test:dual-plugin-e2e')
    expect(workflow).toContain('pnpm pack:profile-smoke')
  })
})
