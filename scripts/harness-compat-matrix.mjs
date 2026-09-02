#!/usr/bin/env node
// Computes the dual-plugin Harness compatibility matrix consumed by the
// Harness Compatibility workflow. Dynamic version discovery (the live
// `git ls-remote` tag listing) is isolated behind --tags-file so the exact
// data feeding the CI matrix stays an auditable, replayable artifact.
//
// Everything fails closed: an unreachable remote, a malformed contracts
// source, fewer than three verifiable Harness tags, a declared supported
// version missing upstream, or an unknown manual ref all exit non-zero.
//
// Usage:
//   node scripts/harness-compat-matrix.mjs [--output matrix.json]
//   node scripts/harness-compat-matrix.mjs --ref dsh-v0.1.2-alpha.4
//   node scripts/harness-compat-matrix.mjs --tags-file tags.txt [--contracts src/contracts.ts]
//
// stdout carries only the compact matrix JSON; diagnostics go to stderr.

import { execFileSync } from 'node:child_process'
import { readFileSync, writeFileSync } from 'node:fs'
import { argv, exit, stderr, stdout } from 'node:process'

const HARNESS_REMOTE = 'https://github.com/deepseek-ai/deepseek-harness.git'
const RECENT_TAG_COUNT = 3
const PRIMARY_OSES = ['ubuntu-latest', 'macos-latest', 'windows-latest']
const SECONDARY_OSES = ['ubuntu-latest']
const NODE_MAJORS = ['22', '24']

function fail(message) {
  stderr.write(`harness-compat-matrix: ${message}\n`)
  exit(1)
}

function parseArgs(args) {
  const options = {
    contractsPath: new URL('../src/contracts.ts', import.meta.url),
    tagsFile: undefined,
    ref: undefined,
    output: undefined,
  }
  for (let index = 0; index < args.length; index += 1) {
    const flag = args[index]
    const value = args[index + 1]
    if (flag === '--tags-file' && value !== undefined) {
      options.tagsFile = value
    } else if (flag === '--contracts' && value !== undefined) {
      options.contractsPath = value
    } else if (flag === '--ref' && value !== undefined) {
      options.ref = value
    } else if (flag === '--output' && value !== undefined) {
      options.output = value
    } else {
      fail(`unrecognized argument: ${flag}`)
    }
    index += 1
  }
  return options
}

function parseVersion(version) {
  const match = /^(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z]+(?:\.[0-9A-Za-z]+)*))?$/.exec(version)
  if (match === null) return undefined
  return {
    major: Number(match[1]),
    minor: Number(match[2]),
    patch: Number(match[3]),
    prerelease: match[4] === undefined ? [] : match[4].split('.'),
  }
}

function compareIdentifiers(left, right) {
  const leftNumeric = /^\d+$/.test(left)
  const rightNumeric = /^\d+$/.test(right)
  if (leftNumeric && rightNumeric) return Number(left) - Number(right)
  if (leftNumeric) return -1
  if (rightNumeric) return 1
  return left < right ? -1 : left > right ? 1 : 0
}

function compareVersions(leftVersion, rightVersion) {
  const left = parseVersion(leftVersion)
  const right = parseVersion(rightVersion)
  if (left === undefined || right === undefined) {
    fail(`cannot compare non-semver Harness versions: ${leftVersion}, ${rightVersion}`)
  }
  for (const key of ['major', 'minor', 'patch']) {
    if (left[key] !== right[key]) return left[key] - right[key]
  }
  if (left.prerelease.length === 0 && right.prerelease.length === 0) return 0
  if (left.prerelease.length === 0) return 1
  if (right.prerelease.length === 0) return -1
  const length = Math.max(left.prerelease.length, right.prerelease.length)
  for (let index = 0; index < length; index += 1) {
    if (index >= left.prerelease.length) return -1
    if (index >= right.prerelease.length) return 1
    const order = compareIdentifiers(left.prerelease[index], right.prerelease[index])
    if (order !== 0) return order
  }
  return 0
}

function parseTagListing(text) {
  const tags = new Map()
  const ignored = []
  for (const line of text.split('\n')) {
    const match = /^([0-9a-f]{40})\trefs\/tags\/dsh-v(\S+?)(\^\{\})?$/.exec(line.trim())
    if (match === null) continue
    const [, commit, version, peeled] = match
    if (parseVersion(version) === undefined) {
      ignored.push(`dsh-v${version}`)
      continue
    }
    // Annotated tags list both the tag object and its peeled commit; keep the
    // peeled target so the recorded commit always points at the release tree.
    const existing = tags.get(version)
    if (existing === undefined || peeled !== undefined) {
      tags.set(version, { version, ref: `dsh-v${version}`, commit })
    }
  }
  if (ignored.length > 0) {
    stderr.write(`harness-compat-matrix: ignored non-semver dsh-v tags: ${ignored.join(', ')}\n`)
  }
  return [...tags.values()]
}

function readDeclaredCompatibility(contractsText) {
  const targetMatch = /export const TARGET_HARNESS_VERSION = '([^']+)' as const/.exec(contractsText)
  const supportedMatch = /export const SUPPORTED_HARNESS_VERSIONS = Object\.freeze\(\[([\s\S]*?)\] as const\)/
    .exec(contractsText)
  if (targetMatch === null || supportedMatch === null) {
    fail('could not parse TARGET_HARNESS_VERSION / SUPPORTED_HARNESS_VERSIONS from contracts source')
  }
  const targetVersion = targetMatch[1]
  const supportedVersions = []
  const entryPattern = /TARGET_HARNESS_VERSION|'([^']+)'/g
  let entry = entryPattern.exec(supportedMatch[1])
  while (entry !== null) {
    supportedVersions.push(entry[1] ?? targetVersion)
    entry = entryPattern.exec(supportedMatch[1])
  }
  if (supportedVersions.length === 0 || supportedVersions[0] !== targetVersion) {
    fail('SUPPORTED_HARNESS_VERSIONS must lead with TARGET_HARNESS_VERSION')
  }
  if (new Set(supportedVersions).size !== supportedVersions.length) {
    fail('SUPPORTED_HARNESS_VERSIONS contains duplicates')
  }
  for (const version of [targetVersion, ...supportedVersions]) {
    if (parseVersion(version) === undefined) {
      fail(`declared Harness version is not semver: ${version}`)
    }
  }
  return { targetVersion, supportedVersions }
}

function buildLanes(tag, track) {
  const oses = track === 'target' || track === 'manual' ? PRIMARY_OSES : SECONDARY_OSES
  return oses.flatMap(os => NODE_MAJORS.map(node => ({
    harness: tag.version,
    ref: tag.ref,
    commit: tag.commit,
    track,
    os,
    node,
  })))
}

function buildCompatibilityMatrix({ tags, targetVersion, supportedVersions, manualRef }) {
  const byVersion = new Map(tags.map(tag => [tag.version, tag]))
  if (manualRef !== undefined) {
    const version = manualRef.startsWith('dsh-v') ? manualRef.slice('dsh-v'.length) : manualRef
    const tag = byVersion.get(version)
    if (tag === undefined) {
      fail(`manual ref ${manualRef} is not a published dsh-v tag on ${HARNESS_REMOTE}`)
    }
    return { include: buildLanes(tag, 'manual') }
  }
  const recent = [...tags]
    .sort((left, right) => compareVersions(right.version, left.version))
    .slice(0, RECENT_TAG_COUNT)
  if (recent.length < RECENT_TAG_COUNT) {
    fail(`only ${recent.length} verifiable Harness tags discovered; ${RECENT_TAG_COUNT} required`)
  }
  if (!byVersion.has(targetVersion)) {
    fail(`primary target ${targetVersion} is not a published Harness tag`)
  }
  for (const version of supportedVersions) {
    if (!byVersion.has(version)) {
      fail(`declared supported Harness version ${version} is not a published tag`)
    }
  }
  const lanes = supportedVersions.flatMap(version => buildLanes(
    byVersion.get(version),
    version === targetVersion ? 'target' : 'supported',
  ))
  for (const tag of recent) {
    if (!supportedVersions.includes(tag.version)) {
      lanes.push(...buildLanes(tag, 'recent'))
    }
  }
  return { include: lanes }
}

function main() {
  const options = parseArgs(argv.slice(2))
  let contractsText
  let listing
  try {
    contractsText = readFileSync(options.contractsPath, 'utf8')
    listing = options.tagsFile === undefined
      ? execFileSync('git', ['ls-remote', '--tags', HARNESS_REMOTE], { encoding: 'utf8', maxBuffer: 16 * 1024 * 1024 })
      : readFileSync(options.tagsFile, 'utf8')
  } catch (error) {
    fail(`discovery input unavailable: ${error instanceof Error ? error.message : String(error)}`)
  }
  const declared = readDeclaredCompatibility(contractsText)
  const tags = parseTagListing(listing)
  if (tags.length === 0) {
    fail(`no verifiable dsh-v* tags discovered on ${HARNESS_REMOTE}`)
  }
  const matrix = buildCompatibilityMatrix({ tags, ...declared, manualRef: options.ref })
  const versions = [...new Set(matrix.include.map(lane => `${lane.harness}(${lane.track})`))]
  stderr.write(`harness-compat-matrix: ${matrix.include.length} lanes across ${versions.join(', ')}\n`)
  if (options.output !== undefined) {
    writeFileSync(options.output, `${JSON.stringify(matrix, null, 2)}\n`)
  }
  stdout.write(`${JSON.stringify(matrix)}\n`)
}

main()
