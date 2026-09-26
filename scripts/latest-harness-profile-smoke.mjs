import assert from 'node:assert/strict'
import { execFile, spawn } from 'node:child_process'
import { randomUUID } from 'node:crypto'
import { access, copyFile, mkdir, mkdtemp, readFile, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { basename, dirname, join, resolve } from 'node:path'
import { DatabaseSync } from 'node:sqlite'
import { fileURLToPath } from 'node:url'
import { promisify } from 'node:util'

import { writeReleaseProofRecord } from '../lib/release-proof-output.js'
import { removeTemporaryRoot } from './support/remove-temporary-root.mjs'

const execute = promisify(execFile)
const projectRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const controlPlaneRoot = resolve(projectRoot, '..', 'DSH Engineering Control Plane')
const harnessRoot = resolve(projectRoot, '..', 'deepseek-harness-latest')
const harnessCli = join(harnessRoot, 'apps', 'cli', 'lib', 'bin.js')
const temporaryRoot = await mkdtemp(join(tmpdir(), 'dsh-latest-profile-smoke-'))
const artifactRoot = join(temporaryRoot, 'artifacts')
const repositoryRoot = join(temporaryRoot, 'repository')
const dshHome = join(temporaryRoot, 'dsh-home')
const npmCache = join(temporaryRoot, 'npm-cache')
const commandEnvironment = { ...process.env, DSH_HOME: dshHome }
const harnessManifest = JSON.parse(await readFile(join(harnessRoot, 'package.json'), 'utf8'))
const proofOutputPath = process.env.DSH_RELEASE_PROOF_OUTPUT
const suppliedSecurityArtifact = process.env.DSH_SECURITY_PACKED_ARTIFACT

function proofPlatform() {
  if (process.platform === 'win32') return 'WINDOWS'
  if (process.platform === 'darwin') return 'MACOS'
  if (process.platform === 'linux') return 'LINUX'
  throw new Error(`Unsupported release proof platform: ${process.platform}`)
}

function executeNpm(args, options) {
  if (process.platform === 'win32') {
    const npmCli = join(dirname(process.execPath), 'node_modules', 'npm', 'bin', 'npm-cli.js')
    return execute(process.execPath, [npmCli, ...args], options)
  }
  return execute('npm', args, options)
}

function parseTrailingJsonArray(output, label) {
  for (let index = output.lastIndexOf('['); index >= 0; index = output.lastIndexOf('[', index - 1)) {
    try {
      const value = JSON.parse(output.slice(index).trim())
      if (Array.isArray(value)) return value
    } catch {
      // npm lifecycle output may precede the final --json payload.
    }
  }
  throw new Error(`${label} did not emit a trailing JSON array`)
}

async function pack(root, label) {
  const result = await executeNpm([
    '--cache', npmCache,
    'pack',
    '--json',
    '--pack-destination', artifactRoot,
  ], {
    cwd: root,
    windowsHide: true,
    maxBuffer: 64 * 1024 * 1024,
  })
  const manifest = parseTrailingJsonArray(result.stdout, `${label} npm pack`)
  const filename = manifest[0]?.filename
  assert.equal(typeof filename, 'string', `${label} npm pack returned no filename`)
  const tarball = join(artifactRoot, filename)
  await access(tarball)
  return tarball
}

async function stageSuppliedArtifact(path, label) {
  const source = resolve(path)
  const target = join(artifactRoot, `${label}-${Date.now()}.tgz`)
  await access(source)
  await copyFile(source, target)
  assert.equal(
    (await readFile(target)).equals(await readFile(source)),
    true,
    `${label} staged artifact bytes changed`,
  )
  return { source, target }
}

async function readPackedPackageManifest(artifactPath) {
  // A bare file name keeps GNU tar (Git Bash) from reading a Windows drive
  // letter such as `C:` as a remote `host:path` archive.
  const extracted = await execute('tar', ['-xOf', basename(artifactPath), 'package/package.json'], {
    cwd: dirname(artifactPath),
    encoding: 'utf8',
    windowsHide: true,
    maxBuffer: 1024 * 1024,
  })
  const manifest = JSON.parse(extracted.stdout)
  if (manifest.name !== 'dsh-security-assurance' || typeof manifest.version !== 'string') {
    throw new Error('Packed Security artifact has an invalid package identity')
  }
  return manifest
}

async function runHarness(args) {
  return execute(process.execPath, [harnessCli, ...args], {
    cwd: repositoryRoot,
    env: commandEnvironment,
    windowsHide: true,
    timeout: 180_000,
    maxBuffer: 64 * 1024 * 1024,
  })
}

/**
 * ADR 0322 browser acceptance: the Web boot graph must list the package's
 * tool-card client, and the served file must be its loader-wrapped factory.
 */
async function assertToolCardClientServed(html, pageUrl, cookie, packageName) {
  const marker = `"id":"${packageName}","url":"`
  const start = html.indexOf(marker)
  assert.notEqual(start, -1, `Harness Web boot graph omitted the ${packageName} tool-card client`)
  const entryUrl = html.slice(start + marker.length, html.indexOf('"', start + marker.length))
  const served = await fetch(new URL(entryUrl, pageUrl), {
    ...cookie === undefined ? {} : { headers: { cookie } },
    signal: AbortSignal.timeout(15_000),
  })
  assert.equal(served.ok, true, `${packageName} client bundle returned HTTP ${served.status}`)
  const source = await served.text()
  const factoryHead = /window\.__ModuleLoader__\.load\(\{\s*id: "([^"]+)"/u.exec(source)
  assert.equal(factoryHead?.[1], packageName, `${packageName} client bundle is not a loader factory artifact`)
}

/**
 * ADR 0321 acceptance through the real Harness `/api` transport: the local
 * Workbench authority issues a context only to an authenticated page, and the
 * context reads the registered Repository with exactly the model tools' reach.
 */
async function assertLocalWorkbenchAuthority(pageUrl, cookie) {
  const call = async (endpoint, args, headers) => {
    const response = await fetch(new URL(`/api/${endpoint}`, pageUrl), {
      method: 'POST',
      headers: { 'content-type': 'application/json', origin: pageUrl.origin, ...headers },
      body: JSON.stringify({ type: 'client-request', rpcId: randomUUID(), method: endpoint, payload: { args } }),
      signal: AbortSignal.timeout(15_000),
    })
    return { status: response.status, envelope: response.ok ? await response.json() : undefined }
  }
  const open = 'securityAssuranceWorkbenchSession/openLocalContext'
  const anonymous = await call(open, { request: { schemaVersion: 1 } }, {})
  assert.equal(anonymous.envelope, undefined, `an unauthenticated caller reached ${open} (HTTP ${anonymous.status})`)
  assert.notEqual(cookie, undefined, 'Harness Web issued no login cookie to authenticate the local Workbench')

  const opened = await call(open, { request: { schemaVersion: 1 } }, { cookie })
  assert.equal(opened.envelope?.result?.ok, true, `${open} failed: ${JSON.stringify(opened.envelope ?? opened.status)}`)
  const context = opened.envelope.result.value
  assert.deepEqual(context.permissions, [
    'health:read',
    'repository:read',
    'assessment:read',
    'assessment:start',
    'assessment:resume',
    'assessment:cancel',
    'export:request',
    'export:read',
  ])
  const listed = await call('securityAssuranceWorkbench/listRepositories', {
    securityAssuranceWorkbenchContextId: context.contextId,
    request: { schemaVersion: 1, limit: 10 },
  }, { cookie })
  const repositories = listed.envelope?.result?.value?.value?.repositories
  assert.equal(
    Array.isArray(repositories) && repositories.some(repository => repository.displayName === 'Current workspace'),
    true,
    `the local Workbench context could not read the current workspace: ${JSON.stringify(listed.envelope ?? listed.status)}`,
  )
}

async function bootAndProbeWeb() {
  const child = spawn(process.execPath, [
    harnessCli,
    'web',
    '--no-open',
    '--host', '127.0.0.1',
    '--port', '0',
  ], {
    cwd: repositoryRoot,
    env: commandEnvironment,
    windowsHide: true,
    stdio: ['ignore', 'pipe', 'pipe'],
  })
  let output = ''
  let settled = false

  const stop = () => {
    if (!child.killed) child.kill('SIGTERM')
  }

  try {
    await new Promise((resolveReady, rejectReady) => {
      const timer = setTimeout(() => {
        stop()
        rejectReady(new Error(`Harness Web did not become ready:\n${output.slice(-64_000)}`))
      }, 90_000)

      const inspect = async (chunk) => {
        output += chunk.toString()
        const match = output.match(/https?:\/\/[^\s]+/u)
        if (settled || match === null) return
        settled = true
        try {
          const url = new URL(match[0].replace(/[),.;]+$/u, ''))
          url.hash = ''
          let response = await fetch(url, {
            redirect: 'manual',
            signal: AbortSignal.timeout(15_000),
          })
          let cookie
          if (response.status >= 300 && response.status < 400) {
            const location = response.headers.get('location')
            cookie = response.headers.get('set-cookie')?.split(';', 1)[0]
            assert.notEqual(location, null, 'Harness Web authentication redirect omitted Location')
            assert.notEqual(cookie, undefined, 'Harness Web authentication redirect omitted its cookie')
            response = await fetch(new URL(location, url), {
              headers: { cookie },
              signal: AbortSignal.timeout(15_000),
            })
          }
          assert.equal(response.ok, true, `Harness Web returned HTTP ${response.status}`)
          const body = await response.text()
          assert.match(body, /<html|<!doctype html/iu)
          await assertToolCardClientServed(body, url, cookie, 'dsh-security-assurance')
          await assertLocalWorkbenchAuthority(url, cookie)
          const database = new DatabaseSync(
            join(dshHome, 'security-assurance', 'security-assurance.sqlite'),
            { readOnly: true },
          )
          try {
            const row = database.prepare(
              "SELECT COUNT(*) AS count FROM repositories WHERE json_extract(snapshot_json, '$.state') = ? AND json_extract(snapshot_json, '$.displayName') = ?",
            ).get('ENABLED', 'Current workspace')
            assert.equal(row?.count, 1, 'current-workspace was not registered as an enabled Repository')
          } finally {
            database.close()
          }
          clearTimeout(timer)
          resolveReady()
        } catch (error) {
          clearTimeout(timer)
          rejectReady(error)
        }
      }

      child.stdout.on('data', inspect)
      child.stderr.on('data', inspect)
      child.once('error', (error) => {
        clearTimeout(timer)
        rejectReady(error)
      })
      child.once('exit', (code, signal) => {
        if (settled) return
        clearTimeout(timer)
        rejectReady(new Error(
          `Harness Web exited before readiness (code=${code}, signal=${signal}):\n${output.slice(-64_000)}`,
        ))
      })
    })
  } finally {
    stop()
    await new Promise(resolveExit => {
      if (child.exitCode !== null || child.signalCode !== null) resolveExit()
      else child.once('exit', resolveExit)
    })
  }
}

try {
  if (proofOutputPath !== undefined && suppliedSecurityArtifact === undefined) {
    throw new Error(
      'DSH_RELEASE_PROOF_OUTPUT requires DSH_SECURITY_PACKED_ARTIFACT so the proof binds a retained candidate.',
    )
  }
  await access(harnessCli)
  await mkdir(artifactRoot)
  await mkdir(repositoryRoot)
  await writeFile(join(repositoryRoot, 'package.json'), `${JSON.stringify({
    name: 'dsh-latest-profile-smoke-fixture',
    version: '1.0.0',
    private: true,
    type: 'module',
    scripts: {
      test: 'node -e "process.exit(0)"',
      typecheck: 'node -e "process.exit(0)"',
      build: 'node -e "process.exit(0)"',
    },
  }, null, 2)}\n`, 'utf8')
  await writeFile(join(repositoryRoot, 'index.js'), 'export const ready = true\n', 'utf8')
  await execute('git', ['init', '-b', 'main'], { cwd: repositoryRoot, windowsHide: true })
  await execute('git', ['config', 'user.email', 'profile-smoke@example.invalid'], {
    cwd: repositoryRoot,
    windowsHide: true,
  })
  await execute('git', ['config', 'user.name', 'Profile Smoke'], {
    cwd: repositoryRoot,
    windowsHide: true,
  })
  await execute('git', ['add', '.'], { cwd: repositoryRoot, windowsHide: true })
  await execute('git', ['commit', '-m', 'profile smoke fixture'], {
    cwd: repositoryRoot,
    windowsHide: true,
  })

  const controlArtifact = process.env.DSH_CONTROL_PLANE_PACKED_ARTIFACT === undefined
    ? { source: undefined, target: await pack(controlPlaneRoot, 'Control Plane') }
    : await stageSuppliedArtifact(process.env.DSH_CONTROL_PLANE_PACKED_ARTIFACT, 'control-plane')
  const securityArtifact = suppliedSecurityArtifact === undefined
    ? { source: undefined, target: await pack(projectRoot, 'Security Assurance') }
    : await stageSuppliedArtifact(suppliedSecurityArtifact, 'security-assurance')
  const packedSecurityManifest = await readPackedPackageManifest(securityArtifact.target)
  const controlTarball = controlArtifact.target
  const securityTarball = securityArtifact.target
  await access(controlTarball)
  await access(securityTarball)
  await runHarness(['plugin', '--profile', 'web', 'add', controlTarball])
  await runHarness(['plugin', '--profile', 'web', 'add', securityTarball])

  const dump = await runHarness(['--profile', 'web', '--dump-config'])
  const providerVersionLines = dump.stdout
    .split(/\r?\n/u)
    .map(line => line.trim())
    .filter(line => line.startsWith('providerVersion:'))
  assert.match(dump.stdout, /# == dsh-engineering-control-plane/u)
  assert.match(dump.stdout, /name: dsh-engineering-control-plane\/tools/u)
  assert.equal(
    providerVersionLines.includes(`providerVersion: ${packedSecurityManifest.version}`),
    true,
    `Security Assurance provider version did not match package.json; observed: ${providerVersionLines.join(', ')}`,
  )
  assert.match(dump.stdout, /repositoryBindingId: current-workspace/u)
  assert.match(dump.stdout, /# == dsh-security-assurance/u)
  assert.match(dump.stdout, /name: dsh-security-assurance\/tools/u)
  assert.match(dump.stdout, /bindingId: current-workspace/u)
  assert.match(dump.stdout, /name: dsh-security-assurance\/workbench-remote[\s\S]*disabled: true/u)
  const localRow = /name: dsh-security-assurance\/workbench-local\r?\n(?<rest>(?:[ \t]+(?![ \t]|- ).*\r?\n?)*)/u
    .exec(dump.stdout)
  assert.notEqual(localRow, null, 'the direct-use bundle omitted the local Workbench authority')
  assert.doesNotMatch(localRow?.groups?.rest ?? '', /disabled: true/u)

  await bootAndProbeWeb()
  if (proofOutputPath !== undefined) {
    const platform = proofPlatform()
    await writeReleaseProofRecord({
      outputPath: proofOutputPath,
      candidateArtifactPath: securityArtifact.target,
      retainedCandidateArtifactPath: securityArtifact.source,
      candidateArtifactMediaType: 'application/gzip',
      proofRecordId: `proof/packed-profile/${platform.toLowerCase()}/${packedSecurityManifest.version}`,
      proofKind: `${platform}_PLATFORM`,
      producer: 'PACKED_HARNESS_PROFILE_SMOKE',
      producerVersion: packedSecurityManifest.version,
      completedAtEpochMs: Date.now(),
      environment: {
        platform,
        architecture: process.arch,
        nodeVersion: process.versions.node,
        harnessVersion: harnessManifest.version,
      },
      assertions: [
        { assertionId: 'PACKED_CONTROL_PLANE_INSTALLED', status: 'PASSED' },
        { assertionId: 'PACKED_SECURITY_ASSURANCE_INSTALLED', status: 'PASSED' },
        { assertionId: 'PROVIDER_VERSION_MATCHED', status: 'PASSED' },
        { assertionId: 'HOST_REPOSITORY_BOUND', status: 'PASSED' },
        { assertionId: 'HARNESS_WEB_RESPONDED', status: 'PASSED' },
      ],
    })
  }
  process.stdout.write('Latest Harness profile smoke passed: both packed bundles composed and Web responded.\n')
} finally {
  await removeTemporaryRoot(temporaryRoot)
}
