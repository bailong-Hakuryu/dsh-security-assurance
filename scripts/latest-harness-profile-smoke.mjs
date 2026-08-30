import assert from 'node:assert/strict'
import { execFile, spawn } from 'node:child_process'
import { access, mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { DatabaseSync } from 'node:sqlite'
import { fileURLToPath } from 'node:url'
import { promisify } from 'node:util'

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

async function runHarness(args) {
  return execute(process.execPath, [harnessCli, ...args], {
    cwd: repositoryRoot,
    env: commandEnvironment,
    windowsHide: true,
    timeout: 180_000,
    maxBuffer: 64 * 1024 * 1024,
  })
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
          if (response.status >= 300 && response.status < 400) {
            const location = response.headers.get('location')
            const cookie = response.headers.get('set-cookie')?.split(';', 1)[0]
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

  const controlTarball = process.env.DSH_CONTROL_PLANE_PACKED_ARTIFACT === undefined
    ? await pack(controlPlaneRoot, 'Control Plane')
    : resolve(process.env.DSH_CONTROL_PLANE_PACKED_ARTIFACT)
  const securityTarball = process.env.DSH_SECURITY_PACKED_ARTIFACT === undefined
    ? await pack(projectRoot, 'Security Assurance')
    : resolve(process.env.DSH_SECURITY_PACKED_ARTIFACT)
  await access(controlTarball)
  await access(securityTarball)
  await runHarness(['plugin', '--profile', 'web', 'add', controlTarball])
  await runHarness(['plugin', '--profile', 'web', 'add', securityTarball])

  const dump = await runHarness(['--profile', 'web', '--dump-config'])
  assert.match(dump.stdout, /# == dsh-engineering-control-plane/u)
  assert.match(dump.stdout, /name: dsh-engineering-control-plane\/tools/u)
  assert.match(dump.stdout, /providerVersion: 0\.1\.0-rc\.7/u)
  assert.match(dump.stdout, /repositoryBindingId: current-workspace/u)
  assert.match(dump.stdout, /# == dsh-security-assurance/u)
  assert.match(dump.stdout, /name: dsh-security-assurance\/tools/u)
  assert.match(dump.stdout, /bindingId: current-workspace/u)
  assert.match(dump.stdout, /name: dsh-security-assurance\/workbench-remote[\s\S]*disabled: true/u)

  await bootAndProbeWeb()
  process.stdout.write('Latest Harness profile smoke passed: both packed bundles composed and Web responded.\n')
} finally {
  await rm(temporaryRoot, { recursive: true, force: true })
}
