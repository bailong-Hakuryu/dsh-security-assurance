import { execFile } from 'node:child_process'
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { promisify } from 'node:util'

const execute = promisify(execFile)
const projectRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const temporaryRoot = await mkdtemp(join(tmpdir(), 'dsh-security-assurance-pack-'))
const artifactRoot = join(temporaryRoot, 'artifacts')
const consumerRoot = join(temporaryRoot, 'consumer')
const npmCache = join(temporaryRoot, 'npm-cache')

function executeNpm(args, options) {
  if (process.platform === 'win32') {
    const npmCli = join(dirname(process.execPath), 'node_modules', 'npm', 'bin', 'npm-cli.js')
    return execute(process.execPath, [npmCli, ...args], options)
  }
  return execute('npm', args, options)
}

try {
  await mkdir(artifactRoot)
  await mkdir(consumerRoot)

  const packed = await executeNpm([
    '--cache', npmCache,
    'pack',
    '--json',
    '--pack-destination', artifactRoot,
  ], {
    cwd: projectRoot,
    windowsHide: true,
  })
  const manifest = JSON.parse(packed.stdout)
  const filename = manifest[0]?.filename
  if (typeof filename !== 'string') throw new Error('npm pack did not report an artifact filename')
  const tarball = join(artifactRoot, filename)

  await writeFile(join(consumerRoot, 'package.json'), `${JSON.stringify({
    name: 'dsh-security-assurance-packed-smoke',
    version: '0.0.0',
    private: true,
    type: 'module',
    dependencies: {
      '@deepseek-ai/cordis': '4.0.1',
      'dsh-security-assurance': pathToFileURL(tarball).href,
    },
  }, null, 2)}\n`, 'utf8')

  await executeNpm([
    '--cache', npmCache,
    'install',
    '--ignore-scripts',
    '--no-audit',
    '--no-fund',
  ], {
    cwd: consumerRoot,
    windowsHide: true,
  })

  const probePath = join(consumerRoot, 'probe.mjs')
  await writeFile(probePath, `
const contracts = await import('dsh-security-assurance/contracts')
if ('SecurityAuthorityResolver' in contracts || 'resolveTrustedInvocation' in contracts) {
  throw new Error('contracts export leaked authority minting')
}
const root = await import('dsh-security-assurance')
const { Context } = await import('@deepseek-ai/cordis')
const ctx = new Context()
if (ctx.reflect.get('securityAssurance') !== undefined) {
  throw new Error('package import activated the Service')
}
const fiber = ctx.plugin(root.default)
await fiber
if (ctx.reflect.get('securityAssurance') === undefined) {
  throw new Error('Cordis activation did not mount securityAssurance')
}
await fiber.dispose()
if (ctx.reflect.get('securityAssurance') !== undefined) {
  throw new Error('Fiber disposal did not remove securityAssurance')
}
process.stdout.write(JSON.stringify({ packedImport: 'PASS', lifecycle: 'PASS' }))
`, 'utf8')

  const probe = await execute(process.execPath, [probePath], {
    cwd: consumerRoot,
    windowsHide: true,
  })
  const result = JSON.parse(probe.stdout)
  if (result.packedImport !== 'PASS' || result.lifecycle !== 'PASS') {
    throw new Error('packed smoke probe returned an invalid result')
  }

  const installedManifest = JSON.parse(await readFile(
    join(consumerRoot, 'node_modules', 'dsh-security-assurance', 'package.json'),
    'utf8',
  ))
  process.stdout.write(`${JSON.stringify({
    artifact: filename,
    packageVersion: installedManifest.version,
    ...result,
  })}\n`)
} finally {
  await rm(temporaryRoot, { recursive: true, force: true })
}
