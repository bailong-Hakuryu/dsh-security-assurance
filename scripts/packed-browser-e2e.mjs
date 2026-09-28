import assert from 'node:assert/strict'
import { execFile, spawn } from 'node:child_process'
import { randomUUID } from 'node:crypto'
import { access, copyFile, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { constants as fsConstants } from 'node:fs'
import { tmpdir } from 'node:os'
import { basename, dirname, join, resolve } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { promisify } from 'node:util'
import { parse as parseYaml } from 'yaml'

import { SUPPORTED_HARNESS_VERSIONS } from '../lib/contracts.js'
import { writeReleaseProofRecord } from '../lib/release-proof-output.js'

const execute = promisify(execFile)
const projectRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const playwrightHarnessRoot = resolve(projectRoot, '..', 'deepseek-harness-latest')
// The npm `latest` Harness a direct-use operator installs; any verified version may be chosen.
const browserHarnessVersion = process.env.DSH_BROWSER_HARNESS_VERSION ?? '0.1.5-rc.3'
if (!SUPPORTED_HARNESS_VERSIONS.includes(browserHarnessVersion)) {
  throw new Error(`DSH_BROWSER_HARNESS_VERSION ${browserHarnessVersion} is outside the verified Harness set`)
}
const temporaryRoot = await mkdtemp(join(tmpdir(), 'dsh-security-browser-e2e-'))
const npmCache = join(temporaryRoot, 'npm-cache')
const artifactRoot = join(temporaryRoot, 'artifacts')
const runnerRoot = join(temporaryRoot, 'runner')
const repositoryRoot = join(temporaryRoot, 'repository')
const dshHome = join(temporaryRoot, 'dsh-home')
const repositoryDisplayName = 'Packed Browser E2E Repository'
const deliveryDestinationId = 'delivery/local-audit'
const scriptBodyMarker = 'browser-e2e-secret-body.js'
const cancellationSummary = 'Packed browser acceptance cancels the blocked Assessment.'
const proofOutputPath = process.env.DSH_RELEASE_PROOF_OUTPUT
const suppliedSecurityArtifact = process.env.DSH_SECURITY_PACKED_ARTIFACT
const openLocalContextEndpoint = 'securityAssuranceWorkbenchSession/openLocalContext'

/** Harness onboarding a fresh profile presents, per browser language. */
const ONBOARDING = Object.freeze({
  en: { notice: 'Internal Testing Notice', continue: 'Continue', provider: 'Add an API key to get started', later: 'Configure later' },
  zh: { notice: '内测声明', continue: '继续', provider: '添加一个 API Key 开始使用', later: '稍后配置' },
})

let hostProcess
let browser
let hostUrl
let pageUrl
let activePage
let hostOutput = ''

function normalizedPath(value) {
  return value.replaceAll('\\', '/')
}

function proofPlatform() {
  if (process.platform === 'win32') return 'WINDOWS'
  if (process.platform === 'darwin') return 'MACOS'
  if (process.platform === 'linux') return 'LINUX'
  throw new Error(`Unsupported release proof platform: ${process.platform}`)
}

function executeNpm(args, options) {
  if (process.platform === 'win32') {
    const npmCli = join(dirname(process.execPath), 'node_modules', 'npm', 'bin', 'npm-cli.js')
    return execute(process.execPath, [npmCli, ...args], { ...options, maxBuffer: 64 * 1024 * 1024 })
  }
  return execute('npm', args, { ...options, maxBuffer: 64 * 1024 * 1024 })
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

function runStreaming(command, args, options) {
  return new Promise((resolveRun, rejectRun) => {
    const child = spawn(command, args, {
      ...options,
      windowsHide: true,
      stdio: 'inherit',
    })
    child.once('error', rejectRun)
    child.once('exit', (code, signal) => {
      if (code === 0) {
        resolveRun()
        return
      }
      rejectRun(new Error(
        `${command} exited with ${code === null ? `signal ${String(signal)}` : `code ${String(code)}`}`,
      ))
    })
  })
}

function runStreamingPnpm(args, options) {
  if (process.platform !== 'win32') return runStreaming('pnpm', args, options)
  const safeArgs = args.map(argument => {
    if (!/^[a-z0-9@./:=+-]+$/iu.test(argument)) {
      throw new TypeError(`Unsafe pnpm command argument: ${JSON.stringify(argument)}`)
    }
    return argument
  })
  return runStreaming(process.env.ComSpec ?? 'cmd.exe', [
    '/d',
    '/s',
    '/c',
    ['pnpm', ...safeArgs].join(' '),
  ], options)
}

async function exists(path) {
  try {
    await access(path, fsConstants.X_OK)
    return true
  } catch {
    return false
  }
}

async function createFixtureRepository() {
  await mkdir(repositoryRoot, { recursive: true })
  await writeFile(join(repositoryRoot, 'package.json'), `${JSON.stringify({
    name: 'dsh-security-packed-browser-e2e-fixture',
    version: '1.0.0',
    type: 'module',
    scripts: { postinstall: `node ${scriptBodyMarker}` },
  }, null, 2)}\n`, 'utf8')
  await writeFile(join(repositoryRoot, scriptBodyMarker), 'throw new Error("must never execute")\n', 'utf8')
  await execute('git', ['init', '-b', 'main'], { cwd: repositoryRoot, windowsHide: true })
  await execute('git', ['config', 'user.email', 'fixture@example.invalid'], {
    cwd: repositoryRoot,
    windowsHide: true,
  })
  await execute('git', ['config', 'user.name', 'Fixture'], {
    cwd: repositoryRoot,
    windowsHide: true,
  })
  await execute('git', ['add', '.'], { cwd: repositoryRoot, windowsHide: true })
  await execute('git', ['commit', '-m', 'packed browser e2e fixture'], {
    cwd: repositoryRoot,
    windowsHide: true,
  })
}

async function packSecurityArtifact() {
  if (suppliedSecurityArtifact) {
    const source = resolve(suppliedSecurityArtifact)
    const target = join(artifactRoot, 'security-assurance-supplied.tgz')
    await mkdir(artifactRoot, { recursive: true })
    await access(source, fsConstants.R_OK)
    await copyFile(source, target)
    assert.equal(
      (await readFile(target)).equals(await readFile(source)),
      true,
      'staged Security Assurance artifact bytes changed',
    )
    return { source, target }
  }
  await mkdir(artifactRoot, { recursive: true })
  const packed = await executeNpm([
    '--cache', npmCache,
    'pack',
    '--json',
    '--pack-destination', artifactRoot,
  ], { cwd: projectRoot, windowsHide: true })
  const manifest = parseTrailingJsonArray(packed.stdout, 'Security npm pack')
  const filename = manifest[0]?.filename
  if (typeof filename !== 'string') throw new Error('npm pack did not report a Security artifact')
  return { source: undefined, target: join(artifactRoot, filename) }
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

async function readPackedBundlePatch(artifactPath) {
  const extracted = await execute('tar', ['-xOf', basename(artifactPath), 'package/cordis.patch.yml'], {
    cwd: dirname(artifactPath),
    encoding: 'utf8',
    windowsHide: true,
    maxBuffer: 1024 * 1024,
  })
  // `!!js` rows are evaluated only by the Harness loader; here they stay inert strings.
  return parseYaml(extracted.stdout, { logLevel: 'silent' })
}

/**
 * The candidate ships the local Workbench (ADRs 0321, 0322) when it exports
 * the browser client and its bundle enables the local authority row. Only
 * the packed bytes decide; no package-private marker is consulted.
 */
async function shipsLocalWorkbench(manifest, artifactPath) {
  if (manifest.exports?.['./client'] === undefined) return false
  if (!Array.isArray(manifest.files) || !manifest.files.includes('lib/client.js')) return false
  const layers = await readPackedBundlePatch(artifactPath)
  return Array.isArray(layers) && layers.some(layer => Array.isArray(layer?.insert) && layer.insert.some(row =>
    row?.name === 'dsh-security-assurance/workbench-local' && row.disabled !== true))
}

async function installFreshHarness(securityTarball) {
  await mkdir(runnerRoot, { recursive: true })
  await writeFile(join(runnerRoot, 'package.json'), `${JSON.stringify({
    name: 'dsh-security-packed-browser-runner',
    version: '0.0.0',
    private: true,
    type: 'module',
    dependencies: { '@deepseek-ai/dsh': browserHarnessVersion },
  }, null, 2)}\n`, 'utf8')
  console.log('packed-browser-e2e: installing @deepseek-ai/dsh runtime closure')
  await runStreamingPnpm([
    'install',
    '--ignore-scripts',
  ], { cwd: runnerRoot, windowsHide: true })
  console.log('packed-browser-e2e: installing the packed Security profile layer')

  const dshBin = join(runnerRoot, 'node_modules', '@deepseek-ai', 'dsh', 'lib', 'bin.js')
  const environment = {
    ...process.env,
    DSH_HOME: dshHome,
    DSH_TELEMETRY_DISABLED: '1',
  }
  await runStreaming(process.execPath, [
    dshBin,
    'plugin',
    '--profile', 'web',
    'add',
    securityTarball,
    '--save-exact',
    '--ignore-scripts',
  ], {
    cwd: runnerRoot,
    env: environment,
  })
  console.log('packed-browser-e2e: fresh Harness profile installation complete')
  return { dshBin, environment }
}

/**
 * Bind the fixture Repository and a registered delivery destination. The
 * Workbench rows keep the packed bundle's defaults: the local authority is
 * enabled and the deployment-resolver Remote stays disabled.
 */
async function configureReferenceHost() {
  const profileRoot = join(dshHome, 'profiles', 'web')
  const profilePatch = join(profileRoot, 'cordis.patch.yml')
  const config = `
- id: dsh-security-assurance
  disabled: false
  config:
    dshHome: ${JSON.stringify(normalizedPath(dshHome))}

- id: dsh-security-assurance-host-repository-provider
  disabled: false
  config:
    repositories:
      - schemaVersion: 1
        bindingId: packed-browser-e2e
        idempotencyKey: packed-browser-e2e:repository:v1
        root: ${JSON.stringify(normalizedPath(repositoryRoot))}
        displayName: ${JSON.stringify(repositoryDisplayName)}
        bindings:
          policyId: security/node-package-lifecycle
          assessmentProfileId: security/standard
          evidenceProtectionId: evidence/local-protected
          dataEgressPolicyId: egress/deny-by-default
          platform: ${process.platform}
          deliveryDestinationIds:
            - ${deliveryDestinationId}

- id: dsh-security-assurance-control-plane-provider
  disabled: true

- id: dsh-security-assurance-invariant
  disabled: true
`.trimStart()
  await writeFile(profilePatch, config, 'utf8')
}

/** Start `dsh web` and read the authenticated page URL it publishes. */
function startHost(dshBin, environment) {
  const child = spawn(process.execPath, [
    dshBin,
    'web',
    '--no-open',
    '--port', '0',
  ], {
    cwd: runnerRoot,
    env: environment,
    windowsHide: true,
    stdio: ['ignore', 'pipe', 'pipe'],
  })
  hostProcess = child
  return new Promise((resolveStart, rejectStart) => {
    let stdout = ''
    let stderr = ''
    const timeout = setTimeout(() => {
      rejectStart(new Error(`Reference Host did not publish a URL\nstdout:\n${stdout}\nstderr:\n${stderr}`))
    }, 90_000)
    const inspect = () => {
      const match = /dsh web:\s+(http:\/\/127\.0\.0\.1:\d+(?:\/\S*)?)/u.exec(`${stdout}\n${stderr}`)
      if (match?.[1] === undefined) return
      clearTimeout(timeout)
      const published = new URL(match[1])
      resolveStart({ origin: published.origin, pageUrl: published.href })
    }
    child.stdout.on('data', chunk => {
      stdout += String(chunk)
      hostOutput = `${hostOutput}${String(chunk)}`.slice(-16_000)
      inspect()
    })
    child.stderr.on('data', chunk => {
      stderr += String(chunk)
      hostOutput = `${hostOutput}${String(chunk)}`.slice(-16_000)
      inspect()
    })
    child.once('error', error => {
      clearTimeout(timeout)
      rejectStart(error)
    })
    child.once('exit', code => {
      clearTimeout(timeout)
      rejectStart(new Error(`Reference Host exited before readiness with ${String(code)}\n${stderr}`))
    })
  })
}

/** Wait until the published Host accepts connections; its URL line can precede listening. */
async function waitForHostListening() {
  for (let attempt = 0; attempt < 60; attempt += 1) {
    if (hostProcess !== undefined && hostProcess.exitCode !== null) {
      throw new Error(`Reference Host exited with ${String(hostProcess.exitCode)} before listening\n${hostOutput}`)
    }
    const reachable = await fetch(hostUrl, { redirect: 'manual', signal: AbortSignal.timeout(2_000) })
      .then(() => true, () => false)
    if (reachable) return
    await new Promise(resolveDelay => setTimeout(resolveDelay, 500))
  }
  throw new Error(`Reference Host at ${hostUrl} never accepted connections\n${hostOutput}`)
}

async function findBrowserExecutable() {
  if (process.env.DSH_BROWSER_EXECUTABLE !== undefined) {
    if (!await exists(process.env.DSH_BROWSER_EXECUTABLE)) {
      throw new Error('DSH_BROWSER_EXECUTABLE is not executable')
    }
    return process.env.DSH_BROWSER_EXECUTABLE
  }
  const candidates = process.platform === 'win32'
    ? [
        'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
        'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe',
        'C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe',
      ]
    : process.platform === 'darwin'
      ? ['/Applications/Google Chrome.app/Contents/MacOS/Google Chrome']
      : ['/usr/bin/google-chrome', '/usr/bin/chromium', '/usr/bin/chromium-browser']
  for (const candidate of candidates) {
    if (await exists(candidate)) return candidate
  }
  throw new Error('No supported local Chrome or Edge executable was found; set DSH_BROWSER_EXECUTABLE')
}

async function loadPlaywright() {
  const playwrightEntry = join(
    playwrightHarnessRoot,
    'apps',
    'web',
    'node_modules',
    'playwright',
    'index.mjs',
  )
  try {
    return await import(pathToFileURL(playwrightEntry).href)
  } catch (error) {
    throw new Error(`Harness Playwright test dependency is unavailable at ${playwrightEntry}`, { cause: error })
  }
}

async function assertFocused(page, locator, message) {
  const focused = await locator.evaluate(element => document.activeElement === element)
  if (focused) return
  // Name what holds focus instead, so a Host-owned modal or inert tree is visible in CI.
  const context = await page.evaluate(() => {
    const describe = element => element === null
      ? 'none'
      : `${element.tagName.toLowerCase()}[${element.getAttribute('aria-label') ?? element.textContent?.trim().slice(0, 40) ?? ''}]`
    return {
      active: describe(document.activeElement),
      inert: [...document.querySelectorAll('[inert]')].map(describe),
      dialogs: [...document.querySelectorAll('[role="dialog"]')].map(dialog => dialog.getAttribute('aria-label')
        ?? dialog.querySelector('h1, h2')?.textContent?.trim() ?? ''),
      moves: globalThis.__dshFocusTrace ?? [],
    }
  })
  assert.fail(`${message}; focus is on ${context.active}; inert: ${context.inert.join(', ') || 'none'}; dialogs: ${context.dialogs.join(', ') || 'none'}; focus moves: ${context.moves.join(' -> ') || 'none'}`)
}

async function dismissHostOnboarding(page, labels, required = false) {
  const dismiss = async (dialogName, actionName) => {
    const dialog = page.getByRole('dialog', { name: dialogName })
    const visible = await dialog.waitFor({ state: 'visible', timeout: required ? 30_000 : 3_000 })
      .then(() => true, () => false)
    if (!visible) return false
    await dialog.getByRole('button', { name: actionName }).click()
    await dialog.waitFor({ state: 'hidden' })
    return true
  }
  const noticeDismissed = await dismiss(labels.notice, labels.continue)
  const providerDismissed = await dismiss(labels.provider, labels.later)
  if (required) {
    assert.equal(noticeDismissed, true, 'fresh Reference Host must present its testing notice')
    assert.equal(providerDismissed, true, 'fresh Reference Host must present provider setup')
  }
  // A Host modal marks the app tree inert; Harness 0.1.7 lifts it after the
  // dialog is already hidden, and a dialog opened in between cannot take focus.
  await page.waitForFunction(() => document.querySelector('[inert]') === null, undefined, { timeout: 10_000 })
}

async function assertNoForbiddenBrowserState(page, forbiddenValues) {
  const state = await page.evaluate(async () => {
    const localStorageValues = Object.entries(localStorage)
    const sessionStorageValues = Object.entries(sessionStorage)
    const databases = typeof indexedDB.databases === 'function' ? await indexedDB.databases() : []
    const cacheNames = 'caches' in window ? await caches.keys() : []
    const serviceWorkers = 'serviceWorker' in navigator
      ? (await navigator.serviceWorker.getRegistrations()).map(registration => registration.scope)
      : []
    return {
      body: document.body.innerText,
      href: location.href,
      historyState: history.state,
      localStorageValues,
      sessionStorageValues,
      databases,
      cacheNames,
      serviceWorkers,
    }
  })
  const serialized = JSON.stringify(state)
  for (const value of forbiddenValues) {
    assert.equal(serialized.includes(value), false, `forbidden browser state retained ${JSON.stringify(value)}`)
  }
}

async function assertAccessibleControls(dialog) {
  const violations = await dialog.evaluate(root => [...root.querySelectorAll('button,input,select,textarea')]
    .filter(element => !element.disabled && element.tabIndex >= 0 && element.getClientRects().length > 0)
    .filter(element => {
      const aria = element.getAttribute('aria-label')
      const labelledBy = element.getAttribute('aria-labelledby')
      const id = element.getAttribute('id')
      const explicitLabel = id === null ? null : document.querySelector(`label[for="${CSS.escape(id)}"]`)
      const wrappingLabel = element.closest('label')
      const text = element.textContent?.trim()
      return !aria && !labelledBy && explicitLabel === null && wrappingLabel === null && !text
    })
    .map(element => element.outerHTML))
  assert.deepEqual(violations, [], 'every visible interactive control must have an accessible name')
}

async function launchBrowser() {
  const { chromium } = await loadPlaywright()
  const executablePath = await findBrowserExecutable()
  browser = await chromium.launch({
    executablePath,
    headless: true,
    args: ['--disable-background-networking', '--disable-component-update'],
  })
  return browser
}

/** Remember every context the local authority issues, so the browser can be proven not to retain one. */
function recordIssuedContexts(page, issued) {
  page.on('response', response => {
    if (new URL(response.url()).pathname !== `/api/${openLocalContextEndpoint}`) return
    void response.json().then(envelope => {
      const contextId = envelope?.result?.value?.contextId
      if (typeof contextId === 'string') issued.push(contextId)
    }, () => {})
  })
}

function assertSameOrigin(requestUrls) {
  const expectedOrigin = new URL(hostUrl).origin
  for (const requestUrl of requestUrls) {
    const parsed = new URL(requestUrl)
    if (parsed.protocol === 'data:' || parsed.protocol === 'blob:') continue
    assert.equal(parsed.origin, expectedOrigin, `unexpected remote browser resource ${requestUrl}`)
  }
}

/** Start one Assessment through the Catalog wizard and return its identity. */
async function startAssessmentFromWizard(dialog, { riskDecisionWindow }) {
  await dialog.getByRole('button', { name: 'Repositories and New Assessment', exact: true }).click()
  await dialog.getByRole('heading', { name: 'Repositories', exact: true }).waitFor()
  await dialog.getByText(repositoryDisplayName, { exact: true }).first().waitFor()
  assert.equal((await dialog.innerText()).includes(normalizedPath(repositoryRoot)), false)
  await dialog.getByRole('button', { name: 'New Assessment', exact: true }).click()
  await dialog.getByRole('heading', { name: 'New Assessment', exact: true }).waitFor()
  await dialog.getByRole('combobox', { name: 'Assessment Subject' }).selectOption('workspace_snapshot')
  if (riskDecisionWindow) await dialog.getByRole('checkbox', { name: /Risk decision window/u }).check()
  await dialog.getByRole('button', { name: 'Resolve and review preflight', exact: true }).click()
  await dialog.getByRole('heading', { name: 'Start Preflight', exact: true }).waitFor()
  await dialog.getByText(/^dsh\/builtin-node-package-lifecycle@/u).first().waitFor()
  await dialog.getByRole('button', { name: 'Confirm and start Assessment', exact: true }).click()
  const identity = dialog.locator('.dsh-security-assessment__id')
  await identity.waitFor({ timeout: 60_000 })
  const assessmentId = (await identity.innerText()).trim()
  assert.match(assessmentId, /^asm-[0-9a-f-]{36}$/u)
  return assessmentId
}

async function waitForAssessmentState(dialog, state) {
  await dialog.locator('.dsh-security-assessment__heading').getByText(state, { exact: true })
    .waitFor({ timeout: 60_000 })
}

/**
 * Drive the shipped local Workbench as an operator would (ADRs 0321, 0322):
 * every step is a real control in the real Harness page, with no test-only
 * bridge, authority context, or package in the browser.
 */
async function runLocalWorkbenchScenario() {
  await launchBrowser()
  const context = await browser.newContext({ locale: 'en-US', viewport: { width: 1280, height: 900 } })
  const page = await context.newPage()
  activePage = page
  const consoleEntries = []
  const pageErrors = []
  const requestUrls = []
  const issuedContextIds = []
  page.on('console', message => { consoleEntries.push(`${message.type()}:${message.text()}`) })
  page.on('pageerror', error => { pageErrors.push(String(error)) })
  page.on('request', request => { requestUrls.push(request.url()) })
  recordIssuedContexts(page, issuedContextIds)

  await page.goto(pageUrl, { waitUntil: 'domcontentloaded' })
  await dismissHostOnboarding(page, ONBOARDING.en, true)

  // Launcher, dialog focus, focus containment, and focus return.
  const launcher = page.getByRole('button', { name: 'Open Security Assurance Workbench' })
  await launcher.waitFor({ timeout: 45_000 })
  // Record every focus move from here on; assertFocused prints them on failure.
  await page.evaluate(() => {
    const started = performance.now()
    globalThis.__dshFocusTrace = []
    document.addEventListener('focusin', event => {
      const target = event.target
      const name = target instanceof Element
        ? `${target.tagName.toLowerCase()}[${target.getAttribute('aria-label') ?? target.textContent?.trim().slice(0, 24) ?? ''}]`
        : String(target)
      globalThis.__dshFocusTrace.push(`${Math.round(performance.now() - started)}ms ${name}`)
    }, true)
  })
  assert.equal(await launcher.evaluate(element => element.tagName), 'BUTTON')
  await launcher.click()
  const dialog = page.getByRole('dialog', { name: 'Security Assurance Workbench' })
  await dialog.waitFor({ state: 'visible' })
  await dialog.getByRole('heading', { name: 'Overview', exact: true }).waitFor()
  await dialog.getByText('No Assessments are visible to the current authority.').waitFor()
  const closeButton = dialog.getByRole('button', { name: 'Close Workbench' })
  await assertFocused(page, closeButton, 'opening the dialog must focus its close control')
  await page.keyboard.press('Tab')
  assert.equal(await dialog.evaluate(element => element.contains(document.activeElement)), true)
  await page.keyboard.press('Shift+Tab')
  assert.equal(await dialog.evaluate(element => element.contains(document.activeElement)), true)
  await page.keyboard.press('Escape')
  await dialog.waitFor({ state: 'hidden' })
  await assertFocused(page, launcher, 'Escape must return focus to the launcher')
  assert.equal(issuedContextIds.length > 0, true, 'the launcher must obtain a local Workbench context')

  // Runtime Health reads through the same local context.
  await launcher.click()
  await dialog.getByRole('heading', { name: 'Overview', exact: true }).waitFor()
  await dialog.getByRole('button', { name: 'Runtime Health', exact: true }).click()
  await dialog.getByRole('heading', { name: 'Runtime Health', exact: true }).waitFor()
  await dialog.getByText('READY', { exact: true }).first().waitFor()
  await dialog.getByRole('button', { name: 'Back to Assessment list', exact: true }).click()
  await dialog.getByRole('heading', { name: 'Overview', exact: true }).waitFor()

  // A Risk Decision Window blocks the Assessment; the local operator may cancel, never decide.
  const blockedId = await startAssessmentFromWizard(dialog, { riskDecisionWindow: true })
  await waitForAssessmentState(dialog, 'BLOCKED')
  await dialog.locator('.dsh-security-recovery').getByText('RISK_DECISION_WINDOW', { exact: true }).waitFor()
  await dialog.locator('.dsh-security-actions').getByText('CANCEL_ASSESSMENT', { exact: true }).waitFor()
  assert.equal(await dialog.getByText('RECORD_RISK_DECISION', { exact: true }).count(), 0,
    'the local operator must not be offered a Risk Decision')

  await dialog.getByRole('button', { name: 'View Findings', exact: true }).click()
  await dialog.getByRole('heading', { name: 'Findings', exact: true }).waitFor()
  await dialog.getByRole('button', { name: 'Open Finding' }).first().click()
  await dialog.getByRole('heading', { name: 'Finding Detail', exact: true }).waitFor()
  await dialog.getByText('/scripts/postinstall', { exact: true }).first().waitFor()
  assert.equal(await dialog.getByRole('radio', { name: 'Deny risk acceptance' }).count(), 0)
  // Evidence Views exist only for sealed records; before the seal the links are facts, not controls.
  await dialog.getByText('Evidence metadata becomes viewable once the Assessment is SEALED.', { exact: true })
    .waitFor()
  assert.equal(await dialog.getByRole('button', { name: /^View Evidence metadata/u }).count(), 0)

  await dialog.getByRole('button', { name: 'Back to Assessment list', exact: true }).click()
  await dialog.getByRole('button', { name: `Open ${blockedId}`, exact: true }).click()
  await waitForAssessmentState(dialog, 'BLOCKED')
  const recovery = dialog.locator('.dsh-security-recovery')
  await recovery.getByRole('textbox', { name: 'Operator reason code' }).fill('OPERATOR_CANCEL')
  await recovery.getByRole('textbox', { name: 'Operator reason summary' }).fill(cancellationSummary)
  await recovery.getByRole('button', { name: 'Request Assessment cancellation', exact: true }).click()
  await waitForAssessmentState(dialog, 'CANCELED')

  // A sealed Assessment exports to its registered destination; download stays deployment-granted.
  await dialog.getByRole('button', { name: 'Back to Assessment list', exact: true }).click()
  await dialog.getByRole('heading', { name: 'Overview', exact: true }).waitFor()
  const sealedId = await startAssessmentFromWizard(dialog, { riskDecisionWindow: false })
  await waitForAssessmentState(dialog, 'SEALED')
  await dialog.getByRole('button', { name: 'View Findings', exact: true }).click()
  await dialog.getByRole('heading', { name: 'Findings', exact: true }).waitFor()
  await dialog.getByRole('button', { name: 'Open Finding' }).first().click()
  await dialog.getByRole('heading', { name: 'Finding Detail', exact: true }).waitFor()
  await dialog.getByRole('button', { name: /^View Evidence metadata/u }).first().click()
  await dialog.getByRole('heading', { name: 'Evidence metadata', exact: true }).waitFor()
  await dialog.getByText('PROFILE_METADATA_ONLY', { exact: true }).first().waitFor()
  await dialog.getByRole('button', { name: 'Explicitly view sensitive Evidence content', exact: true }).click()
  await dialog.getByText('DISCLOSURE_NOT_AUTHORIZED', { exact: true }).first().waitFor()
  await dialog.getByText('Security Service denied sensitive content disclosure.', { exact: true }).first().waitFor()
  assert.equal(await page.locator('pre.dsh-security-evidence-disclosure__json').count(), 0,
    'the local operator must not receive sensitive Evidence content')
  assert.equal((await dialog.innerText()).includes('installLifecycleScripts'), false)
  await dialog.getByRole('button', { name: 'View Bundle and Export Readiness', exact: true }).click()
  await dialog.getByRole('heading', { name: 'Bundle and Export Readiness', exact: true }).waitFor()
  await dialog.getByText(deliveryDestinationId, { exact: true }).first().waitFor()
  await dialog.getByRole('button', { name: 'Preview Export', exact: true }).click()
  await dialog.getByRole('heading', { name: 'Export Preview and Delivery', exact: true }).waitFor()
  await dialog.getByText('security/export/internal-json-v1', { exact: true }).first().waitFor()
  assert.equal((await dialog.innerText()).includes(normalizedPath(dshHome)), false)
  await dialog.getByRole('button', { name: 'Request and deliver Export', exact: true }).click()
  await dialog.getByText('DELIVERED', { exact: true }).first().waitFor({ timeout: 60_000 })
  const exportId = /export-[0-9a-f]{64}/u.exec(await dialog.innerText())?.[0]
  assert.match(exportId ?? '', /^export-[0-9a-f]{64}$/u)
  assert.equal(await dialog.getByRole('button', { name: /download/iu }).count(), 0,
    'the local operator must not be offered an Export download')
  const deliveredArtifact = await readFile(join(
    dshHome,
    'security-assurance',
    'delivery',
    'destinations',
    'local-audit',
    `${exportId}.json`,
  ), 'utf8')
  assert.equal(JSON.parse(deliveredArtifact).source.assessmentId, sealedId)
  assert.equal(deliveredArtifact.includes(normalizedPath(repositoryRoot)), false)

  // Narrow viewport and accessible names.
  await page.setViewportSize({ width: 390, height: 844 })
  const bounded = await dialog.evaluate(element => {
    const rect = element.getBoundingClientRect()
    return rect.left >= 0 && rect.right <= window.innerWidth && rect.width <= window.innerWidth
  })
  assert.equal(bounded, true, 'Workbench dialog must remain inside a narrow viewport')
  await assertAccessibleControls(dialog)
  await page.setViewportSize({ width: 1280, height: 900 })

  // Nothing survives a reload except what the Service returns again.
  await page.reload({ waitUntil: 'domcontentloaded' })
  await dismissHostOnboarding(page, ONBOARDING.en)
  await launcher.click()
  await dialog.getByRole('heading', { name: 'Overview', exact: true }).waitFor()
  assert.equal(await dialog.getByRole('button', { name: `Open ${blockedId}`, exact: true }).count(), 1)
  await dialog.getByRole('button', { name: `Open ${sealedId}`, exact: true }).click()
  await waitForAssessmentState(dialog, 'SEALED')

  // Losing the transport fails closed; the next open recovers with a fresh context.
  await page.keyboard.press('Escape')
  await dialog.waitFor({ state: 'hidden' })
  await context.setOffline(true)
  await launcher.click()
  await dialog.getByText('Assessment unavailable', { exact: true }).first().waitFor({ timeout: 45_000 })
  await page.keyboard.press('Escape')
  await dialog.waitFor({ state: 'hidden' })
  await context.setOffline(false)
  // Reopen only once the page can reach its Host again, as an operator would.
  await page.waitForFunction(async () => {
    try {
      await fetch(location.origin, { method: 'HEAD', cache: 'no-store' })
      return true
    } catch {
      return false
    }
  }, undefined, { timeout: 30_000, polling: 500 })
  await launcher.click()
  await dialog.getByRole('heading', { name: 'Overview', exact: true }).waitFor({ timeout: 45_000 })

  // An unauthenticated caller cannot obtain a context from the same Host.
  const anonymous = await fetch(new URL(`/api/${openLocalContextEndpoint}`, hostUrl), {
    method: 'POST',
    headers: { 'content-type': 'application/json', origin: hostUrl },
    body: JSON.stringify({
      type: 'client-request',
      rpcId: randomUUID(),
      method: openLocalContextEndpoint,
      payload: { args: { request: { schemaVersion: 1 } } },
    }),
    signal: AbortSignal.timeout(15_000),
  })
  assert.equal(anonymous.ok, false, `an unauthenticated caller reached ${openLocalContextEndpoint}`)

  // The Chinese page offers the same Workbench.
  const zhContext = await browser.newContext({ locale: 'zh-CN', viewport: { width: 1280, height: 900 } })
  const zhPage = await zhContext.newPage()
  const zhErrors = []
  zhPage.on('pageerror', error => { zhErrors.push(String(error)) })
  recordIssuedContexts(zhPage, issuedContextIds)
  await zhPage.goto(pageUrl, { waitUntil: 'domcontentloaded' })
  await dismissHostOnboarding(zhPage, ONBOARDING.zh)
  await zhPage.getByRole('button', { name: '打开安全保障工作台' }).click()
  const zhDialog = zhPage.getByRole('dialog', { name: '安全保障工作台' })
  await zhDialog.getByRole('heading', { name: '概览', exact: true }).waitFor()
  await zhDialog.getByRole('button', { name: `打开 ${sealedId}`, exact: true }).click()
  await zhDialog.getByRole('button', { name: '返回 Assessment 列表', exact: true }).waitFor()
  assert.deepEqual(zhErrors, [], `Chinese page errors: ${zhErrors.join('\n')}`)
  await zhContext.close()

  // No context, path, or script body is retained by the browser.
  const forbidden = [
    normalizedPath(repositoryRoot),
    normalizedPath(dshHome),
    scriptBodyMarker,
    ...issuedContextIds,
  ]
  const cdp = await context.newCDPSession(page)
  const navigationHistory = await cdp.send('Page.getNavigationHistory')
  const browserHistory = JSON.stringify(navigationHistory.entries.map(entry => entry.url))
  for (const value of forbidden) {
    assert.equal(browserHistory.includes(value), false, `browser history retained ${JSON.stringify(value)}`)
  }
  await assertNoForbiddenBrowserState(page, forbidden)
  const browserLogs = consoleEntries.join('\n')
  for (const value of forbidden) {
    assert.equal(browserLogs.includes(value), false, `browser console retained ${JSON.stringify(value)}`)
  }
  assert.deepEqual(pageErrors, [], `browser page errors: ${pageErrors.join('\n')}`)
  assertSameOrigin(requestUrls)

  await context.close()
  await browser.close()
  browser = undefined
  activePage = undefined
  return {
    blockedAssessmentId: blockedId,
    sealedAssessmentId: sealedId,
    exportId,
    issuedContexts: issuedContextIds.length,
    requestCount: requestUrls.length,
    consoleCount: consoleEntries.length,
  }
}

async function runCurrentWebScenario() {
  await launchBrowser()
  const context = await browser.newContext({ locale: 'en-US', viewport: { width: 1280, height: 900 } })
  const page = await context.newPage()
  const pageErrors = []
  const requestUrls = []
  page.on('pageerror', error => { pageErrors.push(String(error)) })
  page.on('request', request => { requestUrls.push(request.url()) })

  await page.goto(pageUrl, { waitUntil: 'domcontentloaded' })
  await dismissHostOnboarding(page, ONBOARDING.en)
  const bodyText = await page.locator('body').innerText()
  assert.equal(bodyText.trim().length > 0, true, 'Harness Web must render visible content')
  assert.equal(
    await page.getByRole('button', { name: 'Open Security Assurance Workbench' }).count(),
    0,
    'a candidate without the local Workbench must not expose its launcher',
  )
  assert.deepEqual(pageErrors, [], `browser page errors: ${pageErrors.join('\n')}`)
  assertSameOrigin(requestUrls)

  await context.close()
  await browser.close()
  browser = undefined
  return {
    currentWebShell: 'PASS',
    workbenchClient: 'NOT_SHIPPED',
    requestCount: requestUrls.length,
  }
}

/** On failure, show what the Workbench dialog displayed; it renders no context or Host path. */
async function reportWorkbenchDialog() {
  const text = await activePage?.locator('.dsh-security-dialog').innerText({ timeout: 2_000 }).catch(() => undefined)
  if (text !== undefined) console.error(`packed-browser-e2e: Workbench dialog at failure:\n${text.slice(0, 6_000)}`)
}

async function stopHost() {
  const child = hostProcess
  hostProcess = undefined
  if (child === undefined) return undefined
  if (child.exitCode !== null) return { code: child.exitCode, signal: child.signalCode }
  const exited = new Promise(resolveExit => child.once('exit', (code, signal) => {
    resolveExit({ code, signal })
  }))
  child.kill('SIGTERM')
  const timeout = new Promise(resolveTimeout => setTimeout(() => resolveTimeout('timeout'), 15_000))
  const result = await Promise.race([exited, timeout])
  if (result === 'timeout') {
    child.kill('SIGKILL')
    throw new Error('Reference Host did not stop after SIGTERM')
  }
  return result
}

async function assertHostStopped() {
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), 2_000)
  try {
    await fetch(hostUrl, { signal: controller.signal })
    throw new Error('Reference Host still accepted requests after lifecycle disposal')
  } catch (error) {
    if (error instanceof Error && error.message.includes('still accepted')) throw error
  } finally {
    clearTimeout(timer)
  }
}

try {
  if (proofOutputPath !== undefined && suppliedSecurityArtifact === undefined) {
    throw new Error(
      'DSH_RELEASE_PROOF_OUTPUT requires DSH_SECURITY_PACKED_ARTIFACT so the proof binds a retained candidate.',
    )
  }
  console.log('packed-browser-e2e: creating isolated Repository and packed artifact')
  await mkdir(npmCache, { recursive: true })
  await createFixtureRepository()
  const securityArtifact = await packSecurityArtifact()
  const packedManifest = await readPackedPackageManifest(securityArtifact.target)
  const workbenchShipped = await shipsLocalWorkbench(packedManifest, securityArtifact.target)

  console.log(`packed-browser-e2e: installing fresh Harness ${browserHarnessVersion} profile`)
  const host = await installFreshHarness(securityArtifact.target)
  await configureReferenceHost()

  console.log('packed-browser-e2e: starting packed Reference Test Host')
  const started = await startHost(host.dshBin, host.environment)
  hostUrl = started.origin
  pageUrl = started.pageUrl
  await waitForHostListening()

  console.log(`packed-browser-e2e: driving real browser at ${hostUrl}`)
  const evidence = workbenchShipped
    ? await runLocalWorkbenchScenario()
    : await runCurrentWebScenario()
  const exit = await stopHost()
  assert.equal(
    exit?.code === 0 || (process.platform === 'win32' && exit?.code === null && exit.signal === 'SIGTERM'),
    true,
    `Reference Host must stop cleanly; exit=${JSON.stringify(exit)}`,
  )
  await assertHostStopped()

  if (proofOutputPath !== undefined) {
    const platform = proofPlatform()
    await writeReleaseProofRecord({
      outputPath: proofOutputPath,
      candidateArtifactPath: securityArtifact.target,
      retainedCandidateArtifactPath: securityArtifact.source,
      candidateArtifactMediaType: 'application/gzip',
      proofRecordId: `proof/packed-browser/${platform.toLowerCase()}/${packedManifest.version}`,
      proofKind: 'WORKBENCH',
      producer: 'PACKED_BROWSER_E2E',
      producerVersion: packedManifest.version,
      completedAtEpochMs: Date.now(),
      environment: {
        platform,
        architecture: process.arch,
        nodeVersion: process.versions.node,
        harnessVersion: browserHarnessVersion,
      },
      assertions: workbenchShipped
        ? [
            { assertionId: 'PACKED_HOST_READY', status: 'PASSED' },
            { assertionId: 'WORKBENCH_CLIENT_SHIPPED', status: 'PASSED' },
            { assertionId: 'REAL_BROWSER_FLOW_COMPLETED', status: 'PASSED' },
            { assertionId: 'REAL_AUTHORITY_ENFORCED', status: 'PASSED' },
            { assertionId: 'ACCESSIBILITY_CHECKS_PASSED', status: 'PASSED' },
            { assertionId: 'BILINGUAL_FLOW_PASSED', status: 'PASSED' },
            { assertionId: 'SENSITIVE_STATE_REDACTED', status: 'PASSED' },
            { assertionId: 'RECONNECT_RECOVERED', status: 'PASSED' },
            { assertionId: 'LIFECYCLE_DISPOSED', status: 'PASSED' },
          ]
        : [
            { assertionId: 'PACKED_HOST_READY', status: 'PASSED' },
            { assertionId: 'CURRENT_WEB_SHELL_LOADED', status: 'PASSED' },
            { assertionId: 'WORKBENCH_CLIENT_SHIPPED', status: 'INCONCLUSIVE' },
            { assertionId: 'LIFECYCLE_DISPOSED', status: 'PASSED' },
          ],
    })
  }

  console.log(JSON.stringify(workbenchShipped
    ? {
        packedHost: 'PASS',
        harnessVersion: browserHarnessVersion,
        realBrowser: 'PASS',
        realAuthority: 'PASS',
        accessibility: 'PASS',
        bilingual: 'PASS',
        redaction: 'PASS',
        reconnect: 'PASS',
        lifecycle: 'PASS',
        ...evidence,
      }
    : {
        packedHost: 'PASS',
        harnessVersion: browserHarnessVersion,
        realBrowser: 'PASS',
        lifecycle: 'PASS',
        ...evidence,
      }, null, 2))
} catch (error) {
  await reportWorkbenchDialog()
  throw error
} finally {
  await browser?.close().catch(() => {})
  await stopHost().catch(() => {})
  await rm(temporaryRoot, { recursive: true, force: true })
}
