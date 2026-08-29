import assert from 'node:assert/strict'
import { execFile, spawn } from 'node:child_process'
import { access, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { constants as fsConstants } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { promisify } from 'node:util'

const execute = promisify(execFile)
const projectRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const harnessRoot = resolve(projectRoot, '..', 'deepseek-harness-master')
const temporaryRoot = await mkdtemp(join(tmpdir(), 'dsh-security-browser-e2e-'))
const npmCache = join(temporaryRoot, 'npm-cache')
const artifactRoot = join(temporaryRoot, 'artifacts')
const runnerRoot = join(temporaryRoot, 'runner')
const repositoryRoot = join(temporaryRoot, 'repository')
const dshHome = join(temporaryRoot, 'dsh-home')
const referencePackageRoot = join(temporaryRoot, 'reference-browser')
const fullAuthorityContextId = 'workbench-browser-e2e-full-authority'
const deniedAuthorityContextId = 'workbench-browser-e2e-denied-authority'
const operatorPrincipalId = 'reference-browser-host-operator'
const repositoryDisplayName = 'Packed Browser E2E Repository'
const deliveryDestinationId = 'delivery/local-audit'
const scriptBodyMarker = 'browser-e2e-secret-body.js'
const riskRationale = 'The validated install lifecycle risk remains blocking for this release.'
const fullPermissions = [
  'health:read',
  'repository:read',
  'repository:admin',
  'assessment:start',
  'assessment:read',
  'assessment:resume',
  'assessment:cancel',
  'evidence:disclose:validation-review',
  'assurance-submission:read',
  'export:request',
  'export:read',
  'export:download',
  'risk:decide',
  'risk:break-glass',
]

let hostProcess
let browser
let hostUrl

function normalizedPath(value) {
  return value.replaceAll('\\', '/')
}

function executeNpm(args, options) {
  if (process.platform === 'win32') {
    const npmCli = join(dirname(process.execPath), 'node_modules', 'npm', 'bin', 'npm-cli.js')
    return execute(process.execPath, [npmCli, ...args], { ...options, maxBuffer: 64 * 1024 * 1024 })
  }
  return execute('npm', args, { ...options, maxBuffer: 64 * 1024 * 1024 })
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

function runStreamingNpm(args, options) {
  if (process.platform === 'win32') {
    const npmCli = join(dirname(process.execPath), 'node_modules', 'npm', 'bin', 'npm-cli.js')
    return runStreaming(process.execPath, [npmCli, ...args], options)
  }
  return runStreaming('npm', args, options)
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
  await mkdir(artifactRoot, { recursive: true })
  const packed = await executeNpm([
    '--cache', npmCache,
    'pack',
    '--json',
    '--pack-destination', artifactRoot,
  ], { cwd: projectRoot, windowsHide: true })
  const manifest = JSON.parse(packed.stdout)
  const filename = manifest[0]?.filename
  if (typeof filename !== 'string') throw new Error('npm pack did not report a Security artifact')
  return join(artifactRoot, filename)
}

async function createReferenceBrowserPackage() {
  await mkdir(referencePackageRoot, { recursive: true })
  await writeFile(join(referencePackageRoot, 'package.json'), `${JSON.stringify({
    name: 'dsh-security-assurance-reference-browser',
    version: '0.0.0-test-only',
    private: true,
    type: 'module',
    main: './index.js',
    exports: {
      '.': './index.js',
      './client': './client.js',
      './cordis.patch.yml': './cordis.patch.yml',
      './package.json': './package.json',
    },
    files: ['index.js', 'client.js', 'cordis.patch.yml'],
    dsh: {
      bundle: { patch: './cordis.patch.yml' },
      client: {
        inject: [
          'dsh-security-assurance',
          '@deepseek-ai/dsh-client-locale',
        ],
        platform: 'web',
        immediately: true,
      },
    },
  }, null, 2)}\n`, 'utf8')
  await writeFile(join(referencePackageRoot, 'index.js'), `
export const name = 'dsh-security-assurance-reference-browser'
export function apply() {}
export default { name, apply }
`.trimStart(), 'utf8')
  await writeFile(join(referencePackageRoot, 'cordis.patch.yml'), `
- insert:
    - id: dsh-security-assurance-reference-browser
      name: dsh-security-assurance-reference-browser
`.trimStart(), 'utf8')
  await writeFile(join(referencePackageRoot, 'client.js'), `
window.__ModuleLoader__.load({
  id: 'dsh-security-assurance-reference-browser',
  factory: () => {
    const plugin = {
      name: 'dsh-security-assurance-reference-browser',
      inject: ['securityAssuranceWorkbench', 'locale'],
      apply(ctx) {
        const api = Object.freeze({
          openFull() {
            return ctx.securityAssuranceWorkbench.openAssessmentSelection({
              securityAssuranceWorkbenchContextId: ${JSON.stringify(fullAuthorityContextId)},
            })
          },
          openDenied() {
            return ctx.securityAssuranceWorkbench.openAssessmentSelection({
              securityAssuranceWorkbenchContextId: ${JSON.stringify(deniedAuthorityContextId)},
            })
          },
          close() {
            ctx.securityAssuranceWorkbench.closeAssessment()
          },
          setLocale(locale) {
            ctx.locale.setLocale(locale)
          },
          state() {
            return ctx.securityAssuranceWorkbench.getState()
          },
        })
        Object.defineProperty(window, '__DSH_SECURITY_BROWSER_E2E__', {
          configurable: true,
          enumerable: false,
          writable: false,
          value: api,
        })
        return () => { delete window.__DSH_SECURITY_BROWSER_E2E__ }
      },
    }
    return { ...plugin, default: plugin }
  },
})
`.trimStart(), 'utf8')
}

async function installFreshHarness(securityTarball) {
  await mkdir(runnerRoot, { recursive: true })
  await writeFile(join(runnerRoot, 'package.json'), `${JSON.stringify({
    name: 'dsh-security-packed-browser-runner',
    version: '0.0.0',
    private: true,
    type: 'module',
    dependencies: { '@deepseek-ai/dsh': '0.1.1-rc.2' },
  }, null, 2)}\n`, 'utf8')
  console.log('packed-browser-e2e: installing @deepseek-ai/dsh runtime closure')
  await runStreamingPnpm([
    'install',
    '--ignore-scripts',
  ], { cwd: runnerRoot, windowsHide: true })
  console.log('packed-browser-e2e: installing packed Security and reference Host profile layers')

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
    referencePackageRoot,
    '--save-exact',
    '--ignore-scripts',
  ], {
    cwd: runnerRoot,
    env: environment,
  })
  console.log('packed-browser-e2e: fresh Harness profile installation complete')
  return { dshBin, environment }
}

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

- id: dsh-security-assurance-workbench-remote
  disabled: false
  config: !!js |-
    ({
      resolveAuthorityContext(contextId) {
        if (contextId === ${JSON.stringify(fullAuthorityContextId)}) {
          return {
            principalId: ${JSON.stringify(operatorPrincipalId)},
            permissions: ${JSON.stringify(fullPermissions)}
          }
        }
        if (contextId === ${JSON.stringify(deniedAuthorityContextId)}) {
          return {
            principalId: 'reference-browser-denied-operator',
            permissions: ['health:read']
          }
        }
        return undefined
      }
    })
`.trimStart()
  await writeFile(profilePatch, config, 'utf8')
}

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
      const match = /dsh web:\s+(http:\/\/127\.0\.0\.1:\d+)/u.exec(`${stdout}\n${stderr}`)
      if (match?.[1] === undefined) return
      clearTimeout(timeout)
      resolveStart(match[1])
    }
    child.stdout.on('data', chunk => {
      stdout += String(chunk)
      inspect()
    })
    child.stderr.on('data', chunk => {
      stderr += String(chunk)
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
  const playwrightEntry = join(harnessRoot, 'apps', 'web', 'node_modules', 'playwright', 'index.mjs')
  try {
    return await import(pathToFileURL(playwrightEntry).href)
  } catch (error) {
    throw new Error(`Harness Playwright test dependency is unavailable at ${playwrightEntry}`, { cause: error })
  }
}

async function waitForWorkbenchBridge(page) {
  await page.waitForFunction(() => window.__DSH_SECURITY_BROWSER_E2E__ !== undefined, undefined, {
    timeout: 45_000,
  })
}

async function callWorkbenchBridge(page, method) {
  return page.evaluate(async selectedMethod => {
    const bridge = window.__DSH_SECURITY_BROWSER_E2E__
    if (bridge === undefined) throw new Error('Reference browser bridge is unavailable')
    return bridge[selectedMethod]()
  }, method)
}

async function setWorkbenchLocale(page, locale) {
  await page.evaluate(selectedLocale => {
    const bridge = window.__DSH_SECURITY_BROWSER_E2E__
    if (bridge === undefined) throw new Error('Reference browser bridge is unavailable')
    bridge.setLocale(selectedLocale)
  }, locale)
}

async function waitForWorkbenchState(page, predicateSource, timeout = 45_000) {
  try {
    await page.waitForFunction(source => {
      const bridge = window.__DSH_SECURITY_BROWSER_E2E__
      if (bridge === undefined) return false
      const predicate = Function('state', `return (${source})(state)`)
      return predicate(bridge.state())
    }, predicateSource, { timeout })
  } catch (error) {
    const current = await page.evaluate(() => window.__DSH_SECURITY_BROWSER_E2E__?.state())
    throw new Error(`Timed out waiting for Workbench state ${predicateSource}; current=${JSON.stringify(current)}`, {
      cause: error,
    })
  }
  return page.evaluate(() => window.__DSH_SECURITY_BROWSER_E2E__.state())
}

async function assertFocused(page, locator, message) {
  const focused = await locator.evaluate(element => document.activeElement === element)
  assert.equal(focused, true, message)
}

async function dismissReferenceHostOnboarding(page, required = false) {
  const dismiss = async (dialogName, actionName) => {
    const dialog = page.getByRole('dialog', { name: dialogName })
    const visible = await dialog.waitFor({ state: 'visible', timeout: required ? 30_000 : 3_000 })
      .then(() => true, () => false)
    if (!visible) return false
    await dialog.getByRole('button', { name: actionName }).click()
    await dialog.waitFor({ state: 'hidden' })
    return true
  }
  const noticeDismissed = await dismiss('Internal Testing Notice', 'Continue')
  const providerDismissed = await dismiss('Add an API key to get started', 'Configure later')
  if (required) {
    assert.equal(noticeDismissed, true, 'fresh Reference Host must present its testing notice')
    assert.equal(providerDismissed, true, 'fresh Reference Host must present provider setup')
  }
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

async function runBrowserScenario() {
  const { chromium } = await loadPlaywright()
  const executablePath = await findBrowserExecutable()
  browser = await chromium.launch({
    executablePath,
    headless: true,
    args: ['--disable-background-networking', '--disable-component-update'],
  })
  const context = await browser.newContext({ locale: 'en-US', viewport: { width: 1280, height: 900 } })
  const page = await context.newPage()
  const consoleEntries = []
  const pageErrors = []
  const requestUrls = []
  page.on('console', message => { consoleEntries.push(`${message.type()}:${message.text()}`) })
  page.on('pageerror', error => { pageErrors.push(String(error)) })
  page.on('request', request => { requestUrls.push(request.url()) })

  await page.goto(hostUrl, { waitUntil: 'domcontentloaded' })
  await waitForWorkbenchBridge(page)
  await setWorkbenchLocale(page, 'en')
  await callWorkbenchBridge(page, 'openFull')
  await waitForWorkbenchState(page, 'state => state.kind === "SELECTION_READY"')

  await dismissReferenceHostOnboarding(page, true)

  const launcher = page.getByRole('button', { name: 'Open Security Assurance Workbench' })
  await launcher.focus()
  assert.equal(await launcher.evaluate(element => element.tagName), 'BUTTON')
  assert.equal(await launcher.isEnabled(), true)
  await launcher.click()
  const dialog = page.getByRole('dialog', { name: 'Security Assurance Workbench' })
  await dialog.waitFor({ state: 'visible' })
  const closeButton = page.getByRole('button', { name: 'Close Workbench' })
  await assertFocused(page, closeButton, 'opening the dialog must focus its close control')
  await page.keyboard.press('Tab')
  assert.equal(await dialog.evaluate(element => element.contains(document.activeElement)), true)
  await page.keyboard.press('Shift+Tab')
  assert.equal(await dialog.evaluate(element => element.contains(document.activeElement)), true)
  await page.keyboard.press('Escape')
  await dialog.waitFor({ state: 'hidden' })
  await assertFocused(page, launcher, 'Escape must return focus to the launcher')
  await callWorkbenchBridge(page, 'openFull')
  await waitForWorkbenchState(page, 'state => state.kind === "SELECTION_READY"')
  await launcher.click()
  await dialog.waitFor({ state: 'visible' })

  await page.getByRole('button', { name: 'Runtime Health' }).click()
  await page.getByRole('heading', { name: 'Runtime Health' }).waitFor()
  assert.equal(await page.getByText('READY', { exact: true }).count() > 0, true)
  await page.getByRole('button', { name: 'Back to Assessment list' }).click()

  await page.getByRole('button', { name: 'Repositories and New Assessment' }).click()
  await page.getByRole('heading', { name: 'Repositories' }).waitFor()
  assert.equal(await page.getByText(repositoryDisplayName, { exact: true }).count(), 1)
  assert.equal((await dialog.innerText()).includes(normalizedPath(repositoryRoot)), false)
  await page.getByRole('button', { name: 'New Assessment' }).click()
  await page.getByRole('heading', { name: 'New Assessment' }).waitFor()
  await page.getByRole('combobox', { name: 'Assessment Subject' }).selectOption('workspace_snapshot')
  const riskWindow = page.getByRole('checkbox', { name: /Risk decision window/u })
  await riskWindow.check()
  await page.getByRole('button', { name: 'Resolve and review preflight' }).click()
  await page.getByRole('heading', { name: 'Start Preflight' }).waitFor()
  const preflightState = await waitForWorkbenchState(
    page,
    'state => state.kind === "WIZARD_READY" && state.startPreflight !== null',
  )
  assert.equal(preflightState.startPreflight.providerComposition[0]?.analyzerId, 'dsh/builtin-node-package-lifecycle')
  await page.getByText('dsh/builtin-node-package-lifecycle@1.0.0').waitFor()
  assert.equal(await page.getByText('dsh/builtin-node-package-lifecycle@1.0.0').count(), 1)
  await page.getByRole('button', { name: 'Confirm and start Assessment' }).click()

  const blocked = await waitForWorkbenchState(
    page,
    'state => state.kind === "READY" && state.snapshot.state === "BLOCKED"',
    60_000,
  )
  const assessmentId = blocked.assessmentId
  assert.match(assessmentId, /^asm-[0-9a-f-]{36}$/u)
  assert.equal(await page.getByText('BLOCKED', { exact: true }).count() > 0, true)
  assert.equal(
    await page.locator('.dsh-security-actions').getByText('RECORD_RISK_DECISION', { exact: true }).count(),
    1,
  )
  assert.equal(
    await page.locator('.dsh-security-recovery').getByText('RECORD_RISK_DECISION', { exact: true }).count(),
    1,
  )

  await page.getByRole('button', { name: 'View Findings' }).click()
  await page.getByRole('heading', { name: 'Findings' }).waitFor()
  await page.getByRole('button', { name: 'Open Finding' }).click()
  await page.getByRole('heading', { name: 'Finding Detail' }).waitFor()
  assert.equal(await page.getByText('/scripts/postinstall', { exact: true }).count(), 1)

  await page.getByRole('radio', { name: 'Deny risk acceptance' }).check()
  await page.getByRole('textbox', { name: 'Rationale' }).fill(riskRationale)
  await page.getByRole('button', { name: 'Record Risk Decision' }).click()
  await waitForWorkbenchState(
    page,
    'state => state.kind === "READY" && state.snapshot.state === "SEALED"',
    60_000,
  )
  assert.equal((await dialog.innerText()).includes(riskRationale), false)

  await page.getByRole('button', { name: 'View Findings' }).click()
  await page.getByRole('heading', { name: 'Findings' }).waitFor()
  await page.getByRole('button', { name: 'Open Finding' }).click()
  await page.getByRole('heading', { name: 'Finding Detail' }).waitFor()
  await page.getByRole('button', { name: 'View Evidence metadata' }).click()
  await waitForWorkbenchState(
    page,
    'state => state.kind === "READY" && state.findings.kind === "DETAIL_READY" && state.findings.evidence.kind === "METADATA_READY"',
  )
  await page.getByRole('heading', { name: 'Evidence metadata' }).waitFor()
  assert.equal(await page.getByText('PROFILE_METADATA_ONLY', { exact: true }).count(), 1)
  assert.equal(await page.locator('pre.dsh-security-evidence-disclosure__json').count(), 0)
  await page.getByRole('button', { name: 'Explicitly view sensitive Evidence content' }).click()
  await waitForWorkbenchState(
    page,
    'state => state.kind === "READY" && state.findings.kind === "DETAIL_READY" && state.findings.evidence.kind === "DISCLOSURE_READY"',
  )
  await page.getByRole('heading', { name: 'Sensitive Evidence content' }).waitFor()
  const protectedJsonLocator = page.locator('pre.dsh-security-evidence-disclosure__json')
  await protectedJsonLocator.waitFor()
  const protectedJson = await protectedJsonLocator.innerText()
  assert.equal(protectedJson.includes('installLifecycleScripts'), true)
  assert.equal(protectedJson.includes(scriptBodyMarker), false, 'script bodies must not enter Evidence')
  await assertNoForbiddenBrowserState(page, [
    normalizedPath(repositoryRoot),
    fullAuthorityContextId,
    deniedAuthorityContextId,
    operatorPrincipalId,
    scriptBodyMarker,
  ])
  await page.getByRole('button', { name: 'Hide and discard sensitive content' }).click()
  await protectedJsonLocator.waitFor({ state: 'detached' })
  assert.equal((await dialog.innerText()).includes(protectedJson), false)

  await page.getByRole('button', { name: 'Back to Finding detail' }).click()
  await page.getByRole('heading', { name: 'Finding Detail' }).waitFor()
  await page.getByRole('button', { name: 'View Bundle and Export Readiness' }).click()
  await waitForWorkbenchState(page, 'state => state.kind === "BUNDLE_READY"')
  await page.getByRole('heading', { name: 'Bundle and Export Readiness' }).waitFor()
  assert.equal(await page.getByText(deliveryDestinationId, { exact: true }).count(), 1)
  await page.getByRole('button', { name: 'Preview Export' }).click()
  await waitForWorkbenchState(
    page,
    'state => state.kind === "BUNDLE_READY" && state.export.kind === "PREVIEW_READY"',
  )
  await page.getByRole('heading', { name: 'Export Preview and Delivery' }).waitFor()
  assert.equal(await page.getByText('security/export/internal-json-v1', { exact: true }).count(), 1)
  assert.equal(await page.getByText('PRIVATE_STORE_PATHS', { exact: true }).count(), 1)
  assert.equal((await dialog.innerText()).includes(normalizedPath(dshHome)), false)
  assert.equal(await page.getByRole('button', { name: /download/iu }).count(), 0)
  await page.getByRole('button', { name: 'Request and deliver Export' }).click()
  const deliveredExport = await waitForWorkbenchState(
    page,
    'state => state.kind === "BUNDLE_READY" && state.export.kind === "STATUS_READY" && state.export.status.status === "DELIVERED"',
  )
  const exportId = deliveredExport.export.status.exportId
  assert.match(exportId, /^export-[0-9a-f]{64}$/u)
  assert.equal(deliveredExport.export.status.accessAction.kind, 'ONE_USE_DOWNLOAD')
  assert.equal(deliveredExport.export.status.artifact?.digest.mediaType, 'application/vnd.dsh.security.export+json')
  const deliveredArtifact = await readFile(join(
    dshHome,
    'security-assurance',
    'delivery',
    'destinations',
    'local-audit',
    `${exportId}.json`,
  ), 'utf8')
  const deliveredArtifactValue = JSON.parse(deliveredArtifact)
  assert.equal(deliveredArtifactValue.source.assessmentId, assessmentId)
  assert.equal(deliveredArtifactValue.exportProfileId, 'security/export/internal-json-v1')
  assert.equal(deliveredArtifact.includes(normalizedPath(repositoryRoot)), false)
  const hrefBeforeDownload = page.url()
  const browserDownloadPromise = page.waitForEvent('download')
  await page.getByRole('button', { name: 'Authorize and download once' }).click()
  const browserDownload = await browserDownloadPromise
  const downloadedExport = await waitForWorkbenchState(
    page,
    'state => state.kind === "BUNDLE_READY" && state.export.kind === "STATUS_READY" && state.export.download.kind === "COMPLETE"',
  )
  const downloadedPath = await browserDownload.path()
  assert.notEqual(downloadedPath, null, 'browser download must produce a temporary file')
  const downloadedBytes = await readFile(downloadedPath)
  assert.equal(downloadedBytes.equals(Buffer.from(deliveredArtifact, 'utf8')), true)
  assert.equal(browserDownload.suggestedFilename(), downloadedExport.export.download.fileName)
  assert.equal(downloadedExport.export.download.digest, deliveredExport.export.status.artifact.digest.value)
  assert.equal(JSON.stringify(downloadedExport).includes(Buffer.from(deliveredArtifact).toString('base64')), false)
  assert.equal(page.url(), hrefBeforeDownload, 'one-use download must not enter navigation or history')

  await setWorkbenchLocale(page, 'zh')
  await page.getByRole('dialog', { name: '安全保障工作台' }).waitFor()
  await page.getByRole('heading', { name: 'Bundle 与 Export Readiness' }).waitFor()
  await setWorkbenchLocale(page, 'en')

  await page.setViewportSize({ width: 390, height: 844 })
  const bounded = await dialog.evaluate(element => {
    const rect = element.getBoundingClientRect()
    return rect.left >= 0 && rect.right <= window.innerWidth && rect.width <= window.innerWidth
  })
  assert.equal(bounded, true, 'Workbench dialog must remain inside a narrow viewport')
  await assertAccessibleControls(dialog)

  await page.setViewportSize({ width: 1280, height: 900 })
  await page.reload({ waitUntil: 'domcontentloaded' })
  await waitForWorkbenchBridge(page)
  await setWorkbenchLocale(page, 'en')
  await callWorkbenchBridge(page, 'openFull')
  await waitForWorkbenchState(page, 'state => state.kind === "SELECTION_READY"')
  await dismissReferenceHostOnboarding(page)
  await page.getByRole('button', { name: 'Open Security Assurance Workbench' }).click()
  const reloadedDialog = page.getByRole('dialog', { name: 'Security Assurance Workbench' })
  await reloadedDialog.waitFor({ state: 'visible' })
  await reloadedDialog.getByRole('button', { name: `Open ${assessmentId}`, exact: true }).click()
  await waitForWorkbenchState(
    page,
    `state => state.kind === "READY" && state.assessmentId === ${JSON.stringify(assessmentId)} && state.snapshot.state === "SEALED"`,
  )
  assert.equal((await page.locator('body').innerText()).includes(protectedJson), false)

  await page.keyboard.press('Escape')
  await context.setOffline(true)
  await callWorkbenchBridge(page, 'openFull')
  await waitForWorkbenchState(page, 'state => state.kind === "FAILED"')
  await context.setOffline(false)
  await callWorkbenchBridge(page, 'openFull')
  await waitForWorkbenchState(page, 'state => state.kind === "SELECTION_READY"')
  await callWorkbenchBridge(page, 'openDenied')
  const denied = await waitForWorkbenchState(
    page,
    'state => state.kind === "FAILED" && state.failure.code === "UNAUTHORIZED"',
  )
  assert.equal(denied.assessmentId, null)
  await callWorkbenchBridge(page, 'openFull')
  await waitForWorkbenchState(page, 'state => state.kind === "SELECTION_READY"')

  const cdp = await context.newCDPSession(page)
  const navigationHistory = await cdp.send('Page.getNavigationHistory')
  const browserHistory = JSON.stringify(navigationHistory.entries.map(entry => entry.url))
  const forbidden = [
    normalizedPath(repositoryRoot),
    fullAuthorityContextId,
    deniedAuthorityContextId,
    operatorPrincipalId,
    scriptBodyMarker,
    riskRationale,
    protectedJson,
  ]
  for (const value of forbidden) {
    assert.equal(browserHistory.includes(value), false, `browser history retained ${JSON.stringify(value)}`)
  }
  await assertNoForbiddenBrowserState(page, forbidden)
  const browserLogs = consoleEntries.join('\n')
  for (const value of forbidden) {
    assert.equal(browserLogs.includes(value), false, `browser console retained ${JSON.stringify(value)}`)
  }
  assert.deepEqual(pageErrors, [], `browser page errors: ${pageErrors.join('\n')}`)
  const expectedOrigin = new URL(hostUrl).origin
  for (const requestUrl of requestUrls) {
    const parsed = new URL(requestUrl)
    if (parsed.protocol === 'data:' || parsed.protocol === 'blob:') continue
    assert.equal(parsed.origin, expectedOrigin, `unexpected remote browser resource ${requestUrl}`)
  }

  await context.close()
  await browser.close()
  browser = undefined
  return {
    assessmentId,
    exportId,
    downloadFileName: browserDownload.suggestedFilename(),
    requestCount: requestUrls.length,
    consoleCount: consoleEntries.length,
  }
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
  console.log('packed-browser-e2e: creating isolated Repository and packed artifact')
  await mkdir(npmCache, { recursive: true })
  await createFixtureRepository()
  await createReferenceBrowserPackage()
  const securityTarball = await packSecurityArtifact()

  console.log('packed-browser-e2e: installing fresh Harness 0.1.1-rc.2 profile')
  const host = await installFreshHarness(securityTarball)
  await configureReferenceHost()

  console.log('packed-browser-e2e: starting packed Reference Test Host')
  hostUrl = await startHost(host.dshBin, host.environment)

  console.log(`packed-browser-e2e: driving real browser at ${hostUrl}`)
  const evidence = await runBrowserScenario()
  const exit = await stopHost()
  assert.equal(
    exit?.code === 0 || (process.platform === 'win32' && exit?.code === null && exit.signal === 'SIGTERM'),
    true,
    `Reference Host must stop cleanly; exit=${JSON.stringify(exit)}`,
  )
  await assertHostStopped()

  console.log(JSON.stringify({
    packedHost: 'PASS',
    realBrowser: 'PASS',
    realAuthority: 'PASS',
    accessibility: 'PASS',
    bilingual: 'PASS',
    redaction: 'PASS',
    reconnect: 'PASS',
    lifecycle: 'PASS',
    ...evidence,
  }, null, 2))
} finally {
  await browser?.close().catch(() => {})
  await stopHost().catch(() => {})
  await rm(temporaryRoot, { recursive: true, force: true })
}
