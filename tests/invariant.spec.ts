import { SecurityAssuranceTestComposition } from './support/security-assurance-test-composition.ts'
import { removeTemporaryRoot } from './support/remove-temporary-root.ts'
import { mkdtemp } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { Context, Service, type Fiber } from '@deepseek-ai/cordis'
import { InvariantRegistry } from '@deepseek-ai/dsh-invariants'
import * as invariantEntry from '../src/invariant.ts'
import {
  HARNESS_VERIFICATION_AUTHORITY,
  RECEIVE_HARNESS_VERIFICATION,
  type HarnessVerificationReceiver,
} from '../src/internal/harness-verification.ts'
import { referenceHostInvocation } from './support/reference-host.ts'

const PUBLIC_METHODS = [
  'whenReady',
  'registerAnalyzer',
  'getHealth',
  'getCatalog',
  'registerRepository',
  'updateRepository',
  'disableRepository',
  'getRepository',
  'listRepositories',
  'startAssessment',
  'resumeAssessment',
  'cancelAssessment',
  'listAssessments',
  'getAssessment',
  'listFindings',
  'getFinding',
  'getEvidenceView',
  'recordRiskDecision',
  'waitForAssessmentRevision',
  'getBundleManifest',
  'getAssuranceSubmission',
  'requestExport',
  'getExport',
] as const

interface LoaderEntryFixture {
  readonly options: {
    readonly id: string
    readonly name: string
    readonly disabled?: boolean
  }
}

interface LoaderFixtureConfig {
  readonly entries?: readonly LoaderEntryFixture[]
}

class LoaderFixture extends Service {
  private readonly configuredEntries: readonly LoaderEntryFixture[]

  constructor(ctx: Context, config: LoaderFixtureConfig = {}) {
    super(ctx, 'loader')
    this.configuredEntries = config.entries ?? []
  }

  * entries(): Generator<LoaderEntryFixture, void, void> {
    yield* this.configuredEntries
  }
}

interface TypertRecordFixture {
  readonly package: string
  readonly face: string
  readonly key: string
  readonly model: {
    readonly services: readonly {
      readonly key: string
      readonly exportName: string
      readonly members: readonly {
        readonly kind: 'method'
        readonly name: string
      }[]
    }[]
  }
}

interface TypertFixtureConfig {
  readonly record?: TypertRecordFixture
  readonly failureMessage?: string
}

class TypertFixture extends Service {
  private readonly record: TypertRecordFixture | undefined
  private readonly failureMessage: string | undefined

  constructor(ctx: Context, config: TypertFixtureConfig = {}) {
    super(ctx, 'typert')
    this.record = config.record
    this.failureMessage = config.failureMessage
  }

  getPackage(): TypertRecordFixture | undefined {
    if (this.failureMessage !== undefined) throw new Error(this.failureMessage)
    return this.record
  }
}

interface HostRepositoryProviderFixtureConfig {
  readonly ready: Promise<void>
}

class HostRepositoryProviderFixture extends Service {
  constructor(ctx: Context, private readonly config: HostRepositoryProviderFixtureConfig) {
    super(ctx, 'securityAssuranceHostRepositories')
  }

  async whenReady(): Promise<void> {
    await this.config.ready
  }
}

function validEntries(): readonly LoaderEntryFixture[] {
  return [
    {
      options: {
        id: 'dsh-security-assurance',
        name: 'dsh-security-assurance',
      },
    },
    {
      options: {
        id: 'dsh-security-assurance-invariant',
        name: 'dsh-security-assurance/invariant',
      },
    },
  ]
}

function hostRecord(options: {
  readonly packageName?: string
  readonly face?: string
  readonly packageKey?: string
  readonly serviceKey?: string
  readonly exportName?: string
  readonly methods?: readonly string[]
} = {}): TypertRecordFixture {
  return {
    package: options.packageName ?? 'dsh-security-assurance',
    face: options.face ?? 'host',
    key: options.packageKey ?? 'dsh-security-assurance#host',
    model: {
      services: [{
        key: options.serviceKey ?? 'securityAssurance',
        exportName: options.exportName ?? 'SecurityAssuranceService',
        members: (options.methods ?? PUBLIC_METHODS).map(method => ({
          kind: 'method',
          name: method,
        })),
      }],
    },
  }
}

describe('Invariant Entry', () => {
  let ctx: Context
  let dshHome: string
  let fibers: Fiber[]

  beforeEach(async () => {
    ctx = new Context()
    dshHome = await mkdtemp(join(tmpdir(), 'dsh-security-invariant-test-'))
    fibers = []
  })

  afterEach(async () => {
    for (const fiber of fibers.reverse()) {
      try {
        await fiber.dispose()
      } catch {
        // Best-effort teardown keeps the primary assertion failure visible.
      }
    }
    await removeTemporaryRoot(dshHome).catch(() => {})
  })

  async function activateService(): Promise<void> {
    const fiber = ctx.plugin(SecurityAssuranceTestComposition, { dshHome })
    fibers.push(fiber)
    await fiber
    await ctx.securityAssurance.whenReady()
  }

  async function activateInvariantComposition(options: {
    readonly entries?: readonly LoaderEntryFixture[]
    readonly typertRecord?: TypertRecordFixture
    readonly typertFailureMessage?: string
    readonly omitTypert?: boolean
    readonly hostRepositoryReady?: Promise<void>
  } = {}): Promise<Fiber> {
    const registryFiber = ctx.plugin(InvariantRegistry)
    fibers.push(registryFiber)
    await registryFiber

    const loaderFiber = ctx.plugin(LoaderFixture, {
      entries: options.entries ?? validEntries(),
    })
    fibers.push(loaderFiber)
    await loaderFiber

    if (options.omitTypert !== true) {
      const typertFiber = ctx.plugin(TypertFixture, {
        record: options.typertRecord ?? hostRecord(),
        ...(options.typertFailureMessage === undefined
          ? {}
          : { failureMessage: options.typertFailureMessage }),
      })
      fibers.push(typertFiber)
      await typertFiber
    }

    await activateService()
    if (options.hostRepositoryReady !== undefined) {
      const hostRepositoryFiber = ctx.plugin(HostRepositoryProviderFixture, {
        ready: options.hostRepositoryReady,
      })
      fibers.push(hostRepositoryFiber)
      await hostRepositoryFiber
    }
    const invariantFiber = ctx.plugin(invariantEntry)
    fibers.push(invariantFiber)
    await invariantFiber
    return invariantFiber
  }

  async function health() {
    const invocation = referenceHostInvocation(ctx.securityAssurance)
    const result = await ctx.securityAssurance.getHealth(invocation, { schemaVersion: 1 })
    if (!result.ok) throw new Error(`health failed: ${result.error.code}`)
    return result.value
  }

  it('stays dormant until the optional invariant companion is activated', async () => {
    await activateService()

    const snapshot = await health()

    expect(snapshot.compatibility.harnessVerification).toBe('PENDING_INVARIANT')
    expect(snapshot.checks.filter(check => check.id.startsWith('composition.'))).toEqual([])
  })

  it('reports PASS only when all six required composition checks pass', async () => {
    await activateInvariantComposition()

    const snapshot = await health()
    const compositionChecks = snapshot.checks.filter(check => check.id.startsWith('composition.'))

    expect(snapshot.compatibility.harnessVerification).toBe('PASS')
    expect(snapshot.state).toBe('READY')
    expect(snapshot.admission.mutations).toBe(true)
    expect(compositionChecks.map(check => check.id)).toEqual([
      'composition.harness-version',
      'composition.required-service-definitions',
      'composition.bundle-dependencies',
      'composition.generated-contract',
      'composition.capability-identity',
      'composition.declared-runtime',
    ])
    expect(compositionChecks).toEqual(compositionChecks.map(check => ({
      ...check,
      status: 'PASS',
      required: true,
    })))
  })

  it('rejects a discovered verification slot when the contribution owner is unbranded', async () => {
    await activateInvariantComposition()
    const receiver = Reflect.get(ctx.securityAssurance, RECEIVE_HARNESS_VERIFICATION) as HarnessVerificationReceiver
    const accepted = receiver(
      HARNESS_VERIFICATION_AUTHORITY,
      Object.freeze(Object.create(null) as object),
      { result: 'FAIL', checks: [] },
    )

    expect(accepted).toBe(false)
    expect((await health()).compatibility.harnessVerification).toBe('PASS')
  })

  it('does not close mutation admission before direct-use Host repository bootstrap settles', async () => {
    let releaseHostRepository!: () => void
    const hostRepositoryReady = new Promise<void>(resolve => {
      releaseHostRepository = resolve
    })
    let activated = false
    const activation = activateInvariantComposition({ hostRepositoryReady }).then(fiber => {
      activated = true
      return fiber
    })

    await new Promise<void>(resolve => setImmediate(resolve))
    expect(activated).toBe(false)

    releaseHostRepository()
    await activation
    expect((await health()).compatibility.harnessVerification).toBe('PASS')
  })

  it('fails closed when direct-use Host repository bootstrap rejects', async () => {
    let rejectReady!: (error: Error) => void
    const hostRepositoryReady = new Promise<void>((_, reject) => {
      rejectReady = reject
    })
    void hostRepositoryReady.catch(() => {})
    const activation = activateInvariantComposition({ hostRepositoryReady })
    await new Promise<void>(resolve => setImmediate(resolve))
    rejectReady(new Error('host bootstrap credentials unavailable'))
    await activation

    const snapshot = await health()
    expect(snapshot.compatibility.harnessVerification).toBe('FAIL')
    expect(snapshot.state).toBe('READ_ONLY_SAFE')
    expect(snapshot.checks).toContainEqual(expect.objectContaining({
      id: 'composition.host-repository-bootstrap',
      status: 'FAIL',
      required: true,
    }))
  })

  it('fails closed when a required composition check cannot be evaluated', async () => {
    await activateInvariantComposition({ omitTypert: true })

    const snapshot = await health()
    const invocation = referenceHostInvocation(ctx.securityAssurance)
    const mutation = await ctx.securityAssurance.registerRepository(invocation, {
      schemaVersion: 1,
      contractVersion: 1 as const,
      idempotencyKey: 'invariant-read-only-register-1',
      root: 'D:/must-not-be-resolved-in-invariant-safe-mode',
      displayName: 'Must not register',
      bindings: {
        policyId: 'security/default',
        assessmentProfileId: 'security/standard',
        evidenceProtectionId: 'evidence/local-protected',
        dataEgressPolicyId: 'egress/deny-by-default',
        platform: 'linux',
        deliveryDestinationIds: [],
      },
    })

    expect(snapshot.checks).toContainEqual(expect.objectContaining({
      id: 'composition.generated-contract',
      status: 'NOT_EVALUATED',
      required: true,
    }))
    expect(snapshot.compatibility.harnessVerification).toBe('FAIL')
    expect(snapshot.state).toBe('READ_ONLY_SAFE')
    expect(snapshot.admission.mutations).toBe(false)
    expect(mutation).toMatchObject({ ok: false, error: { code: 'UNAVAILABLE', retryable: true } })
  })

  it('revokes its Health contribution when its real Cordis Fiber is disposed', async () => {
    const invariantFiber = await activateInvariantComposition()
    expect((await health()).compatibility.harnessVerification).toBe('PASS')

    await invariantFiber.dispose()

    const snapshot = await health()
    expect(snapshot.compatibility.harnessVerification).toBe('PENDING_INVARIANT')
    expect(snapshot.checks.filter(check => check.id.startsWith('composition.'))).toEqual([])
  })

  it('rejects incomplete generated methods and incorrect capability identity', async () => {
    await activateInvariantComposition({
      typertRecord: hostRecord({
        packageKey: 'dsh-security-assurance#wrong-face',
        methods: PUBLIC_METHODS.filter(method => method !== 'getExport'),
      }),
    })

    const snapshot = await health()

    expect(snapshot.compatibility.harnessVerification).toBe('FAIL')
    expect(snapshot.checks).toContainEqual(expect.objectContaining({
      id: 'composition.generated-contract',
      status: 'FAIL',
    }))
    expect(snapshot.checks).toContainEqual(expect.objectContaining({
      id: 'composition.capability-identity',
      status: 'FAIL',
    }))
  })

  it('fails when the invariant companion is absent from enabled Loader composition', async () => {
    await activateInvariantComposition({ entries: validEntries().slice(0, 1) })

    const snapshot = await health()

    expect(snapshot.compatibility.harnessVerification).toBe('FAIL')
    expect(snapshot.checks).toContainEqual(expect.objectContaining({
      id: 'composition.declared-runtime',
      status: 'FAIL',
      required: true,
    }))
  })

  it('redacts secrets from unavailable-check diagnostics exposed through Health', async () => {
    // Assemble a deliberately invalid fixture at runtime so repository scanners
    // do not mistake test data for a committed credential.
    const apiKey = ['01234567', '89abcdef', '01234567', '89abcdef'].join('')
    const providerToken = ['sk', 'provider-redaction-fixture'].join('-')
    await activateInvariantComposition({
      typertFailureMessage: `credentials api_key=${apiKey} provider=${providerToken}`,
    })

    const snapshot = await health()
    const messages = snapshot.checks.map(check => check.message).join('\n')

    expect(snapshot.compatibility.harnessVerification).toBe('FAIL')
    expect(messages).not.toContain(apiKey)
    expect(messages).not.toContain(providerToken)
    expect(messages).toContain('[redacted]')
    expect(messages).toContain('[token]')
  })
})
