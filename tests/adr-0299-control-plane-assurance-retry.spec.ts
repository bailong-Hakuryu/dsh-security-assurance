import { readFile } from 'node:fs/promises'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'

describe('ADR 0299 Control Plane Assurance Retry starts a distinct Assessment', () => {
  it('binds Assessment idempotency to the Provider Invocation and reserves recover for the same invocation', async () => {
    const service = await readFile(join(import.meta.dirname, '..', 'src', 'index.ts'), 'utf8')
    const adapter = await readFile(
      join(import.meta.dirname, '..', 'src', 'control-plane-provider.ts'),
      'utf8',
    )
    const keyStart = service.indexOf('function controlPlaneOperationIdempotencyKey(')
    const keyEnd = service.indexOf('\n}\n\nfunction controlPlaneSecurityFailure', keyStart) + 2
    const keyBuilder = service.slice(keyStart, keyEnd)

    expect(keyStart).toBeGreaterThan(-1)
    expect(keyEnd).toBeGreaterThan(keyStart)
    expect(keyBuilder).toContain('context.invocationId')
    expect(keyBuilder).toContain('context.missionId')
    expect(keyBuilder).toContain('context.attempt')
    expect(keyBuilder).toContain("return operation === 'start'")
    expect(adapter).toContain("{ kind: 'ASSESS', context, repositoryId }")
    expect(adapter).toContain("{ kind: 'RECOVER', context, repositoryId }")
    expect(service).toContain("if (operation.kind !== 'RECOVER')")
    expect(service).toContain('CONTROL_PLANE_PROVIDER_RECOVERY')
  })

  it('reuses a content-addressed Subject only after complete integrity verification', async () => {
    const source = await readFile(
      join(import.meta.dirname, '..', 'src', 'internal', 'subject-freeze.ts'),
      'utf8',
    )
    const verifyStart = source.indexOf('async function verifyPublishedSnapshot(')
    const verifyEnd = source.indexOf('/** Freeze one exact Subject', verifyStart)
    const verification = source.slice(verifyStart, verifyEnd)
    const collisionStart = source.indexOf('    } catch (error) {', source.indexOf('await rename(stagingRoot, publishedRoot)'))
    const collisionEnd = source.indexOf('    canceled(options.signal)', collisionStart)
    const collision = source.slice(collisionStart, collisionEnd)

    expect(verification).toContain('canonicalJson(declaredDigest) !== canonicalJson(expectedDigest)')
    expect(verification).toContain('canonicalJson(recomputed) !== canonicalJson(expectedDigest)')
    expect(verification).toContain('Subject file digest verification failed')
    expect(verification).toContain('Subject materialization does not match its Manifest')
    expect(collision).toContain("code !== 'EPERM'")
    expect(collision).toContain("code !== 'EACCES'")
    expect(collision).toContain('await verifyPublishedSnapshot(publishedRoot, rootDigest)')
  })
})
