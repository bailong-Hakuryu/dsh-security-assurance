import { readFile } from 'node:fs/promises'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import SecurityAssuranceControlPlaneProvider, {
  SECURITY_ASSURANCE_CONTROL_PLANE_DESCRIPTOR,
} from '../src/control-plane-provider.ts'

describe('ADR 0295 optional by-value Control Plane Adapter', () => {
  it('keeps both roots independent and makes the Control Plane peer optional', async () => {
    const packageJson = JSON.parse(await readFile(
      join(import.meta.dirname, '..', 'package.json'),
      'utf8',
    )) as {
      readonly peerDependencies?: Record<string, string>
      readonly peerDependenciesMeta?: Record<string, { readonly optional?: boolean }>
      readonly exports?: Record<string, unknown>
    }
    const rootSource = await readFile(join(import.meta.dirname, '..', 'src', 'index.ts'), 'utf8')

    expect(packageJson.peerDependencies?.['dsh-engineering-control-plane']).toBe('^0.1.0')
    expect(packageJson.peerDependenciesMeta?.['dsh-engineering-control-plane']).toEqual({ optional: true })
    expect(packageJson.exports).toHaveProperty('./control-plane-provider')
    expect(rootSource).not.toMatch(/from ['"]dsh-engineering-control-plane/u)
    expect(SecurityAssuranceControlPlaneProvider.inject).toEqual([
      'engineeringControlPlane',
      'securityAssurance',
    ])
    expect(SECURITY_ASSURANCE_CONTROL_PLANE_DESCRIPTOR).toEqual({
      schemaVersion: 1,
      providerId: 'dsh/security-assurance',
      providerVersion: expect.any(String),
    })
  })

  it('accepts only repositoryId configuration and transfers sealed evidence by value', async () => {
    const source = await readFile(
      join(import.meta.dirname, '..', 'src', 'control-plane-provider.ts'),
      'utf8',
    )

    expect(source).toContain("Object.keys(configuration).length !== 1")
    expect(source).toContain("Object.hasOwn(configuration, 'repositoryId')")
    expect(source).toContain('canonicalSubmission: canonicalJson(submission)')
    expect(source).toContain('sourceDigest: `sha256:${submission.digest.value}`')
    expect(source).toContain("artifactId: 'security-assurance-submission'")
    expect(source).not.toMatch(/from ['"]node:(?:fs|path|sqlite|child_process)/u)
    expect(source).not.toMatch(/\b(?:repositoryPath|credential|transaction|sqlite)\b/u)
  })
})
