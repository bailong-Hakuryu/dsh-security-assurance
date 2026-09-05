import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'

const workflow = readFileSync(
  new URL('../.github/workflows/release-evidence.yml', import.meta.url),
  'utf8',
)

describe('exact-artifact release evidence workflow', () => {
  it('is a manual read-only evidence operation', () => {
    expect(workflow).toContain('workflow_dispatch:')
    expect(workflow).toContain('control_plane_ref:')
    expect(workflow).toContain('^[0-9a-f]{40}$')
    expect(workflow).toContain('contents: read')
    expect(workflow).not.toMatch(/\b(?:npm publish|gh release|git tag)\b/u)
  })

  it('packs and binds one candidate before any platform proof runs', () => {
    expect(workflow).toContain('prepare:')
    expect(workflow).toContain('pnpm release:bind')
    expect(workflow).toContain('name: release-candidate-files')
    expect(workflow).toContain('needs: prepare')
    expect(workflow).toContain('DSH_SECURITY_PACKED_ARTIFACT:')
    expect(workflow).toContain('DSH_CONTROL_PLANE_PACKED_ARTIFACT:')
    expect(workflow).toContain('DSH_RELEASE_PROOF_OUTPUT:')
  })

  it('writes step outputs without nested shell quoting', () => {
    expect(workflow).toContain('appendFileSync(process.env.GITHUB_OUTPUT')
    expect(workflow).not.toContain('node -p \\"')
  })

  it('installs only the candidate CLI dependency closure without resolving Host peers', () => {
    expect(workflow).toContain("writeFileSync('release-tool/package.json'")
    expect(workflow).toContain('CANDIDATE_PATH: ${{ github.workspace }}/release-artifacts/')
    expect(workflow).toContain('--omit=peer')
    expect(workflow).toContain('--legacy-peer-deps')
  })

  it('uses Node 24 artifact actions with strict transport digest checks', () => {
    expect(workflow).toContain('actions/upload-artifact@v7')
    expect(workflow).toContain('actions/download-artifact@v8')
    expect(workflow).toContain('pnpm/action-setup@v6')
    expect(workflow).not.toMatch(/actions\/(?:upload|download)-artifact@v[45]/u)
    expect(workflow).not.toContain('pnpm/action-setup@v4')
  })

  it('requires Linux, macOS, and Windows proofs before collection', () => {
    for (const value of [
      'ubuntu-latest',
      'macos-latest',
      'windows-latest',
      'linux-platform.json',
      'macos-platform.json',
      'windows-platform.json',
    ]) {
      expect(workflow).toContain(value)
    }
    expect(workflow).toContain('needs: prove')
    expect(workflow).toContain('pattern: platform-proof-*')
    expect(workflow).toContain('merge-multiple: true')
    expect(workflow).toContain('dsh-security-assurance-release-collect')
    expect(workflow).toContain('name: release-evidence-index')
  })
})
