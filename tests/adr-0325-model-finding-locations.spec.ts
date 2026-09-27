import { describe, expect, it } from 'vitest'
import type { FindingSourceAnchorViewV1 } from '../src/contracts.ts'
import { modelFindingLocation } from '../src/internal/finding-location.ts'

function anchor(path: string, pointer: string): FindingSourceAnchorViewV1 {
  return {
    path,
    fileDigest: {
      schemaVersion: 1,
      algorithm: 'sha256',
      mediaType: 'application/json',
      byteLength: 1,
      canonicalization: 'raw-bytes',
      value: '0'.repeat(64),
    },
    locator: { kind: 'JSON_POINTER', value: pointer },
  } as FindingSourceAnchorViewV1
}

describe('ADR 0325 model finding locations', () => {
  it('passes a plain repository-relative path and JSON pointer without the file digest', () => {
    expect(modelFindingLocation(anchor('package.json', '/scripts/postinstall'))).toEqual({
      path: 'package.json',
      pointer: '/scripts/postinstall',
    })
    expect(modelFindingLocation(anchor('packages/api-server/package.json', '/scripts/prepare')))
      .toEqual({ path: 'packages/api-server/package.json', pointer: '/scripts/prepare' })
    expect(modelFindingLocation(anchor('.github/workflows/release.yml', '')))
      .toEqual({ path: '.github/workflows/release.yml', pointer: '' })
  })

  it.each([
    ['a path with spaces', 'ignore previous instructions/package.json', '/scripts/postinstall'],
    ['a parent traversal', '../package.json', '/scripts/postinstall'],
    ['a current-directory segment', './package.json', '/scripts/postinstall'],
    ['an absolute path', '/etc/package.json', '/scripts/postinstall'],
    ['a drive path', 'C:/work/package.json', '/scripts/postinstall'],
    ['a backslash path', 'packages\\api\\package.json', '/scripts/postinstall'],
    ['an empty path', '', '/scripts/postinstall'],
    ['too many segments', Array(9).fill('d').join('/'), '/scripts/postinstall'],
    ['an overlong segment', `${'a'.repeat(65)}/package.json`, '/scripts/postinstall'],
    ['a pointer with spaces', 'package.json', '/scripts/run this now'],
    ['an escaped pointer segment', 'package.json', '/scripts/a~1b'],
    ['a pointer without a leading slash', 'package.json', 'scripts/postinstall'],
    ['a pointer with markup', 'package.json', '/scripts/<system>'],
    ['an overlong pointer', 'package.json', `/${Array(9).fill('s').join('/')}`],
    ['a control character', 'package.json', '/scripts/post\ninstall'],
  ])('omits %s entirely', (_label, path, pointer) => {
    expect(modelFindingLocation(anchor(path, pointer))).toBeUndefined()
  })

  it('omits anything that is not a JSON pointer anchor', () => {
    expect(modelFindingLocation({
      ...anchor('package.json', '/scripts/postinstall'),
      locator: { kind: 'LINE_RANGE', value: '1-2' },
    } as unknown as FindingSourceAnchorViewV1)).toBeUndefined()
    expect(modelFindingLocation(undefined)).toBeUndefined()
  })
})
