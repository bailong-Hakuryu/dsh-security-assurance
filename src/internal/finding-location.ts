/**
 * The only repository-derived text a model tool may carry (ADR 0325): a
 * repository-relative path and JSON pointer whose every segment matches a
 * narrow allowlist. Anything else is omitted rather than escaped, so no
 * repository-controlled sentence, markup, or control character reaches the
 * model; the anchor's file digest and the file's content never do.
 */
import type { FindingSourceAnchorViewV1 } from '../contracts.ts'

/** Where a Finding is, as a model tool may state it. */
export interface ModelFindingLocationV1 {
  readonly path: string
  readonly pointer: string
}

const SEGMENT = /^[A-Za-z0-9._-]{1,64}$/u
const MAX_SEGMENTS = 8

function plainSegments(segments: readonly string[]): boolean {
  return segments.length <= MAX_SEGMENTS
    && segments.every(segment => SEGMENT.test(segment) && segment !== '.' && segment !== '..')
}

/** Project one Source Anchor to an allowlisted location, or to nothing. */
export function modelFindingLocation(
  anchor: FindingSourceAnchorViewV1 | undefined,
): ModelFindingLocationV1 | undefined {
  if (anchor === undefined || anchor.locator.kind !== 'JSON_POINTER') return undefined
  const path = anchor.path
  const pointer = anchor.locator.value
  if (typeof path !== 'string' || typeof pointer !== 'string') return undefined
  if (!plainSegments(path.split('/'))) return undefined
  if (pointer !== '' && (!pointer.startsWith('/') || !plainSegments(pointer.slice(1).split('/')))) return undefined
  return { path, pointer }
}
