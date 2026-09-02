/**
 * Read the live Session event log across the supported Harness window
 * (ADR 0310). Harness `0.1.2-alpha.1` through `0.1.2-alpha.3` expose the
 * `Session.events` getter; Harness `0.1.2-alpha.4` replaces it with
 * `snapshotEvents()`, whose no-argument call is the same full immutable
 * snapshot. A Session shape offering neither yields an empty list so
 * turn-boundary checks fail closed instead of acting on drifted state.
 */
interface SessionEventsLike<T> {
  readonly events?: readonly T[]
  readonly snapshotEvents?: () => readonly T[]
}

export function readSessionEvents<T>(session: SessionEventsLike<T>): readonly T[] {
  if (typeof session.snapshotEvents === 'function') return session.snapshotEvents()
  return session.events ?? []
}
