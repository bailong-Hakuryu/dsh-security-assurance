export interface ControlPlaneCancellationCrashCheckpointEvent {
  readonly name:
    | 'after_assessment_started'
    | 'after_assessment_canceled_before_provider_outcome'
  readonly assessmentId: string
}

export type ControlPlaneCancellationCrashCheckpoint = (
  event: ControlPlaneCancellationCrashCheckpointEvent,
) => void | Promise<void>

const CONTROL_PLANE_CANCELLATION_CRASH_CHECKPOINT = Symbol(
  'dsh-security-assurance.control-plane-cancellation-crash-checkpoint',
)

interface CrashCheckpointOwner {
  [CONTROL_PLANE_CANCELLATION_CRASH_CHECKPOINT]?: ControlPlaneCancellationCrashCheckpoint
}

/**
 * Test-only, non-authorizing interception at one cross-plugin durable boundary.
 * This module is package-private and deliberately absent from the package export map.
 */
export function installControlPlaneCancellationCrashCheckpoint(
  owner: object,
  checkpoint: ControlPlaneCancellationCrashCheckpoint,
): () => void {
  const target = owner as CrashCheckpointOwner
  if (target[CONTROL_PLANE_CANCELLATION_CRASH_CHECKPOINT] !== undefined) {
    throw new Error('A Control Plane cancellation Crash Checkpoint is already installed')
  }
  Object.defineProperty(target, CONTROL_PLANE_CANCELLATION_CRASH_CHECKPOINT, {
    configurable: true,
    enumerable: false,
    writable: false,
    value: checkpoint,
  })
  let disposed = false
  return () => {
    if (disposed) return
    disposed = true
    if (target[CONTROL_PLANE_CANCELLATION_CRASH_CHECKPOINT] === checkpoint) {
      delete target[CONTROL_PLANE_CANCELLATION_CRASH_CHECKPOINT]
    }
  }
}

/** Reach the named checkpoint after Security commits CANCELED and before the Adapter returns proof. */
export async function reachControlPlaneCancellationCrashCheckpoint(
  owner: object,
  name: ControlPlaneCancellationCrashCheckpointEvent['name'],
  assessmentId: string,
): Promise<void> {
  const checkpoint = (owner as CrashCheckpointOwner)[CONTROL_PLANE_CANCELLATION_CRASH_CHECKPOINT]
  if (checkpoint === undefined) return
  await checkpoint(Object.freeze({
    name,
    assessmentId,
  }))
}
