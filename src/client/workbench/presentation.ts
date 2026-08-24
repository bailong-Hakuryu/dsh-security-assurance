import type { SecurityAssuranceWorkbenchController } from '../index.ts'

/** Immutable visibility state; Assessment authority and payload stay in the Controller. */
export interface WorkbenchPresentationSnapshotV1 {
  readonly open: boolean
}

const CLOSED = Object.freeze({ open: false })
const OPEN = Object.freeze({ open: true })

/**
 * Small presentation machine shared by the additive launcher and overlay.
 * It owns only visibility and an ephemeral focus-return handle.
 */
export class WorkbenchPresentation {
  private snapshot: WorkbenchPresentationSnapshotV1 = CLOSED
  private readonly listeners = new Set<() => void>()
  private returnFocus: HTMLElement | null = null

  constructor(private readonly controller: SecurityAssuranceWorkbenchController) {}

  readonly getSnapshot = (): WorkbenchPresentationSnapshotV1 => this.snapshot

  readonly subscribe = (listener: () => void): (() => void) => {
    this.listeners.add(listener)
    return () => { this.listeners.delete(listener) }
  }

  show(returnFocus: HTMLElement): void {
    this.returnFocus = returnFocus
    this.publish(OPEN)
  }

  hide(): void {
    const focusTarget = this.returnFocus
    this.returnFocus = null
    this.controller.closeAssessment()
    this.publish(CLOSED)
    queueMicrotask(() => { focusTarget?.focus() })
  }

  dispose(): void {
    this.returnFocus = null
    this.controller.closeAssessment()
    this.snapshot = CLOSED
    this.listeners.clear()
  }

  private publish(snapshot: WorkbenchPresentationSnapshotV1): void {
    if (this.snapshot === snapshot) return
    this.snapshot = snapshot
    for (const listener of [...this.listeners]) listener()
  }
}
