/**
 * The one seam between the tool cards and the Workbench (ADR 0323). A card
 * learns only whether the Workbench can open an Assessment and may ask it to;
 * it never sees an authority context, a Remote, or the Service.
 */
import type { AssessmentId } from '../contracts.ts'
import { isAssessmentId } from './model.ts'

/** Whether an installed Workbench can open an Assessment for the cards. */
export interface WorkbenchBridgeSnapshot {
  readonly available: boolean
}

/** Opens one Assessment in the Workbench, returning focus to the card afterwards. */
export type WorkbenchAssessmentOpener = (assessmentId: AssessmentId, returnFocus: HTMLElement) => Promise<void>

const AVAILABLE: WorkbenchBridgeSnapshot = Object.freeze({ available: true })
const UNAVAILABLE: WorkbenchBridgeSnapshot = Object.freeze({ available: false })

/** Snapshot source for the cards' `useWorkbench` hook plus the Workbench's attach point. */
export class WorkbenchBridge {
  private opener: WorkbenchAssessmentOpener | undefined
  private snapshot = UNAVAILABLE
  private readonly listeners = new Set<() => void>()

  readonly getSnapshot = (): WorkbenchBridgeSnapshot => this.snapshot

  readonly subscribe = (listener: () => void): (() => void) => {
    this.listeners.add(listener)
    return () => { this.listeners.delete(listener) }
  }

  /** Let the cards open Assessments until the returned disposer runs. */
  attach(opener: WorkbenchAssessmentOpener): () => void {
    this.opener = opener
    this.publish(AVAILABLE)
    return () => {
      if (this.opener !== opener) return
      this.opener = undefined
      this.publish(UNAVAILABLE)
    }
  }

  /** Ask the attached Workbench to open one well-formed Assessment identity. */
  readonly open = (assessmentId: string, returnFocus: HTMLElement): void => {
    const opener = this.opener
    if (opener === undefined || !isAssessmentId(assessmentId)) return
    void opener(assessmentId, returnFocus)
  }

  private publish(snapshot: WorkbenchBridgeSnapshot): void {
    if (this.snapshot === snapshot) return
    this.snapshot = snapshot
    for (const listener of Array.from(this.listeners)) listener()
  }
}
