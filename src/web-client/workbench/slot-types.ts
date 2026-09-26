/**
 * The Harness slot shares the Workbench components receive, written
 * structurally so the bundle depends on no Harness client type package. Each
 * shape matches `@deepseek-ai/dsh-client-ui-slots` and
 * `@deepseek-ai/dsh-client-store` in every supported Harness version.
 */
import type { WorkbenchKey } from './locales.ts'

/** Snapshot source the slot framework turns into a selector hook. */
export interface HostObservable<T> {
  getSnapshot(): T
  subscribe(listener: () => void): () => void
}

/** Selector hook the framework binds for one `hooks` source. */
export type SnapshotSelectorHook<T> = <S>(selector: (snapshot: T) => S, equal?: (a: S, b: S) => boolean) => S

/** Component view of an inject face's `hooks` compartment: `use<Name>` per source. */
export type PropsHooks<Sources> = {
  readonly [Name in keyof Sources & string as `use${Capitalize<Name>}`]:
  SnapshotSelectorHook<Sources[Name] extends HostObservable<infer T> ? T : never>
}

/** Translator bound to the Workbench locale namespace. */
export interface PropsWorkbenchLocale {
  readonly t: (key: WorkbenchKey, params?: Record<string, unknown>) => string
}

/** Owner share of `sidebar.footer.action`: the sidebar column state. */
export interface SidebarFooterActionOwnerProps {
  /** Whether the sidebar renders wide content (false = the compact rail). */
  readonly wide: boolean
}
