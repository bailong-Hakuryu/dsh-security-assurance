/**
 * The Harness Web page supplies React through its client module table, so the
 * tool-card bundle keeps `react` external and ships no copy of it. This
 * declares only the runtime surface the cards call; it is not a type package.
 */
declare module 'react' {
  export type ReactNode = unknown
  export function createElement(
    type: unknown,
    props?: Readonly<Record<string, unknown>> | null,
    ...children: readonly ReactNode[]
  ): ReactNode
  export function useState<S>(initial: S): [S, (next: S | ((previous: S) => S)) => void]
}
