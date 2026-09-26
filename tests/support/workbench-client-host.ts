import type { Context } from '@deepseek-ai/cordis'

/** One Remote call as the Harness Web connection carrier receives it. */
export type WorkbenchRemoteCall = (
  path: string,
  endpoint: string,
  payload: unknown,
  signal: AbortSignal,
) => Promise<unknown>

/**
 * Stand in for the Harness Web connection carrier that the API Gateway client
 * projection consumes: Remote calls reach one test double, and no socket,
 * event generation, or reconnect loop ever starts.
 */
export function provideConnection(ctx: Context, rpc: { readonly call: WorkbenchRemoteCall }): void {
  ctx.provide('connection', {
    isLoopback: true,
    generation: { getSnapshot: () => undefined, subscribe: () => () => {} },
    rpc: {
      call: rpc.call,
      open: () => { throw new Error('The Workbench opens no Remote stream.') },
    },
    registerGenerationSource: () => () => {},
    start: () => ({ stop() {} }),
  } as never)
}

/** Registered slot entry recorded by {@link provideSlotRecorder}. */
export interface RecordedSlotEntry {
  readonly name: string
  readonly id: string
  readonly component: unknown
  readonly inject: () => Record<string, unknown>
}

/**
 * Stand in for the Host slot registry and locale service: registrations are
 * recorded so a test can reach the launcher and overlay injections.
 */
export function provideSlotRecorder(ctx: Context): RecordedSlotEntry[] {
  const entries: RecordedSlotEntry[] = []
  ctx.provide('slots', {
    inject: (_name: string, register: () => () => void) => register(),
    register: (entry: Omit<RecordedSlotEntry, 'component'>, component: unknown) => {
      const recorded = { ...entry, component }
      entries.push(recorded)
      return () => { entries.splice(entries.indexOf(recorded), 1) }
    },
  } as never)
  ctx.provide('locale', { register: () => () => {} } as never)
  return entries
}
