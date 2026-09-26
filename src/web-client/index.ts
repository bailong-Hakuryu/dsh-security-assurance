/**
 * Browser half of Security Assurance for the Harness Web client module system
 * (ADR 0322). The tool cards replace the generic rows of the eight Security
 * model tools; they hold no authority, call no Service, and read nothing
 * beyond the tool-call blocks the conversation already has. The Workbench
 * starts beside them once the Remote transport exists (ADR 0321).
 */
import { en, zh } from './locales.ts'
import { SECURITY_TOOL_CARD_NAMES } from './model.ts'
import { SECURITY_TOOL_CARD_CSS, SecurityToolCard } from './card.ts'
import { WorkbenchBridge } from './workbench-bridge.ts'
import * as workbench from './workbench/controller.ts'

/** Locale namespace bound to every Security card's `t`. */
export const SECURITY_TOOL_CARD_NAMESPACE = 'dsh-security-assurance.tool-cards'

interface StyleHost {
  readonly head: { appendChild(node: unknown): unknown }
  createElement(tag: 'style'): { textContent: string | null; dataset: Record<string, string>; remove(): void }
}

/** Client services the cards need; everything else stays with the Host. */
interface ToolCardClientContext {
  effect(execute: () => () => void, label?: string): unknown
  plugin(plugin: { readonly name: string; readonly inject: readonly string[]; readonly apply: unknown }): unknown
  readonly slots: {
    inject(name: string, register: () => () => void): unknown
    register(
      options: {
        readonly name: string
        readonly key: string
        readonly locale: string
        readonly inject: () => object
      },
      component: unknown,
    ): () => void
  }
  readonly locale: {
    register(namespace: string, dictionaries: { readonly zh: typeof zh; readonly en: typeof en }): () => void
  }
}

export const name = 'dsh-security-assurance/client'
export const inject = ['slots', 'locale']

function installStyles(): () => void {
  const document = (globalThis as { document?: StyleHost }).document
  if (document === undefined) return () => {}
  const style = document.createElement('style')
  style.dataset['plugin'] = 'dsh-security-assurance'
  style.textContent = SECURITY_TOOL_CARD_CSS
  document.head.appendChild(style)
  return () => { style.remove() }
}

export function apply(ctx: ToolCardClientContext): void {
  const bridge = new WorkbenchBridge()
  ctx.effect(installStyles, 'dsh-security-assurance: tool card styles')
  ctx.effect(
    () => ctx.locale.register(SECURITY_TOOL_CARD_NAMESPACE, { zh, en }),
    'dsh-security-assurance: tool card dictionaries',
  )
  for (const toolName of SECURITY_TOOL_CARD_NAMES) {
    ctx.slots.inject('tool.call.toolview', () => ctx.slots.register({
      name: 'tool.call.toolview',
      key: toolName,
      locale: SECURITY_TOOL_CARD_NAMESPACE,
      inject: () => ({ hooks: { workbench: bridge }, openInWorkbench: bridge.open }),
    }, SecurityToolCard))
  }
  ctx.plugin({
    name: 'dsh-security-assurance/workbench',
    inject: workbench.inject,
    apply: (workbenchCtx: Parameters<typeof workbench.apply>[0]) => workbench.apply(workbenchCtx, { cards: bridge }),
  })
}
