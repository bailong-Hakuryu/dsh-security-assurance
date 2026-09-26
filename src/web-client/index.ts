/**
 * Browser half of Security Assurance for the Harness Web client module system
 * (ADR 0320). It only replaces the generic rows of the eight Security model
 * tools with purpose-built cards; it holds no authority, calls no Service,
 * and reads nothing beyond the tool-call blocks the conversation already has.
 */
import { en, zh } from './locales.ts'
import { SECURITY_TOOL_CARD_NAMES } from './model.ts'
import { SECURITY_TOOL_CARD_CSS, SecurityToolCard } from './card.ts'

/** Locale namespace bound to every Security card's `t`. */
export const SECURITY_TOOL_CARD_NAMESPACE = 'dsh-security-assurance.tool-cards'

interface StyleHost {
  readonly head: { appendChild(node: unknown): unknown }
  createElement(tag: 'style'): { textContent: string | null; dataset: Record<string, string>; remove(): void }
}

/** Client services the cards need; everything else stays with the Host. */
interface ToolCardClientContext {
  effect(execute: () => () => void, label?: string): unknown
  readonly slots: {
    inject(name: string, register: () => () => void): unknown
    register(
      options: { readonly name: string; readonly key: string; readonly locale: string },
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
    }, SecurityToolCard))
  }
}
