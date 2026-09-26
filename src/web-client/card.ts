/**
 * Security tool card view (ADR 0322). It mirrors the Harness tool row — one
 * 24px line of icon, title, and summary that expands into details — and adds
 * state chips whose meaning never relies on color alone. All text renders
 * through React text nodes; nothing is injected as HTML. A card that names an
 * Assessment offers to open it in the Workbench once one is available
 * (ADR 0323); the card itself still calls no Service.
 */
import { createElement as h, useState, type MouseEvent, type ReactNode } from 'react'
import { securityToolCard, type CardLabel } from './model.ts'
import type { WorkbenchBridgeSnapshot } from './workbench-bridge.ts'

/** Namespace-bound translator the Harness slot passes to a keyed tool view. */
export type Translate = (key: string, values?: Readonly<Record<string, string | number>>) => string

export interface SecurityToolCardProps {
  readonly toolName: string
  readonly block: unknown
  readonly t: Translate
  readonly inspect?: (() => void) | undefined
  /** Selector hook over the Workbench bridge, bound by the slot framework. */
  readonly useWorkbench?: (<S>(select: (snapshot: WorkbenchBridgeSnapshot) => S) => S) | undefined
  /** Ask the Workbench to open one Assessment, returning focus to the trigger. */
  readonly openInWorkbench?: ((assessmentId: string, returnFocus: HTMLElement) => void) | undefined
}

function render(label: CardLabel, t: Translate): string {
  if ('literal' in label) return label.literal
  if ('join' in label) return label.join.map(part => render(part, t)).join(' · ')
  const values: Record<string, string | number> = {}
  for (const [name, value] of Object.entries(label.values ?? {})) {
    values[name] = typeof value === 'object' ? render(value, t) : value
  }
  return t(label.key, values)
}

function pretty(raw: string): string {
  try {
    return JSON.stringify(JSON.parse(raw), null, 2)
  } catch {
    return raw
  }
}

function shieldIcon(): ReactNode {
  return h('svg', { className: 'dsa-tc-icon', width: 14, height: 14, viewBox: '0 0 16 16', 'aria-hidden': true },
    h('path', {
      d: 'M8 1.6 2.6 3.6v3.9c0 3.2 2.2 5.9 5.4 6.9 3.2-1 5.4-3.7 5.4-6.9V3.6L8 1.6Z',
      fill: 'none',
      stroke: 'currentColor',
      strokeWidth: 1.3,
      strokeLinejoin: 'round',
    }),
    h('path', {
      d: 'm5.8 8.1 1.6 1.6 2.9-3',
      fill: 'none',
      stroke: 'currentColor',
      strokeWidth: 1.3,
      strokeLinecap: 'round',
      strokeLinejoin: 'round',
    }))
}

function openIcon(): ReactNode {
  return h('svg', { width: 14, height: 14, viewBox: '0 0 16 16', 'aria-hidden': true },
    h('path', {
      d: 'M9.5 2.5h4v4M13.5 2.5 8 8M12 9.5v3a1 1 0 0 1-1 1H3.5a1 1 0 0 1-1-1V5a1 1 0 0 1 1-1h3',
      fill: 'none',
      stroke: 'currentColor',
      strokeWidth: 1.3,
      strokeLinecap: 'round',
      strokeLinejoin: 'round',
    }))
}

function chevron(): ReactNode {
  return h('svg', { className: 'dsa-tc-chevron', width: 12, height: 12, viewBox: '0 0 12 12', 'aria-hidden': true },
    h('path', { d: 'm4.5 2.5 3.5 3.5-3.5 3.5', fill: 'none', stroke: 'currentColor', strokeWidth: 1.2 }))
}

/** One Security tool call rendered as a compact, expandable card. */
export function SecurityToolCard(props: SecurityToolCardProps): ReactNode {
  const { t } = props
  const model = securityToolCard(props.toolName, props.block)
  const [open, setOpen] = useState(false)
  const [raw, setRaw] = useState(false)
  // The slot binds this hook for the registration's lifetime, so the call order is stable.
  const workbenchAvailable = props.useWorkbench?.(snapshot => snapshot.available) ?? false
  const assessmentId = model.assessmentId
  const openInWorkbench = props.openInWorkbench
  const onOpenInWorkbench = workbenchAvailable && assessmentId !== null && openInWorkbench !== undefined
    ? (event: MouseEvent<HTMLButtonElement>) => { openInWorkbench(assessmentId, event.currentTarget) }
    : undefined
  const summary = model.state === 'error'
    ? model.errorText ?? ''
    : model.summary.map(label => render(label, t)).join(' · ')
  const header = h('button', {
    type: 'button',
    className: 'dsa-tc-row',
    'aria-expanded': open,
    onClick: () => { setOpen(value => !value) },
  },
  shieldIcon(),
  h('span', { className: 'dsa-tc-title' }, render(model.title, t)),
  summary.length === 0 ? null : h('span', { className: 'dsa-tc-sep', 'aria-hidden': true }),
  h('span', {
    className: model.state === 'error' ? 'dsa-tc-summary dsa-tc-error' : 'dsa-tc-summary',
    title: summary,
  }, summary),
  ...model.chips.map(chip => h('span', { className: 'dsa-tc-chip', 'data-tone': chip.tone }, render(chip.label, t))),
  chevron())
  const head = onOpenInWorkbench === undefined
    ? header
    : h('div', { className: 'dsa-tc-head' },
        header,
        h('button', {
          type: 'button',
          className: 'dsa-tc-open',
          'aria-label': t('action.openInWorkbench'),
          title: t('action.openInWorkbench'),
          onClick: onOpenInWorkbench,
        }, openIcon()))
  if (!open) return h('div', { className: 'dsa-tc', 'data-state': model.state, 'data-tool': props.toolName }, head)
  const body = h('div', { className: 'dsa-tc-body' },
    model.fields.length === 0
      ? null
      : h('dl', { className: 'dsa-tc-fields' },
          ...model.fields.flatMap(field => [
            h('dt', null, render(field.label, t)),
            h('dd', null, render(field.value, t)),
          ])),
    h('div', { className: 'dsa-tc-actions' },
      h('button', {
        type: 'button',
        className: 'dsa-tc-link',
        'aria-expanded': raw,
        onClick: () => { setRaw(value => !value) },
      }, t(raw ? 'action.hideRaw' : 'action.raw')),
      props.inspect === undefined
        ? null
        : h('button', { type: 'button', className: 'dsa-tc-link', onClick: props.inspect }, t('action.details')),
      onOpenInWorkbench === undefined
        ? null
        : h('button', { type: 'button', className: 'dsa-tc-link', onClick: onOpenInWorkbench },
            t('action.openInWorkbench'))),
    raw ? h('div', { className: 'dsa-tc-rawpair' },
      h('span', { className: 'dsa-tc-rawlabel' }, t('raw.input')),
      h('pre', { className: 'dsa-tc-raw' }, pretty(model.rawInput)),
      model.rawOutput === null ? null : h('span', { className: 'dsa-tc-rawlabel' }, t('raw.output')),
      model.rawOutput === null ? null : h('pre', { className: 'dsa-tc-raw' }, pretty(model.rawOutput))) : null)
  return h('div', { className: 'dsa-tc', 'data-state': model.state, 'data-tool': props.toolName }, head, body)
}

/**
 * Card styles use only Harness theme tokens present in every supported
 * Harness version, so light, dark, and font-size settings apply unchanged.
 */
export const SECURITY_TOOL_CARD_CSS = `
.dsa-tc{display:flex;flex-direction:column}
.dsa-tc-head{display:flex;align-items:center;gap:2px;min-width:0}
.dsa-tc-head>.dsa-tc-row{flex:1 1 auto;min-width:0}
.dsa-tc-open{all:unset;box-sizing:border-box;flex:none;display:inline-flex;align-items:center;justify-content:center;width:24px;height:24px;border-radius:6px;cursor:pointer;color:var(--dsw-alias-label-tertiary)}
.dsa-tc-open:hover{color:var(--dsw-alias-label-primary);background:var(--dsw-alias-interactive-bg-hover)}
.dsa-tc-open:focus-visible{outline:2px solid var(--dsw-alias-state-business-primary);outline-offset:1px}
.dsa-tc-row{all:unset;box-sizing:border-box;position:relative;overflow:hidden;display:flex;align-items:center;gap:6px;width:100%;min-height:24px;cursor:pointer;border-radius:6px;font-size:var(--dsh-content-font-size-secondary,13px);line-height:calc(24px + var(--dsh-content-font-delta,0px));color:var(--dsw-alias-label-secondary)}
.dsa-tc-row:hover .dsa-tc-title{color:var(--dsw-alias-label-primary)}
.dsa-tc-row:focus-visible{outline:2px solid var(--dsw-alias-state-business-primary);outline-offset:1px}
.dsa-tc-icon{flex:none;color:var(--dsw-alias-state-business-primary)}
.dsa-tc-title{flex:none;white-space:nowrap}
.dsa-tc-sep{flex:none;width:2px;height:2px;border-radius:1px;margin:0 2px;background:var(--dsw-alias-label-caption)}
.dsa-tc-summary{flex:1 1 auto;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:var(--dsw-alias-label-tertiary)}
.dsa-tc-error{color:var(--dsw-alias-state-error-primary)}
.dsa-tc-chip{flex:none;padding:0 6px;border:0.5px solid currentColor;border-radius:999px;font-size:11px;line-height:17px;white-space:nowrap}
.dsa-tc-chip[data-tone=neutral]{color:var(--dsw-alias-label-tertiary)}
.dsa-tc-chip[data-tone=info]{color:var(--dsw-alias-state-business-primary)}
.dsa-tc-chip[data-tone=success]{color:var(--dsw-alias-state-success-primary)}
.dsa-tc-chip[data-tone=warning]{color:var(--dsw-alias-state-warn-primary)}
.dsa-tc-chip[data-tone=danger]{color:var(--dsw-alias-state-error-primary)}
.dsa-tc-chevron{flex:none;color:var(--dsw-alias-label-caption);transition:transform 120ms ease}
.dsa-tc-row[aria-expanded=true] .dsa-tc-chevron{transform:rotate(90deg)}
.dsa-tc[data-state=running] .dsa-tc-row::after{content:'';position:absolute;top:0;bottom:0;left:0;width:300px;background:linear-gradient(90deg,transparent 0%,color-mix(in srgb,var(--dsw-alias-bg-base) 60%,transparent) 55%,transparent 100%);animation:dsa-tc-sweep 2.6s ease-out infinite;pointer-events:none}
@keyframes dsa-tc-sweep{0%{left:-300px}90%,100%{left:100%}}
@media (prefers-reduced-motion:reduce){.dsa-tc[data-state=running] .dsa-tc-row::after{animation:none;display:none}.dsa-tc-chevron{transition:none}}
.dsa-tc-body{display:flex;flex-direction:column;gap:8px;margin:2px 0 6px 20px;padding:8px 10px;border:0.5px solid var(--dsw-alias-border-l2);border-radius:8px}
.dsa-tc-fields{display:grid;grid-template-columns:max-content 1fr;gap:4px 12px;margin:0;font-size:12px;line-height:18px}
.dsa-tc-fields dt{color:var(--dsw-alias-label-tertiary)}
.dsa-tc-fields dd{margin:0;min-width:0;overflow-wrap:anywhere;color:var(--dsw-alias-label-primary)}
.dsa-tc-actions{display:flex;gap:12px}
.dsa-tc-link{all:unset;cursor:pointer;font-size:12px;line-height:18px;color:var(--dsw-alias-label-secondary);text-decoration:underline dotted;text-underline-offset:3px}
.dsa-tc-link:hover{color:var(--dsw-alias-label-primary)}
.dsa-tc-link:focus-visible{outline:2px solid var(--dsw-alias-state-business-primary);outline-offset:1px}
.dsa-tc-rawpair{display:flex;flex-direction:column;gap:4px}
.dsa-tc-rawlabel{font-size:11px;color:var(--dsw-alias-label-tertiary)}
.dsa-tc-raw{margin:0;padding:8px;max-height:240px;overflow:auto;border-radius:6px;border:0.5px solid var(--dsw-alias-border-l1);font-family:var(--ds-font-family-code);font-size:11px;line-height:16px;white-space:pre-wrap;overflow-wrap:anywhere;color:var(--dsw-alias-label-secondary)}
`
