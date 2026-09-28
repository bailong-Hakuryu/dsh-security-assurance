/**
 * Pure view models for the Security tool cards (ADR 0322). A model is a
 * function of one Harness tool-call block only — no Service access, clock, or
 * storage — so live streaming and session replay render the same card. Every
 * field is read defensively: a truncated stream, an error result, or a future
 * output shape degrades to a plainer card instead of throwing.
 */
import { assessmentIdSchema, type AssessmentId } from '../contracts.ts'
import type { SecurityCardMessageKey } from './locales.ts'

/** Tools whose calls render as Security cards instead of the generic row. */
export const SECURITY_TOOL_CARD_NAMES = Object.freeze([
  'security_repositories',
  'security_catalog',
  'security_assessment_start',
  'security_assessment_status',
  'security_assessment_findings',
  'security_assessment_resume',
  'security_assessment_cancel',
  'security_assessment_export',
] as const)

type SecurityToolName = (typeof SECURITY_TOOL_CARD_NAMES)[number]

export type ToolCardState = 'running' | 'ok' | 'error'
export type ToolCardTone = 'neutral' | 'info' | 'success' | 'warning' | 'danger'

/**
 * Display text: a localized key whose values may themselves be labels, a
 * canonical identifier shown verbatim, or labels joined by a middle dot.
 */
export type CardLabel =
  | CardText
  | { readonly literal: string }
  | { readonly join: readonly CardLabel[] }

export interface CardText {
  readonly key: SecurityCardMessageKey
  readonly values?: Readonly<Record<string, string | number | CardLabel>>
}

export interface CardChip {
  readonly label: CardLabel
  readonly tone: ToolCardTone
}

export interface CardField {
  readonly label: CardLabel
  readonly value: CardLabel
}

export interface ToolCardModel {
  readonly title: CardText
  readonly state: ToolCardState
  readonly summary: readonly CardLabel[]
  readonly chips: readonly CardChip[]
  readonly fields: readonly CardField[]
  readonly errorText: string | null
  readonly rawInput: string
  readonly rawOutput: string | null
  /** The well-formed Assessment the call concerns, if it did not fail (ADR 0323). */
  readonly assessmentId: AssessmentId | null
}

type Json = Readonly<Record<string, unknown>>
type Body = Pick<ToolCardModel, 'summary' | 'chips' | 'fields'>

interface ToolCallFacts {
  readonly state: ToolCardState
  readonly argsRaw: string
  readonly args: Json
  readonly outputText: string | null
  readonly output: Json
}

const EMPTY: Json = Object.freeze({})
const NONE: Body = Object.freeze({ summary: [], chips: [], fields: [] })

function record(value: unknown): Json {
  return typeof value === 'object' && value !== null && !Array.isArray(value) ? value as Json : EMPTY
}

function parseRecord(raw: string | null): Json {
  if (raw === null) return EMPTY
  try {
    return record(JSON.parse(raw))
  } catch {
    return EMPTY
  }
}

function text(value: unknown): string | undefined {
  return typeof value === 'string' && value.length > 0 ? value : undefined
}

function count(value: unknown): number | undefined {
  return typeof value === 'number' && Number.isInteger(value) && value >= 0 ? value : undefined
}

function list(value: unknown): readonly unknown[] {
  return Array.isArray(value) ? value : []
}

/** Normalize a running call or a settled result node (same shape in every supported Harness). */
function readToolCall(block: unknown): ToolCallFacts {
  const node = record(block)
  const settled = node['kind'] === 'tool-result'
  const head = settled ? record(node['call']) : node
  const argsRaw = typeof head['argsRaw'] === 'string' ? head['argsRaw'] : ''
  const args = parseRecord(argsRaw)
  if (!settled) return { state: 'running', argsRaw, args, outputText: null, output: EMPTY }
  const outputText = list(node['content'])
    .map(record)
    .filter(item => item['type'] === 'text' && typeof item['text'] === 'string')
    .map(item => item['text'] as string)
    .join('\n')
  const isError = node['isError'] === true
  return {
    state: isError ? 'error' : 'ok',
    argsRaw,
    args,
    outputText,
    output: isError ? EMPTY : parseRecord(outputText),
  }
}

function literal(value: string): CardLabel {
  return { literal: value }
}

function msg(key: SecurityCardMessageKey, values?: CardText['values']): CardText {
  return values === undefined ? { key } : { key, values }
}

function join(parts: readonly CardLabel[]): CardLabel {
  return { join: parts }
}

/** `asm-2b81034d-…` → `asm-2b81034d`: enough to tell records apart in one line. */
function shortId(value: string | undefined): string | undefined {
  if (value === undefined) return undefined
  return /^([a-z]+-[0-9a-f]{8})-/u.exec(value)?.[1] ?? value
}

/** Map a closed enum value onto its message key and tone, ignoring unknown values. */
function lookup<V extends string, K extends SecurityCardMessageKey>(
  value: unknown,
  table: Readonly<Record<V, readonly [K, ToolCardTone]>>,
): readonly [K, ToolCardTone] | undefined {
  return typeof value === 'string' && Object.hasOwn(table, value) ? table[value as V] : undefined
}

const ASSESSMENT_STATE = {
  CREATED: ['state.CREATED', 'info'],
  RUNNING: ['state.RUNNING', 'info'],
  BLOCKED: ['state.BLOCKED', 'warning'],
  SEALED: ['state.SEALED', 'success'],
  CANCELED: ['state.CANCELED', 'neutral'],
} as const
const VERDICT = {
  SATISFIED: ['verdict.SATISFIED', 'success'],
  FAILED: ['verdict.FAILED', 'danger'],
  INDETERMINATE: ['verdict.INDETERMINATE', 'warning'],
} as const
const COVERAGE = {
  PENDING: ['coverage.PENDING', 'neutral'],
  COMPLETE: ['coverage.COMPLETE', 'success'],
  GAP: ['coverage.GAP', 'warning'],
} as const
const REPOSITORY_STATE = {
  ENABLED: ['repository.ENABLED', 'success'],
  DISABLED: ['repository.DISABLED', 'neutral'],
} as const
const SEVERITY = {
  CRITICAL: ['severity.CRITICAL', 'danger'],
  HIGH: ['severity.HIGH', 'danger'],
  MEDIUM: ['severity.MEDIUM', 'warning'],
  LOW: ['severity.LOW', 'neutral'],
  INFORMATIONAL: ['severity.INFORMATIONAL', 'neutral'],
} as const
const VALIDATION = {
  VALIDATED: ['validation.VALIDATED', 'success'],
  REJECTED: ['validation.REJECTED', 'neutral'],
  UNRESOLVED: ['validation.UNRESOLVED', 'warning'],
} as const
const SIGNIFICANCE = {
  BLOCKING: ['significance.BLOCKING', 'danger'],
  NON_BLOCKING: ['significance.NON_BLOCKING', 'neutral'],
  ADVISORY: ['significance.ADVISORY', 'neutral'],
} as const

function chip(value: unknown, table: Parameters<typeof lookup>[1]): CardChip[] {
  const entry = lookup(value, table)
  return entry === undefined ? [] : [{ label: msg(entry[0]), tone: entry[1] }]
}

function label(value: unknown, table: Parameters<typeof lookup>[1]): CardLabel[] {
  const entry = lookup(value, table)
  return entry === undefined ? [] : [msg(entry[0])]
}

function assessmentId(value: unknown): CardLabel[] {
  const id = shortId(text(value))
  return id === undefined ? [] : [literal(id)]
}

/** The Repository the Host bound at launch (ADR 0326); display names repeat across launch directories. */
function isLaunchWorkspace(item: Json): boolean {
  return list(item['hostBindingIds']).includes('current-workspace')
}

function repositories({ state, output }: ToolCallFacts): Body {
  if (state !== 'ok') return NONE
  const listed = list(output['repositories']).map(record)
  const items = [...listed.filter(isLaunchWorkspace), ...listed.filter(item => !isLaunchWorkspace(item))]
  const first = items.map(item => text(item['displayName'])).find(name => name !== undefined)
  return {
    summary: [
      msg('summary.repositories', { count: items.length }),
      ...first === undefined ? [] : [literal(first)],
    ],
    chips: output['truncated'] === true ? [{ label: msg('chip.more'), tone: 'neutral' }] : [],
    fields: items.flatMap((item) => {
      const name = text(item['displayName'])
      if (name === undefined) return []
      const id = shortId(text(item['repositoryId']))
      const profile = text(item['assessmentProfileId'])
      return [{
        label: id === undefined ? literal(name) : join([literal(name), literal(id)]),
        value: join([
          ...label(item['state'], REPOSITORY_STATE),
          ...profile === undefined ? [] : [literal(profile)],
          ...isLaunchWorkspace(item) ? [msg('value.launchWorkspace')] : [],
        ]),
      }]
    }),
  }
}

function catalog({ state, args, output }: ToolCallFacts): Body {
  if (state !== 'ok') {
    const id = text(args['repository_id'])
    return { summary: id === undefined ? [] : [literal(id)], chips: [], fields: [] }
  }
  const name = text(record(output['repository'])['displayName'])
  const supported = list(output['assessmentModes']).map(record).filter(mode => mode['support'] === 'SUPPORTED')
  return {
    summary: [
      ...name === undefined ? [] : [literal(name)],
      msg('summary.catalogModes', { count: supported.length }),
    ],
    chips: [],
    fields: [],
  }
}

function start({ state, args, output }: ToolCallFacts): Body {
  const choice = [text(args['assessment_mode']), text(args['assessment_profile_id'])]
    .filter(value => value !== undefined)
    .map(literal)
  const created = shortId(text(output['assessmentId']))
  return {
    summary: [...choice, ...created === undefined ? [] : [msg('summary.created', { id: created })]],
    chips: state === 'ok' ? chip(output['state'], ASSESSMENT_STATE) : [],
    fields: [],
  }
}

function status({ state, args, output }: ToolCallFacts): Body {
  if (state !== 'ok') return { summary: assessmentId(args['assessment_id']), chips: [], fields: [] }
  const coverage = record(output['coverage'])
  const satisfied = count(coverage['satisfiedObligations'])
  const mandatory = count(coverage['mandatoryObligations'])
  const verdict = chip(output['verdict'], VERDICT)
  const id = text(output['assessmentId'])
  const revision = count(output['assessmentRevision'])
  const gaps = count(coverage['gapObligations'])
  return {
    summary: satisfied === undefined || mandatory === undefined
      ? []
      : [msg('summary.coverage', { satisfied, mandatory })],
    // A verdict exists only after sealing; never imply one before that.
    chips: [
      ...chip(output['state'], ASSESSMENT_STATE),
      ...verdict.length > 0 ? verdict : [{ label: msg('chip.verdictPending'), tone: 'neutral' as const }],
    ],
    fields: [
      ...id === undefined ? [] : [{ label: msg('field.assessment'), value: literal(id) }],
      ...revision === undefined ? [] : [{ label: msg('field.revision'), value: literal(String(revision)) }],
      ...label(coverage['status'], COVERAGE).map(value => ({ label: msg('field.coverage'), value })),
      ...gaps === undefined ? [] : [{ label: msg('field.gaps'), value: literal(String(gaps)) }],
    ],
  }
}

function findings({ state, args, output }: ToolCallFacts): Body {
  if (state !== 'ok') return { summary: assessmentId(args['assessment_id']), chips: [], fields: [] }
  if (!Array.isArray(output['findings'])) return NONE
  const items = list(output['findings']).map(record)
  const bySeverity = new Map<keyof typeof SEVERITY, number>()
  for (const item of items) {
    const severity = item['technicalSeverity']
    if (typeof severity === 'string' && Object.hasOwn(SEVERITY, severity)) {
      const key = severity as keyof typeof SEVERITY
      bySeverity.set(key, (bySeverity.get(key) ?? 0) + 1)
    }
  }
  const severityChips = (Object.keys(SEVERITY) as (keyof typeof SEVERITY)[])
    .filter(severity => bySeverity.has(severity))
    .map(severity => ({
      label: msg('chip.severityCount', { severity: msg(SEVERITY[severity][0]), count: bySeverity.get(severity)! }),
      tone: SEVERITY[severity][1],
    }))
  return {
    summary: [items.length === 0 ? msg('summary.noFindings') : msg('summary.findings', { count: items.length })],
    chips: [
      ...severityChips,
      ...text(output['nextCursor']) === undefined ? [] : [{ label: msg('chip.more'), tone: 'neutral' as const }],
    ],
    fields: items.flatMap((item) => {
      const severity = label(item['technicalSeverity'], SEVERITY)
      const weakness = text(record(item['weaknessClassification'])['primary'])
      if (severity.length === 0 || weakness === undefined) return []
      const component = text(item['component'])
      const place = record(item['location'])
      const path = text(place['path'])
      const pointer = typeof place['pointer'] === 'string' ? place['pointer'] : undefined
      return [{
        label: severity[0]!,
        value: join([
          literal(weakness),
          ...component === undefined ? [] : [literal(component)],
          ...path === undefined || pointer === undefined ? [] : [literal(`${path}#${pointer}`)],
          ...label(item['validationState'], VALIDATION),
          ...label(item['policySignificance'], SIGNIFICANCE),
        ]),
      }]
    }),
  }
}

function receipt({ state, args, output }: ToolCallFacts): Body {
  if (state !== 'ok') return { summary: assessmentId(args['assessment_id']), chips: [], fields: [] }
  const revision = count(output['assessmentRevision'])
  const reason = text(args['reason'])
  return {
    summary: [
      ...assessmentId(output['assessmentId']),
      ...revision === undefined ? [] : [msg('summary.revision', { revision })],
    ],
    chips: chip(output['state'] ?? output['acceptedState'], ASSESSMENT_STATE),
    fields: reason === undefined ? [] : [{ label: msg('field.reason'), value: literal(reason) }],
  }
}

function exportReceipt({ state, args, output }: ToolCallFacts): Body {
  if (state !== 'ok') return { summary: assessmentId(args['assessment_id']), chips: [], fields: [] }
  const exportId = shortId(text(output['exportId']))
  return {
    summary: [
      ...assessmentId(output['assessmentId']),
      ...exportId === undefined ? [] : [msg('summary.export', { id: exportId })],
    ],
    chips: output['acceptedState'] === 'PENDING' ? [{ label: msg('state.PENDING'), tone: 'info' }] : [],
    fields: [],
  }
}

/** Tools whose calls concern exactly one Assessment. */
const ASSESSMENT_TOOLS: ReadonlySet<string> = new Set([
  'security_assessment_start',
  'security_assessment_status',
  'security_assessment_findings',
  'security_assessment_resume',
  'security_assessment_cancel',
  'security_assessment_export',
])

/** Whether a value is a canonical Assessment identity. */
export function isAssessmentId(value: unknown): value is AssessmentId {
  return assessmentIdSchema.safeParse(value).success
}

function namedAssessment(toolName: string, { state, args, output }: ToolCallFacts): AssessmentId | null {
  if (state === 'error' || !ASSESSMENT_TOOLS.has(toolName)) return null
  const id = output['assessmentId'] ?? args['assessment_id']
  return isAssessmentId(id) ? id : null
}

const CARDS: Readonly<Record<SecurityToolName, readonly [SecurityCardMessageKey, (facts: ToolCallFacts) => Body]>> = {
  security_repositories: ['title.repositories', repositories],
  security_catalog: ['title.catalog', catalog],
  security_assessment_start: ['title.start', start],
  security_assessment_status: ['title.status', status],
  security_assessment_findings: ['title.findings', findings],
  security_assessment_resume: ['title.resume', receipt],
  security_assessment_cancel: ['title.cancel', receipt],
  security_assessment_export: ['title.export', exportReceipt],
}

/** Build the card model for one Security tool call block. */
export function securityToolCard(toolName: SecurityToolName | string, block: unknown): ToolCardModel {
  const facts = readToolCall(block)
  const card = Object.hasOwn(CARDS, toolName) ? CARDS[toolName as SecurityToolName] : undefined
  const body = card === undefined ? NONE : card[1](facts)
  return {
    title: msg(card?.[0] ?? 'title.status'),
    state: facts.state,
    summary: body.summary,
    chips: facts.state === 'error' ? [] : body.chips,
    fields: body.fields,
    errorText: facts.state === 'error' ? (facts.outputText ?? '').split('\n')[0] ?? '' : null,
    rawInput: facts.argsRaw,
    rawOutput: facts.outputText,
    assessmentId: namedAssessment(toolName, facts),
  }
}
