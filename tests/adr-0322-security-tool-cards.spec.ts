import { describe, expect, it } from 'vitest'
import {
  SECURITY_TOOL_CARD_NAMES,
  securityToolCard,
  type CardLabel,
  type ToolCardModel,
} from '../src/web-client/model.ts'
import { en, zh } from '../src/web-client/locales.ts'

const ASSESSMENT_ID = 'asm-2b81034d-a81b-4705-9f91-ea5044e98ea4'

function running(name: string, args: unknown) {
  return {
    callId: `call-${name}`,
    name,
    argsRaw: typeof args === 'string' ? args : JSON.stringify(args),
    turn: 1,
    step: 1,
    time: 0,
    subCalls: [],
  }
}

function settled(name: string, args: unknown, output: unknown, isError = false) {
  return {
    kind: 'tool-result' as const,
    seq: 1,
    time: 0,
    callId: `call-${name}`,
    call: { name, argsRaw: JSON.stringify(args) },
    callTime: 0,
    content: [{ type: 'text', text: typeof output === 'string' ? output : JSON.stringify(output) }],
    isError,
    subCalls: [],
    ...isError ? { error: { name: 'ToolArgsError', code: 'SECURITY_NOT_FOUND' } } : {},
  }
}

/** Render a label the way the card does, using the Chinese dictionary. */
function text(label: CardLabel): string {
  if ('literal' in label) return label.literal
  if ('join' in label) return label.join.map(text).join(' · ')
  return zh[label.key].replace(/\{(\w+)\}/gu, (_m, name: string) => {
    const value = label.values?.[name]
    return value === undefined ? `{${name}}` : typeof value === 'object' ? text(value) : String(value)
  })
}

function summaryText(model: ToolCardModel): string {
  return model.summary.map(text).join(' · ')
}

function chipTexts(model: ToolCardModel): string[] {
  return model.chips.map(chip => `${text(chip.label)}:${chip.tone}`)
}

describe('ADR 0322 Security tool card view models', () => {
  it('covers every Security model tool', () => {
    expect([...SECURITY_TOOL_CARD_NAMES].sort()).toEqual([
      'security_assessment_cancel',
      'security_assessment_export',
      'security_assessment_findings',
      'security_assessment_resume',
      'security_assessment_start',
      'security_assessment_status',
      'security_catalog',
      'security_repositories',
    ])
  })

  it('summarizes a sealed status with its verdict and coverage', () => {
    const model = securityToolCard('security_assessment_status', settled(
      'security_assessment_status',
      { assessment_id: ASSESSMENT_ID },
      {
        schemaVersion: 1,
        assessmentId: ASSESSMENT_ID,
        assessmentRevision: 9,
        state: 'SEALED',
        coverage: { status: 'COMPLETE', mandatoryObligations: 3, satisfiedObligations: 3, gapObligations: 0 },
        verdict: 'FAILED',
      },
    ))
    expect(model.state).toBe('ok')
    expect(text(model.title)).toBe('安全评估状态')
    expect(chipTexts(model)).toEqual(['已完成:success', '未通过:danger'])
    expect(summaryText(model)).toBe('覆盖 3/3')
    expect(model.fields.map(field => [text(field.label), text(field.value)])).toEqual([
      ['评估', ASSESSMENT_ID],
      ['修订', '9'],
      ['覆盖状态', '覆盖完整'],
      ['缺口义务', '0'],
    ])
  })

  it('keeps a running status readable from its arguments alone', () => {
    const model = securityToolCard('security_assessment_status', running(
      'security_assessment_status',
      { assessment_id: ASSESSMENT_ID },
    ))
    expect(model.state).toBe('running')
    expect(summaryText(model)).toBe('asm-2b81034d')
    expect(model.chips).toEqual([])
    expect(model.rawOutput).toBeNull()
  })

  it('marks an unsealed status as pending instead of implying a verdict', () => {
    const model = securityToolCard('security_assessment_status', settled(
      'security_assessment_status',
      { assessment_id: ASSESSMENT_ID },
      {
        schemaVersion: 1,
        assessmentId: ASSESSMENT_ID,
        assessmentRevision: 2,
        state: 'RUNNING',
        coverage: { status: 'PENDING', mandatoryObligations: 1, satisfiedObligations: 0, gapObligations: 0 },
        verdict: null,
      },
    ))
    expect(chipTexts(model)).toEqual(['运行中:info', '结论待定:neutral'])
    expect(summaryText(model)).toBe('覆盖 0/1')
  })

  it('counts findings by severity and flags another page', () => {
    const finding = (severity: string, primary: string) => ({
      recordKind: 'FINDING',
      recordId: `finding-${severity}`,
      validationState: 'VALIDATED',
      weaknessClassification: { primary, secondary: [] },
      technicalSeverity: severity,
      evidenceConfidence: 'HIGH',
      policySignificance: 'BLOCKING',
      component: 'repository-root',
    })
    const model = securityToolCard('security_assessment_findings', settled(
      'security_assessment_findings',
      { assessment_id: ASSESSMENT_ID },
      {
        schemaVersion: 1,
        assessmentId: ASSESSMENT_ID,
        assessmentRevision: 9,
        findings: [finding('HIGH', 'CWE-94'), finding('MEDIUM', 'DSH-NODE-POLICY-001'), finding('HIGH', 'CWE-78')],
        nextCursor: 'opaque.cursor',
      },
    ))
    expect(summaryText(model)).toBe('3 项发现')
    expect(chipTexts(model)).toEqual(['高 ×2:danger', '中 ×1:warning', '还有更多:neutral'])
    expect(model.fields.map(field => [text(field.label), text(field.value)])).toEqual([
      ['高', 'CWE-94 · repository-root · 已验证 · 阻断'],
      ['中', 'DSH-NODE-POLICY-001 · repository-root · 已验证 · 阻断'],
      ['高', 'CWE-78 · repository-root · 已验证 · 阻断'],
    ])
  })

  it('shows where a finding is when the tool names its location', () => {
    const model = securityToolCard('security_assessment_findings', settled(
      'security_assessment_findings',
      { assessment_id: ASSESSMENT_ID },
      {
        schemaVersion: 1,
        assessmentId: ASSESSMENT_ID,
        assessmentRevision: 3,
        findings: [{
          recordKind: 'FINDING',
          recordId: 'finding-located',
          validationState: 'VALIDATED',
          weaknessClassification: { primary: 'DSH-NODE-POLICY-001', secondary: [] },
          technicalSeverity: 'MEDIUM',
          evidenceConfidence: 'HIGH',
          policySignificance: 'BLOCKING',
          component: 'repository-root',
          location: { path: 'package.json', pointer: '/scripts/postinstall' },
        }],
        nextCursor: null,
      },
    ))
    expect(model.fields.map(field => [text(field.label), text(field.value)])).toEqual([
      ['中', 'DSH-NODE-POLICY-001 · repository-root · package.json#/scripts/postinstall · 已验证 · 阻断'],
    ])
  })

  it('reports an empty findings page without inventing severity', () => {
    const model = securityToolCard('security_assessment_findings', settled(
      'security_assessment_findings',
      { assessment_id: ASSESSMENT_ID },
      { schemaVersion: 1, assessmentId: ASSESSMENT_ID, assessmentRevision: 9, findings: [], nextCursor: null },
    ))
    expect(summaryText(model)).toBe('未发现问题')
    expect(model.chips).toEqual([])
  })

  it('names repositories, catalog choices, and the created assessment', () => {
    const repositories = securityToolCard('security_repositories', settled('security_repositories', {}, {
      schemaVersion: 1,
      repositories: [
        { repositoryId: 'repo-1', repositoryRevision: 1, state: 'ENABLED', displayName: 'Current workspace', policyId: 'p', assessmentProfileId: 'security/standard', platform: 'win32' },
        { repositoryId: 'repo-2', repositoryRevision: 1, state: 'DISABLED', displayName: 'Archive', policyId: 'p', assessmentProfileId: 'security/standard', platform: 'win32' },
      ],
      truncated: false,
    }))
    expect(summaryText(repositories)).toBe('2 个仓库 · Current workspace')
    expect(repositories.fields.map(field => [text(field.label), text(field.value)])).toEqual([
      ['Current workspace · repo-1', '已启用 · security/standard'],
      ['Archive · repo-2', '已停用 · security/standard'],
    ])

    const catalog = securityToolCard('security_catalog', settled('security_catalog', { repository_id: 'repo-1' }, {
      schemaVersion: 1,
      repository: { repositoryId: 'repo-1', repositoryRevision: 1, state: 'ENABLED', displayName: 'Current workspace' },
      assessmentModes: [
        { assessmentMode: 'REPOSITORY', targetKind: 'repository', subjectKinds: ['workspace_snapshot'], support: 'SUPPORTED', limitations: [] },
        { assessmentMode: 'CHANGE', targetKind: 'change', subjectKinds: ['change'], support: 'UNSUPPORTED', limitations: [] },
      ],
      assessmentProfiles: [{ assessmentProfileId: 'security/standard', limitations: [] }],
      strongerControls: [],
      supportedEcosystemIds: ['node'],
      supportedPlatforms: ['win32'],
    }))
    expect(summaryText(catalog)).toBe('Current workspace · 1 种可用模式')

    const started = securityToolCard('security_assessment_start', settled('security_assessment_start', {
      assessment_mode: 'REPOSITORY',
      assessment_profile_id: 'security/standard',
    }, {
      schemaVersion: 1,
      operation: 'start_assessment',
      assessmentId: ASSESSMENT_ID,
      assessmentRevision: 1,
      state: 'CREATED',
      idempotencyKey: 'probe-key',
    }))
    expect(summaryText(started)).toBe('REPOSITORY · security/standard · 已创建 asm-2b81034d')
    expect(chipTexts(started)).toEqual(['已创建:info'])
  })

  it('surfaces a failed call as an error with its first message line', () => {
    const model = securityToolCard('security_assessment_status', settled(
      'security_assessment_status',
      { assessment_id: ASSESSMENT_ID },
      'Assessment does not exist\nsecond line',
      true,
    ))
    expect(model.state).toBe('error')
    expect(model.errorText).toBe('Assessment does not exist')
    expect(model.chips).toEqual([])
  })

  it('never throws on truncated or foreign payloads', () => {
    const truncated = securityToolCard('security_assessment_start', running('security_assessment_start', '{"assessment_mo'))
    expect(truncated.state).toBe('running')
    expect(truncated.summary).toEqual([])

    const foreign = securityToolCard('security_assessment_findings', settled(
      'security_assessment_findings',
      { assessment_id: 7 },
      { findings: 'not-an-array' },
    ))
    expect(foreign.state).toBe('ok')
    expect(foreign.fields).toEqual([])
    expect(securityToolCard('security_repositories', null).state).toBe('running')
  })

  it('ships identical Chinese and English dictionaries', () => {
    expect(Object.keys(zh).sort()).toEqual(Object.keys(en).sort())
    for (const [key, value] of Object.entries(zh)) {
      expect(value.length, key).toBeGreaterThan(0)
      expect(en[key as keyof typeof en].length, key).toBeGreaterThan(0)
    }
  })
})
