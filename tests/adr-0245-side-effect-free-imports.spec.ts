import { describe, it, expect, beforeEach, vi } from 'vitest'

describe('ADR 0245: Contract imports are side-effect-free and runtime entries start dormant', () => {
  let consoleSpies: {
    log: ReturnType<typeof vi.spyOn>
    warn: ReturnType<typeof vi.spyOn>
    error: ReturnType<typeof vi.spyOn>
    info: ReturnType<typeof vi.spyOn>
    debug: ReturnType<typeof vi.spyOn>
  }
  let processSpies: {
    exit: ReturnType<typeof vi.spyOn>
  }

  beforeEach(() => {
    consoleSpies = {
      log: vi.spyOn(console, 'log').mockImplementation(() => {}),
      warn: vi.spyOn(console, 'warn').mockImplementation(() => {}),
      error: vi.spyOn(console, 'error').mockImplementation(() => {}),
      info: vi.spyOn(console, 'info').mockImplementation(() => {}),
      debug: vi.spyOn(console, 'debug').mockImplementation(() => {}),
    }
    processSpies = {
      exit: vi.spyOn(process, 'exit').mockImplementation((() => {}) as never),
    }
  })

  it('importing ./contracts produces no side effects', async () => {
    await import('../src/contracts.js')

    expect(consoleSpies.log).not.toHaveBeenCalled()
    expect(consoleSpies.warn).not.toHaveBeenCalled()
    expect(consoleSpies.error).not.toHaveBeenCalled()
    expect(processSpies.exit).not.toHaveBeenCalled()
  })

  it('importing ./analyzer produces no side effects', async () => {
    await import('../src/analyzer.js')

    expect(consoleSpies.log).not.toHaveBeenCalled()
    expect(consoleSpies.warn).not.toHaveBeenCalled()
    expect(consoleSpies.error).not.toHaveBeenCalled()
    expect(processSpies.exit).not.toHaveBeenCalled()
  })

  it('importing ./evaluation produces no side effects', async () => {
    await import('../src/evaluation.js')

    expect(consoleSpies.log).not.toHaveBeenCalled()
    expect(consoleSpies.warn).not.toHaveBeenCalled()
    expect(consoleSpies.error).not.toHaveBeenCalled()
    expect(processSpies.exit).not.toHaveBeenCalled()
  })

  it('importing ./tools produces no side effects', async () => {
    await import('../src/tools.js')

    expect(consoleSpies.log).not.toHaveBeenCalled()
    expect(consoleSpies.warn).not.toHaveBeenCalled()
    expect(consoleSpies.error).not.toHaveBeenCalled()
    expect(processSpies.exit).not.toHaveBeenCalled()
  })

  it('importing ./control-plane-provider produces no side effects', async () => {
    await import('../src/control-plane-provider.js')

    expect(consoleSpies.log).not.toHaveBeenCalled()
    expect(consoleSpies.warn).not.toHaveBeenCalled()
    expect(consoleSpies.error).not.toHaveBeenCalled()
    expect(processSpies.exit).not.toHaveBeenCalled()
  })

  it('importing ./host-repository-provider produces no side effects', async () => {
    await import('../src/host-repository-provider.js')

    expect(consoleSpies.log).not.toHaveBeenCalled()
    expect(consoleSpies.warn).not.toHaveBeenCalled()
    expect(consoleSpies.error).not.toHaveBeenCalled()
    expect(processSpies.exit).not.toHaveBeenCalled()
  })

  it('importing ./workbench-remote produces no side effects', async () => {
    await import('../src/workbench-remote.js')

    expect(consoleSpies.log).not.toHaveBeenCalled()
    expect(consoleSpies.warn).not.toHaveBeenCalled()
    expect(consoleSpies.error).not.toHaveBeenCalled()
    expect(processSpies.exit).not.toHaveBeenCalled()
  })

  it('importing root entry (.) produces no side effects', async () => {
    await import('../src/index.js')

    expect(consoleSpies.log).not.toHaveBeenCalled()
    expect(consoleSpies.warn).not.toHaveBeenCalled()
    expect(consoleSpies.error).not.toHaveBeenCalled()
    expect(processSpies.exit).not.toHaveBeenCalled()
  })
})
