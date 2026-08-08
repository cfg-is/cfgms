// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * ShellTab suite (Story #2762): WebSocket lifecycle, error-state rendering,
 * and reconnect.
 *
 * @xterm/xterm and @xterm/addon-fit are mocked so the suite runs in jsdom
 * without a canvas/layout engine. WebSocket and ResizeObserver are stubbed
 * globally to control connection lifecycle from tests.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { act, cleanup, fireEvent, render, screen } from '@testing-library/react'
import ShellTab from './ShellTab.tsx'

// ---------------------------------------------------------------------------
// Module mocks — hoisted by vitest to the top of the module graph
// ---------------------------------------------------------------------------

vi.mock('@xterm/xterm', () => {
  function Terminal(this: Record<string, unknown>) {
    this.open = vi.fn()
    this.write = vi.fn()
    this.clear = vi.fn()
    this.dispose = vi.fn()
    this.getSelection = vi.fn().mockReturnValue('')
    this.loadAddon = vi.fn()
    this.onData = vi.fn().mockReturnValue({ dispose: vi.fn() })
    this.onResize = vi.fn().mockReturnValue({ dispose: vi.fn() })
    this.cols = 80
    this.rows = 24
  }
  return { Terminal }
})

vi.mock('@xterm/addon-fit', () => {
  function FitAddon(this: Record<string, unknown>) {
    this.fit = vi.fn()
    this.dispose = vi.fn()
  }
  return { FitAddon }
})

// CSS side-effect import — ignored in jsdom; silenced here so the mock graph
// is consistent across tests.
vi.mock('@xterm/xterm/css/xterm.css', () => ({}))

// ---------------------------------------------------------------------------
// WebSocket stub
// ---------------------------------------------------------------------------

class FakeWebSocket {
  static instances: FakeWebSocket[] = []

  url: string
  readyState: number = WebSocket.CONNECTING
  onopen: ((ev: Event) => void) | null = null
  onclose: ((ev: CloseEvent) => void) | null = null
  onmessage: ((ev: { data: string }) => void) | null = null
  onerror: ((ev: Event) => void) | null = null
  _closed = false
  _sentMessages: string[] = []

  constructor(url: string) {
    this.url = url
    FakeWebSocket.instances.push(this)
  }

  open() {
    this.readyState = WebSocket.OPEN
    this.onopen?.(new Event('open'))
  }

  send(data: string) {
    this._sentMessages.push(data)
  }

  close(code = 1000) {
    if (this._closed) return
    this._closed = true
    this.readyState = WebSocket.CLOSED
    this.onclose?.(new CloseEvent('close', { code }))
  }

  closeWithCode(code: number, reason = '') {
    if (this._closed) return
    this._closed = true
    this.readyState = WebSocket.CLOSED
    this.onclose?.(new CloseEvent('close', { code, reason }))
  }

  deliver(payload: unknown) {
    this.onmessage?.({ data: JSON.stringify(payload) })
  }
}

// ---------------------------------------------------------------------------
// ResizeObserver stub
// ---------------------------------------------------------------------------

class StubResizeObserver {
  observe() {}
  unobserve() {}
  disconnect() {}
}

// ---------------------------------------------------------------------------
// Test setup
// ---------------------------------------------------------------------------

let origWebSocket: typeof WebSocket
let origResizeObserver: typeof ResizeObserver

beforeEach(() => {
  FakeWebSocket.instances = []
  origWebSocket = globalThis.WebSocket
  origResizeObserver = globalThis.ResizeObserver
  // @ts-expect-error intentional stub — FakeWebSocket is not a full WebSocket constructor
  globalThis.WebSocket = FakeWebSocket
  globalThis.ResizeObserver = StubResizeObserver as unknown as typeof ResizeObserver
})

afterEach(() => {
  globalThis.WebSocket = origWebSocket
  globalThis.ResizeObserver = origResizeObserver
  cleanup()
  vi.clearAllMocks()
})

// ---------------------------------------------------------------------------
// WebSocket lifecycle
// ---------------------------------------------------------------------------

describe('WebSocket lifecycle', () => {
  it('opens a WebSocket on mount to the correct terminal endpoint', () => {
    render(<ShellTab stewardId="stw-001" />)
    expect(FakeWebSocket.instances).toHaveLength(1)
    expect(FakeWebSocket.instances[0]!.url).toMatch(/\/api\/v1\/terminal\/ws\/stw-001$/)
  })

  it('encodes the steward ID in the WS URL', () => {
    render(<ShellTab stewardId="stw/special id" />)
    expect(FakeWebSocket.instances[0]!.url).toMatch(/\/api\/v1\/terminal\/ws\/stw%2Fspecial%20id$/)
  })

  it('closes the WebSocket on unmount', () => {
    const { unmount } = render(<ShellTab stewardId="stw-001" />)
    const ws = FakeWebSocket.instances[0]!
    expect(ws._closed).toBe(false)
    unmount()
    expect(ws._closed).toBe(true)
  })

  it('shows a connecting indicator before onopen fires', () => {
    render(<ShellTab stewardId="stw-001" />)
    expect(screen.getByRole('status')).toBeInTheDocument()
    expect(screen.getByText(/opening remote shell/i)).toBeInTheDocument()
  })

  it('removes the connecting indicator once the WS opens', () => {
    render(<ShellTab stewardId="stw-001" />)
    act(() => { FakeWebSocket.instances[0]!.open() })
    expect(screen.queryByText(/opening remote shell/i)).not.toBeInTheDocument()
  })

  it('shows Connected pill after onopen', () => {
    render(<ShellTab stewardId="stw-001" />)
    act(() => { FakeWebSocket.instances[0]!.open() })
    expect(screen.getByText('Connected')).toBeInTheDocument()
  })
})

// ---------------------------------------------------------------------------
// Denied state (403 / pre-connect close)
// ---------------------------------------------------------------------------

describe('denied state', () => {
  it('shows a not-permitted message when WS closes before onopen (HTTP 403)', () => {
    render(<ShellTab stewardId="stw-001" />)
    act(() => { FakeWebSocket.instances[0]!.closeWithCode(0) })
    const alert = screen.getByRole('alert')
    expect(alert.textContent).toMatch(/denied|permission|not have permission/i)
  })

  it('shows a not-permitted message on explicit close code 4403', () => {
    render(<ShellTab stewardId="stw-001" />)
    act(() => { FakeWebSocket.instances[0]!.closeWithCode(4403) })
    const alert = screen.getByRole('alert')
    expect(alert.textContent).toMatch(/denied|permission|not have permission/i)
  })

  it('includes the 403 endpoint path in the denied state', () => {
    render(<ShellTab stewardId="stw-001" />)
    act(() => { FakeWebSocket.instances[0]!.closeWithCode(0) })
    expect(screen.getByRole('alert').textContent).toContain('/api/v1/terminal/ws/stw-001')
  })

  it('does not show a Reconnect button in the denied state', () => {
    render(<ShellTab stewardId="stw-001" />)
    act(() => { FakeWebSocket.instances[0]!.closeWithCode(0) })
    expect(screen.queryByRole('button', { name: /reconnect/i })).not.toBeInTheDocument()
  })
})

// ---------------------------------------------------------------------------
// Disconnected / offline state
// ---------------------------------------------------------------------------

describe('offline / disconnected state', () => {
  it('shows a steward-unreachable message when the WS closes after connecting', () => {
    render(<ShellTab stewardId="stw-001" />)
    act(() => {
      FakeWebSocket.instances[0]!.open()
      FakeWebSocket.instances[0]!.closeWithCode(1006)
    })
    const alert = screen.getByRole('alert')
    expect(alert.textContent).toMatch(/unreachable|offline|interrupted/i)
  })

  it('shows a steward-unreachable message when the server sends an error frame', () => {
    render(<ShellTab stewardId="stw-001" />)
    act(() => {
      FakeWebSocket.instances[0]!.open()
      FakeWebSocket.instances[0]!.deliver({ type: 'error', error: 'steward not connected' })
    })
    const alert = screen.getByRole('alert')
    expect(alert.textContent).toMatch(/unreachable|offline|interrupted/i)
  })

  it('shows a Reconnect button in the disconnected state', () => {
    render(<ShellTab stewardId="stw-001" />)
    act(() => {
      FakeWebSocket.instances[0]!.open()
      FakeWebSocket.instances[0]!.closeWithCode(1006)
    })
    expect(screen.getByRole('button', { name: /reconnect/i })).toBeInTheDocument()
  })

  it('reconnect opens a new WebSocket', () => {
    render(<ShellTab stewardId="stw-001" />)
    act(() => {
      FakeWebSocket.instances[0]!.open()
      FakeWebSocket.instances[0]!.closeWithCode(1006)
    })
    act(() => { fireEvent.click(screen.getByRole('button', { name: /reconnect/i })) })
    expect(FakeWebSocket.instances).toHaveLength(2)
    expect(FakeWebSocket.instances[1]!.url).toMatch(/\/api\/v1\/terminal\/ws\/stw-001$/)
  })

  it('closes the old WebSocket when reconnecting', () => {
    render(<ShellTab stewardId="stw-001" />)
    act(() => {
      FakeWebSocket.instances[0]!.open()
      FakeWebSocket.instances[0]!.closeWithCode(1006)
    })
    const firstWs = FakeWebSocket.instances[0]!
    act(() => { fireEvent.click(screen.getByRole('button', { name: /reconnect/i })) })
    expect(firstWs._closed).toBe(true)
  })
})

// ---------------------------------------------------------------------------
// Disconnect action
// ---------------------------------------------------------------------------

describe('Disconnect button', () => {
  it('shows a Disconnect button while connected', () => {
    render(<ShellTab stewardId="stw-001" />)
    act(() => { FakeWebSocket.instances[0]!.open() })
    expect(screen.getByRole('button', { name: /disconnect shell/i })).toBeInTheDocument()
  })

  it('hides the Disconnect button while connecting', () => {
    render(<ShellTab stewardId="stw-001" />)
    expect(screen.queryByRole('button', { name: /disconnect shell/i })).not.toBeInTheDocument()
  })

  it('closes the WS when Disconnect is clicked', () => {
    render(<ShellTab stewardId="stw-001" />)
    act(() => { FakeWebSocket.instances[0]!.open() })
    const ws = FakeWebSocket.instances[0]!
    act(() => { fireEvent.click(screen.getByRole('button', { name: /disconnect shell/i })) })
    expect(ws._closed).toBe(true)
  })
})

// ---------------------------------------------------------------------------
// Resize protocol
// ---------------------------------------------------------------------------

describe('resize messages', () => {
  it('sends a resize TerminalMessage after the WS opens', () => {
    render(<ShellTab stewardId="stw-001" />)
    act(() => { FakeWebSocket.instances[0]!.open() })
    const ws = FakeWebSocket.instances[0]!
    const resizeMsg = ws._sentMessages.find((m) => {
      try { return (JSON.parse(m) as { type: string }).type === 'resize' } catch { return false }
    })
    expect(resizeMsg).toBeDefined()
  })

  it('resize message data field is base64-encoded JSON with cols and rows', () => {
    render(<ShellTab stewardId="stw-001" />)
    act(() => { FakeWebSocket.instances[0]!.open() })
    const ws = FakeWebSocket.instances[0]!
    const resizeMsg = ws._sentMessages
      .map((m) => { try { return JSON.parse(m) as Record<string, string> } catch { return null } })
      .find((m) => m?.type === 'resize')
    expect(resizeMsg).toBeDefined()
    expect(typeof resizeMsg!.data).toBe('string')
    // Decode base64 and verify it's valid JSON with cols + rows
    const decoded = JSON.parse(atob(resizeMsg!.data ?? '')) as { cols: number; rows: number }
    expect(typeof decoded.cols).toBe('number')
    expect(typeof decoded.rows).toBe('number')
  })
})

// ---------------------------------------------------------------------------
// Stable mount / testid
// ---------------------------------------------------------------------------

describe('component structure', () => {
  it('renders with the shell-tab testid', () => {
    render(<ShellTab stewardId="stw-001" />)
    expect(screen.getByTestId('shell-tab')).toBeInTheDocument()
  })
})
