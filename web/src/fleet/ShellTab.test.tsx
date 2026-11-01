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
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import ShellTab from './ShellTab.tsx'

// ---------------------------------------------------------------------------
// Module mocks — hoisted by vitest to the top of the module graph
// ---------------------------------------------------------------------------

const terminals = vi.hoisted(() => [] as Array<{ options: { theme?: Record<string, string> } }>)

vi.mock('@xterm/xterm', () => {
  function Terminal(this: Record<string, unknown>, opts: Record<string, unknown>) {
    terminals.push(this as never)
    this.open = vi.fn()
    this.write = vi.fn()
    this.clear = vi.fn()
    this.dispose = vi.fn()
    this.getSelection = vi.fn().mockReturnValue('')
    this.loadAddon = vi.fn()
    this.onData = vi.fn().mockReturnValue({ dispose: vi.fn() })
    this.onResize = vi.fn().mockReturnValue({ dispose: vi.fn() })
    this.options = { theme: opts?.theme }
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

  protocols: string[]

  constructor(url: string, protocols: string[] = []) {
    this.url = url
    this.protocols = protocols
    eventLog.push('new WebSocket')
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

const CONTENT = (shell: string, steward = 'stw-001') =>
  btoa(JSON.stringify({
    verb: 'terminal.open', target_kind: 'steward', target_name: steward, parameters: { shell },
  }))

interface FetchCall { path: string; body: unknown }
let fetchCalls: FetchCall[] = []
let fetchStatus = new Map<string, number>()
let eventLog: string[] = []
let credentialsGet: ReturnType<typeof vi.fn>

function jsonResp(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
}

let currentSteward = 'stw-001'

function stubFetch() {
  return vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const path = String(input)
    const body = init?.body ? JSON.parse(String(init.body)) : undefined
    fetchCalls.push({ path, body })
    eventLog.push('fetch:' + path)
    for (const [fragment, status] of fetchStatus) {
      if (path.includes(fragment)) return jsonResp(status, { error: { code: 'NO_CREDENTIALS' } })
    }
    const m = path.match(/\/terminal\/(?:prepare|tickets)\/([^/]+)$/)
    if (m) currentSteward = decodeURIComponent(m[1]!)
    const steward = currentSteward
    if (path.includes('/terminal/prepare/')) {
      return jsonResp(200, { data: { content: CONTENT('bash', steward), shell: 'terminal-open', terminal_shell: 'bash' } })
    }
    if (path.endsWith('/sign/begin')) {
      return jsonResp(200, { data: {
        assertion: { publicKey: { challenge: 'AAEC', allowCredentials: [{ type: 'public-key', id: 'AAEC' }] } },
        envelope: { nonce: 'n1', expires_at: '2030-01-01T00:00:00Z', targets: [steward] },
      } })
    }
    if (path.endsWith('/sign/finish')) {
      return jsonResp(200, { data: { authenticator_data: 'ad', client_data_json: 'cd', signature: 'sg', credential_id: 'ci' } })
    }
    if (path.includes('/terminal/tickets/')) return jsonResp(200, { data: { ticket: 'tkt-123' } })
    return jsonResp(404, {})
  })
}

function fakeCredential() {
  const buf = new Uint8Array([1, 2, 3]).buffer
  return {
    id: 'cred', type: 'public-key', rawId: buf,
    response: { authenticatorData: buf, clientDataJSON: buf, signature: buf, userHandle: null },
  }
}

async function renderShell(steward = 'stw-001') {
  const result = render(<ShellTab stewardId={steward} />)
  await waitFor(() => expect(FakeWebSocket.instances.length).toBeGreaterThan(0))
  return result
}

let origWebSocket: typeof WebSocket
let origFetch: typeof fetch
let origResizeObserver: typeof ResizeObserver

beforeEach(() => {
  FakeWebSocket.instances = []
  origWebSocket = globalThis.WebSocket
  origFetch = globalThis.fetch
  fetchCalls = []
  fetchStatus = new Map()
  eventLog = []
  globalThis.fetch = stubFetch() as unknown as typeof fetch
  credentialsGet = vi.fn(async () => { eventLog.push('credentials.get'); return fakeCredential() })
  Object.defineProperty(navigator, 'credentials', { value: { get: credentialsGet }, configurable: true })
  origResizeObserver = globalThis.ResizeObserver
  // @ts-expect-error intentional stub — FakeWebSocket is not a full WebSocket constructor
  globalThis.WebSocket = FakeWebSocket
  globalThis.ResizeObserver = StubResizeObserver as unknown as typeof ResizeObserver
})

afterEach(() => {
  globalThis.WebSocket = origWebSocket
  globalThis.fetch = origFetch
  globalThis.ResizeObserver = origResizeObserver
  cleanup()
  vi.clearAllMocks()
})

// ---------------------------------------------------------------------------
// WebSocket lifecycle
// ---------------------------------------------------------------------------

describe('WebSocket lifecycle', () => {
  it('opens a WebSocket on mount to the correct terminal endpoint', async () => {
    await renderShell("stw-001")
    expect(FakeWebSocket.instances).toHaveLength(1)
    expect(FakeWebSocket.instances[0]!.url).toMatch(/\/api\/v1\/terminal\/ws\/stw-001$/)
  })

  it('encodes the steward ID in the WS URL path segment', async () => {
    await renderShell("stw/special id")
    expect(FakeWebSocket.instances[0]!.url).toMatch(/\/api\/v1\/terminal\/ws\/stw%2Fspecial%20id$/)
  })

  it('asserts no client-supplied identity in the WS URL (identity is server-derived)', async () => {
    await renderShell("stw-001")
    const url = new URL(FakeWebSocket.instances[0]!.url, 'http://localhost')
    expect(url.search).toBe('')
    expect(url.searchParams.get('user_id')).toBeNull()
    expect(url.searchParams.get('steward_id')).toBeNull()
  })

  it('closes the WebSocket on unmount', async () => {
    const { unmount } = await renderShell("stw-001")
    const ws = FakeWebSocket.instances[0]!
    expect(ws._closed).toBe(false)
    unmount()
    expect(ws._closed).toBe(true)
  })

  it('shows a connecting indicator before onopen fires', async () => {
    await renderShell("stw-001")
    expect(screen.getByRole('status')).toBeInTheDocument()
    expect(screen.getByText(/opening remote shell/i)).toBeInTheDocument()
  })

  it('removes the connecting indicator once the WS opens', async () => {
    await renderShell("stw-001")
    act(() => { FakeWebSocket.instances[0]!.open() })
    expect(screen.queryByText(/opening remote shell/i)).not.toBeInTheDocument()
  })

  it('shows Connected pill after onopen', async () => {
    await renderShell("stw-001")
    act(() => { FakeWebSocket.instances[0]!.open() })
    expect(screen.getByText('Connected')).toBeInTheDocument()
  })
})

// ---------------------------------------------------------------------------
// Denied state (403 / pre-connect close)
// ---------------------------------------------------------------------------

describe('denied state', () => {
  it('shows a not-permitted message when WS closes before onopen (HTTP 403)', async () => {
    await renderShell("stw-001")
    act(() => { FakeWebSocket.instances[0]!.closeWithCode(0) })
    const alert = screen.getByRole('alert')
    expect(alert.textContent).toMatch(/denied|permission|not have permission/i)
  })

  it('shows a not-permitted message on explicit close code 4403', async () => {
    await renderShell("stw-001")
    act(() => { FakeWebSocket.instances[0]!.closeWithCode(4403) })
    const alert = screen.getByRole('alert')
    expect(alert.textContent).toMatch(/denied|permission|not have permission/i)
  })

  it('includes the 403 endpoint path in the denied state', async () => {
    await renderShell("stw-001")
    act(() => { FakeWebSocket.instances[0]!.closeWithCode(0) })
    expect(screen.getByRole('alert').textContent).toContain('/api/v1/terminal/ws/stw-001')
  })

  it('does not show a Reconnect button in the denied state', async () => {
    await renderShell("stw-001")
    act(() => { FakeWebSocket.instances[0]!.closeWithCode(0) })
    expect(screen.queryByRole('button', { name: /reconnect/i })).not.toBeInTheDocument()
  })
})

// ---------------------------------------------------------------------------
// Disconnected / offline state
// ---------------------------------------------------------------------------

describe('offline / disconnected state', () => {
  it('shows a steward-unreachable message when the WS closes after connecting', async () => {
    await renderShell("stw-001")
    act(() => {
      FakeWebSocket.instances[0]!.open()
      FakeWebSocket.instances[0]!.closeWithCode(1006)
    })
    const alert = screen.getByRole('alert')
    expect(alert.textContent).toMatch(/unreachable|offline|interrupted/i)
  })

  it('shows a steward-unreachable message when the server sends an error frame', async () => {
    await renderShell("stw-001")
    act(() => {
      FakeWebSocket.instances[0]!.open()
      FakeWebSocket.instances[0]!.deliver({ type: 'error', error: 'steward not connected' })
    })
    const alert = screen.getByRole('alert')
    expect(alert.textContent).toMatch(/unreachable|offline|interrupted/i)
  })

  it('shows a Reconnect button in the disconnected state', async () => {
    await renderShell("stw-001")
    act(() => {
      FakeWebSocket.instances[0]!.open()
      FakeWebSocket.instances[0]!.closeWithCode(1006)
    })
    expect(screen.getByRole('button', { name: /reconnect/i })).toBeInTheDocument()
  })

  it('reconnect opens a new WebSocket', async () => {
    await renderShell("stw-001")
    act(() => {
      FakeWebSocket.instances[0]!.open()
      FakeWebSocket.instances[0]!.closeWithCode(1006)
    })
    await act(async () => { fireEvent.click(screen.getByRole('button', { name: /reconnect/i })) })
    await waitFor(() => expect(FakeWebSocket.instances).toHaveLength(2))
    expect(FakeWebSocket.instances[1]!.url).toMatch(/\/api\/v1\/terminal\/ws\/stw-001$/)
  })

  it('closes the old WebSocket when reconnecting', async () => {
    await renderShell("stw-001")
    act(() => {
      FakeWebSocket.instances[0]!.open()
      FakeWebSocket.instances[0]!.closeWithCode(1006)
    })
    const firstWs = FakeWebSocket.instances[0]!
    await act(async () => { fireEvent.click(screen.getByRole('button', { name: /reconnect/i })) })
    expect(firstWs._closed).toBe(true)
  })
})

// ---------------------------------------------------------------------------
// Disconnect action
// ---------------------------------------------------------------------------

describe('Disconnect button', () => {
  it('shows a Disconnect button while connected', async () => {
    await renderShell("stw-001")
    act(() => { FakeWebSocket.instances[0]!.open() })
    expect(screen.getByRole('button', { name: /disconnect shell/i })).toBeInTheDocument()
  })

  it('hides the Disconnect button while connecting', async () => {
    await renderShell("stw-001")
    expect(screen.queryByRole('button', { name: /disconnect shell/i })).not.toBeInTheDocument()
  })

  it('closes the WS when Disconnect is clicked', async () => {
    await renderShell("stw-001")
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
  it('sends a resize TerminalMessage after the WS opens', async () => {
    await renderShell("stw-001")
    act(() => { FakeWebSocket.instances[0]!.open() })
    const ws = FakeWebSocket.instances[0]!
    const resizeMsg = ws._sentMessages.find((m) => {
      try { return (JSON.parse(m) as { type: string }).type === 'resize' } catch { return false }
    })
    expect(resizeMsg).toBeDefined()
  })

  it('resize message data field is base64-encoded JSON with cols and rows', async () => {
    await renderShell("stw-001")
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
  it('renders with the shell-tab testid', async () => {
    await renderShell("stw-001")
    expect(screen.getByTestId('shell-tab')).toBeInTheDocument()
  })
})

describe('terminal theme', () => {
  afterEach(() => {
    document.documentElement.removeAttribute('data-theme')
    document.documentElement.removeAttribute('style')
    terminals.length = 0
  })

  it('derives colours from the design tokens and follows a theme toggle', async () => {
    const root = document.documentElement
    root.style.setProperty('--bg-sunk', '#ececea')
    root.style.setProperty('--text-primary', '#5f5e58')
    root.style.setProperty('--accent', '#4a6b7c')
    render(<ShellTab stewardId="stw-001" />)
    const term = terminals[terminals.length - 1]!
    expect(term.options.theme).toMatchObject({ background: '#ececea', foreground: '#5f5e58', cursor: '#4a6b7c' })

    root.style.setProperty('--bg-sunk', '#101010')
    root.style.setProperty('--text-primary', '#bcbbb5')
    root.style.setProperty('--accent', '#7b9fb0')
    root.setAttribute('data-theme', 'dark')
    await waitFor(() => expect(term.options.theme?.background).toBe('#101010'))
    expect(term.options.theme).toMatchObject({ foreground: '#bcbbb5', cursor: '#7b9fb0' })
  })
})

// ---------------------------------------------------------------------------
// Passkey-signed one-time ticket (Issue #5132)
// ---------------------------------------------------------------------------

describe('ticket handshake', () => {
  it('signs and fetches a ticket before creating the WebSocket, offering it as a subprotocol', async () => {
    await renderShell()
    expect(eventLog).toEqual([
      'fetch:/api/v1/terminal/prepare/stw-001',
      'fetch:/api/v1/operator-payload/sign/begin',
      'credentials.get',
      'fetch:/api/v1/operator-payload/sign/finish',
      'fetch:/api/v1/terminal/tickets/stw-001',
      'new WebSocket',
    ])
    expect(fetchCalls[0]!.body).toEqual({ terminal_shell: '' })
    expect(fetchCalls[1]!.body).toMatchObject({ selector: 'id:stw-001', shell: 'terminal-open' })
    expect(fetchCalls[3]!.body).toMatchObject({
      terminal_shell: 'bash', nonce: 'n1', targets: ['stw-001'],
      webauthn: { credential_id: 'ci', signature: 'sg' },
    })
    const ws = FakeWebSocket.instances[0]!
    expect(ws.protocols).toEqual(['cfgms.terminal.v1', 'cfgms.ticket.tkt-123'])
    expect(ws.url).not.toContain('tkt-123')
    expect(new URL(ws.url, 'http://localhost').search).toBe('')
  })

  it('runs the ceremony again on Reconnect', async () => {
    await renderShell()
    act(() => { FakeWebSocket.instances[0]!.open(); FakeWebSocket.instances[0]!.closeWithCode(1006) })
    await act(async () => { fireEvent.click(screen.getByRole('button', { name: /reconnect/i })) })
    await waitFor(() => expect(FakeWebSocket.instances).toHaveLength(2))
    expect(credentialsGet).toHaveBeenCalledTimes(2)
    expect(FakeWebSocket.instances[1]!.protocols[1]).toBe('cfgms.ticket.tkt-123')
  })

  it('opens no WebSocket when the passkey prompt is cancelled', async () => {
    credentialsGet.mockRejectedValue(new DOMException('cancelled', 'NotAllowedError'))
    render(<ShellTab stewardId="stw-001" />)
    expect(await screen.findByText(/passkey prompt was cancelled/i)).toBeInTheDocument()
    expect(screen.getByText('Disconnected')).toBeInTheDocument()
    expect(FakeWebSocket.instances).toHaveLength(0)
  })

  it('opens no WebSocket when the tab unmounts before the ceremony finishes', async () => {
    let release!: () => void
    credentialsGet.mockImplementation(
      () => new Promise((resolve) => { release = () => resolve(fakeCredential()) }),
    )
    const { unmount } = render(<ShellTab stewardId="stw-001" />)
    await waitFor(() => expect(credentialsGet).toHaveBeenCalled())
    unmount()
    await act(async () => { release(); await new Promise((r) => setTimeout(r, 20)) })
    expect(FakeWebSocket.instances).toHaveLength(0)
    expect(fetchCalls.some((c) => c.path.includes('/terminal/tickets/'))).toBe(false)
  })

  it('shows a clear message when no passkey is registered', async () => {
    fetchStatus.set('/sign/begin', 400)
    render(<ShellTab stewardId="stw-001" />)
    expect(await screen.findByText(/no passkey is registered/i)).toBeInTheDocument()
    expect(FakeWebSocket.instances).toHaveLength(0)
  })

  it('shows the denied state on a 403 from prepare', async () => {
    fetchStatus.set('/terminal/prepare/', 403)
    render(<ShellTab stewardId="stw-001" />)
    expect(await screen.findByText(/remote shell denied/i)).toBeInTheDocument()
    expect(FakeWebSocket.instances).toHaveLength(0)
  })

  it('shows the denied state on a 403 from the ticket endpoint', async () => {
    fetchStatus.set('/terminal/tickets/', 403)
    render(<ShellTab stewardId="stw-001" />)
    expect(await screen.findByText(/remote shell denied/i)).toBeInTheDocument()
    expect(FakeWebSocket.instances).toHaveLength(0)
  })
})
