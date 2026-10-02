// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * LiveActivityTab suite (Story #2766): WebSocket lifecycle, process table
 * sorting, service list, disconnect/403 error states.
 *
 * WebSocket is stubbed at the global level; every test verifies observable
 * DOM behaviour, not internal state.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, act } from '@testing-library/react'
import LiveActivityTab from './LiveActivityTab.tsx'

// ---------------------------------------------------------------------------
// WebSocket stub
// ---------------------------------------------------------------------------

interface WSMessage {
  data: string
}

class FakeWebSocket {
  static instances: FakeWebSocket[] = []

  url: string
  readyState: number = WebSocket.CONNECTING
  onopen: ((ev: Event) => void) | null = null
  onclose: ((ev: CloseEvent) => void) | null = null
  onmessage: ((ev: WSMessage) => void) | null = null
  onerror: ((ev: Event) => void) | null = null
  closed = false

  constructor(url: string) {
    this.url = url
    FakeWebSocket.instances.push(this)
  }

  open() {
    this.readyState = WebSocket.OPEN
    this.onopen?.(new Event('open'))
  }

  send() {
    // browser → server direction; ignored in these tests
  }

  close() {
    if (this.closed) return
    this.closed = true
    this.readyState = WebSocket.CLOSED
    this.onclose?.(new CloseEvent('close', { code: 1000 }))
  }

  deliver(payload: unknown) {
    this.onmessage?.({ data: JSON.stringify(payload) })
  }

  closeWithCode(code: number, reason?: string) {
    this.closed = true
    this.readyState = WebSocket.CLOSED
    this.onclose?.(new CloseEvent('close', { code, reason }))
  }
}

// ---------------------------------------------------------------------------
// Snapshot helpers
// ---------------------------------------------------------------------------

function makeSnapshot(overrides?: Partial<{
  processes: unknown[]
  services: unknown[]
}>) {
  return {
    type: 'snapshot',
    steward_id: 'stw-test',
    processes: overrides?.processes ?? [
      { pid: 1, name: 'init', cpu_percent: 0.1, memory_bytes: 4096, disk_read_bytes: 0, disk_write_bytes: 0, net_rx_bytes: 0, net_tx_bytes: 0 },
      { pid: 42, name: 'nginx', cpu_percent: 3.5, memory_bytes: 52428800, disk_read_bytes: 1024, disk_write_bytes: 512, net_rx_bytes: 0, net_tx_bytes: 0 },
      { pid: 99, name: 'postgres', cpu_percent: 12.0, memory_bytes: 209715200, disk_read_bytes: 4096, disk_write_bytes: 2048, net_rx_bytes: 0, net_tx_bytes: 0 },
    ],
    services: overrides?.services ?? [
      { name: 'nginx', state: 'running' },
      { name: 'sshd', state: 'running' },
      { name: 'cron', state: 'stopped' },
    ],
    timestamp: '2026-07-20T10:00:00Z',
  }
}

// ---------------------------------------------------------------------------
// Test setup
// ---------------------------------------------------------------------------

let origWebSocket: typeof WebSocket

beforeEach(() => {
  FakeWebSocket.instances = []
  origWebSocket = globalThis.WebSocket
  // @ts-expect-error intentional stub
  globalThis.WebSocket = FakeWebSocket
})

afterEach(() => {
  globalThis.WebSocket = origWebSocket
  cleanup()
  vi.restoreAllMocks()
})

// ---------------------------------------------------------------------------
// Connection lifecycle
// ---------------------------------------------------------------------------

describe('WebSocket lifecycle', () => {
  it('opens a WebSocket connection on mount', () => {
    render(<LiveActivityTab stewardId="stw-001" />)
    expect(FakeWebSocket.instances).toHaveLength(1)
    expect(FakeWebSocket.instances[0]!.url).toContain('stw-001')
  })

  it('uses the correct telemetry endpoint URL', () => {
    render(<LiveActivityTab stewardId="stw-007" />)
    const ws = FakeWebSocket.instances[0]!
    expect(ws.url).toMatch(/\/api\/v1\/telemetry\/ws\/stw-007$/)
  })

  it('closes the WebSocket on unmount', () => {
    const { unmount } = render(<LiveActivityTab stewardId="stw-001" />)
    const ws = FakeWebSocket.instances[0]!
    expect(ws.closed).toBe(false)
    unmount()
    expect(ws.closed).toBe(true)
  })

  it('does not open a second connection if already mounted', () => {
    render(<LiveActivityTab stewardId="stw-001" />)
    expect(FakeWebSocket.instances).toHaveLength(1)
  })

  it('reconnects if stewardId prop changes', () => {
    const { rerender } = render(<LiveActivityTab stewardId="stw-001" />)
    const first = FakeWebSocket.instances[0]!
    rerender(<LiveActivityTab stewardId="stw-002" />)
    expect(first.closed).toBe(true)
    expect(FakeWebSocket.instances).toHaveLength(2)
    expect(FakeWebSocket.instances[1]!.url).toContain('stw-002')
  })

  it('shows a loading indicator before the first snapshot arrives', () => {
    render(<LiveActivityTab stewardId="stw-001" />)
    expect(screen.getByTestId('live-loading')).toBeInTheDocument()
  })
})

// ---------------------------------------------------------------------------
// Process table rendering
// ---------------------------------------------------------------------------

describe('process table', () => {
  function setup(stewardId = 'stw-001') {
    render(<LiveActivityTab stewardId={stewardId} />)
    const ws = FakeWebSocket.instances[0]!
    act(() => {
      ws.open()
      ws.deliver(makeSnapshot())
    })
    return ws
  }

  it('renders a process table with CPU, memory, disk, and network columns', () => {
    setup()
    expect(screen.getByRole('table', { name: /processes/i })).toBeInTheDocument()
    const headers = screen.getAllByRole('columnheader')
    const headerText = headers.map((h) => h.textContent?.toLowerCase() ?? '')
    expect(headerText.some((t) => t.includes('cpu'))).toBe(true)
    expect(headerText.some((t) => t.includes('mem'))).toBe(true)
    expect(headerText.some((t) => t.includes('disk'))).toBe(true)
    expect(headerText.some((t) => t.includes('net'))).toBe(true)
  })

  it('renders process names in the table', () => {
    setup()
    // nginx appears in both process and service lists; getAllByText handles multiple matches
    expect(screen.getAllByText('nginx').length).toBeGreaterThan(0)
    expect(screen.getByText('postgres')).toBeInTheDocument()
  })

  it('updates in place when a new snapshot arrives', () => {
    const ws = setup()
    act(() => {
      ws.deliver(makeSnapshot({
        processes: [
          { pid: 1, name: 'updated-proc', cpu_percent: 99.9, memory_bytes: 1024, disk_read_bytes: 0, disk_write_bytes: 0, net_rx_bytes: 0, net_tx_bytes: 0 },
        ],
        services: [],
      }))
    })
    expect(screen.getByText('updated-proc')).toBeInTheDocument()
    expect(screen.queryByText('nginx')).not.toBeInTheDocument()
  })
})

// ---------------------------------------------------------------------------
// Process table sorting
// ---------------------------------------------------------------------------

describe('process table sorting', () => {
  function deliverSnapshot() {
    const ws = FakeWebSocket.instances[0]!
    act(() => {
      ws.open()
      ws.deliver(makeSnapshot())
    })
  }

  it('sorts by CPU descending when CPU header is clicked', () => {
    render(<LiveActivityTab stewardId="stw-001" />)
    deliverSnapshot()

    const cpuHeader = screen.getByRole('columnheader', { name: /cpu/i })
    fireEvent.click(cpuHeader)

    const rows = screen.getAllByRole('row').slice(1) // skip header
    const names = rows.map((r) => r.querySelector('td')?.textContent ?? '')
    expect(names[0]).toBe('postgres') // 12.0%
    expect(names[1]).toBe('nginx')    // 3.5%
    expect(names[2]).toBe('init')     // 0.1%
  })

  it('reverses sort direction on second click of the same column', () => {
    render(<LiveActivityTab stewardId="stw-001" />)
    deliverSnapshot()

    const cpuHeader = screen.getByRole('columnheader', { name: /cpu/i })
    fireEvent.click(cpuHeader)
    fireEvent.click(cpuHeader)

    const rows = screen.getAllByRole('row').slice(1)
    const names = rows.map((r) => r.querySelector('td')?.textContent ?? '')
    expect(names[0]).toBe('init')     // 0.1% — ascending
  })

  it('sorts by memory when memory header is clicked', () => {
    render(<LiveActivityTab stewardId="stw-001" />)
    deliverSnapshot()

    const memHeader = screen.getByRole('columnheader', { name: /mem/i })
    fireEvent.click(memHeader)

    const rows = screen.getAllByRole('row').slice(1)
    const names = rows.map((r) => r.querySelector('td')?.textContent ?? '')
    expect(names[0]).toBe('postgres') // 200 MB
  })

  it('applies aria-sort attribute on the active sort column', () => {
    render(<LiveActivityTab stewardId="stw-001" />)
    deliverSnapshot()

    const cpuHeader = screen.getByRole('columnheader', { name: /cpu/i })
    fireEvent.click(cpuHeader)

    expect(cpuHeader).toHaveAttribute('aria-sort', 'descending')
    fireEvent.click(cpuHeader)
    expect(cpuHeader).toHaveAttribute('aria-sort', 'ascending')
  })
})

// ---------------------------------------------------------------------------
// Service list
// ---------------------------------------------------------------------------

describe('service list', () => {
  it('renders a service list with name and state', () => {
    render(<LiveActivityTab stewardId="stw-001" />)
    const ws = FakeWebSocket.instances[0]!
    act(() => {
      ws.open()
      ws.deliver(makeSnapshot())
    })

    expect(screen.getByText('sshd')).toBeInTheDocument()
    expect(screen.getByText('cron')).toBeInTheDocument()
    // state values are present
    const runningCells = screen.getAllByText('running')
    expect(runningCells.length).toBeGreaterThan(0)
    expect(screen.getByText('stopped')).toBeInTheDocument()
  })
})

// ---------------------------------------------------------------------------
// Error states
// ---------------------------------------------------------------------------

describe('error states', () => {
  it('shows a clear denied error state on WebSocket close with code 4403', () => {
    render(<LiveActivityTab stewardId="stw-001" />)
    const ws = FakeWebSocket.instances[0]!
    act(() => {
      ws.closeWithCode(4403, 'forbidden')
    })

    const alert = screen.getByRole('alert')
    expect(alert.textContent?.toLowerCase()).toMatch(/denied|forbidden|permission/i)
  })

  it('shows a disconnect error state when the steward goes offline', () => {
    render(<LiveActivityTab stewardId="stw-001" />)
    const ws = FakeWebSocket.instances[0]!
    act(() => {
      ws.open()
      ws.deliver({ type: 'disconnect', reason: 'steward disconnected' })
    })

    const alert = screen.getByRole('alert')
    expect(alert.textContent?.toLowerCase()).toMatch(/offline|disconnect/i)
  })

  it('shows a connection error when WebSocket closes unexpectedly', () => {
    render(<LiveActivityTab stewardId="stw-001" />)
    const ws = FakeWebSocket.instances[0]!
    act(() => {
      ws.open()
      ws.closeWithCode(1006, '')
    })

    const alert = screen.getByRole('alert')
    expect(alert).toBeInTheDocument()
  })
})
