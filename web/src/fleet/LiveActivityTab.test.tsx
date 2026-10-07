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
import { installHarness } from './actionTestHarness.ts'

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

  it('shows an interrupted state when WebSocket closes unexpectedly', () => {
    render(<LiveActivityTab stewardId="stw-001" />)
    const ws = FakeWebSocket.instances[0]!
    act(() => {
      ws.open()
      ws.closeWithCode(1006, '')
    })

    expect(screen.getByRole('alert').textContent).toMatch(/interrupted/i)
  })
})

// ---------------------------------------------------------------------------
// Filter
// ---------------------------------------------------------------------------

function mountWithSnapshot(props: { onViewDna?: () => void } = {}) {
  render(<LiveActivityTab stewardId="stw-001" {...props} />)
  const ws = FakeWebSocket.instances[0]!
  act(() => {
    ws.open()
    ws.deliver(makeSnapshot())
  })
  return ws
}

describe('filter', () => {
  it('narrows both tables case-insensitively by process name and service name', () => {
    mountWithSnapshot()
    fireEvent.change(screen.getByLabelText(/filter/i), { target: { value: 'NGINX' } })
    expect(screen.queryByText('postgres')).not.toBeInTheDocument()
    expect(screen.queryByText('sshd')).not.toBeInTheDocument()
    expect(screen.getAllByText('nginx')).toHaveLength(2)
  })

  it('matches processes by PID', () => {
    mountWithSnapshot()
    fireEvent.change(screen.getByLabelText(/filter/i), { target: { value: '99' } })
    expect(screen.getByText('postgres')).toBeInTheDocument()
    expect(screen.queryByText('init')).not.toBeInTheDocument()
  })

  it('shows an empty state with a clear-filter action when nothing matches', () => {
    mountWithSnapshot()
    fireEvent.change(screen.getByLabelText(/filter/i), { target: { value: 'zzz-none' } })
    expect(screen.getByText(/no matches/i)).toBeInTheDocument()
    expect(screen.queryByRole('table', { name: /processes/i })).not.toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: /clear filter/i }))
    expect(screen.getByText('postgres')).toBeInTheDocument()
    expect(screen.getByLabelText(/filter/i)).toHaveValue('')
  })
})

// ---------------------------------------------------------------------------
// Pause / resume and freshness
// ---------------------------------------------------------------------------

describe('pause and resume', () => {
  const updated = () => makeSnapshot({
    processes: [
      { pid: 7, name: 'fresh-proc', cpu_percent: 1, memory_bytes: 1, disk_read_bytes: 0, disk_write_bytes: 0, net_rx_bytes: 0, net_tx_bytes: 0 },
    ],
    services: [],
  })

  it('freezes displayed rows while paused and shows the latest snapshot on Resume', () => {
    const ws = mountWithSnapshot()
    fireEvent.click(screen.getByRole('button', { name: 'Pause' }))
    expect(screen.getByText('Paused')).toBeInTheDocument()

    act(() => ws.deliver(updated()))
    expect(screen.queryByText('fresh-proc')).not.toBeInTheDocument()
    expect(screen.getByText('postgres')).toBeInTheDocument()
    expect(ws.closed).toBe(false)

    fireEvent.click(screen.getByRole('button', { name: 'Resume' }))
    expect(screen.getByText('fresh-proc')).toBeInTheDocument()
    expect(screen.queryByText('postgres')).not.toBeInTheDocument()
    expect(screen.queryByText('Paused')).not.toBeInTheDocument()
  })
})

describe('freshness', () => {
  afterEach(() => {
    vi.useRealTimers()
  })

  it('shows seconds since the last applied snapshot without re-rendering the tables', () => {
    vi.useFakeTimers()
    const ws = mountWithSnapshot()
    expect(screen.getByText(/updated/).textContent).toContain('0s')
    const table = screen.getByRole('table', { name: /processes/i })
    const row = table.querySelector('tbody tr')

    act(() => { vi.advanceTimersByTime(5000) })
    expect(screen.getByText(/updated/).textContent).toContain('5s')
    // Same DOM node: the table was not re-rendered or remounted by the tick.
    expect(table.querySelector('tbody tr')).toBe(row)

    act(() => ws.deliver(makeSnapshot()))
    act(() => { vi.advanceTimersByTime(1000) })
    expect(screen.getByText(/updated/).textContent).toContain('1s')
  })

  it('treats a silent stream as interrupted after the receive timeout', () => {
    vi.useFakeTimers()
    const ws = mountWithSnapshot()
    act(() => { vi.advanceTimersByTime(36_000) })
    expect(screen.getByRole('alert').textContent).toMatch(/interrupted/i)
    expect(ws.closed).toBe(true)
  })
})

// ---------------------------------------------------------------------------
// Interrupted vs offline
// ---------------------------------------------------------------------------

describe('interrupted vs offline', () => {
  it('renders distinct copy and CTAs for each', () => {
    const onViewDna = vi.fn()
    const ws = mountWithSnapshot({ onViewDna })
    act(() => ws.deliver({ type: 'disconnect' }))
    expect(screen.getByRole('alert').textContent).toMatch(/steward offline/i)
    expect(screen.queryByRole('button', { name: /reconnect/i })).not.toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: /view last-known dna/i }))
    expect(onViewDna).toHaveBeenCalledTimes(1)
    cleanup()

    FakeWebSocket.instances = []
    const ws2 = mountWithSnapshot({ onViewDna })
    act(() => ws2.closeWithCode(1006, ''))
    const text = screen.getByRole('alert').textContent ?? ''
    expect(text).toMatch(/interrupted/i)
    expect(text).not.toMatch(/steward offline/i)
    expect(screen.queryByRole('button', { name: /last-known dna/i })).not.toBeInTheDocument()
  })

  it('Reconnect opens a new WebSocket and resumes streaming', () => {
    const ws = mountWithSnapshot()
    act(() => ws.closeWithCode(1006, ''))
    fireEvent.click(screen.getByRole('button', { name: /reconnect/i }))

    expect(FakeWebSocket.instances).toHaveLength(2)
    expect(screen.getByTestId('live-loading')).toBeInTheDocument()
    const ws2 = FakeWebSocket.instances[1]!
    expect(ws2.url).toBe(ws.url)
    act(() => {
      ws2.open()
      ws2.deliver(makeSnapshot())
    })
    expect(screen.getByText('postgres')).toBeInTheDocument()
    expect(screen.queryByRole('alert')).not.toBeInTheDocument()
  })
})

// ---------------------------------------------------------------------------
// Row action menus (Story #4629)
// ---------------------------------------------------------------------------

describe('row action menus', () => {
  function mount(extra?: { onViewDna?: () => void; processes?: unknown[] }) {
    render(<LiveActivityTab stewardId="stw-test" onViewDna={extra?.onViewDna} />)
    act(() => {
      FakeWebSocket.instances[0]!.deliver(makeSnapshot(extra?.processes ? { processes: extra.processes } : undefined))
    })
  }

  it('renders a menu per process row and per service row', () => {
    mount()
    expect(screen.getByRole('button', { name: 'Actions for PID 42' })).toBeTruthy()
    expect(screen.getByRole('button', { name: 'Actions for PID 99' })).toBeTruthy()
    expect(screen.getByRole('button', { name: 'Actions for sshd' })).toBeTruthy()
    expect(screen.getAllByRole('button', { name: /^Actions for/ })).toHaveLength(6)
  })

  it('the service menu invokes its endpoint after confirm and sign', async () => {
    const h = installHarness()
    mount()
    fireEvent.click(screen.getByRole('button', { name: 'Actions for sshd' }))
    fireEvent.click(screen.getByRole('menuitem', { name: 'Restart' }))
    fireEvent.change(screen.getByLabelText(/Justification/), { target: { value: 'config reload' } })
    fireEvent.click(screen.getByRole('button', { name: 'Sign with passkey' }))
    await screen.findByText('Restart service: done')
    expect(h.calls.some((c) => c.url === '/api/v1/stewards/stw-test/services/sshd/actions')).toBe(true)
  })

  it('Open in DNA switches to the DNA tab', () => {
    const onViewDna = vi.fn()
    mount({ onViewDna })
    fireEvent.click(screen.getByRole('button', { name: 'Actions for PID 42' }))
    fireEvent.click(screen.getByRole('menuitem', { name: 'Open in DNA' }))
    expect(onViewDna).toHaveBeenCalled()
  })

  it('offers Resume for a suspended process from the stream status', () => {
    mount({
      processes: [
        { pid: 7, name: 'worker', cpu_percent: 0, memory_bytes: 1, disk_read_bytes: 0, disk_write_bytes: 0, net_rx_bytes: 0, net_tx_bytes: 0, status: 'suspended' },
      ],
    })
    fireEvent.click(screen.getByRole('button', { name: 'Actions for PID 7' }))
    expect(screen.getByRole('menuitem', { name: 'Resume' })).toBeTruthy()
  })

  it('End task on the steward process shows blocked and the row stays', async () => {
    installHarness({ jobs: [{ status: 'failed', result_code: 'self_protect' }] })
    mount()
    fireEvent.click(screen.getByRole('button', { name: 'Actions for PID 42' }))
    fireEvent.click(screen.getByRole('menuitem', { name: 'End task' }))
    fireEvent.change(screen.getByLabelText(/Justification/), { target: { value: 'x' } })
    fireEvent.click(screen.getByRole('button', { name: 'Sign with passkey' }))
    await screen.findByText(/blocked\. The steward does not act on its own process/)
    // A snapshot arriving afterwards still lists the process and keeps the status visible.
    act(() => {
      FakeWebSocket.instances[0]!.deliver(makeSnapshot())
    })
    expect(screen.getByRole('button', { name: 'Actions for PID 42' })).toBeTruthy()
    expect(screen.getByText(/blocked\./)).toBeTruthy()
    fireEvent.click(screen.getByRole('button', { name: 'Actions for PID 42' }))
    expect((screen.getByRole('menuitem', { name: 'End task (blocked)' }) as HTMLButtonElement).disabled).toBe(true)
  })
})
