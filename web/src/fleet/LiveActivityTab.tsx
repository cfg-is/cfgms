// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * LiveActivityTab (Story #2766) — real-time process table and service list for
 * one steward, streamed from /api/v1/telemetry/ws/{id}.
 *
 * Lifecycle: the WebSocket opens on mount and closes on unmount, implementing
 * the connect-on-open/disconnect-on-close discipline that makes the upstream
 * fan-out chain (steward → controller → browser) actually collect-only-while-
 * watched in practice.
 *
 * Network column caveat: NetRxBytes/NetTxBytes are structurally present in
 * the wire format but the collector never populates them (usermode-only;
 * reserved for a future kernel-assisted story). They are always 0 today.
 *
 * Sort convention: reuses the SortState shape from FleetTable.tsx
 * ({ key, direction: 1|-1 }) and the click-header-to-sort interaction with
 * aria-sort on the active column.
 *
 * ADR-018: same-origin cookie auth — no token handling in JS.
 * No client-side RBAC: render a clear denied state on close code 4403.
 */
import { useEffect, useReducer, useRef } from 'react'
import type { SortState } from './FleetTable.tsx'

// ---------------------------------------------------------------------------
// Wire types (matches telemetry_handler.go JSON serialisation)
// ---------------------------------------------------------------------------

interface ProcessSnapshot {
  pid: number
  name: string
  cpu_percent: number
  memory_bytes: number
  disk_read_bytes: number
  disk_write_bytes: number
  net_rx_bytes: number
  net_tx_bytes: number
}

interface ServiceSnapshot {
  name: string
  state: string
}

interface TelemetrySnapshotMessage {
  type: 'snapshot'
  steward_id: string
  processes: ProcessSnapshot[]
  services: ServiceSnapshot[]
  timestamp?: string
}

interface DisconnectMessage {
  type: 'disconnect'
  reason?: string
}

type TelemetryMessage = TelemetrySnapshotMessage | DisconnectMessage

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

type ErrorKind = 'denied' | 'offline' | 'connection'

interface TabState {
  loading: boolean
  error: { kind: ErrorKind; detail?: string } | null
  processes: ProcessSnapshot[]
  services: ServiceSnapshot[]
  sort: SortState
}

type TabAction =
  | { type: 'snapshot'; processes: ProcessSnapshot[]; services: ServiceSnapshot[] }
  | { type: 'disconnect' }
  | { type: 'denied'; detail?: string }
  | { type: 'connection-error' }
  | { type: 'sort'; key: string }

const initialState: TabState = {
  loading: true,
  error: null,
  processes: [],
  services: [],
  // Initial sort on 'name' so the first click on any numeric column defaults to descending.
  sort: { key: 'name', direction: 1 },
}

function reducer(state: TabState, action: TabAction): TabState {
  switch (action.type) {
    case 'snapshot':
      return { ...state, loading: false, error: null, processes: action.processes, services: action.services }
    case 'disconnect':
      return { ...state, loading: false, error: { kind: 'offline' } }
    case 'denied':
      return { ...state, loading: false, error: { kind: 'denied', detail: action.detail } }
    case 'connection-error':
      return { ...state, loading: false, error: { kind: 'connection' } }
    case 'sort': {
      const sameKey = state.sort.key === action.key
      return {
        ...state,
        sort: {
          key: action.key,
          direction: sameKey ? (state.sort.direction === -1 ? 1 : -1) : -1,
        },
      }
    }
  }
}

// ---------------------------------------------------------------------------
// Sort helpers
// ---------------------------------------------------------------------------

function readSortValue(proc: ProcessSnapshot, key: string): number | string {
  switch (key) {
    case 'pid': return proc.pid
    case 'name': return proc.name
    case 'cpu_percent': return proc.cpu_percent
    case 'memory_bytes': return proc.memory_bytes
    case 'disk_read_bytes': return proc.disk_read_bytes
    case 'disk_write_bytes': return proc.disk_write_bytes
    case 'net_rx_bytes': return proc.net_rx_bytes
    case 'net_tx_bytes': return proc.net_tx_bytes
    default: return 0
  }
}

function sortProcesses(procs: ProcessSnapshot[], sort: SortState): ProcessSnapshot[] {
  return [...procs].sort((a, b) => {
    const av = readSortValue(a, sort.key)
    const bv = readSortValue(b, sort.key)
    if (typeof av === 'string' && typeof bv === 'string') {
      return sort.direction * av.localeCompare(bv)
    }
    // Numeric columns: direction=1 → ascending, direction=-1 → descending.
    // Matches FleetTable convention: direction > 0 = ascending.
    return sort.direction * ((av as number) - (bv as number))
  })
}

// ---------------------------------------------------------------------------
// Format helpers
// ---------------------------------------------------------------------------

function fmtBytes(n: number): string {
  if (n === 0) return '0'
  const thresholds: [number, string][] = [
    [1024 * 1024 * 1024, 'GB'],
    [1024 * 1024, 'MB'],
    [1024, 'KB'],
  ]
  for (const [threshold, label] of thresholds) {
    if (n >= threshold) return `${(n / threshold).toFixed(1)} ${label}`
  }
  return `${n} B`
}

function fmtCPU(n: number): string {
  return `${n.toFixed(1)}%`
}

// ---------------------------------------------------------------------------
// Sub-components
// ---------------------------------------------------------------------------

function SortArrow({ active, direction }: { active: boolean; direction: 1 | -1 }) {
  if (!active) return <span className="ar" aria-hidden="true">▼</span>
  return (
    <span className="ar" aria-hidden="true">
      {direction < 0 ? '▲' : '▼'}
    </span>
  )
}

interface ProcessTableProps {
  processes: ProcessSnapshot[]
  sort: SortState
  onSort: (key: string) => void
}

function ProcessTable({ processes, sort, onSort }: ProcessTableProps) {
  const sorted = sortProcesses(processes, sort)

  const cols: { key: string; label: string; fmt: (p: ProcessSnapshot) => string }[] = [
    { key: 'name', label: 'Name', fmt: (p) => p.name },
    { key: 'pid', label: 'PID', fmt: (p) => String(p.pid) },
    { key: 'cpu_percent', label: 'CPU', fmt: (p) => fmtCPU(p.cpu_percent) },
    { key: 'memory_bytes', label: 'Mem', fmt: (p) => fmtBytes(p.memory_bytes) },
    { key: 'disk_read_bytes', label: 'Disk R', fmt: (p) => fmtBytes(p.disk_read_bytes) },
    { key: 'disk_write_bytes', label: 'Disk W', fmt: (p) => fmtBytes(p.disk_write_bytes) },
    { key: 'net_rx_bytes', label: 'Net RX', fmt: (p) => fmtBytes(p.net_rx_bytes) },
    { key: 'net_tx_bytes', label: 'Net TX', fmt: (p) => fmtBytes(p.net_tx_bytes) },
  ]

  return (
    <table className="tbl" aria-label="Processes">
      <thead>
        <tr>
          {cols.map((col) => {
            const active = sort.key === col.key
            return (
              <th
                key={col.key}
                className={`c-${col.key}${active ? ' sort' : ''}`}
                aria-sort={
                  active
                    ? sort.direction > 0
                      ? 'ascending'
                      : 'descending'
                    : undefined
                }
                onClick={() => onSort(col.key)}
              >
                {col.label}
                <SortArrow active={active} direction={sort.direction} />
              </th>
            )
          })}
        </tr>
      </thead>
      <tbody>
        {sorted.map((proc) => (
          <tr key={`${proc.pid}-${proc.name}`}>
            {cols.map((col) => (
              <td key={col.key} className={`c-${col.key}`}>
                <span className="mono2">{col.fmt(proc)}</span>
              </td>
            ))}
          </tr>
        ))}
      </tbody>
    </table>
  )
}

function stateClass(s: string): string {
  switch (s.toLowerCase()) {
    case 'running':
    case 'active':
      return 'ok'
    case 'stopped':
    case 'inactive':
    case 'dead':
      return 'neutral'
    case 'failed':
    case 'error':
      return 'crit'
    default:
      return 'neutral'
  }
}

interface ServiceListProps {
  services: ServiceSnapshot[]
}

function ServiceList({ services }: ServiceListProps) {
  return (
    <table className="tbl" aria-label="Services">
      <thead>
        <tr>
          <th>Service</th>
          <th>State</th>
        </tr>
      </thead>
      <tbody>
        {services.map((svc) => (
          <tr key={svc.name}>
            <td><span className="nm">{svc.name}</span></td>
            <td>
              <span className={`pill ${stateClass(svc.state)}`}>
                <span className="dot" />
                {svc.state}
              </span>
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}

// ---------------------------------------------------------------------------
// Main component
// ---------------------------------------------------------------------------

interface LiveActivityTabProps {
  stewardId: string
}

export default function LiveActivityTab({ stewardId }: LiveActivityTabProps) {
  const [state, dispatch] = useReducer(reducer, initialState)
  const wsRef = useRef<WebSocket | null>(null)

  useEffect(() => {
    const proto = location.protocol === 'https:' ? 'wss:' : 'ws:'
    const url = `${proto}//${location.host}/api/v1/telemetry/ws/${encodeURIComponent(stewardId)}`
    const ws = new WebSocket(url)
    wsRef.current = ws

    ws.onmessage = (ev) => {
      let msg: TelemetryMessage
      try {
        msg = JSON.parse(ev.data as string) as TelemetryMessage
      } catch {
        return
      }
      if (msg.type === 'snapshot') {
        dispatch({ type: 'snapshot', processes: msg.processes, services: msg.services })
      } else if (msg.type === 'disconnect') {
        dispatch({ type: 'disconnect' })
      }
    }

    ws.onclose = (ev) => {
      if (ev.code === 4403) {
        dispatch({ type: 'denied', detail: ev.reason })
      } else if (ev.code !== 1000 && ev.code !== 1001) {
        dispatch({ type: 'connection-error' })
      }
    }

    return () => {
      wsRef.current = null
      ws.close()
    }
  }, [stewardId])

  function onSort(key: string) {
    dispatch({ type: 'sort', key })
  }

  if (state.error) {
    const { kind } = state.error
    let message: string
    if (kind === 'denied') {
      message = 'Permission denied. You do not have access to live telemetry for this device.'
    } else if (kind === 'offline') {
      message = 'Steward offline. The device disconnected from the controller.'
    } else {
      message = 'Connection lost. Unable to reach the telemetry stream.'
    }
    return (
      <div role="alert" className="notice notice-error">
        <p>{message}</p>
      </div>
    )
  }

  if (state.loading) {
    return <div data-testid="live-loading" className="loading-skeleton">Loading live activity…</div>
  }

  return (
    <div className="live-activity">
      <section>
        <h2>Processes</h2>
        <ProcessTable processes={state.processes} sort={state.sort} onSort={onSort} />
      </section>
      <section>
        <h2>Services</h2>
        <ServiceList services={state.services} />
      </section>
    </div>
  )
}
