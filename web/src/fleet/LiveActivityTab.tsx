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
import { memo, useEffect, useMemo, useReducer, useRef, useState } from 'react'
import type { SortState } from './FleetTable.tsx'
import './LiveActivityTab.css'

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

// 'offline' = the controller reported the steward gone; 'interrupted' = the
// stream itself dropped (socket closed abnormally or went silent) while the
// steward was still reported online.
type ErrorKind = 'denied' | 'offline' | 'interrupted'

// A steward streams roughly once a second; silence for this long means the
// stream is dead even if the socket never reported a close.
const RECEIVE_TIMEOUT_MS = 30_000
const TIMEOUT_CHECK_MS = 5_000

interface Pending {
  processes: ProcessSnapshot[]
  services: ServiceSnapshot[]
}

interface TabState {
  loading: boolean
  error: { kind: ErrorKind; detail?: string } | null
  processes: ProcessSnapshot[]
  services: ServiceSnapshot[]
  sort: SortState
  paused: boolean
  // Latest snapshot received while paused; applied instantly on Resume.
  pending: Pending | null
}

type TabAction =
  | { type: 'snapshot'; processes: ProcessSnapshot[]; services: ServiceSnapshot[] }
  | { type: 'disconnect' }
  | { type: 'denied'; detail?: string }
  | { type: 'interrupted' }
  | { type: 'sort'; key: string }
  | { type: 'pause' }
  | { type: 'resume' }
  | { type: 'reset' }

const initialState: TabState = {
  loading: true,
  error: null,
  processes: [],
  services: [],
  paused: false,
  pending: null,
  // Initial sort on 'name' so the first click on any numeric column defaults to descending.
  sort: { key: 'name', direction: 1 },
}

function reducer(state: TabState, action: TabAction): TabState {
  switch (action.type) {
    case 'snapshot':
      if (state.paused) {
        return { ...state, loading: false, pending: { processes: action.processes, services: action.services } }
      }
      return { ...state, loading: false, error: null, processes: action.processes, services: action.services }
    case 'pause':
      return { ...state, paused: true }
    case 'resume':
      return state.pending
        ? { ...state, paused: false, pending: null, processes: state.pending.processes, services: state.pending.services }
        : { ...state, paused: false }
    case 'reset':
      return { ...initialState, sort: state.sort }
    case 'disconnect':
      return { ...state, loading: false, error: { kind: 'offline' } }
    case 'denied':
      return { ...state, loading: false, error: { kind: 'denied', detail: action.detail } }
    case 'interrupted':
      return { ...state, loading: false, error: { kind: 'interrupted' } }
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

const ProcessTable = memo(function ProcessTable({ processes, sort, onSort }: ProcessTableProps) {
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
})

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

const ServiceList = memo(function ServiceList({ services }: ServiceListProps) {
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
})

// Ticks on its own state so the per-second update never re-renders the tables.
function Freshness({ paused, lastAppliedRef }: { paused: boolean; lastAppliedRef: { current: number } }) {
  const [secs, setSecs] = useState(0)
  useEffect(() => {
    const id = setInterval(() => {
      setSecs(Math.max(0, Math.floor((Date.now() - lastAppliedRef.current) / 1000)))
    }, 1000)
    return () => clearInterval(id)
  }, [lastAppliedRef])
  if (paused) return <span className="live-fresh">Feed frozen</span>
  return (
    <span className="live-fresh">
      <b>Streaming</b> · updated <span className="mono2">{secs}s</span> ago
    </span>
  )
}

function matches(q: string, ...fields: string[]): boolean {
  return fields.some((f) => f.toLowerCase().includes(q))
}

// ---------------------------------------------------------------------------
// Main component
// ---------------------------------------------------------------------------

interface LiveActivityTabProps {
  stewardId: string
  // Switches the host (asset page / drawer) to its DNA tab.
  onViewDna?: () => void
}

export default function LiveActivityTab({ stewardId, onViewDna }: LiveActivityTabProps) {
  const [state, dispatch] = useReducer(reducer, initialState)
  const [filter, setFilter] = useState('')
  const [reconnectKey, setReconnectKey] = useState(0)
  const wsRef = useRef<WebSocket | null>(null)
  const pausedRef = useRef(false)
  const lastAppliedRef = useRef(0)
  const lastReceivedRef = useRef(0)

  useEffect(() => {
    lastReceivedRef.current = Date.now()
    lastAppliedRef.current = Date.now()
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
        lastReceivedRef.current = Date.now()
        if (!pausedRef.current) lastAppliedRef.current = Date.now()
        dispatch({ type: 'snapshot', processes: msg.processes, services: msg.services })
      } else if (msg.type === 'disconnect') {
        dispatch({ type: 'disconnect' })
      }
    }

    ws.onclose = (ev) => {
      if (ev.code === 4403) {
        dispatch({ type: 'denied', detail: ev.reason })
      } else if (ev.code !== 1000 && ev.code !== 1001) {
        dispatch({ type: 'interrupted' })
      }
    }

    const watchdog = setInterval(() => {
      if (Date.now() - lastReceivedRef.current > RECEIVE_TIMEOUT_MS) {
        clearInterval(watchdog)
        dispatch({ type: 'interrupted' })
        ws.close()
      }
    }, TIMEOUT_CHECK_MS)

    return () => {
      clearInterval(watchdog)
      wsRef.current = null
      ws.close()
    }
  }, [stewardId, reconnectKey])

  function onReconnect() {
    pausedRef.current = false
    dispatch({ type: 'reset' })
    setReconnectKey((k) => k + 1)
  }

  function onTogglePause() {
    if (state.paused) {
      pausedRef.current = false
      lastAppliedRef.current = Date.now()
      dispatch({ type: 'resume' })
    } else {
      pausedRef.current = true
      dispatch({ type: 'pause' })
    }
  }

  const q = filter.trim().toLowerCase()
  const processes = useMemo(
    () => (q ? state.processes.filter((p) => matches(q, p.name, String(p.pid))) : state.processes),
    [state.processes, q],
  )
  const services = useMemo(
    () => (q ? state.services.filter((s) => matches(q, s.name)) : state.services),
    [state.services, q],
  )

  function onSort(key: string) {
    dispatch({ type: 'sort', key })
  }

  if (state.error) {
    const { kind } = state.error
    if (kind === 'denied') {
      return (
        <div role="alert" className="notice notice-error">
          <p>Permission denied. You do not have access to live telemetry for this device.</p>
        </div>
      )
    }
    if (kind === 'offline') {
      return (
        <div role="alert" className="notice notice-error">
          <h3>Steward offline</h3>
          <p>
            Live activity streams only while the steward is connected. The device disconnected
            from the controller. DNA and config remain available from the other tabs.
          </p>
          {onViewDna && (
            <button type="button" className="live-btn" onClick={onViewDna}>
              View last-known DNA
            </button>
          )}
        </div>
      )
    }
    return (
      <div role="alert" className="notice notice-error">
        <h3>Live stream interrupted</h3>
        <p>
          The telemetry stream dropped while the steward is still reported online. This does not
          change the device&apos;s health — only the live view.
        </p>
        <button type="button" className="live-btn" onClick={onReconnect}>
          Reconnect
        </button>
      </div>
    )
  }

  if (state.loading) {
    return <div data-testid="live-loading" className="loading-skeleton">Loading live activity…</div>
  }

  return (
    <div className="live-activity">
      <div className="live-toolbar">
        <Freshness paused={state.paused} lastAppliedRef={lastAppliedRef} />
        {state.paused && <span className="pill neutral">Paused</span>}
        <input
          type="text"
          className="live-filter"
          placeholder="Filter by name or PID…"
          aria-label="Filter processes and services"
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
        />
        <button type="button" className="live-btn" onClick={onTogglePause}>
          {state.paused ? 'Resume' : 'Pause'}
        </button>
      </div>
      {q && processes.length === 0 && services.length === 0 ? (
        <div className="notice empty">
          <h3>No matches</h3>
          <p>No process or service matches the current filter.</p>
          <button type="button" className="live-btn" onClick={() => setFilter('')}>
            Clear filter
          </button>
        </div>
      ) : (
        <>
          <section>
            <h2>Processes</h2>
            <ProcessTable processes={processes} sort={state.sort} onSort={onSort} />
          </section>
          <section>
            <h2>Services</h2>
            <ServiceList services={services} />
          </section>
        </>
      )}
    </div>
  )
}
