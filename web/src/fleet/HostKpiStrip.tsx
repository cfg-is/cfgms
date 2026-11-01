// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * HostKpiStrip (Story #4630) — CPU, memory, disk and network tiles with
 * sparklines over a bounded window of recent snapshots. Pure presentation: the
 * window itself is the ring buffer LiveActivityTab keeps in its reducer state.
 * A snapshot from an older steward carries no `host` totals; the strip then
 * renders an empty state instead of NaN.
 */
import Sparkline from '../reports/Sparkline.tsx'

export interface HostTotals {
  cpu_percent: number
  memory_used_bytes: number
  memory_total_bytes: number
  disk_read_bytes_per_sec: number
  disk_write_bytes_per_sec: number
  disk_used_bytes: number
  disk_total_bytes: number
  net_rx_bytes_per_sec: number
  net_tx_bytes_per_sec: number
}

/** Number of snapshots the sparklines hold. */
export const HOST_HISTORY_LIMIT = 60

/** Appends to the window, dropping the oldest entries beyond the limit. */
export function pushHostHistory(history: HostTotals[], host: HostTotals): HostTotals[] {
  const next = [...history, host]
  return next.length > HOST_HISTORY_LIMIT ? next.slice(next.length - HOST_HISTORY_LIMIT) : next
}

const num = (n: unknown): number => (typeof n === 'number' && Number.isFinite(n) ? n : 0)

function fmtBytes(n: number): string {
  const v = num(n)
  if (v >= 1024 ** 3) return `${(v / 1024 ** 3).toFixed(1)} GB`
  if (v >= 1024 ** 2) return `${(v / 1024 ** 2).toFixed(1)} MB`
  if (v >= 1024) return `${(v / 1024).toFixed(1)} KB`
  return `${Math.round(v)} B`
}

const pct = (used: number, total: number): number =>
  num(total) > 0 ? (num(used) / num(total)) * 100 : 0

interface TileProps {
  id: string
  label: string
  value: string
  sub: string
  values: number[]
}

function Tile({ id, label, value, sub, values }: TileProps) {
  return (
    <div className="kpi-tile" data-testid={`kpi-${id}`}>
      <span className="kpi-label">{label}</span>
      <div className="kpi-row">
        <span className="kpi-value">{value}</span>
        <Sparkline values={values} />
      </div>
      <span className="kpi-sub">{sub}</span>
    </div>
  )
}

export default function HostKpiStrip({ history }: { history: HostTotals[] }) {
  const host = history.at(-1)
  if (!host) {
    return (
      <div className="kpi-strip kpi-empty" data-testid="kpi-empty">
        Host totals unavailable — this steward does not report them.
      </div>
    )
  }
  const netTotal = (h: HostTotals) => num(h.net_rx_bytes_per_sec) + num(h.net_tx_bytes_per_sec)
  const diskIO = (h: HostTotals) => num(h.disk_read_bytes_per_sec) + num(h.disk_write_bytes_per_sec)

  return (
    <div className="kpi-strip" data-testid="kpi-strip">
      <Tile
        id="cpu"
        label="CPU"
        value={`${num(host.cpu_percent).toFixed(1)}%`}
        sub="host total"
        values={history.map((h) => num(h.cpu_percent))}
      />
      <Tile
        id="memory"
        label="Memory"
        value={`${pct(host.memory_used_bytes, host.memory_total_bytes).toFixed(1)}%`}
        sub={`${fmtBytes(host.memory_used_bytes)} of ${fmtBytes(host.memory_total_bytes)}`}
        values={history.map((h) => pct(h.memory_used_bytes, h.memory_total_bytes))}
      />
      <Tile
        id="disk"
        label="Disk"
        value={`${pct(host.disk_used_bytes, host.disk_total_bytes).toFixed(1)}%`}
        sub={`R ${fmtBytes(host.disk_read_bytes_per_sec)}/s · W ${fmtBytes(host.disk_write_bytes_per_sec)}/s`}
        values={history.map(diskIO)}
      />
      <Tile
        id="network"
        label="Network"
        value={`${fmtBytes(netTotal(host))}/s`}
        sub={`↓ ${fmtBytes(host.net_rx_bytes_per_sec)}/s · ↑ ${fmtBytes(host.net_tx_bytes_per_sec)}/s`}
        values={history.map(netTotal)}
      />
    </div>
  )
}
