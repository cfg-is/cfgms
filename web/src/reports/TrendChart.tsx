// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * TrendChart (Story #3269) — line/area chart primitive for the reports-
 * dashboard trends surface. Implements the chart mark spec from design
 * system §4:
 *
 *   Line:    2px, round join and cap
 *   Area:    series hue at 10% opacity (a wash, never a saturated block)
 *   Marker:  r=4 (≥8px), filled with series colour; 2px surface ring so the
 *            dot stays legible when crossing another line
 *   Grid:    --border, hairline 1px solid, horizontal only (never dashed)
 *   Spacer:  2px --bg-surface ring around markers (no drawn border)
 *
 * Palette rules — enforced in code, not just in docs:
 *   - Wire colours (SeriesData.color, ChartConfig.colors) are IGNORED.
 *   - Series are mapped by index into the validated --cat-* palette via
 *     buildSeriesSlots() in palette.ts.
 *   - The 4-series cap for multi-line (adjacent pairlist) is enforced:
 *     series beyond index 3 fold into a single "Other" series.
 *   - --state-warn and --state-crit are never used for series lines.
 *     State series carry icon + text label in the legend (never colour alone).
 */

import './Reports.css'
import { buildSeriesSlots } from './palette.ts'
import type { ChartData, DataPoint, FoldedSeries } from './palette.ts'

// Fixed chart dimensions (SVG scales to 100% container width via viewBox).
const W = 900
const H = 200
const PAD = { t: 12, r: 14, b: 22, l: 34 } as const
const IW = W - PAD.l - PAD.r  // inner width
const IH = H - PAD.t - PAD.b  // inner height

function xPos(i: number, count: number): number {
  return count <= 1 ? PAD.l + IW / 2 : PAD.l + (IW * i) / (count - 1)
}

function yPos(v: number, ymin: number, yrange: number): number {
  return PAD.t + IH - (IH * (v - ymin)) / yrange
}

function linePath(data: DataPoint[], xCount: number, ymin: number, yrange: number): string {
  return data
    .map((p, i) => `${i === 0 ? 'M' : 'L'}${xPos(i, xCount).toFixed(1)},${yPos(p.y, ymin, yrange).toFixed(1)}`)
    .join(' ')
}

function areaPath(data: DataPoint[], xCount: number, ymin: number, yrange: number): string {
  const d = linePath(data, xCount, ymin, yrange)
  const last = data.length - 1
  const base = yPos(ymin, ymin, yrange).toFixed(1)
  return `${d} L${xPos(last, xCount).toFixed(1)},${base} L${xPos(0, xCount).toFixed(1)},${base} Z`
}

function formatX(x: string | number): string {
  if (typeof x === 'string' && /^\d{4}-\d{2}-\d{2}/.test(x)) return x.slice(5)
  return String(x)
}

// Warn icon — used in the legend when warn-like and crit-like series coexist.
function WarnIcon() {
  return (
    <svg
      width="11"
      height="11"
      viewBox="0 0 16 16"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      className="trend-legend-icon"
    >
      <path d="M8 2.6L14.6 13.4H1.4z" />
      <path d="M8 6.6v3.1" />
      <path d="M8 11.8v.05" />
    </svg>
  )
}

// Crit icon — used in the legend when warn-like and crit-like series coexist.
function CritIcon() {
  return (
    <svg
      width="11"
      height="11"
      viewBox="0 0 16 16"
      fill="none"
      stroke="currentColor"
      strokeWidth="2.1"
      strokeLinecap="round"
      aria-hidden="true"
      className="trend-legend-icon"
    >
      <circle cx="8" cy="8" r="6.2" />
      <path d="M8 4.8v4" />
      <path d="M8 11.2v.05" />
    </svg>
  )
}

function isWarnSeries(name: string): boolean {
  return /warn|warning|drift/i.test(name)
}

function isCritSeries(name: string): boolean {
  return /crit|critical|error/i.test(name)
}

// Both warn-like and crit-like series present → legend must show icons so
// identity is never colour-alone for state-adjacent series.
function needsStateIcons(slots: FoldedSeries[]): boolean {
  return slots.some(s => isWarnSeries(s.name)) && slots.some(s => isCritSeries(s.name))
}

function legendIcon(name: string): React.ReactNode {
  if (isWarnSeries(name)) return <WarnIcon />
  if (isCritSeries(name)) return <CritIcon />
  return null
}

export default function TrendChart({ chart }: { chart: ChartData }) {
  const slots = buildSeriesSlots(chart.series)

  if (slots.length === 0) return null

  // Use the first slot's data as the x-axis reference.
  const firstSlot = slots[0]
  if (!firstSlot) return null
  const xData = firstSlot.data
  const xCount = xData.length

  // Y range across all series (always start from 0 for trend charts).
  const allY = slots.flatMap(s => s.data.map(p => p.y))
  const rawMax = allY.length > 0 ? Math.max(...allY) : 1
  const ymax = rawMax > 0 ? Math.ceil(rawMax / 10) * 10 : 10
  const ymin = 0
  const yrange = ymax - ymin || 1

  const ticks = [0, ymax / 2, ymax]
  const showStateIcons = needsStateIcons(slots)

  return (
    <div data-testid="trend-chart" className="trend-chart">
      <div className="trend-chart-head">
        <div>
          <h2 className="trend-chart-title">{chart.title}</h2>
          <p className="trend-chart-sub">
            {chart.x_axis.title} · {chart.y_axis.title}
          </p>
        </div>
        {slots.length >= 2 && (
          <div className="trend-chart-legend" data-testid="legend">
            {slots.map((s, i) => (
              <span key={i} className="trend-chart-legend-key" data-testid={`legend-item-${i}`}>
                <span
                  className="trend-chart-legend-line"
                  style={{ background: s.token }}
                  aria-hidden="true"
                />
                {showStateIcons && legendIcon(s.name)}
                {s.name}
              </span>
            ))}
          </div>
        )}
      </div>

      <div className="trend-chart-svg-wrap">
        <svg
          viewBox={`0 0 ${W} ${H}`}
          width="100%"
          role="img"
          aria-label={chart.title}
          style={{ display: 'block', overflow: 'visible' }}
        >
          {/* Gridlines — hairline 1px solid --border, never dashed */}
          {ticks.map((t, i) => {
            const y = yPos(t, ymin, yrange)
            return (
              <g key={i}>
                <line
                  x1={PAD.l}
                  y1={y}
                  x2={W - PAD.r}
                  y2={y}
                  stroke="var(--border)"
                  strokeWidth="1"
                />
                <text
                  x={PAD.l - 7}
                  y={y + 3.5}
                  textAnchor="end"
                  fill="var(--text-faint)"
                  fontSize="10"
                >
                  {t}
                </text>
              </g>
            )
          })}

          {/* Area fills — series hue at 10% opacity; drawn before lines */}
          {slots.map((s, i) =>
            s.data.length >= 2 ? (
              <path
                key={`area-${i}`}
                d={areaPath(s.data, xCount, ymin, yrange)}
                fill={s.token}
                fillOpacity="0.10"
              />
            ) : null,
          )}

          {/* Series lines — 2px, round join and cap */}
          {slots.map((s, i) =>
            s.data.length >= 2 ? (
              <path
                key={`line-${i}`}
                data-testid={`series-line-${i}`}
                d={linePath(s.data, xCount, ymin, yrange)}
                fill="none"
                stroke={s.token}
                strokeWidth="2"
                strokeLinecap="round"
                strokeLinejoin="round"
              />
            ) : null,
          )}

          {/* End markers — r=4 (≥8px), surface ring separates from crossing lines */}
          {slots.map((s, i) => {
            if (s.data.length === 0) return null
            const last = s.data.length - 1
            const lastPoint = s.data.at(-1)
            if (!lastPoint) return null
            const cx = xPos(last, xCount)
            const cy = yPos(lastPoint.y, ymin, yrange)
            return (
              <circle
                key={`dot-${i}`}
                cx={cx}
                cy={cy}
                r={4}
                fill={s.token}
                stroke="var(--bg-surface)"
                strokeWidth="2"
              />
            )
          })}

          {/* X-axis labels — first, last, and every other point */}
          {xData.map((pt, i) => {
            if (i !== 0 && i !== xCount - 1 && i % 2 !== 0) return null
            const anchor = i === 0 ? 'start' : i === xCount - 1 ? 'end' : 'middle'
            return (
              <text
                key={`xl-${i}`}
                x={xPos(i, xCount)}
                y={H - 6}
                textAnchor={anchor}
                fill="var(--text-faint)"
                fontSize="10"
              >
                {formatX(pt.x)}
              </text>
            )
          })}
        </svg>
      </div>

      {/* Table view — identity is never colour-alone; every chart has a table view */}
      <details className="trend-chart-table">
        <summary className="trend-chart-table-summary">Table view</summary>
        <table className="trend-chart-table-data">
          <thead>
            <tr>
              <th>{chart.x_axis.title}</th>
              {slots.map((s, i) => (
                <th key={i}>{s.name}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {xData.map((pt, i) => (
              <tr key={i}>
                <td className="trend-chart-table-x">{formatX(pt.x)}</td>
                {slots.map((s, si) => (
                  <td key={si} className="trend-chart-table-y">
                    {s.data.at(i)?.y ?? '—'}
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </details>
    </div>
  )
}
