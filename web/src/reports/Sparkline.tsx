// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * Sparkline (Story #3269) — the stat-tile trend mark from design system §4.
 *
 * Mark spec:
 *   - 2px line, --text-faint for history; the current-period end is marked
 *     with --accent
 *   - End marker: r=4 (≥8px total), --accent fill, 2px --bg-surface ring so
 *     the dot stays legible against a line crossing it
 *   - No axis, no gridlines, no per-point labels — the tile's value is the
 *     label
 *   - aria-hidden: the stat tile's visible value is the label; the sparkline
 *     is decorative context, not informational text
 */

interface SparklineProps {
  values: number[]
  /** Width in px (default 74) */
  width?: number
  /** Height in px (default 26) */
  height?: number
}

export default function Sparkline({ values, width = 74, height = 26 }: SparklineProps) {
  if (values.length < 2) return null

  const W = width, H = height
  const min = Math.min(...values)
  const max = Math.max(...values)
  const rng = max - min || 1

  const X = (i: number) => (W * i) / (values.length - 1)
  const Y = (v: number) => H - 2 - ((H - 6) * (v - min)) / rng

  const d = values
    .map((v, i) => `${i === 0 ? 'M' : 'L'}${X(i).toFixed(1)},${Y(v).toFixed(1)}`)
    .join(' ')

  const last = values.length - 1
  const lastVal = values.at(-1) ?? 0  // noUncheckedIndexedAccess; length >= 2 checked above

  return (
    <svg
      viewBox={`0 0 ${W} ${H}`}
      width={W}
      height={H}
      aria-hidden="true"
    >
      <path
        d={d}
        fill="none"
        stroke="var(--text-faint)"
        strokeWidth="2"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
      {/* End marker: current period in --accent, 2px surface ring */}
      <circle
        cx={X(last)}
        cy={Y(lastVal)}
        r={4}
        fill="var(--accent)"
        stroke="var(--bg-surface)"
        strokeWidth="2"
      />
    </svg>
  )
}
