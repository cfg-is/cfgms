// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * Chart palette utilities (Story #3269 — design system §4 chart marks).
 *
 * The two hard rules encoded here:
 *
 * 1. IGNORE wire colours. ChartData.Config.Colors and SeriesData.Color come
 *    off the wire and must not be used. Map by series index into CAT_TOKENS
 *    instead. buildSeriesSlots() never reads those fields.
 *
 * 2. ENFORCE the series cap. 4 max for multi-line (adjacent pairlist); no
 *    generated 5th hue. Series beyond the cap fold into a single "Other"
 *    series that uses the last validated palette slot. buildSeriesSlots()
 *    computes this automatically.
 *
 * State tokens (--state-warn, --state-crit) are never used for categorical
 * series. Charts that represent state categories must use status tokens AND
 * icon + text labels — never colour alone. That constraint applies to
 * separate chart forms (stacked bar, donut), not to TrendChart line series.
 */

// Subset of features/reports/interfaces/interfaces.go types consumed by the
// chart primitives. The color fields are declared here to accurately reflect
// the wire format; they must never be read by the client.
export interface DataPoint {
  x: string | number
  y: number
  label?: string
  extra?: Record<string, unknown>
}

export interface SeriesData {
  name: string
  data: DataPoint[]
  color?: string  // wire field — client MUST ignore; use CAT_TOKENS by index
}

export interface AxisConfig {
  title: string
  type: string  // "time" | "category" | "numeric"
  format?: string
}

export interface ChartConfig {
  show_legend?: boolean
  colors?: string[]  // wire field — client MUST ignore; palette is index-only
  height?: number
  options?: Record<string, unknown>
}

export type ChartType = 'line' | 'bar' | 'pie' | 'scatter' | 'heatmap' | 'histogram'

export interface ChartData {
  id: string
  type: ChartType
  title: string
  series: SeriesData[]
  x_axis: AxisConfig
  y_axis: AxisConfig
  config?: ChartConfig
}

// Validated categorical palette tokens (docs/design/web-ui-design-tokens.css).
// Slots 1–3 pass all-pairs CVD (ΔE ≥ 8.2 dark / ΔE ≥ 18.5 light).
// Slot 4 (mauve) passes adjacent-forms check only — not all-pairs.
export const CAT_TOKENS = [
  'var(--cat-1)',  // index 0 — slate
  'var(--cat-2)',  // index 1 — green
  'var(--cat-3)',  // index 2 — amber
  'var(--cat-4)',  // index 3 — mauve (adjacent forms only)
] as const

// Maximum distinct series for multi-line and stacked-bar (adjacent pairlist).
// Exceeding this folds excess into "Other" — never silently renders a 5th colour.
export const MAX_ADJACENT_SERIES = 4

export interface FoldedSeries {
  name: string
  data: DataPoint[]
  token: string
  isOther: boolean
}

// Resolve a catalogue token by index. keptCount is bounded to ≤ 4 = CAT_TOKENS.length,
// so this is always in range at runtime; the explicit bounds check keeps the lookup
// from reading outside the palette (and rules out .at()'s negative-index wrap) for
// any future caller.
function catToken(i: number): string {
  if (!Number.isInteger(i) || i < 0 || i >= CAT_TOKENS.length) return CAT_TOKENS[0]
  return CAT_TOKENS.at(i) ?? CAT_TOKENS[0]
}

// Map wire series to palette slots, enforcing MAX_ADJACENT_SERIES.
//
// When series.length > MAX: keeps first MAX-1 series (slots 1..3), then folds
// series[MAX-1..] into a single "Other" series assigned to slot MAX (cat-4).
// Total rendered series is always ≤ MAX_ADJACENT_SERIES.
//
// Never reads SeriesData.color or ChartConfig.colors.
export function buildSeriesSlots(series: SeriesData[]): FoldedSeries[] {
  if (series.length === 0) return []

  // If count fits within cap, keep all. Otherwise reserve last slot for "Other".
  const keptCount =
    series.length <= MAX_ADJACENT_SERIES ? series.length : MAX_ADJACENT_SERIES - 1
  const kept = series.slice(0, keptCount)
  const excess = series.slice(keptCount)

  const slots: FoldedSeries[] = kept.map((s, i) => ({
    name: s.name,
    data: s.data,
    token: catToken(i),
    isOther: false,
  }))

  if (excess.length > 0) {
    // Sum excess y values point-by-point onto the first available x coordinate set.
    const baseData = kept[0]?.data ?? excess[0]?.data ?? []
    const otherData: DataPoint[] = baseData.map((pt, i) => ({
      x: pt.x,
      y: excess.reduce((sum, s) => sum + (s.data.at(i)?.y ?? 0), 0),
    }))
    slots.push({
      name: 'Other',
      data: otherData,
      token: catToken(MAX_ADJACENT_SERIES - 1),
      isOther: true,
    })
  }

  return slots
}
