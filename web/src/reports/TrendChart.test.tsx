// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * TrendChart suite (Story #3269): series-cap enforcement and server-colour-
 * ignored behaviour — the two load-bearing rules from design system §4.
 *
 * AC: series cap of 4 is enforced (5th+ series folds into "Other");
 *     SeriesData.Color and ChartConfig.Colors from the wire are ignored;
 *     series are mapped by index to the validated --cat-* palette tokens.
 */
import { describe, expect, it } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import TrendChart from './TrendChart.tsx'
import type { ChartData } from './palette.ts'

function makePoints(count: number) {
  return Array.from({ length: count }, (_, i) => ({
    x: `2026-01-${String(i + 1).padStart(2, '0')}`,
    y: (i + 1) * 10,
  }))
}

function makeChart(seriesCount: number, overrides: Partial<ChartData> = {}): ChartData {
  return {
    id: 'test-chart',
    type: 'line',
    title: 'Test Chart',
    series: Array.from({ length: seriesCount }, (_, i) => ({
      name: `Series ${i + 1}`,
      data: makePoints(7),
      color: '#ff0000',  // server-supplied — must be ignored
    })),
    x_axis: { title: 'Date', type: 'time' },
    y_axis: { title: 'Count', type: 'numeric' },
    config: {
      colors: ['#ff0000', '#00ff00'],  // server-supplied — must be ignored
    },
    ...overrides,
  }
}

describe('TrendChart — series cap enforcement', () => {
  it('renders all series when count is at or below 4', () => {
    const { container } = render(<TrendChart chart={makeChart(4)} />)
    const lines = container.querySelectorAll('[data-testid^="series-line-"]')
    expect(lines).toHaveLength(4)
    expect(screen.queryByText('Other')).toBeNull()
  })

  it('folds the 5th+ series into Other when series count exceeds 4', () => {
    render(<TrendChart chart={makeChart(5)} />)
    // "Other" appears in both the legend and the table header — check the legend
    const legend = screen.getByTestId('legend')
    expect(within(legend).getByText('Other')).toBeDefined()
  })

  it('renders at most 4 series lines when series count exceeds 4', () => {
    const { container } = render(<TrendChart chart={makeChart(6)} />)
    const lines = container.querySelectorAll('[data-testid^="series-line-"]')
    expect(lines.length).toBeLessThanOrEqual(4)
  })

  it('renders at most 4 series lines for a large series count', () => {
    const { container } = render(<TrendChart chart={makeChart(10)} />)
    const lines = container.querySelectorAll('[data-testid^="series-line-"]')
    expect(lines.length).toBeLessThanOrEqual(4)
  })

  it('shows Other in the legend when series count exceeds 4', () => {
    render(<TrendChart chart={makeChart(5)} />)
    const legend = screen.getByTestId('legend')
    expect(legend.textContent).toContain('Other')
  })

  it('does not show Other in the legend when series count is 4', () => {
    render(<TrendChart chart={makeChart(4)} />)
    const legend = screen.getByTestId('legend')
    expect(legend.textContent).not.toContain('Other')
  })
})

// Every attribute value and text node in the rendered tree, joined. Used to prove
// wire colours reach no rendered surface. Serialising via innerHTML would trip the
// banned HTML-sink lint rule, and this reads the live DOM rather than a string.
function renderedValues(root: Element): string {
  const parts: string[] = []
  for (const el of root.querySelectorAll('*')) {
    for (const attr of el.attributes) parts.push(attr.value)
  }
  parts.push(root.textContent ?? '')
  return parts.join('\n')
}

describe('TrendChart — server-colour ignored', () => {
  it('does not render SeriesData.Color from the wire', () => {
    const { container } = render(<TrendChart chart={makeChart(1)} />)
    expect(renderedValues(container)).not.toContain('#ff0000')
  })

  it('does not render ChartConfig.Colors from the wire', () => {
    const { container } = render(<TrendChart chart={makeChart(2)} />)
    expect(renderedValues(container)).not.toContain('#00ff00')
  })

  it('does not render any non-token colour strings from a multi-series chart', () => {
    const { container } = render(<TrendChart chart={makeChart(4)} />)
    const rendered = renderedValues(container)
    // Guard against a vacuous scan: the palette tokens must be visible to it
    expect(rendered).toContain('var(--cat-1)')
    // Server-supplied colours must not appear anywhere in the output
    expect(rendered).not.toContain('#ff0000')
    expect(rendered).not.toContain('#00ff00')
  })

  it('maps series index 0 to --cat-1', () => {
    const { container } = render(<TrendChart chart={makeChart(1)} />)
    const line = container.querySelector('[data-testid="series-line-0"]')
    expect(line?.getAttribute('stroke')).toBe('var(--cat-1)')
  })

  it('maps series index 1 to --cat-2', () => {
    const { container } = render(<TrendChart chart={makeChart(2)} />)
    const line = container.querySelector('[data-testid="series-line-1"]')
    expect(line?.getAttribute('stroke')).toBe('var(--cat-2)')
  })

  it('maps series index 2 to --cat-3', () => {
    const { container } = render(<TrendChart chart={makeChart(3)} />)
    const line = container.querySelector('[data-testid="series-line-2"]')
    expect(line?.getAttribute('stroke')).toBe('var(--cat-3)')
  })

  it('maps series index 3 to --cat-4', () => {
    const { container } = render(<TrendChart chart={makeChart(4)} />)
    const line = container.querySelector('[data-testid="series-line-3"]')
    expect(line?.getAttribute('stroke')).toBe('var(--cat-4)')
  })

  it('uses cat-* token for the Other series, not a generated colour', () => {
    const { container } = render(<TrendChart chart={makeChart(5)} />)
    // The Other series occupies the last rendered slot (index 3)
    const line = container.querySelector('[data-testid="series-line-3"]')
    // Must be one of the validated cat-* tokens, not a bare hex or generated value
    const stroke = line?.getAttribute('stroke') ?? ''
    expect(stroke).toMatch(/^var\(--cat-[1-4]\)$/)
  })
})

// Series names deliberately avoid makeChart's `#ff0000`/wire-colour scaffolding —
// this suite is only about the warn/crit legend icon rule.
function makeStateChart(names: string[]): ChartData {
  return {
    id: 'test-chart',
    type: 'line',
    title: 'Test Chart',
    series: names.map(name => ({ name, data: makePoints(7) })),
    x_axis: { title: 'Date', type: 'time' },
    y_axis: { title: 'Count', type: 'numeric' },
    config: {},
  }
}

describe('TrendChart — state-adjacent icon + label', () => {
  it('renders an icon in the legend for both a warn-like and a crit-like series when both are present', () => {
    const { container } = render(<TrendChart chart={makeStateChart(['Drift warnings', 'Critical errors'])} />)
    const warnItem = container.querySelector('[data-testid="legend-item-0"]')
    const critItem = container.querySelector('[data-testid="legend-item-1"]')
    expect(warnItem?.querySelector('.trend-legend-icon')).not.toBeNull()
    expect(critItem?.querySelector('.trend-legend-icon')).not.toBeNull()
  })

  it('renders the warn icon (triangle path, no circle) for the warn-like series', () => {
    const { container } = render(<TrendChart chart={makeStateChart(['Drift warnings', 'Critical errors'])} />)
    const warnItem = container.querySelector('[data-testid="legend-item-0"]')
    expect(warnItem?.querySelector('.trend-legend-icon circle')).toBeNull()
    expect(warnItem?.querySelector('.trend-legend-icon path')).not.toBeNull()
  })

  it('renders the crit icon (circle) for the crit-like series', () => {
    const { container } = render(<TrendChart chart={makeStateChart(['Drift warnings', 'Critical errors'])} />)
    const critItem = container.querySelector('[data-testid="legend-item-1"]')
    expect(critItem?.querySelector('.trend-legend-icon circle')).not.toBeNull()
  })

  it('still shows the series name as text alongside the icon (identity is never icon-alone)', () => {
    render(<TrendChart chart={makeStateChart(['Drift warnings', 'Critical errors'])} />)
    const legend = screen.getByTestId('legend')
    expect(within(legend).getByText('Drift warnings')).toBeDefined()
    expect(within(legend).getByText('Critical errors')).toBeDefined()
  })

  it('does not render legend icons when only a warn-like series is present (no adjacent crit)', () => {
    const { container } = render(<TrendChart chart={makeStateChart(['Drift warnings', 'Normal traffic'])} />)
    expect(container.querySelectorAll('.trend-legend-icon')).toHaveLength(0)
  })

  it('does not render legend icons when only a crit-like series is present (no adjacent warn)', () => {
    const { container } = render(<TrendChart chart={makeStateChart(['Critical errors', 'Normal traffic'])} />)
    expect(container.querySelectorAll('.trend-legend-icon')).toHaveLength(0)
  })

  it('does not render legend icons when neither warn-like nor crit-like series are present', () => {
    const { container } = render(<TrendChart chart={makeStateChart(['CPU usage', 'Memory usage'])} />)
    expect(container.querySelectorAll('.trend-legend-icon')).toHaveLength(0)
  })

  it('only icons the warn/crit series, leaving unrelated series without an icon', () => {
    const { container } = render(
      <TrendChart chart={makeStateChart(['Drift warnings', 'Critical errors', 'Normal traffic'])} />,
    )
    const normalItem = container.querySelector('[data-testid="legend-item-2"]')
    expect(normalItem?.querySelector('.trend-legend-icon')).toBeNull()
    expect(container.querySelectorAll('.trend-legend-icon')).toHaveLength(2)
  })
})

describe('TrendChart — structural requirements', () => {
  it('renders the chart title', () => {
    render(<TrendChart chart={makeChart(1)} />)
    expect(screen.getByText('Test Chart')).toBeDefined()
  })

  it('renders the table view disclosure', () => {
    const { container } = render(<TrendChart chart={makeChart(1)} />)
    expect(container.querySelector('details')).not.toBeNull()
    expect(container.querySelector('summary')).not.toBeNull()
  })

  it('shows a legend for 2 or more series', () => {
    const { container } = render(<TrendChart chart={makeChart(2)} />)
    expect(container.querySelector('[data-testid="legend"]')).not.toBeNull()
  })

  it('does not show a legend for a single series', () => {
    const { container } = render(<TrendChart chart={makeChart(1)} />)
    expect(container.querySelector('[data-testid="legend"]')).toBeNull()
  })

  it('renders nothing for an empty series array', () => {
    const { container } = render(<TrendChart chart={makeChart(0)} />)
    expect(container.querySelector('[data-testid="trend-chart"]')).toBeNull()
  })
})
