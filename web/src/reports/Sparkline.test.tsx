// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * Sparkline suite (Story #3269): mark spec enforcement — design system §4
 * sparkline mark: 2px line, --text-faint for history, --accent end marker,
 * 2px --bg-surface ring, no axes/gridlines/per-point labels.
 */
import { describe, expect, it } from 'vitest'
import { render } from '@testing-library/react'
import Sparkline from './Sparkline.tsx'

describe('Sparkline — rendering', () => {
  it('returns null for empty values', () => {
    const { container } = render(<Sparkline values={[]} />)
    expect(container.querySelector('svg')).toBeNull()
  })

  it('returns null for a single value (needs >= 2 to draw a line)', () => {
    const { container } = render(<Sparkline values={[42]} />)
    expect(container.querySelector('svg')).toBeNull()
  })

  it('renders an svg for two or more values', () => {
    const { container } = render(<Sparkline values={[10, 20]} />)
    expect(container.querySelector('svg')).not.toBeNull()
  })
})

describe('Sparkline — mark spec', () => {
  it('uses --text-faint for the line stroke (history colour)', () => {
    const { container } = render(<Sparkline values={[10, 20, 30]} />)
    const path = container.querySelector('path')
    expect(path?.getAttribute('stroke')).toBe('var(--text-faint)')
  })

  it('renders a 2px line (stroke-width 2)', () => {
    const { container } = render(<Sparkline values={[10, 20, 30]} />)
    const path = container.querySelector('path')
    expect(path?.getAttribute('stroke-width')).toBe('2')
  })

  it('renders round line cap and join', () => {
    const { container } = render(<Sparkline values={[10, 20, 30]} />)
    const path = container.querySelector('path')
    expect(path?.getAttribute('stroke-linecap')).toBe('round')
    expect(path?.getAttribute('stroke-linejoin')).toBe('round')
  })

  it('renders no area fill (line only)', () => {
    const { container } = render(<Sparkline values={[10, 20, 30]} />)
    const path = container.querySelector('path')
    expect(path?.getAttribute('fill')).toBe('none')
  })

  it('renders an end marker at the last data point (r=4)', () => {
    const { container } = render(<Sparkline values={[10, 20, 30]} />)
    const circle = container.querySelector('circle')
    expect(circle).not.toBeNull()
    expect(Number(circle?.getAttribute('r'))).toBeGreaterThanOrEqual(4)
  })

  it('uses --accent for the end marker fill (current period)', () => {
    const { container } = render(<Sparkline values={[10, 20, 30]} />)
    const circle = container.querySelector('circle')
    expect(circle?.getAttribute('fill')).toBe('var(--accent)')
  })

  it('uses --bg-surface ring on the end marker (2px separation)', () => {
    const { container } = render(<Sparkline values={[10, 20, 30]} />)
    const circle = container.querySelector('circle')
    expect(circle?.getAttribute('stroke')).toBe('var(--bg-surface)')
    expect(circle?.getAttribute('stroke-width')).toBe('2')
  })

  it('is aria-hidden (tile value is the label; sparkline is decorative)', () => {
    const { container } = render(<Sparkline values={[10, 20, 30]} />)
    const svg = container.querySelector('svg')
    expect(svg?.getAttribute('aria-hidden')).toBe('true')
  })

  it('renders no axis or gridline elements', () => {
    const { container } = render(<Sparkline values={[10, 20, 30, 40, 50]} />)
    // No <line> elements (gridlines); sparkline has a <path> and <circle> only
    expect(container.querySelectorAll('line')).toHaveLength(0)
    expect(container.querySelectorAll('text')).toHaveLength(0)
  })
})

describe('Sparkline — SVG geometry', () => {
  it('uses default dimensions of 74x26 when none provided', () => {
    const { container } = render(<Sparkline values={[10, 20, 30]} />)
    const svg = container.querySelector('svg')
    expect(svg?.getAttribute('viewBox')).toBe('0 0 74 26')
    expect(svg?.getAttribute('width')).toBe('74')
    expect(svg?.getAttribute('height')).toBe('26')
  })

  it('respects custom width and height props', () => {
    const { container } = render(<Sparkline values={[10, 20, 30]} width={100} height={40} />)
    const svg = container.querySelector('svg')
    expect(svg?.getAttribute('viewBox')).toBe('0 0 100 40')
    expect(svg?.getAttribute('width')).toBe('100')
    expect(svg?.getAttribute('height')).toBe('40')
  })

  it('normalises X across the full width and Y across the padded height', () => {
    // width=74, height=26: X spans 0..74; Y maps min -> H-2 (24) and max -> H-2-(H-6) (4)
    const { container } = render(<Sparkline values={[0, 100]} />)
    expect(container.querySelector('path')?.getAttribute('d')).toBe('M0.0,24.0 L74.0,4.0')
  })

  it('scales intermediate values proportionally between min and max', () => {
    // midpoint of 0..100 sits halfway between Y(min)=24 and Y(max)=4 -> 14
    const { container } = render(<Sparkline values={[0, 50, 100]} />)
    expect(container.querySelector('path')?.getAttribute('d')).toBe('M0.0,24.0 L37.0,14.0 L74.0,4.0')
  })

  it('emits one path command per value', () => {
    const { container } = render(<Sparkline values={[1, 2, 3, 4, 5]} />)
    const d = container.querySelector('path')?.getAttribute('d') ?? ''
    expect(d.split(' ')).toHaveLength(5)
    expect(d.match(/L/g)).toHaveLength(4)
  })

  it('renders a flat baseline without NaN when every value is identical', () => {
    // max - min === 0; the || 1 range fallback must keep coordinates finite
    const { container } = render(<Sparkline values={[7, 7, 7]} />)
    const d = container.querySelector('path')?.getAttribute('d') ?? ''
    expect(d).not.toContain('NaN')
    expect(d).toBe('M0.0,24.0 L37.0,24.0 L74.0,24.0')
  })

  it('positions the end marker on the last value, not the first', () => {
    const { container } = render(<Sparkline values={[0, 100]} />)
    const circle = container.querySelector('circle')
    expect(Number(circle?.getAttribute('cy'))).toBeCloseTo(4, 5)
  })

  it('positions the end marker low when the series ends at its minimum', () => {
    const { container } = render(<Sparkline values={[100, 0]} />)
    const circle = container.querySelector('circle')
    expect(Number(circle?.getAttribute('cy'))).toBeCloseTo(24, 5)
  })

  it('positions the end-marker circle at the right edge (last x position)', () => {
    // For values [10, 20, 30] with default width=74: X(last) = 74 * 2 / 2 = 74
    const { container } = render(<Sparkline values={[10, 20, 30]} />)
    const circle = container.querySelector('circle')
    expect(Number(circle?.getAttribute('cx'))).toBeCloseTo(74, 0)
  })

  it('builds a valid SVG path starting with M', () => {
    const { container } = render(<Sparkline values={[5, 10, 15]} />)
    const path = container.querySelector('path')
    expect(path?.getAttribute('d')).toMatch(/^M/)
  })
})
