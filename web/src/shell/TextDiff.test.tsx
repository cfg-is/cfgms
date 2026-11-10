// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * TextDiff unit tests (Issue #6036): per-line classification, the file-header
 * exemption for +++/---, and literal-text rendering of untrusted diff content.
 */
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest'
import { cleanup, render, screen } from '@testing-library/react'
import TextDiff, { classifyDiffLine } from './TextDiff.tsx'

afterEach(() => cleanup())

const lineEls = (container: HTMLElement) =>
  Array.from(container.querySelectorAll<HTMLElement>('.textdiff-line'))

describe('TextDiff — line classes', () => {
  const diff = [
    '--- a/run.ps1',
    '+++ b/run.ps1',
    '@@ -1,3 +1,3 @@',
    ' context line',
    '-old line',
    '+new line',
    '',
  ].join('\n')

  it('gives each line its own element with the right class', () => {
    const { container } = render(<TextDiff diff={diff} />)
    const classes = lineEls(container).map((el) => el.className.replace('textdiff-line ', ''))
    expect(classes).toEqual([
      'textdiff-header',
      'textdiff-header',
      'textdiff-header',
      'textdiff-context',
      'textdiff-removed',
      'textdiff-added',
      'textdiff-context',
    ])
  })

  it('does not class +++ and --- file headers as added or removed', () => {
    const { container } = render(<TextDiff diff={diff} />)
    const [minus, plus] = lineEls(container) as [HTMLElement, HTMLElement]
    expect(minus).toHaveTextContent('--- a/run.ps1')
    expect(minus).not.toHaveClass('textdiff-removed')
    expect(plus).toHaveTextContent('+++ b/run.ps1')
    expect(plus).not.toHaveClass('textdiff-added')
  })

  it('keeps the +/- prefix visible and the container text equal to the diff', () => {
    render(<TextDiff diff={diff} data-testid="d" />)
    const box = screen.getByTestId('d')
    expect(box.textContent).toBe(diff)
    expect(box.textContent).toContain('+new line')
    expect(box.textContent).toContain('-old line')
  })

  it('classifies single-character and empty lines', () => {
    expect(classifyDiffLine('+')).toBe('added')
    expect(classifyDiffLine('-')).toBe('removed')
    expect(classifyDiffLine('')).toBe('context')
    expect(classifyDiffLine('\\ No newline at end of file')).toBe('context')
  })
})

describe('TextDiff — untrusted content', () => {
  it('renders HTML in a line as literal text and adds no element', () => {
    const payload = '+<script>alert(1)</script><img src=x onerror=alert(1)>'
    const { container } = render(<TextDiff diff={`${payload}\n context`} />)
    expect(container.querySelector('script')).toBeNull()
    expect(container.querySelector('img')).toBeNull()
    const els = lineEls(container)
    expect(els).toHaveLength(2)
    expect(els[0]?.textContent).toContain(payload)
    expect(els[0]?.children).toHaveLength(0)
    // Only the <pre> and one <span> per line exist.
    expect(container.querySelectorAll('*')).toHaveLength(1 + 2)
  })
})

describe('TextDiff — styles', () => {
  // Vitest serves CSS imports as empty strings (even ?raw), so read the file
  // directly. The path is relative to the web/ package root, where vitest runs.
  let css = ''
  beforeAll(async () => {
    const fs = await vi.importActual<{ readFileSync(path: string, enc: 'utf8'): string }>('node:fs')
    // Comments are stripped so only declarations are checked.
    css = fs.readFileSync('src/shell/TextDiff.css', 'utf8').replace(/\/\*[\s\S]*?\*\//g, '')
  })

  it('uses only var(--…) tokens: no hex, rgb or px colour literals', () => {
    expect(css).toContain('var(--state-ok)')
    const colourDecls = css
      .split('\n')
      .filter((l: string) => /^\s*(color|background|background-color|border[a-z-]*)\s*:/.test(l))
    expect(colourDecls.length).toBeGreaterThan(0)
    for (const l of colourDecls) {
      expect(l).not.toMatch(/#[0-9a-fA-F]{3,8}\b/)
      expect(l).not.toMatch(/rgba?\(|hsla?\(/)
    }
    expect(css).not.toMatch(/#[0-9a-fA-F]{3,8}\b/)
    expect(css).not.toMatch(/rgba?\(|hsla?\(/)
  })
})
