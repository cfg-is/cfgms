// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * InvestigationRail tests (Story #3608 + Story #3613).
 *
 * Story #3608 verifies:
 *  - Investigation tab is active by default.
 *  - Findings (kind="finding") render in the Investigation pane.
 *  - Non-finding content entries do not render in the Investigation pane.
 *  - Empty state renders when there are no finding entries.
 *  - Chat tab is present and its pane renders as a placeholder.
 *  - Clicking Chat tab switches the active pane.
 *  - ArrowRight/ArrowLeft keyboard navigation cycles between tabs.
 *  - Roving tabindex: exactly one tab carries tabIndex=0 and it is the active
 *    one; activation moves DOM focus onto the newly active tab.
 *
 * Story #3613 adds:
 *  - LIVE indicator is absent when isLive=false.
 *  - LIVE indicator is present when isLive=true.
 *  - LIVE indicator disappears when isLive transitions from true to false
 *    (the disconnect assertion is load-bearing — proves the indicator is not
 *    hardcoded to visible).
 *  - The pulse animation class is absent when prefers-reduced-motion: reduce
 *    is set (accessibility requirement).
 */
import { afterEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen } from '@testing-library/react'
import InvestigationRail from './InvestigationRail.tsx'
import type { ContentEntry } from './caseTypes.ts'

afterEach(() => {
  vi.unstubAllGlobals()
  cleanup()
})

function makeEntry(overrides: Partial<ContentEntry> = {}): ContentEntry {
  return {
    id: 'content-001',
    case_id: 'case-001',
    kind: 'finding',
    body: 'Config push r2291 caused drift on sql-primary',
    author: 'cfgms',
    created_at: '2026-07-03T08:52:00Z',
    ...overrides,
  }
}

describe('InvestigationRail', () => {
  it('Investigation tab is active by default', () => {
    render(<InvestigationRail content={[]} />)
    const invTab = screen.getByRole('tab', { name: /investigation/i })
    expect(invTab).toHaveAttribute('aria-selected', 'true')
    const chatTab = screen.getByRole('tab', { name: /chat/i })
    expect(chatTab).toHaveAttribute('aria-selected', 'false')
  })

  it('renders finding content entries in the Investigation pane', () => {
    const findings: ContentEntry[] = [
      makeEntry({ id: 'f-001', body: 'Drift detected on sql-primary' }),
      makeEntry({ id: 'f-002', body: 'Config push r2291 partial apply' }),
    ]
    render(<InvestigationRail content={findings} />)
    expect(screen.getByText('Drift detected on sql-primary')).toBeInTheDocument()
    expect(screen.getByText('Config push r2291 partial apply')).toBeInTheDocument()
  })

  it('renders the empty state when there are no findings', () => {
    render(<InvestigationRail content={[]} />)
    expect(screen.getByText(/No investigation findings yet/i)).toBeInTheDocument()
  })

  it('does not render transcript-entry or note kinds in the Investigation pane', () => {
    const mixed: ContentEntry[] = [
      makeEntry({ id: 'f-001', body: 'Finding entry' }),
      makeEntry({ id: 't-001', kind: 'transcript-entry', body: 'Transcript text should not appear' }),
      makeEntry({ id: 'n-001', kind: 'note', body: 'Note should not appear' }),
    ]
    render(<InvestigationRail content={mixed} />)
    expect(screen.getByText('Finding entry')).toBeInTheDocument()
    expect(screen.queryByText('Transcript text should not appear')).toBeNull()
    expect(screen.queryByText('Note should not appear')).toBeNull()
  })

  it('Chat tab renders as a static placeholder pane', () => {
    render(<InvestigationRail content={[]} />)
    const chatTab = screen.getByRole('tab', { name: /chat/i })
    fireEvent.click(chatTab)
    expect(screen.getByText(/Chat is not yet available/i)).toBeInTheDocument()
  })

  it('clicking Chat tab makes it active and hides the Investigation pane', () => {
    render(<InvestigationRail content={[makeEntry()]} />)
    const chatTab = screen.getByRole('tab', { name: /chat/i })
    fireEvent.click(chatTab)
    expect(chatTab).toHaveAttribute('aria-selected', 'true')
    const invTab = screen.getByRole('tab', { name: /investigation/i })
    expect(invTab).toHaveAttribute('aria-selected', 'false')
  })

  it('ArrowRight navigates from Investigation to Chat tab', () => {
    render(<InvestigationRail content={[]} />)
    const invTab = screen.getByRole('tab', { name: /investigation/i })
    fireEvent.keyDown(invTab.closest('[role="tablist"]')!, { key: 'ArrowRight' })
    const chatTab = screen.getByRole('tab', { name: /chat/i })
    expect(chatTab).toHaveAttribute('aria-selected', 'true')
  })

  it('ArrowLeft navigates from Chat back to Investigation tab', () => {
    render(<InvestigationRail content={[]} />)
    // First switch to chat by clicking.
    fireEvent.click(screen.getByRole('tab', { name: /chat/i }))
    const chatTab = screen.getByRole('tab', { name: /chat/i })
    expect(chatTab).toHaveAttribute('aria-selected', 'true')
    // Then navigate back with ArrowLeft.
    fireEvent.keyDown(chatTab.closest('[role="tablist"]')!, { key: 'ArrowLeft' })
    const invTab = screen.getByRole('tab', { name: /investigation/i })
    expect(invTab).toHaveAttribute('aria-selected', 'true')
  })

  it('ArrowRight wraps around from the last tab back to the first', () => {
    render(<InvestigationRail content={[]} />)
    const tablist = screen.getByRole('tablist')
    // Investigation → Chat.
    fireEvent.keyDown(tablist, { key: 'ArrowRight' })
    expect(screen.getByRole('tab', { name: /chat/i })).toHaveAttribute('aria-selected', 'true')
    // Chat → wraps to Investigation.
    fireEvent.keyDown(tablist, { key: 'ArrowRight' })
    expect(screen.getByRole('tab', { name: /investigation/i })).toHaveAttribute(
      'aria-selected',
      'true',
    )
  })

  it('ignores keys other than ArrowLeft/ArrowRight', () => {
    render(<InvestigationRail content={[]} />)
    const tablist = screen.getByRole('tablist')
    fireEvent.keyDown(tablist, { key: 'ArrowDown' })
    fireEvent.keyDown(tablist, { key: 'a' })
    expect(screen.getByRole('tab', { name: /investigation/i })).toHaveAttribute(
      'aria-selected',
      'true',
    )
    expect(screen.getByRole('tab', { name: /chat/i })).toHaveAttribute('aria-selected', 'false')
  })

  it('roving tabindex: only the active tab is in the tab order, and it takes focus', () => {
    render(<InvestigationRail content={[]} />)
    const invTab = screen.getByRole('tab', { name: /investigation/i })
    const chatTab = screen.getByRole('tab', { name: /chat/i })
    // Initial: Investigation active → tabIndex 0, Chat removed from tab order.
    expect(invTab).toHaveAttribute('tabindex', '0')
    expect(chatTab).toHaveAttribute('tabindex', '-1')

    // ArrowRight activates Chat: tabindex rolls over and focus follows.
    fireEvent.keyDown(screen.getByRole('tablist'), { key: 'ArrowRight' })
    expect(chatTab).toHaveAttribute('tabindex', '0')
    expect(invTab).toHaveAttribute('tabindex', '-1')
    expect(document.activeElement).toBe(chatTab)
  })
})

// ── LIVE indicator (Story #3613) ───────────────────────────────────────────

describe('InvestigationRail LIVE indicator', () => {
  // [REQUIRED TEST] Indicator state test: absent before connect, present after
  // connect, and absent again after disconnect. The disconnect assertion is the
  // load-bearing half — it proves the indicator is driven by real connection
  // state, not hardcoded to visible.
  it('is absent when isLive=false (not connected)', () => {
    render(<InvestigationRail content={[]} isLive={false} />)
    expect(document.querySelector('.ctx-live')).toBeNull()
    expect(document.querySelector('.ctx')).toBeNull()
  })

  it('is present when isLive=true (connected)', () => {
    render(<InvestigationRail content={[]} isLive={true} connectedSince={new Date()} />)
    const indicator = document.querySelector('.ctx-live')
    expect(indicator).not.toBeNull()
    expect(indicator!.textContent).toContain('LIVE')
  })

  it('disappears when isLive transitions from true to false (disconnect)', () => {
    const connectedSince = new Date()
    const { rerender } = render(
      <InvestigationRail content={[]} isLive={true} connectedSince={connectedSince} />,
    )
    expect(document.querySelector('.ctx-live')).not.toBeNull()

    // Simulate socket disconnect by re-rendering with isLive=false.
    rerender(<InvestigationRail content={[]} isLive={false} connectedSince={null} />)
    expect(document.querySelector('.ctx-live')).toBeNull()
  })

  it('renders the elapsed timer in mm:ss monospace form', () => {
    render(<InvestigationRail content={[]} isLive={true} connectedSince={new Date()} />)
    // The mono span renders an elapsed time; at t≈0 it should be "00:00".
    const mono = document.querySelector('.ctx-live .mono')
    expect(mono).not.toBeNull()
    expect(mono!.textContent).toMatch(/^\d{2}:\d{2}$/)
  })

  // [REQUIRED TEST] Reduced-motion test: the pulse animation class must not be
  // applied to the dot when prefers-reduced-motion: reduce is set.
  it('omits the pulse animation class when prefers-reduced-motion: reduce is set', () => {
    vi.stubGlobal('matchMedia', (query: string) => ({
      matches: query.includes('prefers-reduced-motion'),
      media: query,
      onchange: null,
      addListener: () => {},
      removeListener: () => {},
      addEventListener: () => {},
      removeEventListener: () => {},
      dispatchEvent: () => false,
    }))

    render(<InvestigationRail content={[]} isLive={true} connectedSince={new Date()} />)
    const dot = document.querySelector('.ctx-live .dot')
    expect(dot).not.toBeNull()
    expect(dot!.classList.contains('dot--pulse')).toBe(false)
  })

  it('applies the pulse animation class when prefers-reduced-motion is not set', () => {
    vi.stubGlobal('matchMedia', (query: string) => ({
      matches: false, // reduced motion not active
      media: query,
      onchange: null,
      addListener: () => {},
      removeListener: () => {},
      addEventListener: () => {},
      removeEventListener: () => {},
      dispatchEvent: () => false,
    }))

    render(<InvestigationRail content={[]} isLive={true} connectedSince={new Date()} />)
    const dot = document.querySelector('.ctx-live .dot')
    expect(dot).not.toBeNull()
    expect(dot!.classList.contains('dot--pulse')).toBe(true)
  })

  it('uses --crit colour token via CSS class (not inline style)', () => {
    render(<InvestigationRail content={[]} isLive={true} connectedSince={new Date()} />)
    const indicator = document.querySelector('.ctx-live')
    expect(indicator).not.toBeNull()
    // The live-ind class must be present so CSS can apply var(--crit).
    expect(indicator!.classList.contains('live-ind')).toBe(true)
    // No inline color — colour must come from the design token via CSS class.
    expect((indicator as HTMLElement).style.color).toBe('')
  })
})
