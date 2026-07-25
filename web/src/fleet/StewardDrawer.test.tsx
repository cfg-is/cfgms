// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * StewardDrawer suite (Story #2917): overlay drawer component that renders
 * asset tabs over the fleet list without a route change.
 *
 * Tests: expand toggle changes layout class, second click reverts, ESC closes,
 * scrim click closes, and the drawer is accessible as a dialog.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router'
import StewardDrawer from './StewardDrawer.tsx'

const fetchMock = vi.fn<typeof fetch>()

// Stub WebSocket so LiveActivityTab does not attempt real connections.
class StubWebSocket {
  readyState: number = WebSocket.CONNECTING
  onopen: (() => void) | null = null
  onclose: ((ev: { code: number }) => void) | null = null
  onmessage: ((ev: { data: string }) => void) | null = null
  onerror: (() => void) | null = null
  close() { this.readyState = WebSocket.CLOSED }
}

beforeEach(() => {
  fetchMock.mockReset()
  fetchMock.mockReturnValue(new Promise(() => {}))
  vi.stubGlobal('fetch', fetchMock)
  vi.stubGlobal('WebSocket', StubWebSocket)
})

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

function renderDrawer(onClose = vi.fn()) {
  return render(
    <MemoryRouter>
      <StewardDrawer stewardId="stw-42" onClose={onClose} />
    </MemoryRouter>,
  )
}

describe('expand toggle (Story #2917 AC)', () => {
  it('drawer starts without the expanded class', () => {
    renderDrawer()
    const drawer = screen.getByTestId('steward-drawer')
    expect(drawer.className).not.toContain('det-expanded')
  })

  it('expand toggle adds the expanded class', () => {
    renderDrawer()
    const toggle = screen.getByTestId('drawer-expand-toggle')
    fireEvent.click(toggle)

    const drawer = screen.getByTestId('steward-drawer')
    expect(drawer.className).toContain('det-expanded')
  })

  it('second click on expand toggle collapses back to original class', () => {
    renderDrawer()
    const toggle = screen.getByTestId('drawer-expand-toggle')

    fireEvent.click(toggle)
    expect(screen.getByTestId('steward-drawer').className).toContain('det-expanded')

    fireEvent.click(toggle)
    expect(screen.getByTestId('steward-drawer').className).not.toContain('det-expanded')
  })

  it('expand toggle button has accessible label describing the action', () => {
    renderDrawer()
    expect(screen.getByLabelText('Expand drawer')).toBeInTheDocument()
  })

  it('label changes to "Collapse drawer" when expanded', () => {
    renderDrawer()
    fireEvent.click(screen.getByTestId('drawer-expand-toggle'))
    expect(screen.getByLabelText('Collapse drawer')).toBeInTheDocument()
  })
})

describe('close behaviour', () => {
  it('close button calls onClose', () => {
    const onClose = vi.fn()
    renderDrawer(onClose)
    fireEvent.click(screen.getByTestId('drawer-close'))
    expect(onClose).toHaveBeenCalledTimes(1)
  })

  it('ESC key calls onClose', () => {
    const onClose = vi.fn()
    renderDrawer(onClose)
    fireEvent.keyDown(document, { key: 'Escape' })
    expect(onClose).toHaveBeenCalledTimes(1)
  })

  it('scrim click calls onClose', () => {
    const onClose = vi.fn()
    renderDrawer(onClose)
    fireEvent.click(screen.getByTestId('drawer-scrim'))
    expect(onClose).toHaveBeenCalledTimes(1)
  })
})

describe('accessibility', () => {
  it('drawer is a dialog with an aria-label', () => {
    renderDrawer()
    const dialog = screen.getByRole('dialog')
    expect(dialog).toBeInTheDocument()
    expect(dialog).toHaveAttribute('aria-label', 'Asset details: stw-42')
  })

  it('renders a tab strip with DNA selected by default', () => {
    renderDrawer()
    expect(screen.getByRole('tab', { name: /^DNA/i })).toHaveAttribute('aria-selected', 'true')
  })
})

describe('tab keyboard navigation', () => {
  it('ArrowRight cycles forward through tabs', () => {
    renderDrawer()
    const tablist = screen.getByRole('tablist')

    // DNA → Config
    fireEvent.keyDown(tablist, { key: 'ArrowRight' })
    expect(screen.getByRole('tab', { name: /^Config/i })).toHaveAttribute('aria-selected', 'true')
    expect(screen.getByRole('tab', { name: /^DNA/i })).toHaveAttribute('aria-selected', 'false')

    // Config → Shell
    fireEvent.keyDown(tablist, { key: 'ArrowRight' })
    expect(screen.getByRole('tab', { name: /^Shell/i })).toHaveAttribute('aria-selected', 'true')
  })

  it('ArrowLeft wraps from DNA back to Live Activity', () => {
    renderDrawer()
    const tablist = screen.getByRole('tablist')

    fireEvent.keyDown(tablist, { key: 'ArrowLeft' })
    expect(screen.getByRole('tab', { name: /^Live Activity/i })).toHaveAttribute(
      'aria-selected',
      'true',
    )
    expect(screen.getByRole('tab', { name: /^DNA/i })).toHaveAttribute('aria-selected', 'false')
  })
})
