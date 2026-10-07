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
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router'
import StewardDrawer from './StewardDrawer.tsx'

// The real ShellTab mounts inside the drawer. Only its third-party terminal
// dependency is replaced: @xterm/xterm needs a canvas/layout engine jsdom
// does not provide (same approach as ShellTab.test.tsx).
vi.mock('@xterm/xterm', () => {
  function Terminal(this: Record<string, unknown>) {
    this.open = vi.fn()
    this.write = vi.fn()
    this.clear = vi.fn()
    this.dispose = vi.fn()
    this.getSelection = vi.fn().mockReturnValue('')
    this.loadAddon = vi.fn()
    this.onData = vi.fn().mockReturnValue({ dispose: vi.fn() })
    this.onResize = vi.fn().mockReturnValue({ dispose: vi.fn() })
    this.options = {}
    this.cols = 80
    this.rows = 24
  }
  return { Terminal }
})

vi.mock('@xterm/addon-fit', () => {
  function FitAddon(this: Record<string, unknown>) {
    this.fit = vi.fn()
    this.dispose = vi.fn()
  }
  return { FitAddon }
})

vi.mock('@xterm/xterm/css/xterm.css', () => ({}))

const fetchMock = vi.fn<typeof fetch>()

// Stub WebSocket so LiveActivityTab and ShellTab do not attempt real
// connections; record URLs so tests can assert which endpoint was dialled.
class StubWebSocket {
  static urls: string[] = []
  url: string
  readyState: number = WebSocket.CONNECTING
  onopen: (() => void) | null = null
  onclose: ((ev: { code: number }) => void) | null = null
  onmessage: ((ev: { data: string }) => void) | null = null
  onerror: (() => void) | null = null
  constructor(url: string) {
    this.url = url
    StubWebSocket.urls.push(url)
  }
  send() {}
  close() { this.readyState = WebSocket.CLOSED }
}

class StubResizeObserver {
  observe() {}
  unobserve() {}
  disconnect() {}
}

beforeEach(() => {
  StubWebSocket.urls = []
  fetchMock.mockReset()
  fetchMock.mockReturnValue(new Promise(() => {}))
  vi.stubGlobal('fetch', fetchMock)
  vi.stubGlobal('WebSocket', StubWebSocket)
  vi.stubGlobal('ResizeObserver', StubResizeObserver)
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

describe('Shell tab (Story #4591)', () => {
  it('renders ShellTab, not SoonPanel, only once selected', () => {
    renderDrawer()
    expect(screen.queryByTestId('shell-tab')).toBeNull()
    const tab = screen.getByRole('tab', { name: /^Shell/i })
    expect(tab.className).not.toContain('soon')
    fireEvent.click(tab)
    const shell = screen.getByTestId('shell-tab')
    expect(shell).toHaveTextContent('stw-42')
    expect(
      StubWebSocket.urls.some((u) => u.endsWith('/api/v1/terminal/ws/stw-42')),
    ).toBe(true)
    expect(screen.queryByText(/not yet available/i)).toBeNull()
  })
})

describe('Export DNA (Story #4591)', () => {
  const dnaBody = {
    data: {
      hostname: 'host-1',
      os: 'linux',
      architecture: 'amd64',
      config_hash: 'abc',
      collected_at: '2026-01-01T00:00:00Z',
      attributes: { tenant: 'acme-corp' },
    },
  }

  it('is disabled with a reason while DNA is loading', () => {
    renderDrawer()
    const btn = screen.getByTestId('drawer-export-dna')
    expect(btn).toBeDisabled()
    expect(btn).toHaveAttribute('title', 'DNA is still loading')
  })

  it('is disabled with a reason when DNA is unavailable', async () => {
    fetchMock.mockResolvedValue(new Response('nope', { status: 404 }))
    renderDrawer()
    await waitFor(() =>
      expect(screen.getByTestId('drawer-export-dna')).toHaveAttribute(
        'title',
        'DNA is unavailable for this steward',
      ),
    )
    expect(screen.getByTestId('drawer-export-dna')).toBeDisabled()
  })

  it('downloads a Blob whose JSON equals the fetched DNA', async () => {
    fetchMock.mockResolvedValue(new Response(JSON.stringify(dnaBody), { status: 200 }))
    let blob: Blob | undefined
    URL.createObjectURL = vi.fn((b: Blob | MediaSource) => {
      blob = b as Blob
      return 'blob:test'
    })
    URL.revokeObjectURL = vi.fn()
    const names: string[] = []
    const click = vi
      .spyOn(HTMLAnchorElement.prototype, 'click')
      .mockImplementation(function (this: HTMLAnchorElement) {
        names.push(this.download)
      })

    renderDrawer()
    await waitFor(() => expect(screen.getByTestId('drawer-export-dna')).toBeEnabled())
    fireEvent.click(screen.getByTestId('drawer-export-dna'))

    expect(click).toHaveBeenCalledTimes(1)
    expect(names).toEqual(['stw-42-dna.json'])
    const text = await new Promise<string>((resolve) => {
      const r = new FileReader()
      r.onload = () => resolve(r.result as string)
      r.readAsText(blob!)
    })
    expect(JSON.parse(text)).toEqual({
      hostname: 'host-1',
      os: 'linux',
      architecture: 'amd64',
      configHash: 'abc',
      collectedAt: '2026-01-01T00:00:00Z',
      attributes: { tenant: 'acme-corp' },
    })
    click.mockRestore()
  })
})
