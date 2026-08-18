// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * StewardAssetPage suite (Story #2723 + #2766 + #2762): tab switching,
 * inert-placeholder rendering for Config, DNA-tab content parity with the
 * pre-router DnaDrawer behavior, live tab mounts LiveActivityTab (#2766),
 * and shell tab mounts ShellTab (#2762).
 *
 * The component reads :id from the route param; tests use MemoryRouter to
 * provide the steward ID without a real browser.
 *
 * WebSocket is stubbed so LiveActivityTab and ShellTab do not attempt real
 * network connections when their tabs are activated. xterm/addon-fit are
 * mocked so ShellTab renders without a canvas/layout engine in jsdom.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, within } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router'
import StewardAssetPage, { PanelContent, TABS } from './StewardAssetPage.tsx'

// Mock xterm modules so ShellTab renders cleanly in jsdom (no canvas needed).
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

const fetchMock = vi.fn<typeof fetch>()

// Minimal WebSocket stub — keeps LiveActivityPanel and ShellTab from throwing
// when their tabs mount during StewardAssetPage tests.
class StubWebSocket {
  readyState: number = WebSocket.CONNECTING
  onopen: (() => void) | null = null
  onclose: ((ev: { code: number }) => void) | null = null
  onmessage: ((ev: { data: string }) => void) | null = null
  onerror: (() => void) | null = null
  send() {}
  close() {
    this.readyState = WebSocket.CLOSED
  }
}

class StubResizeObserver {
  observe() {}
  unobserve() {}
  disconnect() {}
}

beforeEach(() => {
  fetchMock.mockReset()
  vi.stubGlobal('fetch', fetchMock)
  vi.stubGlobal('WebSocket', StubWebSocket)
  vi.stubGlobal('ResizeObserver', StubResizeObserver)
})

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

/**
 * Creates a fresh Response on every call — reusing the same Response object
 * causes "Body has already been read" when DnaDrawer remounts and refetches.
 */
function mockDNA(attributes: Record<string, string> = {}) {
  fetchMock.mockImplementation(() =>
    Promise.resolve(
      new Response(
        JSON.stringify({
          data: {
            hostname: 'asset-test-host',
            os: 'Ubuntu 24.04',
            architecture: 'amd64',
            config_hash: 'abc123',
            collected_at: '2026-07-14T10:00:00Z',
            attributes,
          },
          timestamp: new Date().toISOString(),
        }),
        { status: 200, headers: { 'Content-Type': 'application/json' } },
      ),
    ),
  )
}

function renderAssetPage(stewardId = 'stw-001') {
  return render(
    <MemoryRouter initialEntries={[`/stewards/${encodeURIComponent(stewardId)}`]}>
      <Routes>
        <Route path="/stewards/:id" element={<StewardAssetPage />} />
        <Route path="/" element={<div data-testid="fleet-page">Fleet</div>} />
      </Routes>
    </MemoryRouter>,
  )
}

describe('tab strip', () => {
  it('renders all tabs: DNA, Config, Shell, Logs, Modules, Live Activity', () => {
    fetchMock.mockReturnValue(new Promise(() => {}))
    renderAssetPage()

    const tablist = screen.getByRole('tablist')
    expect(tablist).toBeInTheDocument()
    expect(screen.getByRole('tab', { name: /^DNA/i })).toBeInTheDocument()
    expect(screen.getByRole('tab', { name: /^Config/i })).toBeInTheDocument()
    expect(screen.getByRole('tab', { name: /^Shell/i })).toBeInTheDocument()
    expect(screen.getByRole('tab', { name: /^Logs/i })).toBeInTheDocument()
    expect(screen.getByRole('tab', { name: /^Modules/i })).toBeInTheDocument()
    expect(screen.getByRole('tab', { name: /^Live Activity/i })).toBeInTheDocument()
  })

  it('DNA tab is selected by default', () => {
    fetchMock.mockReturnValue(new Promise(() => {}))
    renderAssetPage()

    const dnaTab = screen.getByRole('tab', { name: /^DNA/i })
    expect(dnaTab).toHaveAttribute('aria-selected', 'true')
    expect(screen.getByRole('tab', { name: /^Config/i })).toHaveAttribute(
      'aria-selected',
      'false',
    )
  })

  it('Config tab carries the soon badge text; Shell no longer does', () => {
    fetchMock.mockReturnValue(new Promise(() => {}))
    renderAssetPage()

    // Only Config remains soon; Shell was promoted in Story #2762.
    for (const tab of TABS.filter((t) => t.soon)) {
      const tabEl = screen.getByRole('tab', { name: (n) => n.startsWith(tab.label) })
      expect(within(tabEl).getByText(/soon/i)).toBeInTheDocument()
    }
    // Shell tab must have no soon badge.
    const shellTab = screen.getByRole('tab', { name: /^Shell/i })
    expect(within(shellTab).queryByText(/soon/i)).not.toBeInTheDocument()
  })

  it('clicking an inert tab switches selection and shows a coming-soon placeholder', () => {
    fetchMock.mockReturnValue(new Promise(() => {}))
    renderAssetPage()

    fireEvent.click(screen.getByRole('tab', { name: /^Config/i }))

    expect(screen.getByRole('tab', { name: /^Config/i })).toHaveAttribute(
      'aria-selected',
      'true',
    )
    expect(screen.getByRole('tab', { name: /^DNA/i })).toHaveAttribute(
      'aria-selected',
      'false',
    )
    expect(screen.getByRole('tabpanel').textContent).toContain('Config')
  })

  it('clicking Shell mounts ShellTab (not a SoonPanel)', () => {
    fetchMock.mockReturnValue(new Promise(() => {}))
    renderAssetPage()

    fireEvent.click(screen.getByRole('tab', { name: /^Shell/i }))

    expect(screen.getByTestId('shell-tab')).toBeInTheDocument()
    expect(screen.queryByText(/Shell is not yet available/i)).not.toBeInTheDocument()
  })

  it('Shell tab has no soon badge', () => {
    fetchMock.mockReturnValue(new Promise(() => {}))
    renderAssetPage()

    const shellTab = screen.getByRole('tab', { name: /^Shell/i })
    expect(within(shellTab).queryByText(/soon/i)).not.toBeInTheDocument()
  })

  it('clicking Logs tab mounts LogsPanel (shows loading state, not a SoonPanel)', () => {
    fetchMock.mockReturnValue(new Promise(() => {}))
    renderAssetPage()

    fireEvent.click(screen.getByRole('tab', { name: /^Logs/i }))

    expect(screen.getByTestId('logs-loading')).toBeInTheDocument()
    expect(screen.queryByText(/Logs is not yet available/i)).not.toBeInTheDocument()
  })

  it('Logs tab has no soon badge', () => {
    fetchMock.mockReturnValue(new Promise(() => {}))
    renderAssetPage()

    const logsTab = screen.getByRole('tab', { name: /^Logs/i })
    expect(within(logsTab).queryByText(/soon/i)).not.toBeInTheDocument()
  })

  it('clicking Modules tab mounts ModulesPanel (shows loading state, not a SoonPanel)', () => {
    fetchMock.mockReturnValue(new Promise(() => {}))
    renderAssetPage()

    fireEvent.click(screen.getByRole('tab', { name: /^Modules/i }))

    expect(screen.getByTestId('modules-loading')).toBeInTheDocument()
    expect(screen.queryByText(/Modules is not yet available/i)).not.toBeInTheDocument()
  })

  it('Modules tab has no soon badge', () => {
    fetchMock.mockReturnValue(new Promise(() => {}))
    renderAssetPage()

    const modulesTab = screen.getByRole('tab', { name: /^Modules/i })
    expect(within(modulesTab).queryByText(/soon/i)).not.toBeInTheDocument()
  })

  it('clicking Live Activity mounts LiveActivityTab (not a SoonPanel)', () => {
    fetchMock.mockReturnValue(new Promise(() => {}))
    renderAssetPage()

    fireEvent.click(screen.getByRole('tab', { name: /^Live Activity/i }))

    // LiveActivityTab renders a loading indicator, not the "soon" placeholder.
    expect(screen.getByTestId('live-loading')).toBeInTheDocument()
    expect(screen.queryByText(/Live Activity is not yet available/i)).not.toBeInTheDocument()
  })

  it('Live Activity tab has no soon badge', () => {
    fetchMock.mockReturnValue(new Promise(() => {}))
    renderAssetPage()

    const liveTab = screen.getByRole('tab', { name: /^Live Activity/i })
    expect(within(liveTab).queryByText(/soon/i)).not.toBeInTheDocument()
  })

  it('clicking back to DNA after an inert tab restores DNA content', async () => {
    mockDNA({ primary_ip: '10.20.30.40' })
    renderAssetPage()

    fireEvent.click(screen.getByRole('tab', { name: /^Config/i }))
    fireEvent.click(screen.getByRole('tab', { name: /^DNA/i }))

    expect(screen.getByRole('tab', { name: /^DNA/i })).toHaveAttribute(
      'aria-selected',
      'true',
    )
    expect(await screen.findByText('10.20.30.40')).toBeInTheDocument()
  })

  it('ArrowRight cycles through tabs in order', () => {
    fetchMock.mockReturnValue(new Promise(() => {}))
    renderAssetPage()

    const tablist = screen.getByRole('tablist')
    fireEvent.keyDown(tablist, { key: 'ArrowRight' })
    expect(screen.getByRole('tab', { name: /^Config/i })).toHaveAttribute(
      'aria-selected',
      'true',
    )

    fireEvent.keyDown(tablist, { key: 'ArrowRight' })
    expect(screen.getByRole('tab', { name: /^Shell/i })).toHaveAttribute(
      'aria-selected',
      'true',
    )
  })

  it('ArrowLeft wraps from DNA back to Compliance (last tab)', () => {
    fetchMock.mockReturnValue(new Promise(() => {}))
    renderAssetPage()

    const tablist = screen.getByRole('tablist')
    fireEvent.keyDown(tablist, { key: 'ArrowLeft' })
    expect(screen.getByRole('tab', { name: /^Compliance/i })).toHaveAttribute(
      'aria-selected',
      'true',
    )
  })
})

describe('DNA tab content parity', () => {
  it('fetches the steward DNA endpoint for the route :id and renders grouped attributes', async () => {
    mockDNA({
      primary_ip: '192.168.1.1',
      tenant: 'root/msp-a',
      current_user: 'admin',
    })
    renderAssetPage('stw-42')

    expect(await screen.findByText('192.168.1.1')).toBeInTheDocument()
    expect(screen.getByText('Network')).toBeInTheDocument()
    expect(screen.getByText('IP address')).toBeInTheDocument()
    expect(screen.getByText('Identity')).toBeInTheDocument()
    expect(screen.getByText('root/msp-a')).toBeInTheDocument()

    const url = String(fetchMock.mock.calls[0]?.[0])
    expect(url).toBe('/api/v1/stewards/stw-42/dna')
  })

  it('renders the top-level DNA fields (hostname, OS) in their designed groups', async () => {
    mockDNA({})
    renderAssetPage()

    expect(await screen.findByText('asset-test-host')).toBeInTheDocument()
    expect(screen.getByText('Ubuntu 24.04')).toBeInTheDocument()
  })

  it('shows a loading skeleton before the DNA response arrives', () => {
    fetchMock.mockReturnValue(new Promise(() => {}))
    renderAssetPage()

    expect(screen.getByTestId('dna-loading')).toBeInTheDocument()
  })

  it('shows the DNA error state on a failed fetch', async () => {
    fetchMock.mockResolvedValue(
      new Response('{}', { status: 500 }),
    )
    renderAssetPage()

    const alert = await screen.findByRole('alert')
    expect(alert.textContent).toContain('500')
  })

  it('encodes special characters in the steward ID in the DNA fetch URL', async () => {
    mockDNA({})
    renderAssetPage('stw/special id')

    await screen.findByText('Ubuntu 24.04')
    const url = String(fetchMock.mock.calls[0]?.[0])
    expect(url).toBe('/api/v1/stewards/stw%2Fspecial%20id/dna')
  })
})

describe('navigation', () => {
  it('renders a Fleet breadcrumb link that navigates back to /', () => {
    fetchMock.mockReturnValue(new Promise(() => {}))
    renderAssetPage()

    const link = screen.getByRole('link', { name: /fleet/i })
    expect(link).toBeInTheDocument()
    expect(link).toHaveAttribute('href', '/')
  })

  it('displays the decoded steward ID in the breadcrumb', () => {
    fetchMock.mockReturnValue(new Promise(() => {}))
    renderAssetPage('stw-99')

    expect(screen.getByText('stw-99')).toBeInTheDocument()
  })
})

describe('panel resolution', () => {
  it('renders each tab\'s own Panel when two entries each carry a distinct Panel', () => {
    function AlphaPanel() {
      return <div data-testid="alpha-panel">Alpha</div>
    }
    function BetaPanel() {
      return <div data-testid="beta-panel">Beta</div>
    }

    const { rerender } = render(
      <PanelContent spec={{ key: 'dna', label: 'Alpha', soon: false, Panel: AlphaPanel }} />,
    )
    expect(screen.getByTestId('alpha-panel')).toBeInTheDocument()
    expect(screen.queryByTestId('beta-panel')).not.toBeInTheDocument()

    rerender(
      <PanelContent spec={{ key: 'config', label: 'Beta', soon: false, Panel: BetaPanel }} />,
    )
    expect(screen.getByTestId('beta-panel')).toBeInTheDocument()
    expect(screen.queryByTestId('alpha-panel')).not.toBeInTheDocument()
  })

  it('falls back to SoonPanel when no Panel is set', () => {
    render(
      <PanelContent spec={{ key: 'shell', label: 'Shell', soon: true }} />,
    )
    expect(screen.getByText(/Shell is not yet available/i)).toBeInTheDocument()
  })
})

describe('"soon" badge separation (Story #2917)', () => {
  it('renders the "soon" badge as its own <span> element, not concatenated with the label', () => {
    fetchMock.mockReturnValue(new Promise(() => {}))
    renderAssetPage()

    for (const tab of TABS.filter((t) => t.soon)) {
      const tabEl = screen.getByRole('tab', { name: (n) => n.startsWith(tab.label) })
      const badge = within(tabEl).getByText(/^soon$/i)
      // The badge must be its own element, not the same text node as the label.
      expect(badge.tagName).toBe('SPAN')
      // The tab element's textContent concatenates label + badge, but they
      // must be SEPARATE nodes: the label text node and the badge element.
      const labelNode = [...tabEl.childNodes].find(
        (n) => n.nodeType === Node.TEXT_NODE && n.textContent?.trim() === tab.label,
      )
      expect(labelNode).toBeTruthy()
    }
  })

  it('the "soon" badge element has CSS margin-left so it is visually separated', () => {
    fetchMock.mockReturnValue(new Promise(() => {}))
    renderAssetPage()

    for (const tab of TABS.filter((t) => t.soon)) {
      const tabEl = screen.getByRole('tab', { name: (n) => n.startsWith(tab.label) })
      const badge = within(tabEl).getByText(/^soon$/i)
      // The badge carries the .tag class that AppShell.css styles with margin-left.
      expect(badge).toHaveClass('tag')
    }
  })
})

describe('direct load / deep-link (Story #2917)', () => {
  it('mounting at /stewards/:id directly renders the full StewardAssetPage layout', () => {
    fetchMock.mockReturnValue(new Promise(() => {}))
    renderAssetPage('stw-direct')

    // Full page has breadcrumb, h1, and tab strip — not a drawer.
    expect(screen.getByRole('link', { name: /fleet/i })).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: /device/i })).toBeInTheDocument()
    expect(screen.getByRole('tablist')).toBeInTheDocument()
    // There is no drawer close button or scrim in the full-page rendering.
    expect(screen.queryByTestId('steward-drawer')).not.toBeInTheDocument()
    expect(screen.queryByTestId('drawer-close')).not.toBeInTheDocument()
  })

  it('the breadcrumb shows the decoded steward ID even for encoded IDs', () => {
    fetchMock.mockReturnValue(new Promise(() => {}))
    renderAssetPage('stw/encoded')

    // React Router decodes the path param — the page should show the decoded ID.
    expect(screen.getByText('stw/encoded')).toBeInTheDocument()
  })
})
