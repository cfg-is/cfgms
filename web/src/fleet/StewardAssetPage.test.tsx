// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * StewardAssetPage suite (Story #2723): tab switching, inert-placeholder
 * rendering for Config/Shell/Live Activity, and DNA-tab content parity
 * with the pre-router DnaDrawer behavior.
 *
 * The component reads :id from the route param; tests use MemoryRouter to
 * provide the steward ID without a real browser.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, within } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import StewardAssetPage from './StewardAssetPage.tsx'

const fetchMock = vi.fn<typeof fetch>()

beforeEach(() => {
  fetchMock.mockReset()
  vi.stubGlobal('fetch', fetchMock)
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
  it('renders all four tabs: DNA, Config, Shell, Live Activity', () => {
    fetchMock.mockReturnValue(new Promise(() => {}))
    renderAssetPage()

    const tablist = screen.getByRole('tablist')
    expect(tablist).toBeInTheDocument()
    expect(screen.getByRole('tab', { name: /^DNA/i })).toBeInTheDocument()
    expect(screen.getByRole('tab', { name: /^Config/i })).toBeInTheDocument()
    expect(screen.getByRole('tab', { name: /^Shell/i })).toBeInTheDocument()
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

  it('inert tabs (Config, Shell, Live Activity) carry the soon badge text', () => {
    fetchMock.mockReturnValue(new Promise(() => {}))
    renderAssetPage()

    for (const name of [/^Config/i, /^Shell/i, /^Live Activity/i]) {
      const tab = screen.getByRole('tab', { name })
      expect(within(tab).getByText(/soon/i)).toBeInTheDocument()
    }
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

  it('clicking Shell shows a coming-soon placeholder', () => {
    fetchMock.mockReturnValue(new Promise(() => {}))
    renderAssetPage()

    fireEvent.click(screen.getByRole('tab', { name: /^Shell/i }))
    expect(screen.getByRole('tabpanel').textContent).toContain('Shell')
  })

  it('clicking Live Activity shows a coming-soon placeholder', () => {
    fetchMock.mockReturnValue(new Promise(() => {}))
    renderAssetPage()

    fireEvent.click(screen.getByRole('tab', { name: /^Live Activity/i }))
    expect(screen.getByRole('tabpanel').textContent).toContain('Live Activity')
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

  it('ArrowLeft wraps from DNA back to Live Activity', () => {
    fetchMock.mockReturnValue(new Promise(() => {}))
    renderAssetPage()

    const tablist = screen.getByRole('tablist')
    fireEvent.keyDown(tablist, { key: 'ArrowLeft' })
    expect(screen.getByRole('tab', { name: /^Live Activity/i })).toHaveAttribute(
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
