// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * Asset-DNA content suite (Story #2498, #2723): fetch/render of grouped
 * attributes, the "Other attributes" overflow group, loading and error
 * states (incl. 404-redaction tolerance — the endpoint 404s cross-tenant
 * and for denylisted attributes), and the hostile-DNA guarantees: attribute
 * KEYS and VALUES render as escaped text only, and group headings come from
 * the fixed client-side allowlist, never from data (security A10.1).
 *
 * DnaDrawer is now route-driven — rendered at /stewards/:id; test wrapper
 * uses MemoryRouter to provide the :id param.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router'
import DnaDrawer, { DNA_GROUP_HEADINGS, parseDNAInfo } from './DnaDrawer.tsx'

const fetchMock = vi.fn<typeof fetch>()

beforeEach(() => {
  fetchMock.mockReset()
  vi.stubGlobal('fetch', fetchMock)
})

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

function mockDNA(attributes: Record<string, string>, extra: Record<string, unknown> = {}) {
  fetchMock.mockResolvedValue(
    new Response(
      JSON.stringify({
        data: {
          hostname: 'web-ingest-04',
          os: 'Ubuntu 24.04',
          architecture: 'amd64',
          config_hash: 'abc123',
          collected_at: '2026-07-14T10:00:00Z',
          attributes,
          ...extra,
        },
        timestamp: new Date().toISOString(),
      }),
      { status: 200, headers: { 'Content-Type': 'application/json' } },
    ),
  )
}

/**
 * Renders DnaDrawer within a MemoryRouter that provides /stewards/:id.
 * The steward ID is URL-encoded in the initial path so that IDs containing
 * special characters (including /) are correctly matched by the route.
 */
function renderDrawer(stewardId = 'stw-001') {
  return render(
    <MemoryRouter initialEntries={[`/stewards/${encodeURIComponent(stewardId)}`]}>
      <Routes>
        <Route path="/stewards/:id" element={<DnaDrawer />} />
        <Route path="/" element={<div data-testid="fleet-page">Fleet</div>} />
      </Routes>
    </MemoryRouter>,
  )
}

describe('parseDNAInfo (untrusted wire data)', () => {
  it('rejects non-object payloads', () => {
    expect(() => parseDNAInfo(null)).toThrow()
    expect(() => parseDNAInfo('str')).toThrow()
    expect(() => parseDNAInfo(42)).toThrow()
  })

  it('drops non-string attribute values and tolerates a missing attribute map', () => {
    const parsed = parseDNAInfo({
      hostname: 'h',
      attributes: { good: 'v', bad: 7, worse: { nested: true } },
    })
    expect(parsed.attributes).toEqual({ good: 'v' })
    expect(parseDNAInfo({ hostname: 'h' }).attributes).toEqual({})
  })

  it('coerces missing top-level fields to empty strings', () => {
    const parsed = parseDNAInfo({})
    expect(parsed.hostname).toBe('')
    expect(parsed.os).toBe('')
    expect(parsed.collectedAt).toBe('')
  })
})

describe('DNA fetch and grouped rendering', () => {
  it('fetches the steward DNA endpoint and renders known attributes in their designed groups', async () => {
    mockDNA({
      primary_ip: '10.20.4.14',
      tenant: 'root/acme-corp',
      current_user: 'svc_deploy',
    })
    renderDrawer()

    expect(await screen.findByText('10.20.4.14')).toBeTruthy()
    const url = String(fetchMock.mock.calls[0]?.[0])
    expect(url).toBe('/api/v1/stewards/stw-001/dna')

    // Known attributes appear under their fixed group headings.
    expect(screen.getByText('Network')).toBeTruthy()
    expect(screen.getByText('IP address')).toBeTruthy()
    expect(screen.getByText('Identity')).toBeTruthy()
    expect(screen.getByText('root/acme-corp')).toBeTruthy()
    expect(screen.getByText('Session & agent')).toBeTruthy()
    expect(screen.getByText('svc_deploy')).toBeTruthy()
  })

  it('encodes the steward ID in the fetch URL', async () => {
    mockDNA({})
    renderDrawer('stw/special chars')
    await screen.findByText('Ubuntu 24.04')
    const url = String(fetchMock.mock.calls[0]?.[0])
    expect(url).toBe('/api/v1/stewards/stw%2Fspecial%20chars/dna')
  })

  it('lists unrecognized attributes under the Other attributes group', async () => {
    mockDNA({ some_novel_key: 'novel-value' })
    renderDrawer()

    expect(await screen.findByText('Other attributes')).toBeTruthy()
    expect(screen.getByText('some_novel_key')).toBeTruthy()
    expect(screen.getByText('novel-value')).toBeTruthy()
  })

  it('shows a loading state before the response arrives', () => {
    fetchMock.mockReturnValue(new Promise(() => {}))
    renderDrawer()
    expect(screen.getByTestId('dna-loading')).toBeTruthy()
  })

  it('tolerates a redacted/empty attribute set — top-level fields still render, never a blank panel', async () => {
    mockDNA({})
    renderDrawer()
    expect(await screen.findByText('Ubuntu 24.04')).toBeTruthy()
    expect(screen.getByText('web-ingest-04', { selector: '.v' })).toBeTruthy()
    expect(screen.queryByText('Other attributes')).toBeNull()
  })
})

describe('DNA error states', () => {
  it('renders the error state on 404 (cross-tenant / DNA not found), never a blank panel', async () => {
    fetchMock.mockResolvedValue(
      new Response(JSON.stringify({ error: 'DNA not found', code: 'DNA_NOT_FOUND' }), {
        status: 404,
      }),
    )
    renderDrawer()
    const alert = await screen.findByRole('alert')
    expect(alert.textContent).toContain('404')
  })

  it('renders the error state on network failure and retry refetches', async () => {
    fetchMock.mockRejectedValueOnce(new Error('network down'))
    mockDNA({ primary_ip: '10.0.0.1' })
    renderDrawer()

    await screen.findByRole('alert')
    fireEvent.click(screen.getByRole('button', { name: /retry/i }))
    expect(await screen.findByText('10.0.0.1')).toBeTruthy()
    expect(fetchMock).toHaveBeenCalledTimes(2)
  })
})

describe('hostile DNA rendering (security A10.1)', () => {
  const hostileKey = '<img src=x onerror="window.__pwned_key=1">'
  const hostileValue = '<script>window.__pwned_val=1</script><b>bold</b>'

  it('renders hostile attribute KEYS and VALUES as escaped text in Other attributes', async () => {
    mockDNA({ [hostileKey]: hostileValue })
    const { container } = renderDrawer()

    expect(await screen.findByText('Other attributes')).toBeTruthy()
    // The hostile strings are present as literal TEXT...
    expect(screen.getByText(hostileKey)).toBeTruthy()
    expect(screen.getByText(hostileValue)).toBeTruthy()
    // ...and never became live markup.
    expect(container.querySelector('img')).toBeNull()
    expect(container.querySelector('script')).toBeNull()
    expect(container.querySelector('b')).toBeNull()
    expect(
      (window as unknown as Record<string, unknown>).__pwned_key,
    ).toBeUndefined()
    expect(
      (window as unknown as Record<string, unknown>).__pwned_val,
    ).toBeUndefined()
  })

  it('group headings come only from the fixed client-side allowlist, never from data', async () => {
    mockDNA({
      'Injected heading': 'x',
      '<h1>evil</h1>': 'y',
      primary_ip: '10.0.0.1',
    })
    const { container } = renderDrawer()
    await screen.findByText('Other attributes')

    const headings = [...container.querySelectorAll('.grp .lbl')].map(
      (el) => el.textContent,
    )
    expect(headings.length).toBeGreaterThan(0)
    for (const heading of headings) {
      expect(DNA_GROUP_HEADINGS).toContain(heading)
    }
  })
})
