// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * ModulesPanel suite (Story #2940): fetch and render of steward modules,
 * distinct 501 MODULES_UNAVAILABLE state (separate from generic errors),
 * loading/error/empty states, and untrusted wire data validation.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router'
import ModulesPanel, { parseModulesResponse } from './ModulesPanel.tsx'

const fetchMock = vi.fn<typeof fetch>()

beforeEach(() => {
  fetchMock.mockReset()
  vi.stubGlobal('fetch', fetchMock)
})

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

function renderPanel(stewardId = 'stw-001') {
  return render(
    <MemoryRouter initialEntries={[`/stewards/${encodeURIComponent(stewardId)}`]}>
      <Routes>
        <Route path="/stewards/:id" element={<ModulesPanel />} />
      </Routes>
    </MemoryRouter>,
  )
}

function mockModules(names: string[]) {
  fetchMock.mockResolvedValue(
    new Response(
      JSON.stringify({
        data: { modules: names.map((name) => ({ name })) },
        timestamp: new Date().toISOString(),
      }),
      { status: 200, headers: { 'Content-Type': 'application/json' } },
    ),
  )
}

function mockUnavailable() {
  fetchMock.mockResolvedValue(
    new Response(
      JSON.stringify({
        error: {
          code: 'MODULES_UNAVAILABLE',
          message: 'steward does not report loaded modules in DNA; ensure steward version supports module DNA attributes',
        },
        timestamp: new Date().toISOString(),
      }),
      { status: 501 },
    ),
  )
}

function mockError(status: number) {
  fetchMock.mockResolvedValue(
    new Response(
      JSON.stringify({ error: { code: 'INTERNAL_ERROR', message: 'server error' } }),
      { status },
    ),
  )
}

// ---------------------------------------------------------------------------
// parseModulesResponse (untrusted wire data)
// ---------------------------------------------------------------------------

describe('parseModulesResponse (untrusted wire data)', () => {
  it('rejects non-object payloads', () => {
    expect(() => parseModulesResponse(null)).toThrow()
    expect(() => parseModulesResponse('str')).toThrow()
    expect(() => parseModulesResponse(42)).toThrow()
  })

  it('rejects payloads without a modules array', () => {
    expect(() => parseModulesResponse({})).toThrow()
    expect(() => parseModulesResponse({ modules: 'not-array' })).toThrow()
  })

  it('returns an empty array for an empty modules list', () => {
    expect(parseModulesResponse({ modules: [] })).toEqual([])
  })

  it('filters out entries where name is not a non-empty string', () => {
    const result = parseModulesResponse({
      modules: [
        { name: 'file' },
        { name: '' },        // empty string — filtered
        { name: 42 },        // not a string — filtered
        { name: null },      // null — filtered
        { name: 'service' },
      ],
    })
    expect(result).toHaveLength(2)
    expect(result.map((m) => m.name)).toEqual(['file', 'service'])
  })

  it('filters out non-object array entries', () => {
    const result = parseModulesResponse({
      modules: ['bad', null, 42, { name: 'patch' }],
    })
    expect(result).toHaveLength(1)
    expect(result[0]?.name).toBe('patch')
  })
})

// ---------------------------------------------------------------------------
// 501 MODULES_UNAVAILABLE — distinct not-available state
// ---------------------------------------------------------------------------

describe('501 MODULES_UNAVAILABLE state', () => {
  it('renders the not-available state on a 501 response', async () => {
    mockUnavailable()
    renderPanel()

    const unavail = await screen.findByTestId('modules-unavailable')
    expect(unavail).toBeTruthy()
    expect(unavail.textContent?.toLowerCase()).toMatch(/older version|doesn.*t report|not available/i)
  })

  it('501 not-available state is distinct from the generic error alert', async () => {
    mockUnavailable()
    renderPanel()

    await screen.findByTestId('modules-unavailable')
    // The generic error alert (role="alert") must NOT be rendered.
    expect(screen.queryByRole('alert')).toBeNull()
  })

  it('501 not-available state is distinct from the generic error on a 500', async () => {
    mockError(500)
    renderPanel()

    // Generic error uses role="alert" and data-testid="modules-error".
    const alert = await screen.findByRole('alert')
    expect(alert).toBeTruthy()
    // The not-available node must NOT be rendered.
    expect(screen.queryByTestId('modules-unavailable')).toBeNull()
  })
})

// ---------------------------------------------------------------------------
// Fetch and rendering
// ---------------------------------------------------------------------------

describe('ModulesPanel fetch and rendering', () => {
  it('fetches the correct endpoint for the route :id', async () => {
    mockModules(['file', 'service'])
    renderPanel('stw-55')

    await screen.findByText('file')
    const url = String(fetchMock.mock.calls[0]?.[0])
    expect(url).toBe('/api/v1/stewards/stw-55/modules')
  })

  it('encodes special characters in the steward ID', async () => {
    mockModules(['patch'])
    renderPanel('stw/special id')

    await screen.findByText('patch')
    const url = String(fetchMock.mock.calls[0]?.[0])
    expect(url).toBe('/api/v1/stewards/stw%2Fspecial%20id/modules')
  })

  it('renders loaded module names', async () => {
    mockModules(['file', 'service', 'patch', 'cert_trust'])
    renderPanel()

    expect(await screen.findByText('file')).toBeTruthy()
    expect(screen.getByText('service')).toBeTruthy()
    expect(screen.getByText('patch')).toBeTruthy()
    expect(screen.getByText('cert_trust')).toBeTruthy()
  })
})

// ---------------------------------------------------------------------------
// Loading state
// ---------------------------------------------------------------------------

describe('loading state', () => {
  it('shows a loading indicator before the response arrives', () => {
    fetchMock.mockReturnValue(new Promise(() => {}))
    renderPanel()
    expect(screen.getByTestId('modules-loading')).toBeTruthy()
  })

  it('loading state is distinct from error and not-available states', () => {
    fetchMock.mockReturnValue(new Promise(() => {}))
    renderPanel()
    expect(screen.queryByRole('alert')).toBeNull()
    expect(screen.queryByTestId('modules-unavailable')).toBeNull()
    expect(screen.queryByTestId('modules-empty')).toBeNull()
  })
})

// ---------------------------------------------------------------------------
// Empty state
// ---------------------------------------------------------------------------

describe('empty state', () => {
  it('renders a distinct empty state when modules array is empty', async () => {
    mockModules([])
    renderPanel()

    expect(await screen.findByTestId('modules-empty')).toBeTruthy()
    expect(screen.queryByTestId('modules-list')).toBeNull()
    expect(screen.queryByRole('alert')).toBeNull()
    expect(screen.queryByTestId('modules-unavailable')).toBeNull()
  })
})

// ---------------------------------------------------------------------------
// Error state
// ---------------------------------------------------------------------------

describe('error states', () => {
  it('renders a generic error alert on a non-ok non-501 response', async () => {
    mockError(503)
    renderPanel()

    const alert = await screen.findByRole('alert')
    expect(alert.textContent).toContain('503')
    expect(screen.queryByTestId('modules-loading')).toBeNull()
    expect(screen.queryByTestId('modules-unavailable')).toBeNull()
  })

  it('renders an error alert on network failure with a retry button', async () => {
    fetchMock.mockRejectedValueOnce(new Error('network down'))
    mockModules(['file'])
    renderPanel()

    await screen.findByRole('alert')
    fireEvent.click(screen.getByRole('button', { name: /retry/i }))
    expect(await screen.findByText('file')).toBeTruthy()
    expect(fetchMock).toHaveBeenCalledTimes(2)
  })

  it('renders an error alert on malformed response body (wire validation)', async () => {
    fetchMock.mockResolvedValue(
      new Response(
        JSON.stringify({ data: { not_modules: [] } }),
        { status: 200, headers: { 'Content-Type': 'application/json' } },
      ),
    )
    renderPanel()

    const alert = await screen.findByRole('alert')
    expect(alert).toBeTruthy()
    expect(screen.queryByTestId('modules-list')).toBeNull()
  })

  it('shows server-error copy (not connectivity) for a 5xx response', async () => {
    mockError(503)
    renderPanel()

    await screen.findByRole('alert')
    expect(screen.queryByText(/check your connection/i)).toBeNull()
    expect(screen.getByText(/server.*error|returned an error/i)).toBeInTheDocument()
  })

  it('shows connectivity copy for a network-level failure', async () => {
    fetchMock.mockRejectedValue(new Error('network down'))
    renderPanel()

    await screen.findByRole('alert')
    expect(screen.getByText(/check your connection/i)).toBeInTheDocument()
  })
})
