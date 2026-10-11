// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { act, fireEvent, render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router'
import ElevationBanner from './ElevationBanner.tsx'
import { parseActiveCrossingList } from '../tenants/useTenantCrossings.ts'

const fetchMock = vi.fn<typeof fetch>()
const NOW = new Date('2030-01-01T00:00:00Z').getTime()

function crossings(items: Record<string, unknown>[]) {
  return parseActiveCrossingList(
    items.map((i) => ({
      id: 'c-1',
      tenant_id: 'msp-a',
      kind: 'break_glass',
      principal_name: 'root-op',
      reason_category: 'account_recovery',
      expires_at: new Date(NOW + 90_000).toISOString(),
      tenant_name: 'MSP A',
      ...i,
    })),
  )
}

function renderBanner(items: Record<string, unknown>[], root: boolean, onChanged = vi.fn()) {
  render(
    <MemoryRouter>
      <ElevationBanner crossings={crossings(items)} root={root} onChanged={onChanged} />
    </MemoryRouter>,
  )
  return onChanged
}

beforeEach(() => {
  vi.useFakeTimers({ toFake: ['setInterval', 'clearInterval', 'Date'] })
  vi.setSystemTime(NOW)
  vi.stubGlobal('fetch', fetchMock)
  fetchMock.mockReset()
})
afterEach(() => {
  vi.useRealTimers()
  vi.unstubAllGlobals()
})

describe('ElevationBanner — root operator', () => {
  it('shows tenant, reason category and a countdown that decreases', () => {
    renderBanner([{}], true)
    expect(screen.getByTestId('elevation-tenant')).toHaveTextContent('MSP A')
    expect(screen.getByTestId('elevation-reason')).toHaveTextContent('Account recovery')
    expect(screen.getByTestId('elevation-countdown')).toHaveTextContent('01:30')
    act(() => {
      vi.advanceTimersByTime(10_000)
    })
    expect(screen.getByTestId('elevation-countdown')).toHaveTextContent('01:20')
  })

  it('renders nothing for an empty feed', () => {
    renderBanner([], true)
    expect(screen.queryByTestId('elevation-banner')).not.toBeInTheDocument()
  })

  it('names no tenant when tenant_name is empty', () => {
    renderBanner([{ tenant_name: '' }], true)
    expect(screen.getByTestId('elevation-banner')).toBeInTheDocument()
    expect(screen.queryByTestId('elevation-tenant')).not.toBeInTheDocument()
    expect(screen.getByTestId('elevation-banner')).not.toHaveTextContent('msp-a')
  })

  it('End revokes through the endpoint then asks for a feed refresh', async () => {
    fetchMock.mockResolvedValue(new Response('{}', { status: 200 }))
    const onChanged = renderBanner([{}], true)
    await act(async () => {
      fireEvent.click(screen.getByTestId('elevation-end-btn'))
    })
    const [url, init] = fetchMock.mock.calls[0]!
    expect(String(url)).toContain('/api/v1/tenants/msp-a/access-grants/c-1')
    expect(init?.method).toBe('DELETE')
    expect(onChanged).toHaveBeenCalledTimes(1)
  })

  it('a refusal shows inline and keeps the banner', async () => {
    fetchMock.mockResolvedValue(
      new Response(JSON.stringify({ error: { code: 'FORBIDDEN', message: 'not allowed' } }), { status: 403 }),
    )
    const onChanged = renderBanner([{}], true)
    await act(async () => {
      fireEvent.click(screen.getByTestId('elevation-end-btn'))
    })
    expect(screen.getByTestId('elevation-error')).toHaveTextContent('not allowed')
    expect(screen.getByTestId('elevation-banner')).toBeInTheDocument()
    expect(onChanged).not.toHaveBeenCalled()
  })

  it('lists several crossings compactly', () => {
    renderBanner([{ id: 'a' }, { id: 'b' }], true)
    expect(screen.getAllByTestId('elevation-row')).toHaveLength(2)
    expect(screen.getByTestId('elevation-banner')).toHaveClass('compact')
  })
})

describe('ElevationBanner — MSP administrator', () => {
  it('shows MSP wording, the principal name and a Support access link for a break-glass', () => {
    renderBanner([{}], false)
    const banner = screen.getByTestId('elevation-banner')
    expect(banner).toHaveTextContent('CFGMS support access active')
    expect(screen.getByTestId('elevation-holder')).toHaveTextContent('root-op')
    expect(screen.getByTestId('elevation-reason')).toHaveTextContent('Account recovery')
    expect(screen.getByRole('link', { name: 'Support access' })).toHaveAttribute('href', '/support-access')
    expect(screen.queryByTestId('elevation-end-btn')).not.toBeInTheDocument()
  })

  it('shows "All root support" for a grant, with no reason category', () => {
    renderBanner([{ kind: 'grant', principal_name: '', reason_category: '' }], false)
    expect(screen.getByTestId('elevation-holder')).toHaveTextContent('All root support')
    expect(screen.queryByTestId('elevation-reason')).not.toBeInTheDocument()
  })

  it('renders principal and tenant names containing markup literally', () => {
    renderBanner([{ principal_name: '<img src=x onerror=alert(1)>', tenant_name: '<b>evil</b>' }], false)
    expect(screen.getByTestId('elevation-holder')).toHaveTextContent('<img src=x onerror=alert(1)>')
    expect(screen.getByTestId('elevation-tenant')).toHaveTextContent('<b>evil</b>')
    expect(screen.getByTestId('elevation-banner').querySelector('img')).toBeNull()
    expect(screen.getByTestId('elevation-banner').querySelector('b + b')).toBeNull()
  })
})
