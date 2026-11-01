// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen } from '@testing-library/react'
import GroupsPage from './GroupsPage.tsx'

const fetchMock = vi.fn<typeof fetch>()

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify({ data, timestamp: 't' }), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

beforeEach(() => {
  vi.stubGlobal('fetch', fetchMock)
  fetchMock.mockReset()
})
afterEach(() => vi.unstubAllGlobals())

const group = {
  source: 'm365',
  kind: 'group',
  id: 'g1',
  authority: 'tenant-guid',
  display_name: 'Finance',
  managed: false,
  last_observed: '2026-10-01T00:00:00Z',
  stale: false,
}

describe('GroupsPage', () => {
  it('lists groups without an Enabled column', async () => {
    fetchMock.mockResolvedValue(json({ items: [group] }))
    render(<GroupsPage />)
    expect(await screen.findByText('Finance')).toBeTruthy()
    expect(screen.queryByText('Enabled')).toBeNull()
    expect(String(fetchMock.mock.calls[0]![0])).toContain('/api/v1/directory/groups')
  })

  it('loads drawer members across two pages', async () => {
    fetchMock.mockImplementation((input) => {
      const url = new URL(String(input), 'https://x')
      if (!url.pathname.endsWith('/members')) return Promise.resolve(json({ items: [group] }))
      return Promise.resolve(
        url.searchParams.get('page_token') === 'm2'
          ? json({ members: [{ id: 'u2', type: 'user', display_name: 'Second Member' }] })
          : json({ members: [{ id: 'u1', type: 'user', display_name: 'First Member' }], next_page_token: 'm2' }),
      )
    })
    render(<GroupsPage />)
    fireEvent.click(await screen.findByText('Finance'))
    expect(await screen.findByText('First Member')).toBeTruthy()
    expect(screen.queryByText('Second Member')).toBeNull()
    fireEvent.click(screen.getByRole('button', { name: 'Load more' }))
    expect(await screen.findByText('Second Member')).toBeTruthy()
    expect(screen.getByText('First Member')).toBeTruthy()
    expect(screen.queryByRole('button', { name: 'Load more' })).toBeNull()
  })

  it('shows the empty drawer state for a group with no members', async () => {
    fetchMock.mockImplementation((input) =>
      Promise.resolve(String(input).includes('/members') ? json({ members: [] }) : json({ items: [group] })),
    )
    render(<GroupsPage />)
    fireEvent.click(await screen.findByText('Finance'))
    expect(await screen.findByTestId('drawer-empty')).toBeTruthy()
  })
})
