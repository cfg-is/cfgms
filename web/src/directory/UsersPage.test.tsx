// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import UsersPage from './UsersPage.tsx'

const fetchMock = vi.fn<typeof fetch>()

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify({ data, timestamp: 't' }), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

const user = (over: Record<string, unknown> = {}) => ({
  source: 'ad',
  kind: 'user',
  id: 'u1',
  authority: 'corp.example',
  display_name: 'Ann Lee',
  sam_account_name: 'alee',
  enabled: true,
  managed: true,
  last_observed: '2026-10-01T12:30:00Z',
  stale: false,
  ...over,
})

beforeEach(() => {
  vi.stubGlobal('fetch', fetchMock)
  fetchMock.mockReset()
})
afterEach(() => vi.unstubAllGlobals())

describe('UsersPage', () => {
  it('renders a hostile display name as literal text', async () => {
    fetchMock.mockResolvedValue(json({ items: [user({ display_name: '<img src=x onerror=alert(1)>' })] }))
    const { container } = render(<UsersPage />)
    expect(await screen.findByText('<img src=x onerror=alert(1)>')).toBeTruthy()
    expect(container.querySelector('img')).toBeNull()
  })

  it('renders the ready state with managed, enabled and stale indicators', async () => {
    fetchMock.mockResolvedValue(
      json({ items: [user(), user({ id: 'u2', display_name: 'Old Bob', managed: false, stale: true, enabled: false })] }),
    )
    render(<UsersPage />)
    expect(await screen.findByText('Ann Lee')).toBeTruthy()
    expect(screen.getAllByText('alee').length).toBe(2)
    expect(screen.getAllByText('Managed').length).toBeGreaterThan(0)
    expect(screen.getAllByText('Unmanaged').length).toBe(2)
    expect(screen.getByText('Disabled')).toBeTruthy()
    expect(screen.getAllByTestId('stale-marker')).toHaveLength(1)
    expect(screen.getAllByText('2026-10-01 12:30Z')).toHaveLength(2)
  })

  it('renders the loading state while the request is pending', () => {
    fetchMock.mockReturnValue(new Promise(() => {}))
    render(<UsersPage />)
    expect(screen.getByTestId('fleet-loading')).toBeTruthy()
  })

  it('renders the error state and retries', async () => {
    fetchMock.mockResolvedValueOnce(json({}, 503))
    render(<UsersPage />)
    expect(await screen.findByRole('alert')).toBeTruthy()
    expect(screen.getByText(/503/)).toBeTruthy()
    fetchMock.mockResolvedValueOnce(json({ items: [user()] }))
    fireEvent.click(screen.getByRole('button', { name: 'Retry' }))
    expect(await screen.findByText('Ann Lee')).toBeTruthy()
  })

  it('renders the empty state', async () => {
    fetchMock.mockResolvedValue(json({ items: [] }))
    render(<UsersPage />)
    expect(await screen.findByTestId('directory-empty')).toBeTruthy()
  })

  it('renders the neutral state on 404', async () => {
    fetchMock.mockResolvedValue(json({}, 404))
    render(<UsersPage />)
    expect(await screen.findByTestId('directory-not-available')).toBeTruthy()
    expect(screen.queryByRole('alert')).toBeNull()
  })

  it('sends filters and pages with page_token', async () => {
    fetchMock.mockImplementation((input) => {
      const url = new URL(String(input), 'https://x')
      return Promise.resolve(
        url.searchParams.get('page_token') === 'next1'
          ? json({ items: [user({ id: 'u9', display_name: 'Page Two' })] })
          : json({ items: [user()], next_page_token: 'next1' }),
      )
    })
    render(<UsersPage />)
    await screen.findByText('Ann Lee')
    fireEvent.click(screen.getByRole('button', { name: 'Next page' }))
    expect(await screen.findByText('Page Two')).toBeTruthy()
    fireEvent.click(screen.getByRole('button', { name: 'Previous page' }))
    expect(await screen.findByText('Ann Lee')).toBeTruthy()

    fireEvent.change(screen.getByLabelText('Source'), { target: { value: 'm365' } })
    fireEvent.change(screen.getByLabelText('Managed'), { target: { value: 'true' } })
    fireEvent.change(screen.getByLabelText('Search users'), { target: { value: 'ann' } })
    await waitFor(() => {
      const last = new URL(String(fetchMock.mock.calls.at(-1)![0]), 'https://x').searchParams
      expect(last.get('q')).toBe('ann')
      expect(last.get('source')).toBe('m365')
      expect(last.get('managed')).toBe('true')
      expect(last.get('page_token')).toBeNull()
    })
  })

  it('opens the drawer with the user groups', async () => {
    fetchMock.mockImplementation((input) =>
      Promise.resolve(
        String(input).includes('/groups')
          ? json({ groups: [{ id: 'g1', display_name: 'Admins' }] })
          : json({ items: [user()] }),
      ),
    )
    render(<UsersPage />)
    fireEvent.click(await screen.findByText('Ann Lee'))
    expect(await screen.findByText('Admins')).toBeTruthy()
    expect(String(fetchMock.mock.calls.at(-1)![0])).toContain('/api/v1/directory/users/ad/u1/groups')
  })
})
