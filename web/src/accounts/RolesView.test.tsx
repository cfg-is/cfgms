// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * RolesView test suite (Issue #2733): role list rendering, data states,
 * and permission expansion on row click.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { AuthProvider } from '../auth/AuthContext.tsx'
import RolesView from './RolesView.tsx'

const fetchMock = vi.fn<typeof fetch>()

beforeEach(() => {
  vi.stubGlobal('fetch', fetchMock)
  fetchMock.mockReset()
})

afterEach(() => {
  vi.unstubAllGlobals()
  cleanup()
})

function makeRolesResponse(roles: object[], status = 200) {
  return new Response(
    JSON.stringify({ data: roles }),
    { status, headers: { 'Content-Type': 'application/json' } },
  )
}

function makeRole(overrides: Partial<Record<string, unknown>> = {}) {
  return {
    id: 'role-1',
    name: 'fleet-viewer',
    description: 'Read-only fleet access',
    permissions: ['steward:list', 'steward:read'],
    tenant_id: 'tenant-a',
    created_at: '2026-01-01T00:00:00Z',
    updated_at: '2026-02-01T00:00:00Z',
    ...overrides,
  }
}

function renderRolesView() {
  return render(
    <MemoryRouter>
      <AuthProvider>
        <RolesView />
      </AuthProvider>
    </MemoryRouter>,
  )
}

describe('RolesView — loading state', () => {
  it('shows loading state while fetching', () => {
    fetchMock.mockReturnValue(new Promise(() => {}))
    renderRolesView()
    expect(screen.getByTestId('roles-loading')).toBeInTheDocument()
  })
})

describe('RolesView — empty state', () => {
  it('shows empty state when no roles returned', async () => {
    fetchMock.mockResolvedValue(makeRolesResponse([]))
    renderRolesView()
    await waitFor(() => {
      expect(screen.getByTestId('roles-empty')).toBeInTheDocument()
    })
  })
})

describe('RolesView — roles list', () => {
  it('renders role rows in a table', async () => {
    fetchMock.mockResolvedValue(
      makeRolesResponse([
        makeRole({ name: 'fleet-viewer' }),
        makeRole({ id: 'role-2', name: 'config-manager' }),
      ]),
    )
    renderRolesView()
    await waitFor(() => {
      expect(screen.getByTestId('roles-table')).toBeInTheDocument()
    })
    expect(screen.getAllByTestId('role-row')).toHaveLength(2)
    expect(screen.getByText('fleet-viewer')).toBeInTheDocument()
    expect(screen.getByText('config-manager')).toBeInTheDocument()
  })

  it('shows role count', async () => {
    fetchMock.mockResolvedValue(makeRolesResponse([makeRole()]))
    renderRolesView()
    await waitFor(() => {
      expect(screen.getByTestId('role-count')).toHaveTextContent('1 role')
    })
  })

  it('shows plural for multiple roles', async () => {
    fetchMock.mockResolvedValue(
      makeRolesResponse([makeRole(), makeRole({ id: 'role-2', name: 'role-b' })]),
    )
    renderRolesView()
    await waitFor(() => {
      expect(screen.getByTestId('role-count')).toHaveTextContent('2 roles')
    })
  })

  it('shows error state on fetch failure', async () => {
    fetchMock.mockResolvedValue(makeRolesResponse([], 500))
    renderRolesView()
    await waitFor(() => {
      expect(screen.getByRole('alert')).toBeInTheDocument()
      expect(screen.getByText(/couldn't load roles/i)).toBeInTheDocument()
    })
  })
})

describe('RolesView — role permission expansion', () => {
  it('expands permissions when a row is clicked', async () => {
    fetchMock.mockResolvedValue(
      makeRolesResponse([makeRole({ permissions: ['steward:list', 'steward:read'] })]),
    )
    renderRolesView()
    await waitFor(() => expect(screen.getByTestId('roles-table')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId('role-row'))
    expect(screen.getByTestId('role-permissions-row')).toBeInTheDocument()
    expect(screen.getByText('steward:list')).toBeInTheDocument()
    expect(screen.getByText('steward:read')).toBeInTheDocument()
  })

  it('collapses permissions when the same row is clicked again', async () => {
    fetchMock.mockResolvedValue(makeRolesResponse([makeRole()]))
    renderRolesView()
    await waitFor(() => expect(screen.getByTestId('roles-table')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId('role-row'))
    expect(screen.getByTestId('role-permissions-row')).toBeInTheDocument()
    fireEvent.click(screen.getByTestId('role-row'))
    expect(screen.queryByTestId('role-permissions-row')).not.toBeInTheDocument()
  })

  it('shows None when a role has no permissions', async () => {
    fetchMock.mockResolvedValue(makeRolesResponse([makeRole({ permissions: [] })]))
    renderRolesView()
    await waitFor(() => expect(screen.getByTestId('roles-table')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId('role-row'))
    expect(screen.getByText('None')).toBeInTheDocument()
  })
})
