// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * AccountsView test suite (Issue #2733): list rendering, data states,
 * create panel, delete confirm, and tab switching to roles.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { AuthProvider } from '../auth/AuthContext.tsx'
import AccountsView from './AccountsView.tsx'

const fetchMock = vi.fn<typeof fetch>()

beforeEach(() => {
  vi.stubGlobal('fetch', fetchMock)
  fetchMock.mockReset()
})

afterEach(() => {
  vi.unstubAllGlobals()
  cleanup()
})

function makeAccountsResponse(accounts: object[], status = 200) {
  return new Response(
    JSON.stringify({ data: accounts }),
    { status, headers: { 'Content-Type': 'application/json' } },
  )
}

function makeRolesResponse(roles: object[], status = 200) {
  return new Response(
    JSON.stringify({ data: roles }),
    { status, headers: { 'Content-Type': 'application/json' } },
  )
}

function makeAccount(overrides: Partial<Record<string, unknown>> = {}) {
  return {
    id: 'acc-1',
    username: 'fleet-admin',
    tenant_id: 'tenant-a',
    permissions: ['steward:list'],
    created_at: '2026-01-01T00:00:00Z',
    ...overrides,
  }
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

function renderAccountsView() {
  return render(
    <MemoryRouter>
      <AuthProvider>
        <AccountsView />
      </AuthProvider>
    </MemoryRouter>,
  )
}

describe('AccountsView — heading and page structure', () => {
  it('shows the Accounts heading', () => {
    fetchMock.mockReturnValue(new Promise(() => {}))
    renderAccountsView()
    expect(screen.getByRole('heading', { name: /accounts/i, level: 1 })).toBeInTheDocument()
  })

  it('shows Accounts and Roles tabs', () => {
    fetchMock.mockReturnValue(new Promise(() => {}))
    renderAccountsView()
    expect(screen.getByTestId('tab-accounts')).toBeInTheDocument()
    expect(screen.getByTestId('tab-roles')).toBeInTheDocument()
  })

  it('shows the New account button', () => {
    fetchMock.mockResolvedValue(makeAccountsResponse([]))
    renderAccountsView()
    expect(screen.getByTestId('toggle-create-btn')).toBeInTheDocument()
  })
})

describe('AccountsView — accounts tab', () => {
  it('shows loading state while fetching', () => {
    fetchMock.mockReturnValue(new Promise(() => {}))
    renderAccountsView()
    expect(screen.getByTestId('accounts-loading')).toBeInTheDocument()
  })

  it('shows empty state when no accounts returned', async () => {
    fetchMock.mockResolvedValue(makeAccountsResponse([]))
    renderAccountsView()
    await waitFor(() => {
      expect(screen.getByTestId('accounts-empty')).toBeInTheDocument()
    })
  })

  it('renders account rows in a table', async () => {
    fetchMock.mockResolvedValue(
      makeAccountsResponse([
        makeAccount({ username: 'admin-a' }),
        makeAccount({ id: 'acc-2', username: 'admin-b', tenant_id: 'tenant-b' }),
      ]),
    )
    renderAccountsView()
    await waitFor(() => {
      expect(screen.getByTestId('accounts-table')).toBeInTheDocument()
    })
    expect(screen.getAllByTestId('account-row')).toHaveLength(2)
    expect(screen.getByText('admin-a')).toBeInTheDocument()
    expect(screen.getByText('admin-b')).toBeInTheDocument()
  })

  it('shows account count', async () => {
    fetchMock.mockResolvedValue(makeAccountsResponse([makeAccount()]))
    renderAccountsView()
    await waitFor(() => {
      expect(screen.getByTestId('account-count')).toHaveTextContent('1 account')
    })
  })

  it('shows plural count for multiple accounts', async () => {
    fetchMock.mockResolvedValue(
      makeAccountsResponse([makeAccount(), makeAccount({ id: 'acc-2', username: 'admin-b' })]),
    )
    renderAccountsView()
    await waitFor(() => {
      expect(screen.getByTestId('account-count')).toHaveTextContent('2 accounts')
    })
  })

  it('shows error state on fetch failure', async () => {
    fetchMock.mockResolvedValue(makeAccountsResponse([], 500))
    renderAccountsView()
    await waitFor(() => {
      expect(screen.getByRole('alert')).toBeInTheDocument()
      expect(screen.getByText(/couldn't load accounts/i)).toBeInTheDocument()
    })
  })
})

describe('AccountsView — create panel', () => {
  it('opens the create panel when New account is clicked', async () => {
    fetchMock.mockResolvedValue(makeAccountsResponse([]))
    renderAccountsView()
    await waitFor(() => expect(screen.getByTestId('toggle-create-btn')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId('toggle-create-btn'))
    expect(screen.getByTestId('account-form-panel')).toBeInTheDocument()
  })

  it('closes the create panel when Close is clicked', async () => {
    fetchMock.mockResolvedValue(makeAccountsResponse([]))
    renderAccountsView()
    await waitFor(() => expect(screen.getByTestId('toggle-create-btn')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId('toggle-create-btn'))
    expect(screen.getByTestId('account-form-panel')).toBeInTheDocument()
    fireEvent.click(screen.getByTestId('toggle-create-btn'))
    expect(screen.queryByTestId('account-form-panel')).not.toBeInTheDocument()
  })

  it('shows username and password inputs in the create panel', async () => {
    fetchMock.mockResolvedValue(makeAccountsResponse([]))
    renderAccountsView()
    await waitFor(() => expect(screen.getByTestId('toggle-create-btn')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId('toggle-create-btn'))
    expect(screen.getByLabelText(/username/i)).toBeInTheDocument()
    expect(screen.getByLabelText(/password/i)).toBeInTheDocument()
  })

  it('shows validation error when submitting without username', async () => {
    fetchMock.mockResolvedValue(makeAccountsResponse([]))
    renderAccountsView()
    await waitFor(() => expect(screen.getByTestId('toggle-create-btn')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId('toggle-create-btn'))
    fireEvent.click(screen.getByTestId('account-save-btn'))
    expect(screen.getByTestId('account-save-error')).toHaveTextContent(/username is required/i)
  })

  it('shows validation error when submitting without password', async () => {
    fetchMock.mockResolvedValue(makeAccountsResponse([]))
    renderAccountsView()
    await waitFor(() => expect(screen.getByTestId('toggle-create-btn')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId('toggle-create-btn'))
    fireEvent.change(screen.getByLabelText(/username/i), { target: { value: 'fleet-admin' } })
    fireEvent.click(screen.getByTestId('account-save-btn'))
    expect(screen.getByTestId('account-save-error')).toHaveTextContent(/password is required/i)
  })
})

describe('AccountsView — delete confirm', () => {
  it('shows delete confirm dialog when Delete is clicked', async () => {
    fetchMock.mockResolvedValue(makeAccountsResponse([makeAccount()]))
    renderAccountsView()
    await waitFor(() => expect(screen.getByTestId('accounts-table')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId('account-delete-btn'))
    expect(screen.getByRole('dialog')).toBeInTheDocument()
    expect(screen.getByTestId('delete-confirm-btn')).toBeInTheDocument()
  })

  it('closes the confirm dialog on Cancel', async () => {
    fetchMock.mockResolvedValue(makeAccountsResponse([makeAccount()]))
    renderAccountsView()
    await waitFor(() => expect(screen.getByTestId('accounts-table')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId('account-delete-btn'))
    expect(screen.getByRole('dialog')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: /cancel/i }))
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
  })

  it('calls DELETE and refreshes on confirm', async () => {
    fetchMock
      .mockResolvedValueOnce(makeAccountsResponse([makeAccount()]))
      .mockResolvedValueOnce(new Response(JSON.stringify({ data: { deleted: true } }), { status: 200 }))
      .mockResolvedValueOnce(makeAccountsResponse([]))
    renderAccountsView()
    await waitFor(() => expect(screen.getByTestId('accounts-table')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId('account-delete-btn'))
    fireEvent.click(screen.getByTestId('delete-confirm-btn'))
    await waitFor(() => {
      expect(fetchMock).toHaveBeenCalledWith(
        expect.stringContaining('/api/v1/web/accounts/'),
        expect.objectContaining({ method: 'DELETE' }),
      )
    })
  })
})

describe('AccountsView — roles tab', () => {
  it('switches to the Roles tab when clicked', async () => {
    fetchMock
      .mockResolvedValueOnce(makeAccountsResponse([]))
      .mockResolvedValueOnce(makeRolesResponse([makeRole()]))
    renderAccountsView()
    await waitFor(() => expect(screen.getByTestId('toggle-create-btn')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId('tab-roles'))
    await waitFor(() => {
      expect(screen.getByTestId('roles-table')).toBeInTheDocument()
    })
    expect(screen.getByText('fleet-viewer')).toBeInTheDocument()
  })

  it('does not show the New account button on the Roles tab', async () => {
    fetchMock
      .mockResolvedValueOnce(makeAccountsResponse([]))
      .mockResolvedValueOnce(makeRolesResponse([]))
    renderAccountsView()
    await waitFor(() => expect(screen.getByTestId('toggle-create-btn')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId('tab-roles'))
    expect(screen.queryByTestId('toggle-create-btn')).not.toBeInTheDocument()
  })
})
