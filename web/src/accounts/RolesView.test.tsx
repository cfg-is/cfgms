// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * RolesView test suite (Issue #2733, #3133): role list rendering, data states,
 * permission expansion, create, edit, and delete.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router'
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

function makePermissionsResponse(perms: object[], status = 200) {
  return new Response(
    JSON.stringify({ data: perms }),
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

function makePermission(overrides: Partial<Record<string, unknown>> = {}) {
  return {
    id: 'perm-1',
    name: 'steward:list',
    description: 'List stewards',
    resource_type: 'steward',
    actions: ['list'],
    ...overrides,
  }
}

function setupRolesFetch(roles: object[], permissions: object[] = []) {
  fetchMock.mockImplementation((url: RequestInfo | URL) => {
    const u = String(url)
    if (u.includes('/rbac/permissions')) return Promise.resolve(makePermissionsResponse(permissions))
    if (u.includes('/rbac/roles')) return Promise.resolve(makeRolesResponse(roles))
    return Promise.resolve(new Response('{}', { status: 404 }))
  })
}

// M-AUTH-2: every role mutation requires a justification of at least 10 chars.
const VALID_JUSTIFICATION = 'rotating fleet viewer permissions for audit'

function fillJustification(
  testId = 'role-justification-input',
  value: string = VALID_JUSTIFICATION,
) {
  fireEvent.change(screen.getByTestId(testId), { target: { value } })
}

/** Requests recorded by the fetch mock, for header/body assertions. */
interface RecordedRequest {
  url: string
  method: string
  justification: string | null
  body: unknown
}

function recordRequest(url: RequestInfo | URL, init?: RequestInit): RecordedRequest {
  const headers = new Headers((init as RequestInit | undefined)?.headers)
  const raw = (init as RequestInit | undefined)?.body
  return {
    url: String(url),
    method: ((init as RequestInit | undefined)?.method ?? 'GET').toUpperCase(),
    justification: headers.get('X-Justification'),
    body: typeof raw === 'string' ? JSON.parse(raw) : null,
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
    setupRolesFetch([])
    renderRolesView()
    await waitFor(() => {
      expect(screen.getByTestId('roles-empty')).toBeInTheDocument()
    })
  })
})

describe('RolesView — roles list', () => {
  it('renders role rows in a table', async () => {
    setupRolesFetch([
      makeRole({ name: 'fleet-viewer' }),
      makeRole({ id: 'role-2', name: 'config-manager' }),
    ])
    renderRolesView()
    await waitFor(() => {
      expect(screen.getByTestId('roles-table')).toBeInTheDocument()
    })
    expect(screen.getAllByTestId('role-row')).toHaveLength(2)
    expect(screen.getByText('fleet-viewer')).toBeInTheDocument()
    expect(screen.getByText('config-manager')).toBeInTheDocument()
  })

  it('shows role count', async () => {
    setupRolesFetch([makeRole()])
    renderRolesView()
    await waitFor(() => {
      expect(screen.getByTestId('role-count')).toHaveTextContent('1 role')
    })
  })

  it('shows plural for multiple roles', async () => {
    setupRolesFetch([makeRole(), makeRole({ id: 'role-2', name: 'role-b' })])
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
    setupRolesFetch([makeRole({ permissions: ['steward:list', 'steward:read'] })])
    renderRolesView()
    await waitFor(() => expect(screen.getByTestId('roles-table')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId('role-row'))
    expect(screen.getByTestId('role-permissions-row')).toBeInTheDocument()
    expect(screen.getByText('steward:list')).toBeInTheDocument()
    expect(screen.getByText('steward:read')).toBeInTheDocument()
  })

  it('collapses permissions when the same row is clicked again', async () => {
    setupRolesFetch([makeRole()])
    renderRolesView()
    await waitFor(() => expect(screen.getByTestId('roles-table')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId('role-row'))
    expect(screen.getByTestId('role-permissions-row')).toBeInTheDocument()
    fireEvent.click(screen.getByTestId('role-row'))
    expect(screen.queryByTestId('role-permissions-row')).not.toBeInTheDocument()
  })

  it('shows None when a role has no permissions', async () => {
    setupRolesFetch([makeRole({ permissions: [] })])
    renderRolesView()
    await waitFor(() => expect(screen.getByTestId('roles-table')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId('role-row'))
    expect(screen.getByText('None')).toBeInTheDocument()
  })
})

describe('RolesView — create role', () => {
  it('shows and hides the create panel on toggle', async () => {
    setupRolesFetch([makeRole()])
    renderRolesView()
    await waitFor(() => expect(screen.getByTestId('roles-table')).toBeInTheDocument())
    expect(screen.queryByTestId('role-form-panel')).not.toBeInTheDocument()
    fireEvent.click(screen.getByTestId('toggle-create-role-btn'))
    expect(screen.getByTestId('role-form-panel')).toBeInTheDocument()
    fireEvent.click(screen.getByTestId('toggle-create-role-btn'))
    expect(screen.queryByTestId('role-form-panel')).not.toBeInTheDocument()
  })

  it('closes create panel via Cancel button', async () => {
    setupRolesFetch([], [])
    renderRolesView()
    await waitFor(() => expect(screen.getByTestId('roles-empty')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId('toggle-create-role-btn'))
    expect(screen.getByTestId('role-form-panel')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }))
    expect(screen.queryByTestId('role-form-panel')).not.toBeInTheDocument()
  })

  it('shows permission checkboxes from GET /api/v1/rbac/permissions', async () => {
    setupRolesFetch([], [
      makePermission({ id: 'p1', name: 'steward:list' }),
      makePermission({ id: 'p2', name: 'steward:read' }),
    ])
    renderRolesView()
    await waitFor(() => expect(screen.getByTestId('roles-empty')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId('toggle-create-role-btn'))
    await waitFor(() => {
      expect(screen.getByTestId('permission-selector')).toBeInTheDocument()
    })
    const checkboxes = screen.getAllByRole('checkbox')
    expect(checkboxes).toHaveLength(2)
  })

  it('shows error when creating with empty name', async () => {
    setupRolesFetch([], [])
    renderRolesView()
    await waitFor(() => expect(screen.getByTestId('roles-empty')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId('toggle-create-role-btn'))
    fireEvent.click(screen.getByTestId('role-save-btn'))
    expect(screen.getByTestId('role-save-error')).toHaveTextContent(/role name is required/i)
  })

  it('calls POST /api/v1/rbac/roles with the justification header and refreshes list', async () => {
    const rolesAfterCreate = [makeRole(), makeRole({ id: 'role-new', name: 'new-role' })]
    const posts: RecordedRequest[] = []
    let callCount = 0
    fetchMock.mockImplementation((url: RequestInfo | URL, init?: RequestInit) => {
      const u = String(url)
      const method = ((init as RequestInit | undefined)?.method ?? 'GET').toUpperCase()
      if (method === 'POST' && u.includes('/rbac/roles')) {
        posts.push(recordRequest(url, init))
        return Promise.resolve(new Response(
          JSON.stringify({ data: makeRole({ id: 'role-new', name: 'new-role' }) }),
          { status: 201, headers: { 'Content-Type': 'application/json' } },
        ))
      }
      if (u.includes('/rbac/permissions')) return Promise.resolve(makePermissionsResponse([makePermission()]))
      if (u.includes('/rbac/roles')) {
        callCount++
        const list = callCount === 1 ? [makeRole()] : rolesAfterCreate
        return Promise.resolve(makeRolesResponse(list))
      }
      return Promise.resolve(new Response('{}', { status: 404 }))
    })
    renderRolesView()
    await waitFor(() => expect(screen.getByTestId('roles-table')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId('toggle-create-role-btn'))
    await waitFor(() => expect(screen.getByTestId('role-form-panel')).toBeInTheDocument())
    fireEvent.change(screen.getByTestId('role-name-input'), { target: { value: 'new-role' } })
    fillJustification()
    fireEvent.click(screen.getByTestId('role-save-btn'))
    await waitFor(() => {
      expect(screen.queryByTestId('role-form-panel')).not.toBeInTheDocument()
    })
    await waitFor(() => {
      expect(screen.getAllByTestId('role-row')).toHaveLength(2)
    })
    expect(posts).toHaveLength(1)
    expect(posts[0]!.justification).toBe(VALID_JUSTIFICATION)
    // A browser-supplied tenant would be a cross-tenant write vector: the
    // create body carries none.
    expect(posts[0]!.body).not.toHaveProperty('tenant_id')
  })

  it('blocks create and issues no request when the justification is too short', async () => {
    setupRolesFetch([], [])
    renderRolesView()
    await waitFor(() => expect(screen.getByTestId('roles-empty')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId('toggle-create-role-btn'))
    fireEvent.change(screen.getByTestId('role-name-input'), { target: { value: 'new-role' } })
    fillJustification('role-justification-input', 'too short')
    fireEvent.click(screen.getByTestId('role-save-btn'))
    expect(screen.getByTestId('role-save-error')).toHaveTextContent(/at least 10 characters/i)
    expect(
      fetchMock.mock.calls.some(
        ([, init]) => ((init as RequestInit | undefined)?.method ?? 'GET').toUpperCase() === 'POST',
      ),
    ).toBe(false)
  })

  it('requires a justification before create', async () => {
    setupRolesFetch([], [])
    renderRolesView()
    await waitFor(() => expect(screen.getByTestId('roles-empty')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId('toggle-create-role-btn'))
    fireEvent.change(screen.getByTestId('role-name-input'), { target: { value: 'new-role' } })
    fireEvent.click(screen.getByTestId('role-save-btn'))
    expect(screen.getByTestId('role-save-error')).toHaveTextContent(/justification is required/i)
  })

  it('shows server error when create fails', async () => {
    fetchMock.mockImplementation((url: RequestInfo | URL, init?: RequestInit) => {
      const u = String(url)
      const method = ((init as RequestInit | undefined)?.method ?? 'GET').toUpperCase()
      if (method === 'POST' && u.includes('/rbac/roles')) {
        return Promise.resolve(new Response(
          JSON.stringify({ error: { message: 'name already exists' } }),
          { status: 409, headers: { 'Content-Type': 'application/json' } },
        ))
      }
      if (u.includes('/rbac/permissions')) return Promise.resolve(makePermissionsResponse([]))
      return Promise.resolve(makeRolesResponse([]))
    })
    renderRolesView()
    await waitFor(() => expect(screen.getByTestId('roles-empty')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId('toggle-create-role-btn'))
    fireEvent.change(screen.getByTestId('role-name-input'), { target: { value: 'fleet-viewer' } })
    fillJustification()
    fireEvent.click(screen.getByTestId('role-save-btn'))
    await waitFor(() => {
      expect(screen.getByTestId('role-save-error')).toBeInTheDocument()
    })
    expect(screen.getByTestId('role-save-error')).toHaveTextContent('name already exists')
  })
})

describe('RolesView — edit role', () => {
  it('shows Edit and Delete buttons in the expanded row', async () => {
    setupRolesFetch([makeRole()])
    renderRolesView()
    await waitFor(() => expect(screen.getByTestId('roles-table')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId('role-row'))
    expect(screen.getByTestId('role-edit-btn')).toBeInTheDocument()
    expect(screen.getByTestId('role-delete-btn')).toBeInTheDocument()
  })

  it('shows edit form pre-filled with current values on Edit click', async () => {
    setupRolesFetch([makeRole({ name: 'fleet-viewer', description: 'Read-only fleet access' })])
    renderRolesView()
    await waitFor(() => expect(screen.getByTestId('roles-table')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId('role-row'))
    fireEvent.click(screen.getByTestId('role-edit-btn'))
    await waitFor(() => {
      expect(screen.getByTestId('role-edit-panel')).toBeInTheDocument()
    })
    const nameInput = screen.getByTestId('role-name-input')
    expect((nameInput as HTMLInputElement).value).toBe('fleet-viewer')
    const descInput = screen.getByTestId('role-description-input')
    expect((descInput as HTMLInputElement).value).toBe('Read-only fleet access')
  })

  it('hides permissions row while edit panel is open', async () => {
    setupRolesFetch([makeRole()])
    renderRolesView()
    await waitFor(() => expect(screen.getByTestId('roles-table')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId('role-row'))
    expect(screen.getByTestId('role-permissions-row')).toBeInTheDocument()
    fireEvent.click(screen.getByTestId('role-edit-btn'))
    await waitFor(() => expect(screen.getByTestId('role-edit-panel')).toBeInTheDocument())
    expect(screen.queryByTestId('role-permissions-row')).not.toBeInTheDocument()
  })

  it('cancels edit and returns to permissions view', async () => {
    setupRolesFetch([makeRole()])
    renderRolesView()
    await waitFor(() => expect(screen.getByTestId('roles-table')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId('role-row'))
    fireEvent.click(screen.getByTestId('role-edit-btn'))
    await waitFor(() => expect(screen.getByTestId('role-edit-panel')).toBeInTheDocument())
    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }))
    expect(screen.queryByTestId('role-edit-panel')).not.toBeInTheDocument()
    expect(screen.getByTestId('role-permissions-row')).toBeInTheDocument()
  })

  it('calls PUT /api/v1/rbac/roles/{id} with justification and tenant, and refreshes list', async () => {
    const puts: RecordedRequest[] = []
    let rolesCallCount = 0
    fetchMock.mockImplementation((url: RequestInfo | URL, init?: RequestInit) => {
      const u = String(url)
      const method = ((init as RequestInit | undefined)?.method ?? 'GET').toUpperCase()
      if (method === 'PUT' && u.includes('/rbac/roles/role-1')) {
        puts.push(recordRequest(url, init))
        return Promise.resolve(new Response(
          JSON.stringify({ data: makeRole({ name: 'updated-viewer' }) }),
          { status: 200, headers: { 'Content-Type': 'application/json' } },
        ))
      }
      if (u.includes('/rbac/permissions')) return Promise.resolve(makePermissionsResponse([]))
      if (u.includes('/rbac/roles')) {
        rolesCallCount++
        return Promise.resolve(makeRolesResponse([makeRole({ name: rolesCallCount > 1 ? 'updated-viewer' : 'fleet-viewer' })]))
      }
      return Promise.resolve(new Response('{}', { status: 404 }))
    })
    renderRolesView()
    await waitFor(() => expect(screen.getByTestId('roles-table')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId('role-row'))
    fireEvent.click(screen.getByTestId('role-edit-btn'))
    await waitFor(() => expect(screen.getByTestId('role-edit-panel')).toBeInTheDocument())
    fireEvent.change(screen.getByTestId('role-name-input'), { target: { value: 'updated-viewer' } })
    fillJustification()
    fireEvent.click(screen.getByTestId('role-update-btn'))
    await waitFor(() => {
      expect(puts).toHaveLength(1)
    })
    await waitFor(() => {
      expect(screen.queryByTestId('role-edit-panel')).not.toBeInTheDocument()
    })
    expect(puts[0]!.justification).toBe(VALID_JUSTIFICATION)
    expect(puts[0]!.body).toMatchObject({ name: 'updated-viewer' })
    // A browser-supplied tenant would be a cross-tenant write vector: the edit
    // body carries none, and the server preserves the stored attribution.
    expect(puts[0]!.body).not.toHaveProperty('tenant_id')
  })

  it('blocks the update and issues no request when the justification is too short', async () => {
    setupRolesFetch([makeRole()])
    renderRolesView()
    await waitFor(() => expect(screen.getByTestId('roles-table')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId('role-row'))
    fireEvent.click(screen.getByTestId('role-edit-btn'))
    await waitFor(() => expect(screen.getByTestId('role-edit-panel')).toBeInTheDocument())
    fillJustification('role-justification-input', 'nope')
    fireEvent.click(screen.getByTestId('role-update-btn'))
    expect(screen.getByTestId('role-edit-error')).toHaveTextContent(/at least 10 characters/i)
    expect(
      fetchMock.mock.calls.some(
        ([, init]) => ((init as RequestInit | undefined)?.method ?? 'GET').toUpperCase() === 'PUT',
      ),
    ).toBe(false)
  })

  it('requires a justification before update', async () => {
    setupRolesFetch([makeRole()])
    renderRolesView()
    await waitFor(() => expect(screen.getByTestId('roles-table')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId('role-row'))
    fireEvent.click(screen.getByTestId('role-edit-btn'))
    await waitFor(() => expect(screen.getByTestId('role-edit-panel')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId('role-update-btn'))
    expect(screen.getByTestId('role-edit-error')).toHaveTextContent(/justification is required/i)
  })

  it('sends no tenant_id when editing a role listed without one', async () => {
    const puts: RecordedRequest[] = []
    fetchMock.mockImplementation((url: RequestInfo | URL, init?: RequestInit) => {
      const u = String(url)
      const method = ((init as RequestInit | undefined)?.method ?? 'GET').toUpperCase()
      if (method === 'PUT' && u.includes('/rbac/roles/role-1')) {
        puts.push(recordRequest(url, init))
        return Promise.resolve(new Response(
          JSON.stringify({ data: makeRole({ tenant_id: '' }) }),
          { status: 200, headers: { 'Content-Type': 'application/json' } },
        ))
      }
      if (u.includes('/rbac/permissions')) return Promise.resolve(makePermissionsResponse([]))
      return Promise.resolve(makeRolesResponse([makeRole({ tenant_id: '' })]))
    })
    renderRolesView()
    await waitFor(() => expect(screen.getByTestId('roles-table')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId('role-row'))
    fireEvent.click(screen.getByTestId('role-edit-btn'))
    await waitFor(() => expect(screen.getByTestId('role-edit-panel')).toBeInTheDocument())
    fillJustification()
    fireEvent.click(screen.getByTestId('role-update-btn'))
    await waitFor(() => expect(puts).toHaveLength(1))
    expect(puts[0]!.body).not.toHaveProperty('tenant_id')
  })

  it('shows error when edit name is empty', async () => {
    setupRolesFetch([makeRole()])
    renderRolesView()
    await waitFor(() => expect(screen.getByTestId('roles-table')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId('role-row'))
    fireEvent.click(screen.getByTestId('role-edit-btn'))
    await waitFor(() => expect(screen.getByTestId('role-edit-panel')).toBeInTheDocument())
    const nameInput = screen.getByTestId('role-name-input')
    fireEvent.change(nameInput, { target: { value: '' } })
    fireEvent.click(screen.getByTestId('role-update-btn'))
    expect(screen.getByTestId('role-edit-error')).toHaveTextContent(/role name is required/i)
  })

  it('shows server error when update fails', async () => {
    fetchMock.mockImplementation((url: RequestInfo | URL, init?: RequestInit) => {
      const u = String(url)
      const method = ((init as RequestInit | undefined)?.method ?? 'GET').toUpperCase()
      if (method === 'PUT' && u.includes('/rbac/roles/')) {
        return Promise.resolve(new Response(
          JSON.stringify({ error: { message: 'role not found' } }),
          { status: 404, headers: { 'Content-Type': 'application/json' } },
        ))
      }
      if (u.includes('/rbac/permissions')) return Promise.resolve(makePermissionsResponse([]))
      return Promise.resolve(makeRolesResponse([makeRole()]))
    })
    renderRolesView()
    await waitFor(() => expect(screen.getByTestId('roles-table')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId('role-row'))
    fireEvent.click(screen.getByTestId('role-edit-btn'))
    await waitFor(() => expect(screen.getByTestId('role-edit-panel')).toBeInTheDocument())
    fillJustification()
    fireEvent.click(screen.getByTestId('role-update-btn'))
    await waitFor(() => {
      expect(screen.getByTestId('role-edit-error')).toBeInTheDocument()
    })
    expect(screen.getByTestId('role-edit-error')).toHaveTextContent('role not found')
  })
})

describe('RolesView — delete role', () => {
  it('shows delete confirm modal when Delete is clicked', async () => {
    setupRolesFetch([makeRole({ name: 'fleet-viewer' })])
    renderRolesView()
    await waitFor(() => expect(screen.getByTestId('roles-table')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId('role-row'))
    fireEvent.click(screen.getByTestId('role-delete-btn'))
    expect(screen.getByRole('dialog')).toBeInTheDocument()
    expect(screen.getAllByText(/fleet-viewer/).length).toBeGreaterThan(0)
  })

  it('closes delete modal on Cancel', async () => {
    setupRolesFetch([makeRole()])
    renderRolesView()
    await waitFor(() => expect(screen.getByTestId('roles-table')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId('role-row'))
    fireEvent.click(screen.getByTestId('role-delete-btn'))
    expect(screen.getByRole('dialog')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }))
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
  })

  it('calls DELETE /api/v1/rbac/roles/{id} with the justification header on confirm', async () => {
    const deletes: RecordedRequest[] = []
    let rolesCallCount = 0
    fetchMock.mockImplementation((url: RequestInfo | URL, init?: RequestInit) => {
      const u = String(url)
      const method = ((init as RequestInit | undefined)?.method ?? 'GET').toUpperCase()
      if (method === 'DELETE' && u.includes('/rbac/roles/role-1')) {
        deletes.push(recordRequest(url, init))
        return Promise.resolve(new Response(
          JSON.stringify({ data: { id: 'role-1', deleted: true } }),
          { status: 200, headers: { 'Content-Type': 'application/json' } },
        ))
      }
      if (u.includes('/rbac/roles')) {
        rolesCallCount++
        const list = rolesCallCount === 1 ? [makeRole()] : []
        return Promise.resolve(makeRolesResponse(list))
      }
      return Promise.resolve(new Response('{}', { status: 404 }))
    })
    renderRolesView()
    await waitFor(() => expect(screen.getByTestId('roles-table')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId('role-row'))
    fireEvent.click(screen.getByTestId('role-delete-btn'))
    expect(screen.getByRole('dialog')).toBeInTheDocument()
    fillJustification('delete-role-justification-input')
    fireEvent.click(screen.getByTestId('delete-role-confirm-btn'))
    await waitFor(() => {
      expect(deletes).toHaveLength(1)
    })
    await waitFor(() => {
      expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
    })
    expect(deletes[0]!.justification).toBe(VALID_JUSTIFICATION)
  })

  it('keeps the modal open and issues no request without a justification', async () => {
    setupRolesFetch([makeRole()])
    renderRolesView()
    await waitFor(() => expect(screen.getByTestId('roles-table')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId('role-row'))
    fireEvent.click(screen.getByTestId('role-delete-btn'))
    fireEvent.click(screen.getByTestId('delete-role-confirm-btn'))
    expect(screen.getByTestId('delete-role-justification-error')).toHaveTextContent(
      /justification is required/i,
    )
    expect(screen.getByRole('dialog')).toBeInTheDocument()
    expect(
      fetchMock.mock.calls.some(
        ([, init]) =>
          ((init as RequestInit | undefined)?.method ?? 'GET').toUpperCase() === 'DELETE',
      ),
    ).toBe(false)
  })

  it('rejects a too-short delete justification', async () => {
    setupRolesFetch([makeRole()])
    renderRolesView()
    await waitFor(() => expect(screen.getByTestId('roles-table')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId('role-row'))
    fireEvent.click(screen.getByTestId('role-delete-btn'))
    fillJustification('delete-role-justification-input', 'brief')
    fireEvent.click(screen.getByTestId('delete-role-confirm-btn'))
    expect(screen.getByTestId('delete-role-justification-error')).toHaveTextContent(
      /at least 10 characters/i,
    )
    expect(screen.getByRole('dialog')).toBeInTheDocument()
  })

  it('shows error when delete fails', async () => {
    fetchMock.mockImplementation((url: RequestInfo | URL, init?: RequestInit) => {
      const u = String(url)
      const method = ((init as RequestInit | undefined)?.method ?? 'GET').toUpperCase()
      if (method === 'DELETE' && u.includes('/rbac/roles/')) {
        return Promise.resolve(new Response(
          JSON.stringify({ error: { message: 'role is in use' } }),
          { status: 400, headers: { 'Content-Type': 'application/json' } },
        ))
      }
      return Promise.resolve(makeRolesResponse([makeRole()]))
    })
    renderRolesView()
    await waitFor(() => expect(screen.getByTestId('roles-table')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId('role-row'))
    fireEvent.click(screen.getByTestId('role-delete-btn'))
    fillJustification('delete-role-justification-input')
    fireEvent.click(screen.getByTestId('delete-role-confirm-btn'))
    await waitFor(() => {
      expect(screen.getByTestId('role-delete-error')).toBeInTheDocument()
    })
    expect(screen.getByTestId('role-delete-error')).toHaveTextContent('role is in use')
  })
})
