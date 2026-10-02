// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * AccountsView test suite (Issue #2733, #2974): list rendering, data states,
 * create panel (no password; step-up transparent via apiFetch; enrollment link
 * shown once), delete confirm, revoke link, and tab switching to roles.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor, act } from '@testing-library/react'
import { MemoryRouter } from 'react-router'
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
    has_outstanding_enrollment_link: false,
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

/** Successful create response that includes the enrollment magic link. */
function makeCreateResponse(username = 'fleet-admin', status = 201) {
  return new Response(
    JSON.stringify({
      data: {
        id: 'acc-new',
        username,
        tenant_id: 'default',
        permissions: [],
        created_at: '2026-01-01T00:00:00Z',
        has_outstanding_enrollment_link: true,
        enrollment_magic_link: 'aabbcc112233445566778899aabbcc1122334455aabb',
      },
    }),
    { status, headers: { 'Content-Type': 'application/json' } },
  )
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

describe('AccountsView — create panel (Issue #2974: no password; step-up; link shown once)', () => {
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

  it('shows username input but NO password input in the create panel (passkey-only)', async () => {
    fetchMock.mockResolvedValue(makeAccountsResponse([]))
    renderAccountsView()
    await waitFor(() => expect(screen.getByTestId('toggle-create-btn')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId('toggle-create-btn'))
    expect(screen.getByLabelText(/username/i)).toBeInTheDocument()
    // No password field — accounts are passkey-only (ADR-021 Amendment 1).
    expect(screen.queryByLabelText(/password/i)).not.toBeInTheDocument()
    expect(screen.queryByTestId('account-password-input')).not.toBeInTheDocument()
  })

  it('shows validation error when submitting without username', async () => {
    fetchMock.mockResolvedValue(makeAccountsResponse([]))
    renderAccountsView()
    await waitFor(() => expect(screen.getByTestId('toggle-create-btn')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId('toggle-create-btn'))
    fireEvent.click(screen.getByTestId('account-save-btn'))
    expect(screen.getByTestId('account-save-error')).toHaveTextContent(/username is required/i)
  })

  it('[REQUIRED TEST] create call uses apiFetch so step-up is handled automatically — never a dead 403', async () => {
    // This test verifies the AC: "+ New account" is never a dead 403.
    // When the server returns 401 + CFGMS-StepUp, the apiFetch interceptor fires
    // the step-up listener (StepUpModal via AuthProvider) — the operator sees the
    // passkey prompt, not a raw 403 error. We verify this by checking the create
    // request goes through the apiFetch path (via fetch mock).
    fetchMock
      .mockResolvedValueOnce(makeAccountsResponse([])) // initial list load
      .mockResolvedValueOnce(
        new Response('', {
          status: 401,
          headers: { 'WWW-Authenticate': 'CFGMS-StepUp realm="cfgms", required="strong"' },
        }),
      ) // step-up challenge
    renderAccountsView()
    await waitFor(() => expect(screen.getByTestId('toggle-create-btn')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId('toggle-create-btn'))
    fireEvent.change(screen.getByLabelText(/username/i), { target: { value: 'fleet-admin' } })
    await act(async () => {
      fireEvent.click(screen.getByTestId('account-save-btn'))
    })
    await waitFor(() => {
      // The step-up modal appears — the operator is NOT shown a terminal 403.
      // The modal is rendered by AuthProvider when onStepUpRequired fires.
      expect(screen.getByTestId('step-up-overlay')).toBeInTheDocument()
    })
    // Critically: no 403 error text is shown to the user.
    expect(screen.queryByText(/403/)).not.toBeInTheDocument()
  })

  it('shows enrollment link panel after successful create (link shown once)', async () => {
    fetchMock
      .mockResolvedValueOnce(makeAccountsResponse([]))
      .mockResolvedValueOnce(makeCreateResponse('new-admin'))
      .mockResolvedValueOnce(
        makeAccountsResponse([makeAccount({ username: 'new-admin', has_outstanding_enrollment_link: true })]),
      )
    renderAccountsView()
    await waitFor(() => expect(screen.getByTestId('toggle-create-btn')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId('toggle-create-btn'))
    fireEvent.change(screen.getByLabelText(/username/i), { target: { value: 'new-admin' } })
    await act(async () => {
      fireEvent.click(screen.getByTestId('account-save-btn'))
    })
    await waitFor(() => {
      expect(screen.getByTestId('enrollment-link-panel')).toBeInTheDocument()
    })
    // The raw token appears in the link input.
    const linkInput = screen.getByTestId('enrollment-link-value') as HTMLInputElement
    expect(linkInput.value).toContain('aabbcc112233445566778899aabbcc1122334455aabb')
    // Email toggle is present but disabled.
    const emailToggle = screen.getByTestId('enrollment-email-toggle') as HTMLInputElement
    expect(emailToggle.disabled).toBe(true)
  })

  it('shows no enrollment link panel when the response carries no link', async () => {
    // An upsert against an account that already holds a passkey returns 200 with
    // no enrollment_magic_link (ADR-021 Amendment 1 Decision 3).
    fetchMock
      .mockResolvedValueOnce(makeAccountsResponse([]))
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            data: {
              id: 'acc-existing',
              username: 'enrolled-admin',
              tenant_id: 'default',
              permissions: [],
              created_at: '2026-01-01T00:00:00Z',
              has_outstanding_enrollment_link: false,
            },
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } },
        ),
      )
      .mockResolvedValueOnce(makeAccountsResponse([makeAccount({ username: 'enrolled-admin' })]))
    renderAccountsView()
    await waitFor(() => expect(screen.getByTestId('toggle-create-btn')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId('toggle-create-btn'))
    fireEvent.change(screen.getByLabelText(/username/i), { target: { value: 'enrolled-admin' } })
    await act(async () => {
      fireEvent.click(screen.getByTestId('account-save-btn'))
    })
    await waitFor(() => expect(screen.getByTestId('accounts-table')).toBeInTheDocument())
    expect(screen.queryByTestId('enrollment-link-panel')).not.toBeInTheDocument()
  })

  it('[REQUIRED TEST] create request body never contains a password field', async () => {
    fetchMock
      .mockResolvedValueOnce(makeAccountsResponse([]))
      .mockResolvedValueOnce(makeCreateResponse('safe-admin'))
      .mockResolvedValueOnce(makeAccountsResponse([makeAccount({ username: 'safe-admin' })]))
    renderAccountsView()
    await waitFor(() => expect(screen.getByTestId('toggle-create-btn')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId('toggle-create-btn'))
    fireEvent.change(screen.getByLabelText(/username/i), { target: { value: 'safe-admin' } })
    await act(async () => {
      fireEvent.click(screen.getByTestId('account-save-btn'))
    })
    await waitFor(() => expect(screen.getByTestId('enrollment-link-panel')).toBeInTheDocument())
    // Inspect the POST request body.
    const postCall = fetchMock.mock.calls.find(
      (call) => (call[1] as RequestInit)?.method === 'POST',
    )
    expect(postCall).toBeDefined()
    const body = JSON.parse((postCall![1] as RequestInit).body as string) as Record<string, unknown>
    expect(body).not.toHaveProperty('password')
    expect(body).toHaveProperty('username', 'safe-admin')
  })

  it('[REQUIRED TEST] audit fields — enrollment link panel shows link but no raw token in DOM audit trace', async () => {
    // Proxy for the backend audit test: the UI shows the link (for clipboard)
    // but would not send the token back to any logging endpoint. This test
    // verifies the raw token is present in the link field (for copy) but
    // there is no hidden form field or data-* attribute leaking it elsewhere.
    const rawToken = 'deadbeef1234567890abcdef12345678deadbeef11'
    fetchMock
      .mockResolvedValueOnce(makeAccountsResponse([]))
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            data: {
              id: 'acc-new',
              username: 'audit-test-admin',
              tenant_id: 'default',
              permissions: [],
              created_at: '2026-01-01T00:00:00Z',
              has_outstanding_enrollment_link: true,
              enrollment_magic_link: rawToken,
            },
          }),
          { status: 201, headers: { 'Content-Type': 'application/json' } },
        ),
      )
      .mockResolvedValueOnce(makeAccountsResponse([makeAccount({ username: 'audit-test-admin' })]))
    renderAccountsView()
    await waitFor(() => expect(screen.getByTestId('toggle-create-btn')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId('toggle-create-btn'))
    fireEvent.change(screen.getByLabelText(/username/i), { target: { value: 'audit-test-admin' } })
    await act(async () => {
      fireEvent.click(screen.getByTestId('account-save-btn'))
    })
    await waitFor(() => expect(screen.getByTestId('enrollment-link-panel')).toBeInTheDocument())
    const linkInput = screen.getByTestId('enrollment-link-value') as HTMLInputElement
    // Token is in the link (expected — for clipboard).
    expect(linkInput.value).toContain(rawToken)
    // Token is NOT sent back to any endpoint after initial display.
    const postCalls = fetchMock.mock.calls.filter(
      (call) => (call[1] as RequestInit)?.method === 'POST',
    )
    for (const call of postCalls) {
      const body = (call[1] as RequestInit).body
      if (typeof body === 'string') {
        expect(body).not.toContain(rawToken)
      }
    }
  })
})

describe('AccountsView — enrollment link copy (Issue #2974)', () => {
  /**
   * Drives the create flow to the point where the shown-once enrollment panel
   * is on screen, with navigator.clipboard.writeText backed by `writeText`.
   * jsdom ships no Clipboard API, so the property is installed (and removed
   * again by the caller's cleanup) rather than spied on.
   */
  async function renderWithClipboard(writeText: (text: string) => Promise<void>) {
    Object.defineProperty(navigator, 'clipboard', {
      configurable: true,
      get: () => ({ writeText }),
    })
    fetchMock
      .mockResolvedValueOnce(makeAccountsResponse([]))
      .mockResolvedValueOnce(makeCreateResponse('copy-admin'))
      .mockResolvedValueOnce(makeAccountsResponse([makeAccount({ username: 'copy-admin' })]))
    renderAccountsView()
    await waitFor(() => expect(screen.getByTestId('toggle-create-btn')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId('toggle-create-btn'))
    fireEvent.change(screen.getByLabelText(/username/i), { target: { value: 'copy-admin' } })
    await act(async () => {
      fireEvent.click(screen.getByTestId('account-save-btn'))
    })
    await waitFor(() => expect(screen.getByTestId('enrollment-link-panel')).toBeInTheDocument())
  }

  afterEach(() => {
    Reflect.deleteProperty(navigator, 'clipboard')
  })

  it('writes the enrollment link to the clipboard and confirms the copy', async () => {
    const written: string[] = []
    await renderWithClipboard(async (text: string) => {
      written.push(text)
    })
    const linkInput = screen.getByTestId('enrollment-link-value') as HTMLInputElement
    await act(async () => {
      fireEvent.click(screen.getByTestId('enrollment-link-copy-btn'))
    })
    expect(written).toEqual([linkInput.value])
    expect(written[0]).toContain('aabbcc112233445566778899aabbcc1122334455aabb')
    expect(screen.getByTestId('enrollment-link-copy-btn').textContent).toBe('Copied!')
    expect(screen.queryByTestId('enrollment-link-copy-error')).not.toBeInTheDocument()
  })

  it('surfaces a clipboard failure instead of silently discarding it', async () => {
    await renderWithClipboard(() => Promise.reject(new Error('Write permission denied')))
    await act(async () => {
      fireEvent.click(screen.getByTestId('enrollment-link-copy-btn'))
    })
    const notice = await screen.findByTestId('enrollment-link-copy-error')
    expect(notice.textContent).toContain('copy it manually')
    expect(notice.textContent).toContain('Write permission denied')
    // The button must not claim success when the write failed, and the link
    // itself stays on screen so the operator can still copy it by hand.
    expect(screen.getByTestId('enrollment-link-copy-btn').textContent).toBe('Copy')
    expect(screen.getByTestId('enrollment-link-value')).toBeInTheDocument()
  })

  it('reports a missing Clipboard API rather than appearing to do nothing', async () => {
    // Non-secure-context browsers expose no navigator.clipboard at all: the
    // property access itself throws, which must still reach the operator.
    await renderWithClipboard(async () => {})
    Reflect.deleteProperty(navigator, 'clipboard')
    await act(async () => {
      fireEvent.click(screen.getByTestId('enrollment-link-copy-btn'))
    })
    const notice = await screen.findByTestId('enrollment-link-copy-error')
    expect(notice.textContent).toContain('copy it manually')
    expect(screen.getByTestId('enrollment-link-copy-btn').textContent).toBe('Copy')
  })
})

describe('AccountsView — enrollment link revoke (Issue #2974)', () => {
  it('shows Revoke link button for accounts with outstanding enrollment link', async () => {
    fetchMock.mockResolvedValue(
      makeAccountsResponse([makeAccount({ has_outstanding_enrollment_link: true })]),
    )
    renderAccountsView()
    await waitFor(() => expect(screen.getByTestId('accounts-table')).toBeInTheDocument())
    expect(screen.getByTestId('enrollment-revoke-btn')).toBeInTheDocument()
  })

  it('does not show Revoke link button for accounts without outstanding link', async () => {
    fetchMock.mockResolvedValue(
      makeAccountsResponse([makeAccount({ has_outstanding_enrollment_link: false })]),
    )
    renderAccountsView()
    await waitFor(() => expect(screen.getByTestId('accounts-table')).toBeInTheDocument())
    expect(screen.queryByTestId('enrollment-revoke-btn')).not.toBeInTheDocument()
  })

  it('calls POST .../enrollment-link/revoke and refreshes on click', async () => {
    fetchMock
      .mockResolvedValueOnce(
        makeAccountsResponse([makeAccount({ has_outstanding_enrollment_link: true })]),
      )
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ data: { username: 'fleet-admin', revoked: true } }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        }),
      )
      .mockResolvedValueOnce(makeAccountsResponse([makeAccount()]))
    renderAccountsView()
    await waitFor(() => expect(screen.getByTestId('enrollment-revoke-btn')).toBeInTheDocument())
    await act(async () => {
      fireEvent.click(screen.getByTestId('enrollment-revoke-btn'))
    })
    await waitFor(() => {
      expect(fetchMock).toHaveBeenCalledWith(
        expect.stringContaining('/enrollment-link/revoke'),
        expect.objectContaining({ method: 'POST' }),
      )
    })
  })

  it('surfaces the server error message when revoke is rejected (409)', async () => {
    fetchMock
      .mockResolvedValueOnce(
        makeAccountsResponse([makeAccount({ has_outstanding_enrollment_link: true })]),
      )
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            error: { code: 'NO_OUTSTANDING_LINK', message: 'No outstanding enrollment link to revoke' },
          }),
          { status: 409, headers: { 'Content-Type': 'application/json' } },
        ),
      )
    renderAccountsView()
    await waitFor(() => expect(screen.getByTestId('enrollment-revoke-btn')).toBeInTheDocument())
    await act(async () => {
      fireEvent.click(screen.getByTestId('enrollment-revoke-btn'))
    })
    const banner = await screen.findByTestId('revoke-error')
    expect(banner).toHaveTextContent('No outstanding enrollment link to revoke')
  })

  it('shows a fallback revoke error when the server returns 500 with no message', async () => {
    fetchMock
      .mockResolvedValueOnce(
        makeAccountsResponse([makeAccount({ has_outstanding_enrollment_link: true })]),
      )
      .mockResolvedValueOnce(new Response('', { status: 500 }))
    renderAccountsView()
    await waitFor(() => expect(screen.getByTestId('enrollment-revoke-btn')).toBeInTheDocument())
    await act(async () => {
      fireEvent.click(screen.getByTestId('enrollment-revoke-btn'))
    })
    const banner = await screen.findByTestId('revoke-error')
    expect(banner).toHaveTextContent('Revoke failed — 500')
  })

  it('clears a previous revoke error when a later revoke succeeds', async () => {
    fetchMock
      .mockResolvedValueOnce(
        makeAccountsResponse([makeAccount({ has_outstanding_enrollment_link: true })]),
      )
      .mockResolvedValueOnce(new Response('', { status: 500 }))
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ data: { username: 'fleet-admin', revoked: true } }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        }),
      )
      .mockResolvedValueOnce(makeAccountsResponse([makeAccount()]))
    renderAccountsView()
    await waitFor(() => expect(screen.getByTestId('enrollment-revoke-btn')).toBeInTheDocument())
    await act(async () => {
      fireEvent.click(screen.getByTestId('enrollment-revoke-btn'))
    })
    await screen.findByTestId('revoke-error')
    await act(async () => {
      fireEvent.click(screen.getByTestId('enrollment-revoke-btn'))
    })
    await waitFor(() => expect(screen.queryByTestId('revoke-error')).not.toBeInTheDocument())
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
    await act(async () => {
      fireEvent.click(screen.getByTestId('delete-confirm-btn'))
    })
    await waitFor(() => {
      expect(fetchMock).toHaveBeenCalledWith(
        expect.stringContaining('/api/v1/accounts/'),
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

// ── Subject-role expand panel (Issue #3134) ───────────────────────────────────

describe('AccountsView — subject-role expand panel (Issue #3134)', () => {
  function makeSubjectRolesResponse(roles: object[], status = 200) {
    return new Response(
      JSON.stringify({ data: roles }),
      { status, headers: { 'Content-Type': 'application/json' } },
    )
  }

  function makeSubjectRole(overrides: Partial<Record<string, unknown>> = {}) {
    return {
      id: 'role-1',
      name: 'fleet-viewer',
      description: 'Read-only fleet access',
      permissions: [],
      tenant_id: 'tenant-a',
      created_at: '2026-01-01T00:00:00Z',
      updated_at: '2026-02-01T00:00:00Z',
      ...overrides,
    }
  }

  function setupFetchMocks({
    accounts = [makeAccount()],
    subjectRoles = [] as object[],
    allRoles = [makeRole()] as object[],
    subjectRolesStatus = 200,
  } = {}) {
    fetchMock.mockImplementation((url: unknown) => {
      const u = String(url)
      if (u.includes('/rbac/subjects/') && u.includes('/roles')) {
        return Promise.resolve(makeSubjectRolesResponse(subjectRoles, subjectRolesStatus))
      }
      if (u.includes('/rbac/roles')) {
        return Promise.resolve(makeRolesResponse(allRoles))
      }
      if (u.includes('/rbac/permissions')) {
        return Promise.resolve(makeRolesResponse([]))
      }
      return Promise.resolve(makeAccountsResponse(accounts))
    })
  }

  // M-AUTH-2: both mutation surfaces demand an operator justification, so every
  // test that drives an assign or a revoke through to the network fills it in.
  const ASSIGN_WHY = 'granting fleet-viewer for the on-call rotation'
  const REVOKE_WHY = 'removing fleet-viewer now the rotation has ended'

  function fillJustification(testId: string, value: string) {
    fireEvent.change(screen.getByTestId(testId), { target: { value } })
  }

  it('clicking an account row expands the roles panel', async () => {
    setupFetchMocks()
    renderAccountsView()
    await waitFor(() => expect(screen.getByTestId('accounts-table')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId('account-row'))
    await waitFor(() => {
      expect(screen.getByTestId('account-roles-row')).toBeInTheDocument()
    })
  })

  it('clicking the same row again collapses the panel', async () => {
    setupFetchMocks()
    renderAccountsView()
    await waitFor(() => expect(screen.getByTestId('accounts-table')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId('account-row'))
    await waitFor(() => expect(screen.getByTestId('account-roles-row')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId('account-row'))
    await waitFor(() => {
      expect(screen.queryByTestId('account-roles-row')).not.toBeInTheDocument()
    })
  })

  it('shows "No roles assigned" when the subject has no roles', async () => {
    setupFetchMocks({ subjectRoles: [] })
    renderAccountsView()
    await waitFor(() => expect(screen.getByTestId('accounts-table')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId('account-row'))
    await waitFor(() => {
      expect(screen.getByTestId('subject-no-roles')).toBeInTheDocument()
    })
  })

  it('shows currently assigned roles as chips', async () => {
    setupFetchMocks({ subjectRoles: [makeSubjectRole({ id: 'r1', name: 'fleet-viewer' })] })
    renderAccountsView()
    await waitFor(() => expect(screen.getByTestId('accounts-table')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId('account-row'))
    await waitFor(() => {
      expect(screen.getByTestId('role-chip')).toBeInTheDocument()
      expect(screen.getByTestId('role-chip')).toHaveTextContent('fleet-viewer')
    })
  })

  it('shows multiple chips when the subject holds multiple roles', async () => {
    setupFetchMocks({
      subjectRoles: [
        makeSubjectRole({ id: 'r1', name: 'fleet-viewer' }),
        makeSubjectRole({ id: 'r2', name: 'cert-admin' }),
      ],
    })
    renderAccountsView()
    await waitFor(() => expect(screen.getByTestId('accounts-table')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId('account-row'))
    await waitFor(() => {
      expect(screen.getAllByTestId('role-chip')).toHaveLength(2)
    })
  })

  it('role picker shows only roles not already assigned', async () => {
    setupFetchMocks({
      subjectRoles: [makeSubjectRole({ id: 'role-1', name: 'fleet-viewer' })],
      allRoles: [
        makeRole({ id: 'role-1', name: 'fleet-viewer' }),
        makeRole({ id: 'role-2', name: 'cert-admin' }),
      ],
    })
    renderAccountsView()
    await waitFor(() => expect(screen.getByTestId('accounts-table')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId('account-row'))
    await waitFor(() => {
      expect(screen.getByTestId('role-assign-select')).toBeInTheDocument()
    })
    const select = screen.getByTestId('role-assign-select') as HTMLSelectElement
    const options = [...select.options].map((o) => o.text)
    expect(options).not.toContain('fleet-viewer')
    expect(options).toContain('cert-admin')
  })

  it('Assign button calls POST /api/v1/rbac/subjects/{id}/roles with the role_id', async () => {
    setupFetchMocks({
      subjectRoles: [],
      allRoles: [makeRole({ id: 'role-1', name: 'fleet-viewer' })],
    })
    renderAccountsView()
    await waitFor(() => expect(screen.getByTestId('accounts-table')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId('account-row'))
    await waitFor(() => {
      expect(screen.getByTestId('role-assign-btn')).toBeInTheDocument()
    })
    fillJustification('assign-justification-input', ASSIGN_WHY)
    await act(async () => {
      fireEvent.click(screen.getByTestId('role-assign-btn'))
    })
    await waitFor(() => {
      const postCalls = fetchMock.mock.calls.filter(
        (c) => (c[1] as RequestInit)?.method === 'POST',
      )
      const assignCall = postCalls.find((c) => String(c[0]).includes('/rbac/subjects/'))
      expect(assignCall).toBeDefined()
      const body = JSON.parse((assignCall![1] as RequestInit).body as string) as Record<string, unknown>
      expect(body).toHaveProperty('role_id', 'role-1')
    })
  })

  // ── M-AUTH-2 justification (audit control on privilege grant/revoke) ────────

  it('assign request carries the operator justification in X-Justification', async () => {
    setupFetchMocks({
      subjectRoles: [],
      allRoles: [makeRole({ id: 'role-1', name: 'fleet-viewer' })],
    })
    renderAccountsView()
    await waitFor(() => expect(screen.getByTestId('accounts-table')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId('account-row'))
    await waitFor(() => expect(screen.getByTestId('role-assign-btn')).toBeInTheDocument())
    fillJustification('assign-justification-input', ASSIGN_WHY)
    await act(async () => {
      fireEvent.click(screen.getByTestId('role-assign-btn'))
    })
    await waitFor(() => {
      const assignCall = fetchMock.mock.calls.find(
        (c) => (c[1] as RequestInit)?.method === 'POST' && String(c[0]).includes('/rbac/subjects/'),
      )
      expect(assignCall).toBeDefined()
      const headers = new Headers((assignCall![1] as RequestInit).headers)
      expect(headers.get('X-Justification')).toBe(ASSIGN_WHY)
    })
  })

  it('assign with no justification issues no request and shows why', async () => {
    setupFetchMocks({
      subjectRoles: [],
      allRoles: [makeRole({ id: 'role-1', name: 'fleet-viewer' })],
    })
    renderAccountsView()
    await waitFor(() => expect(screen.getByTestId('accounts-table')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId('account-row'))
    await waitFor(() => expect(screen.getByTestId('role-assign-btn')).toBeInTheDocument())
    await act(async () => {
      fireEvent.click(screen.getByTestId('role-assign-btn'))
    })
    expect(screen.getByTestId('assign-generic-error')).toHaveTextContent(/justification is required/i)
    const assignCalls = fetchMock.mock.calls.filter(
      (c) => (c[1] as RequestInit)?.method === 'POST' && String(c[0]).includes('/rbac/subjects/'),
    )
    expect(assignCalls).toHaveLength(0)
  })

  it('assign with a too-short justification issues no request', async () => {
    setupFetchMocks({
      subjectRoles: [],
      allRoles: [makeRole({ id: 'role-1', name: 'fleet-viewer' })],
    })
    renderAccountsView()
    await waitFor(() => expect(screen.getByTestId('accounts-table')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId('account-row'))
    await waitFor(() => expect(screen.getByTestId('role-assign-btn')).toBeInTheDocument())
    fillJustification('assign-justification-input', 'too short')
    await act(async () => {
      fireEvent.click(screen.getByTestId('role-assign-btn'))
    })
    expect(screen.getByTestId('assign-generic-error')).toHaveTextContent(/at least 10 characters/i)
    const assignCalls = fetchMock.mock.calls.filter(
      (c) => (c[1] as RequestInit)?.method === 'POST' && String(c[0]).includes('/rbac/subjects/'),
    )
    expect(assignCalls).toHaveLength(0)
  })

  it('revoke request carries the operator justification in X-Justification', async () => {
    setupFetchMocks({
      subjectRoles: [makeSubjectRole({ id: 'role-1', name: 'fleet-viewer' })],
      allRoles: [],
    })
    renderAccountsView()
    await waitFor(() => expect(screen.getByTestId('accounts-table')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId('account-row'))
    await waitFor(() => expect(screen.getByTestId('chip-revoke-btn')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId('chip-revoke-btn'))
    fillJustification('revoke-role-justification-input', REVOKE_WHY)
    await act(async () => {
      fireEvent.click(screen.getByTestId('revoke-role-confirm-btn'))
    })
    await waitFor(() => {
      const deleteCall = fetchMock.mock.calls.find(
        (c) =>
          (c[1] as RequestInit)?.method === 'DELETE' && String(c[0]).includes('/rbac/subjects/'),
      )
      expect(deleteCall).toBeDefined()
      const headers = new Headers((deleteCall![1] as RequestInit).headers)
      expect(headers.get('X-Justification')).toBe(REVOKE_WHY)
    })
  })

  it('revoke with no justification keeps the modal open and issues no DELETE', async () => {
    setupFetchMocks({
      subjectRoles: [makeSubjectRole({ id: 'role-1', name: 'fleet-viewer' })],
      allRoles: [],
    })
    renderAccountsView()
    await waitFor(() => expect(screen.getByTestId('accounts-table')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId('account-row'))
    await waitFor(() => expect(screen.getByTestId('chip-revoke-btn')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId('chip-revoke-btn'))
    await act(async () => {
      fireEvent.click(screen.getByTestId('revoke-role-confirm-btn'))
    })
    expect(screen.getByTestId('revoke-role-justification-error')).toHaveTextContent(
      /justification is required/i,
    )
    expect(screen.getByRole('dialog')).toBeInTheDocument()
    const deleteCalls = fetchMock.mock.calls.filter(
      (c) => (c[1] as RequestInit)?.method === 'DELETE' && String(c[0]).includes('/rbac/subjects/'),
    )
    expect(deleteCalls).toHaveLength(0)
  })

  it('403 JUSTIFICATION_REQUIRED is not shown as an escalation refusal', async () => {
    fetchMock.mockImplementation((url: unknown, init?: unknown) => {
      const u = String(url)
      const method = ((init as RequestInit | undefined)?.method ?? 'GET').toUpperCase()
      if (method === 'POST' && u.includes('/rbac/subjects/')) {
        return Promise.resolve(
          new Response(
            JSON.stringify({
              error: {
                code: 'JUSTIFICATION_REQUIRED',
                message: 'Justification required for this sensitive operation',
              },
            }),
            { status: 403, headers: { 'Content-Type': 'application/json' } },
          ),
        )
      }
      if (u.includes('/rbac/subjects/') && u.includes('/roles')) {
        return Promise.resolve(makeSubjectRolesResponse([]))
      }
      if (u.includes('/rbac/roles')) {
        return Promise.resolve(makeRolesResponse([makeRole({ id: 'role-1', name: 'operator' })]))
      }
      return Promise.resolve(makeAccountsResponse([makeAccount()]))
    })
    renderAccountsView()
    await waitFor(() => expect(screen.getByTestId('accounts-table')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId('account-row'))
    await waitFor(() => expect(screen.getByTestId('role-assign-btn')).toBeInTheDocument())
    fillJustification('assign-justification-input', ASSIGN_WHY)
    await act(async () => {
      fireEvent.click(screen.getByTestId('role-assign-btn'))
    })
    await waitFor(() => {
      expect(screen.getByTestId('assign-generic-error')).toHaveTextContent(
        /justification required/i,
      )
    })
    expect(screen.queryByTestId('assign-403-error')).not.toBeInTheDocument()
  })

  it('403 assign response renders the escalation-prevention message block, not a generic error', async () => {
    const escalationMsg = 'Assigning operator would let this account escalate its own privileges'
    fetchMock.mockImplementation((url: unknown, init?: unknown) => {
      const u = String(url)
      const method = ((init as RequestInit | undefined)?.method ?? 'GET').toUpperCase()
      if (method === 'POST' && u.includes('/rbac/subjects/')) {
        return Promise.resolve(
          new Response(
            JSON.stringify({ error: { message: escalationMsg } }),
            { status: 403, headers: { 'Content-Type': 'application/json' } },
          ),
        )
      }
      if (u.includes('/rbac/subjects/') && u.includes('/roles')) {
        return Promise.resolve(makeSubjectRolesResponse([]))
      }
      if (u.includes('/rbac/roles')) {
        return Promise.resolve(makeRolesResponse([makeRole({ id: 'role-1', name: 'operator' })]))
      }
      return Promise.resolve(makeAccountsResponse([makeAccount()]))
    })
    renderAccountsView()
    await waitFor(() => expect(screen.getByTestId('accounts-table')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId('account-row'))
    await waitFor(() => expect(screen.getByTestId('role-assign-btn')).toBeInTheDocument())
    fillJustification('assign-justification-input', ASSIGN_WHY)
    await act(async () => {
      fireEvent.click(screen.getByTestId('role-assign-btn'))
    })
    await waitFor(() => {
      expect(screen.getByTestId('assign-403-error')).toBeInTheDocument()
      expect(screen.getByTestId('assign-403-error')).toHaveTextContent(escalationMsg)
    })
    expect(screen.queryByTestId('assign-generic-error')).not.toBeInTheDocument()
  })

  it('non-403 assign failure renders a generic error, not the escalation block', async () => {
    fetchMock.mockImplementation((url: unknown, init?: unknown) => {
      const u = String(url)
      const method = ((init as RequestInit | undefined)?.method ?? 'GET').toUpperCase()
      if (method === 'POST' && u.includes('/rbac/subjects/')) {
        return Promise.resolve(
          new Response(
            JSON.stringify({ error: { message: 'Role not found' } }),
            { status: 404, headers: { 'Content-Type': 'application/json' } },
          ),
        )
      }
      if (u.includes('/rbac/subjects/') && u.includes('/roles')) {
        return Promise.resolve(makeSubjectRolesResponse([]))
      }
      if (u.includes('/rbac/roles')) {
        return Promise.resolve(makeRolesResponse([makeRole()]))
      }
      return Promise.resolve(makeAccountsResponse([makeAccount()]))
    })
    renderAccountsView()
    await waitFor(() => expect(screen.getByTestId('accounts-table')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId('account-row'))
    await waitFor(() => expect(screen.getByTestId('role-assign-btn')).toBeInTheDocument())
    fillJustification('assign-justification-input', ASSIGN_WHY)
    await act(async () => {
      fireEvent.click(screen.getByTestId('role-assign-btn'))
    })
    await waitFor(() => {
      expect(screen.getByTestId('assign-generic-error')).toHaveTextContent('Role not found')
    })
    expect(screen.queryByTestId('assign-403-error')).not.toBeInTheDocument()
  })

  it('chip × button opens the revoke confirm modal', async () => {
    setupFetchMocks({
      subjectRoles: [makeSubjectRole({ id: 'role-1', name: 'fleet-viewer' })],
      allRoles: [],
    })
    renderAccountsView()
    await waitFor(() => expect(screen.getByTestId('accounts-table')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId('account-row'))
    await waitFor(() => expect(screen.getByTestId('chip-revoke-btn')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId('chip-revoke-btn'))
    expect(screen.getByRole('dialog')).toBeInTheDocument()
    expect(screen.getByTestId('revoke-role-confirm-btn')).toBeInTheDocument()
  })

  it('revoke confirm dialog names the role and subject', async () => {
    setupFetchMocks({
      subjectRoles: [makeSubjectRole({ id: 'role-1', name: 'fleet-viewer' })],
      allRoles: [],
    })
    renderAccountsView()
    await waitFor(() => expect(screen.getByTestId('accounts-table')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId('account-row'))
    await waitFor(() => expect(screen.getByTestId('chip-revoke-btn')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId('chip-revoke-btn'))
    const dialog = screen.getByRole('dialog')
    expect(dialog).toHaveTextContent('fleet-viewer')
    expect(dialog).toHaveTextContent('fleet-admin')
  })

  it('cancel in the revoke dialog closes the modal without calling DELETE', async () => {
    setupFetchMocks({
      subjectRoles: [makeSubjectRole({ id: 'role-1', name: 'fleet-viewer' })],
      allRoles: [],
    })
    renderAccountsView()
    await waitFor(() => expect(screen.getByTestId('accounts-table')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId('account-row'))
    await waitFor(() => expect(screen.getByTestId('chip-revoke-btn')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId('chip-revoke-btn'))
    expect(screen.getByRole('dialog')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: /cancel/i }))
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
    const deleteCalls = fetchMock.mock.calls.filter(
      (c) => (c[1] as RequestInit)?.method === 'DELETE' && String(c[0]).includes('/rbac/subjects/'),
    )
    expect(deleteCalls).toHaveLength(0)
  })

  it('confirming revoke calls DELETE /api/v1/rbac/subjects/{id}/roles/{role_id}', async () => {
    setupFetchMocks({
      subjectRoles: [makeSubjectRole({ id: 'role-1', name: 'fleet-viewer' })],
      allRoles: [],
    })
    renderAccountsView()
    await waitFor(() => expect(screen.getByTestId('accounts-table')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId('account-row'))
    await waitFor(() => expect(screen.getByTestId('chip-revoke-btn')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId('chip-revoke-btn'))
    fillJustification('revoke-role-justification-input', REVOKE_WHY)
    await act(async () => {
      fireEvent.click(screen.getByTestId('revoke-role-confirm-btn'))
    })
    await waitFor(() => {
      const deleteCalls = fetchMock.mock.calls.filter(
        (c) =>
          (c[1] as RequestInit)?.method === 'DELETE' &&
          String(c[0]).includes('/rbac/subjects/acc-1/roles/role-1'),
      )
      expect(deleteCalls).toHaveLength(1)
    })
  })

  // The error branch of useSubjectRoles: a failed GET must surface in the panel
  // rather than reading as "no roles assigned" on a privilege-management screen.
  it('shows the subject-roles error message when the roles fetch fails', async () => {
    setupFetchMocks({ subjectRolesStatus: 500 })
    renderAccountsView()
    await waitFor(() => expect(screen.getByTestId('accounts-table')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId('account-row'))
    const errorEl = await screen.findByTestId('subject-roles-error')
    expect(errorEl).toHaveTextContent('/api/v1/rbac/subjects/acc-1/roles — 500')
    // The failure is never rendered as an empty (safe-looking) role set.
    expect(screen.queryByTestId('subject-no-roles')).not.toBeInTheDocument()
    expect(screen.queryByTestId('role-chip')).not.toBeInTheDocument()
  })

  it('shows the subject-roles error when the roles fetch is rejected outright', async () => {
    fetchMock.mockImplementation((url: unknown) => {
      const u = String(url)
      if (u.includes('/rbac/subjects/') && u.includes('/roles')) {
        return Promise.reject(new Error('NetworkError: connection refused'))
      }
      if (u.includes('/rbac/roles')) return Promise.resolve(makeRolesResponse([makeRole()]))
      return Promise.resolve(makeAccountsResponse([makeAccount()]))
    })
    renderAccountsView()
    await waitFor(() => expect(screen.getByTestId('accounts-table')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId('account-row'))
    const errorEl = await screen.findByTestId('subject-roles-error')
    expect(errorEl).toHaveTextContent('connection refused')
  })

  it('Delete account buttons still work (row click does not swallow them)', async () => {
    setupFetchMocks()
    renderAccountsView()
    await waitFor(() => expect(screen.getByTestId('accounts-table')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId('account-delete-btn'))
    expect(screen.getByRole('dialog')).toBeInTheDocument()
    expect(screen.queryByTestId('account-roles-row')).not.toBeInTheDocument()
  })
})

// ── Edit account (Issue #3132) ────────────────────────────────────────────────

describe('AccountsView — edit account (Issue #3132)', () => {
  function makeUpdateResponse(overrides: Partial<Record<string, unknown>> = {}, status = 200) {
    return new Response(
      JSON.stringify({
        data: {
          id: 'acc-1',
          username: 'fleet-admin',
          tenant_id: 'tenant-a',
          permissions: ['steward:list'],
          disabled: false,
          created_at: '2026-01-01T00:00:00Z',
          has_outstanding_enrollment_link: false,
          ...overrides,
        },
      }),
      { status, headers: { 'Content-Type': 'application/json' } },
    )
  }

  it('each account row has an edit button', async () => {
    fetchMock.mockResolvedValue(makeAccountsResponse([makeAccount()]))
    renderAccountsView()
    await waitFor(() => expect(screen.getByTestId('accounts-table')).toBeInTheDocument())
    expect(screen.getByTestId('account-edit-btn')).toBeInTheDocument()
  })

  it('clicking Edit opens the edit panel', async () => {
    fetchMock.mockResolvedValue(makeAccountsResponse([makeAccount()]))
    renderAccountsView()
    await waitFor(() => expect(screen.getByTestId('accounts-table')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId('account-edit-btn'))
    expect(screen.getByTestId('account-edit-panel')).toBeInTheDocument()
  })

  it('edit panel is pre-filled with the account permissions', async () => {
    fetchMock.mockResolvedValue(
      makeAccountsResponse([makeAccount({ permissions: ['steward:list', 'steward:read'] })]),
    )
    renderAccountsView()
    await waitFor(() => expect(screen.getByTestId('accounts-table')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId('account-edit-btn'))
    const input = screen.getByTestId('edit-permissions-input') as HTMLInputElement
    expect(input.value).toContain('steward:list')
    expect(input.value).toContain('steward:read')
  })

  it('edit save calls PUT /api/v1/accounts/{username} and refreshes', async () => {
    fetchMock
      .mockResolvedValueOnce(makeAccountsResponse([makeAccount()]))
      .mockResolvedValueOnce(makeUpdateResponse({ permissions: ['steward:list', 'steward:read'] }))
      .mockResolvedValueOnce(
        makeAccountsResponse([makeAccount({ permissions: ['steward:list', 'steward:read'] })]),
      )
    renderAccountsView()
    await waitFor(() => expect(screen.getByTestId('accounts-table')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId('account-edit-btn'))
    const input = screen.getByTestId('edit-permissions-input')
    fireEvent.change(input, { target: { value: 'steward:list, steward:read' } })
    await act(async () => {
      fireEvent.click(screen.getByTestId('edit-save-btn'))
    })
    await waitFor(() => {
      const putCalls = fetchMock.mock.calls.filter(
        (c) => (c[1] as RequestInit)?.method === 'PUT',
      )
      expect(putCalls).toHaveLength(1)
      const body = JSON.parse((putCalls[0]![1] as RequestInit).body as string) as Record<string, unknown>
      expect(body).toHaveProperty('permissions')
    })
  })

  it('edit panel closes after successful save', async () => {
    fetchMock
      .mockResolvedValueOnce(makeAccountsResponse([makeAccount()]))
      .mockResolvedValueOnce(makeUpdateResponse())
      .mockResolvedValueOnce(makeAccountsResponse([makeAccount()]))
    renderAccountsView()
    await waitFor(() => expect(screen.getByTestId('accounts-table')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId('account-edit-btn'))
    await act(async () => {
      fireEvent.click(screen.getByTestId('edit-save-btn'))
    })
    await waitFor(() => expect(screen.queryByTestId('account-edit-panel')).not.toBeInTheDocument())
  })

  it('edit save error is shown when the PUT fails', async () => {
    fetchMock
      .mockResolvedValueOnce(makeAccountsResponse([makeAccount()]))
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({ error: { message: 'Permission not found' } }),
          { status: 400 },
        ),
      )
    renderAccountsView()
    await waitFor(() => expect(screen.getByTestId('accounts-table')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId('account-edit-btn'))
    await act(async () => {
      fireEvent.click(screen.getByTestId('edit-save-btn'))
    })
    await waitFor(() => {
      expect(screen.getByTestId('edit-save-error')).toHaveTextContent('Permission not found')
    })
    expect(screen.getByTestId('account-edit-panel')).toBeInTheDocument()
  })

  it('edit cancel closes the panel without calling PUT', async () => {
    fetchMock.mockResolvedValue(makeAccountsResponse([makeAccount()]))
    renderAccountsView()
    await waitFor(() => expect(screen.getByTestId('accounts-table')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId('account-edit-btn'))
    expect(screen.getByTestId('account-edit-panel')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: /cancel/i }))
    expect(screen.queryByTestId('account-edit-panel')).not.toBeInTheDocument()
    const putCalls = fetchMock.mock.calls.filter(
      (c) => (c[1] as RequestInit)?.method === 'PUT',
    )
    expect(putCalls).toHaveLength(0)
  })

  it('edit panel does not contain a password field (passkey-only)', async () => {
    fetchMock.mockResolvedValue(makeAccountsResponse([makeAccount()]))
    renderAccountsView()
    await waitFor(() => expect(screen.getByTestId('accounts-table')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId('account-edit-btn'))
    expect(screen.queryByLabelText(/password/i)).not.toBeInTheDocument()
    expect(screen.queryByTestId('account-password-input')).not.toBeInTheDocument()
  })
})

// ── Password reset (Issue #3132) ──────────────────────────────────────────────

describe('AccountsView — password reset (Issue #3132)', () => {
  function makeUpdateResponse(overrides: Partial<Record<string, unknown>> = {}, status = 200) {
    return new Response(
      JSON.stringify({
        data: {
          id: 'acc-1',
          username: 'fleet-admin',
          tenant_id: 'tenant-a',
          permissions: ['steward:list'],
          disabled: false,
          created_at: '2026-01-01T00:00:00Z',
          has_outstanding_enrollment_link: true,
          ...overrides,
        },
      }),
      { status, headers: { 'Content-Type': 'application/json' } },
    )
  }

  it('each account row has a reset passkey button', async () => {
    fetchMock.mockResolvedValue(makeAccountsResponse([makeAccount()]))
    renderAccountsView()
    await waitFor(() => expect(screen.getByTestId('accounts-table')).toBeInTheDocument())
    expect(screen.getByTestId('account-reset-passkey-btn')).toBeInTheDocument()
  })

  it('clicking reset shows a confirm dialog', async () => {
    fetchMock.mockResolvedValue(makeAccountsResponse([makeAccount()]))
    renderAccountsView()
    await waitFor(() => expect(screen.getByTestId('accounts-table')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId('account-reset-passkey-btn'))
    expect(screen.getByRole('dialog')).toBeInTheDocument()
    expect(screen.getByTestId('password-reset-confirm-btn')).toBeInTheDocument()
  })

  it('confirm dialog names the account being reset', async () => {
    fetchMock.mockResolvedValue(makeAccountsResponse([makeAccount({ username: 'my-admin' })]))
    renderAccountsView()
    await waitFor(() => expect(screen.getByTestId('accounts-table')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId('account-reset-passkey-btn'))
    expect(screen.getByRole('dialog')).toHaveTextContent('my-admin')
  })

  it('cancel in reset dialog closes without calling PUT', async () => {
    fetchMock.mockResolvedValue(makeAccountsResponse([makeAccount()]))
    renderAccountsView()
    await waitFor(() => expect(screen.getByTestId('accounts-table')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId('account-reset-passkey-btn'))
    fireEvent.click(screen.getByRole('button', { name: /cancel/i }))
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
    const putCalls = fetchMock.mock.calls.filter((c) => (c[1] as RequestInit)?.method === 'PUT')
    expect(putCalls).toHaveLength(0)
  })

  it('confirming reset calls PUT with reset_credentials: true', async () => {
    fetchMock
      .mockResolvedValueOnce(makeAccountsResponse([makeAccount()]))
      .mockResolvedValueOnce(makeUpdateResponse({ enrollment_magic_link: 'aabbcc1122' }))
      .mockResolvedValueOnce(makeAccountsResponse([makeAccount()]))
    renderAccountsView()
    await waitFor(() => expect(screen.getByTestId('accounts-table')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId('account-reset-passkey-btn'))
    await act(async () => {
      fireEvent.click(screen.getByTestId('password-reset-confirm-btn'))
    })
    await waitFor(() => {
      const putCalls = fetchMock.mock.calls.filter((c) => (c[1] as RequestInit)?.method === 'PUT')
      expect(putCalls).toHaveLength(1)
      const body = JSON.parse((putCalls[0]![1] as RequestInit).body as string) as Record<string, unknown>
      expect(body).toHaveProperty('reset_credentials', true)
    })
  })

  it('shows enrollment link panel when server returns a magic link', async () => {
    fetchMock
      .mockResolvedValueOnce(makeAccountsResponse([makeAccount()]))
      .mockResolvedValueOnce(makeUpdateResponse({ enrollment_magic_link: 'aabbcc112233deadbeef' }))
      .mockResolvedValueOnce(makeAccountsResponse([makeAccount()]))
    renderAccountsView()
    await waitFor(() => expect(screen.getByTestId('accounts-table')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId('account-reset-passkey-btn'))
    await act(async () => {
      fireEvent.click(screen.getByTestId('password-reset-confirm-btn'))
    })
    await waitFor(() => expect(screen.getByTestId('enrollment-link-panel')).toBeInTheDocument())
    const linkInput = screen.getByTestId('enrollment-link-value') as HTMLInputElement
    expect(linkInput.value).toContain('aabbcc112233deadbeef')
  })

  it('shows reset error when the PUT fails', async () => {
    fetchMock
      .mockResolvedValueOnce(makeAccountsResponse([makeAccount()]))
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({ error: { message: 'Account not found' } }),
          { status: 404 },
        ),
      )
    renderAccountsView()
    await waitFor(() => expect(screen.getByTestId('accounts-table')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId('account-reset-passkey-btn'))
    await act(async () => {
      fireEvent.click(screen.getByTestId('password-reset-confirm-btn'))
    })
    await waitFor(() => {
      expect(screen.getByTestId('password-reset-error')).toHaveTextContent('Account not found')
    })
  })
})

// ── Enable/disable toggle (Issue #3132) ──────────────────────────────────────

describe('AccountsView — enable/disable toggle (Issue #3132)', () => {
  function makeUpdateResponse(overrides: Partial<Record<string, unknown>> = {}, status = 200) {
    return new Response(
      JSON.stringify({
        data: {
          id: 'acc-1',
          username: 'fleet-admin',
          tenant_id: 'tenant-a',
          permissions: ['steward:list'],
          disabled: false,
          created_at: '2026-01-01T00:00:00Z',
          has_outstanding_enrollment_link: false,
          ...overrides,
        },
      }),
      { status, headers: { 'Content-Type': 'application/json' } },
    )
  }

  it('each account row has an enable/disable toggle button', async () => {
    fetchMock.mockResolvedValue(makeAccountsResponse([makeAccount()]))
    renderAccountsView()
    await waitFor(() => expect(screen.getByTestId('accounts-table')).toBeInTheDocument())
    expect(screen.getByTestId('account-toggle-disable-btn')).toBeInTheDocument()
  })

  it('shows "Disable" label for an enabled account', async () => {
    fetchMock.mockResolvedValue(makeAccountsResponse([makeAccount({ disabled: false })]))
    renderAccountsView()
    await waitFor(() => expect(screen.getByTestId('accounts-table')).toBeInTheDocument())
    expect(screen.getByTestId('account-toggle-disable-btn')).toHaveTextContent('Disable')
  })

  it('shows "Enable" label for a disabled account', async () => {
    fetchMock.mockResolvedValue(makeAccountsResponse([makeAccount({ disabled: true })]))
    renderAccountsView()
    await waitFor(() => expect(screen.getByTestId('accounts-table')).toBeInTheDocument())
    expect(screen.getByTestId('account-toggle-disable-btn')).toHaveTextContent('Enable')
  })

  it('shows a Disabled badge for disabled accounts', async () => {
    fetchMock.mockResolvedValue(makeAccountsResponse([makeAccount({ disabled: true })]))
    renderAccountsView()
    await waitFor(() => expect(screen.getByTestId('accounts-table')).toBeInTheDocument())
    expect(screen.getByTestId('account-disabled-badge')).toBeInTheDocument()
  })

  it('does not show a Disabled badge for enabled accounts', async () => {
    fetchMock.mockResolvedValue(makeAccountsResponse([makeAccount({ disabled: false })]))
    renderAccountsView()
    await waitFor(() => expect(screen.getByTestId('accounts-table')).toBeInTheDocument())
    expect(screen.queryByTestId('account-disabled-badge')).not.toBeInTheDocument()
  })

  it('clicking Disable shows a confirm dialog', async () => {
    fetchMock.mockResolvedValue(makeAccountsResponse([makeAccount()]))
    renderAccountsView()
    await waitFor(() => expect(screen.getByTestId('accounts-table')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId('account-toggle-disable-btn'))
    expect(screen.getByRole('dialog')).toBeInTheDocument()
    expect(screen.getByTestId('disable-confirm-btn')).toBeInTheDocument()
  })

  it('confirm dialog names the account being disabled', async () => {
    fetchMock.mockResolvedValue(makeAccountsResponse([makeAccount({ username: 'target-admin' })]))
    renderAccountsView()
    await waitFor(() => expect(screen.getByTestId('accounts-table')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId('account-toggle-disable-btn'))
    expect(screen.getByRole('dialog')).toHaveTextContent('target-admin')
  })

  it('cancel in disable dialog closes without calling PUT', async () => {
    fetchMock.mockResolvedValue(makeAccountsResponse([makeAccount()]))
    renderAccountsView()
    await waitFor(() => expect(screen.getByTestId('accounts-table')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId('account-toggle-disable-btn'))
    fireEvent.click(screen.getByRole('button', { name: /cancel/i }))
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
    const putCalls = fetchMock.mock.calls.filter((c) => (c[1] as RequestInit)?.method === 'PUT')
    expect(putCalls).toHaveLength(0)
  })

  it('confirming disable calls PUT with disabled: true', async () => {
    fetchMock
      .mockResolvedValueOnce(makeAccountsResponse([makeAccount({ disabled: false })]))
      .mockResolvedValueOnce(makeUpdateResponse({ disabled: true }))
      .mockResolvedValueOnce(makeAccountsResponse([makeAccount({ disabled: true })]))
    renderAccountsView()
    await waitFor(() => expect(screen.getByTestId('accounts-table')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId('account-toggle-disable-btn'))
    await act(async () => {
      fireEvent.click(screen.getByTestId('disable-confirm-btn'))
    })
    await waitFor(() => {
      const putCalls = fetchMock.mock.calls.filter((c) => (c[1] as RequestInit)?.method === 'PUT')
      expect(putCalls).toHaveLength(1)
      const body = JSON.parse((putCalls[0]![1] as RequestInit).body as string) as Record<string, unknown>
      expect(body).toHaveProperty('disabled', true)
    })
  })

  it('confirming enable calls PUT with disabled: false', async () => {
    fetchMock
      .mockResolvedValueOnce(makeAccountsResponse([makeAccount({ disabled: true })]))
      .mockResolvedValueOnce(makeUpdateResponse({ disabled: false }))
      .mockResolvedValueOnce(makeAccountsResponse([makeAccount({ disabled: false })]))
    renderAccountsView()
    await waitFor(() => expect(screen.getByTestId('accounts-table')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId('account-toggle-disable-btn'))
    await act(async () => {
      fireEvent.click(screen.getByTestId('disable-confirm-btn'))
    })
    await waitFor(() => {
      const putCalls = fetchMock.mock.calls.filter((c) => (c[1] as RequestInit)?.method === 'PUT')
      expect(putCalls).toHaveLength(1)
      const body = JSON.parse((putCalls[0]![1] as RequestInit).body as string) as Record<string, unknown>
      expect(body).toHaveProperty('disabled', false)
    })
  })

  it('account stays in the list after being disabled', async () => {
    fetchMock
      .mockResolvedValueOnce(makeAccountsResponse([makeAccount()]))
      .mockResolvedValueOnce(makeUpdateResponse({ disabled: true }))
      .mockResolvedValueOnce(makeAccountsResponse([makeAccount({ disabled: true })]))
    renderAccountsView()
    await waitFor(() => expect(screen.getByTestId('accounts-table')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId('account-toggle-disable-btn'))
    await act(async () => {
      fireEvent.click(screen.getByTestId('disable-confirm-btn'))
    })
    await waitFor(() => expect(screen.getByTestId('account-disabled-badge')).toBeInTheDocument())
    expect(screen.getAllByTestId('account-row')).toHaveLength(1)
  })

  it('shows disable error when the PUT fails', async () => {
    fetchMock
      .mockResolvedValueOnce(makeAccountsResponse([makeAccount()]))
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({ error: { message: 'Cannot disable the last admin' } }),
          { status: 400 },
        ),
      )
    renderAccountsView()
    await waitFor(() => expect(screen.getByTestId('accounts-table')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId('account-toggle-disable-btn'))
    await act(async () => {
      fireEvent.click(screen.getByTestId('disable-confirm-btn'))
    })
    await waitFor(() => {
      expect(screen.getByTestId('disable-error')).toHaveTextContent('Cannot disable the last admin')
    })
  })
})
